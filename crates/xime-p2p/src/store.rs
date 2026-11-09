//! 已配对设备表（§6.2）。
//!
//! 落盘为单个 JSON 文件，写入采用「临时文件 + rename」保证原子性：
//! 中途断电只会丢失本次更新，不会留下半个文件把整张表读废。
//!
//! 与同步配置不同，**解析失败必须报错而不是回落默认值**：
//! 表里是用户已建立的信任关系，静默清空等于把所有设备退回到未配对状态。
//! 因此 [`PeerStore::load`] 在文件存在但内容非法时返回 [`Error::Store`]。

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::Error;
use crate::identity::{Did, PublicIdentity};

/// 存储格式版本。升级格式时递增，并在此处做迁移。
const STORE_VERSION: u32 = 1;

/// 一个已配对的对端。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairedPeer {
    /// 设备标识，32 位小写 hex。
    pub did: String,
    /// 对端自报的设备名，仅用于 UI，不参与任何校验。
    pub name: String,
    /// Ed25519 身份公钥，hex。
    pub pub_ed: String,
    /// X25519 静态公钥，hex（Noise IK 的目标）。
    pub pub_x25519: String,
    /// 最近一次成功连接的地址 `ip:port`，用于发现失败时直连。
    #[serde(default)]
    pub last_addr: Option<String>,
    /// 配对完成时间（Unix 秒）。
    #[serde(default)]
    pub paired_at: i64,
}

impl PairedPeer {
    /// 由对端公开身份构造。
    pub fn from_public(public: &PublicIdentity, last_addr: Option<String>) -> Self {
        Self {
            did: public.did().to_hex(),
            name: public.name().to_string(),
            pub_ed: hex::encode(public.ed_public()),
            pub_x25519: hex::encode(public.x_public()),
            last_addr,
            paired_at: now_unix(),
        }
    }

    /// 还原为可校验的公开身份（会重新派生并比对 `did`）。
    pub fn public_identity(&self) -> Result<PublicIdentity, Error> {
        let did = Did::from_hex(&self.did)?;
        let ed = decode32(&self.pub_ed, "pub_ed")?;
        let x = decode32(&self.pub_x25519, "pub_x25519")?;
        PublicIdentity::from_parts(&did, &ed, &x, self.name.clone())
    }

    pub fn did(&self) -> Result<Did, Error> {
        Did::from_hex(&self.did)
    }

    /// 供日志展示的短名。
    pub fn label(&self) -> String {
        format!("{} ({})", self.name, &self.did[..self.did.len().min(8)])
    }
}

/// 已配对设备表。
///
/// `Clone` 是有意提供的：连接处理需要在握手期间持有一份稳定快照，
/// 避免与配对写入争锁。配对表只有几项，克隆成本可忽略。
#[derive(Debug, Clone)]
pub struct PeerStore {
    path: PathBuf,
    peers: BTreeMap<String, PairedPeer>,
}

impl PeerStore {
    /// 从磁盘加载；文件不存在视为空表。
    pub fn load(path: impl Into<PathBuf>) -> Result<Self, Error> {
        let path = path.into();
        if !path.exists() {
            return Ok(Self {
                path,
                peers: BTreeMap::new(),
            });
        }
        let raw = std::fs::read_to_string(&path).map_err(|e| store_err(&path, e))?;
        let file: StoreFile = serde_json::from_str(&raw).map_err(|e| {
            Error::Store(format!(
                "已配对表解析失败（{}）：{e}。文件未改动，请修复或删除后重新配对",
                path.display()
            ))
        })?;
        if file.version > STORE_VERSION {
            return Err(Error::Store(format!(
                "已配对表版本 {} 高于本程序支持的 {STORE_VERSION}",
                file.version
            )));
        }
        let peers = file
            .peers
            .into_iter()
            .map(|p| (p.did.clone(), p))
            .collect::<BTreeMap<_, _>>();
        Ok(Self { path, peers })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// 从磁盘重新读取配对表（内存内容被整体替换）。
    ///
    /// 设置应用与输入法是两个进程：配对在设置里完成，常驻的输入法进程若不重读，
    /// 会一直认为新设备未配对——用户看到的是「配对成功了，但剪贴板同步不过来」。
    /// 文件不存在视为空表（与 [`Self::load`] 一致）。
    pub fn reload(&mut self) -> Result<(), Error> {
        let fresh = Self::load(&self.path)?;
        self.peers = fresh.peers;
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.peers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }

    pub fn get(&self, did: &str) -> Option<&PairedPeer> {
        self.peers.get(did)
    }

    /// 按 X25519 静态公钥反查。Responder 用它把 Noise 握手识别到的密钥映射到设备。
    pub fn by_x25519(&self, pub_x25519: &[u8; 32]) -> Option<&PairedPeer> {
        let want = hex::encode(pub_x25519);
        self.peers.values().find(|p| p.pub_x25519 == want)
    }

    pub fn all(&self) -> impl Iterator<Item = &PairedPeer> {
        self.peers.values()
    }

    /// 插入或更新并立即落盘。
    pub fn upsert(&mut self, peer: PairedPeer) -> Result<(), Error> {
        self.peers.insert(peer.did.clone(), peer);
        self.save()
    }

    /// 删除并落盘，返回是否确实删掉了。
    pub fn remove(&mut self, did: &str) -> Result<bool, Error> {
        let existed = self.peers.remove(did).is_some();
        if existed {
            self.save()?;
        }
        Ok(existed)
    }

    /// 记录最近一次成功连接的地址。
    pub fn set_last_addr(&mut self, did: &str, addr: impl Into<String>) -> Result<(), Error> {
        let addr = addr.into();
        let Some(peer) = self.peers.get_mut(did) else {
            return Err(Error::Store(format!("未找到已配对设备 {did}")));
        };
        if peer.last_addr.as_deref() == Some(addr.as_str()) {
            return Ok(());
        }
        peer.last_addr = Some(addr);
        self.save()
    }

    /// 原子写入：写临时文件 → 落盘 → rename 覆盖。
    pub fn save(&self) -> Result<(), Error> {
        if let Some(parent) = self.path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent).map_err(|e| store_err(parent, e))?;
        }
        let file = StoreFile {
            version: STORE_VERSION,
            peers: self.peers.values().cloned().collect(),
        };
        let json = serde_json::to_vec_pretty(&file)
            .map_err(|e| Error::Store(format!("序列化已配对表失败: {e}")))?;

        let tmp = self.path.with_extension("json.tmp");
        {
            use std::io::Write;
            let mut f = std::fs::File::create(&tmp).map_err(|e| store_err(&tmp, e))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                // 表里是设备公钥与地址，不是秘密，但没必要让同机其他用户读到。
                let _ = f.set_permissions(std::fs::Permissions::from_mode(0o600));
            }
            f.write_all(&json).map_err(|e| store_err(&tmp, e))?;
            f.sync_all().map_err(|e| store_err(&tmp, e))?;
        }
        std::fs::rename(&tmp, &self.path).map_err(|e| store_err(&self.path, e))?;
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
struct StoreFile {
    version: u32,
    #[serde(default)]
    peers: Vec<PairedPeer>,
}

fn decode32(value: &str, field: &str) -> Result<[u8; 32], Error> {
    let raw = hex::decode(value).map_err(|e| Error::Store(format!("{field} 不是合法 hex: {e}")))?;
    raw.try_into()
        .map_err(|_| Error::Store(format!("{field} 长度应为 32 字节")))
}

fn store_err(path: &Path, e: std::io::Error) -> Error {
    Error::Store(format!("{}: {e}", path.display()))
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;

    fn peer(seed: u8, name: &str) -> PairedPeer {
        let id = Identity::from_seed(&[seed; 32]);
        PairedPeer::from_public(&id.public(name), None)
    }

    #[test]
    fn 插入后重新加载仍在() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("peers.json");

        let mut store = PeerStore::load(&path).unwrap();
        assert!(store.is_empty());
        let p = peer(1, "MacBook");
        let did = p.did.clone();
        store.upsert(p.clone()).unwrap();

        let reloaded = PeerStore::load(&path).unwrap();
        assert_eq!(reloaded.len(), 1);
        let got = reloaded.get(&did).unwrap();
        assert_eq!(got.name, "MacBook");
        assert_eq!(got.pub_x25519, p.pub_x25519);
        assert!(got.public_identity().is_ok());
    }

    #[test]
    fn 按_x25519_反查() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = PeerStore::load(dir.path().join("peers.json")).unwrap();
        let p = peer(2, "PC");
        let x: [u8; 32] = hex::decode(&p.pub_x25519).unwrap().try_into().unwrap();
        store.upsert(p.clone()).unwrap();

        assert_eq!(store.by_x25519(&x).unwrap().did, p.did);
        assert!(store.by_x25519(&[0u8; 32]).is_none());
    }

    #[test]
    fn 删除后落盘() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("peers.json");
        let mut store = PeerStore::load(&path).unwrap();
        let p = peer(3, "Old");
        let did = p.did.clone();
        store.upsert(p).unwrap();

        assert!(store.remove(&did).unwrap());
        assert!(!store.remove(&did).unwrap());
        assert!(PeerStore::load(&path).unwrap().is_empty());
    }

    #[test]
    fn 记录上次地址且不重复写盘() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = PeerStore::load(dir.path().join("peers.json")).unwrap();
        let p = peer(4, "Laptop");
        let did = p.did.clone();
        store.upsert(p).unwrap();

        store.set_last_addr(&did, "192.168.1.9:47821").unwrap();
        assert_eq!(
            store.get(&did).unwrap().last_addr.as_deref(),
            Some("192.168.1.9:47821")
        );
        store.set_last_addr(&did, "192.168.1.9:47821").unwrap();
        let reloaded = PeerStore::load(store.path()).unwrap();
        assert_eq!(
            reloaded.get(&did).unwrap().last_addr.as_deref(),
            Some("192.168.1.9:47821")
        );
    }

    #[test]
    fn 未配对设备写地址时报错() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = PeerStore::load(dir.path().join("peers.json")).unwrap();
        assert!(store.set_last_addr("deadbeef", "1.2.3.4:1").is_err());
    }

    #[test]
    fn 文件损坏时报错而非清空() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("peers.json");
        std::fs::write(&path, "{ this is not json").unwrap();
        let err = PeerStore::load(&path).unwrap_err();
        assert!(matches!(err, Error::Store(_)));
        // 原文件必须保持不变，便于人工修复
        assert!(std::fs::read_to_string(&path).unwrap().contains("not json"));
    }

    #[test]
    fn 高版本表被拒绝() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("peers.json");
        std::fs::write(&path, r#"{"version":99,"peers":[]}"#).unwrap();
        assert!(matches!(PeerStore::load(&path), Err(Error::Store(_))));
    }

    #[test]
    fn 篡改_did_后身份校验失败() {
        let mut p = peer(5, "Victim");
        p.did = "00".repeat(16);
        assert!(p.public_identity().is_err());
    }
}
