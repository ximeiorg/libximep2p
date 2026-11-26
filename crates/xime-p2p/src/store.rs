//! 已配对设备：**读接口**与最小内存实现。
//!
//! 存储不属于协议层。这个 crate 只认识「谁已经配对过」这件事——
//! 它需要 `by_x25519` 来验证入站握手，需要 `set_last_addr` 记住上次连通的地址，
//! 但**数据存在哪、用什么格式、要不要加密、谁负责迁移，全归客户端**：
//!
//! | 宿主 | 实现 |
//! |---|---|
//! | macOS 桌面 | 统一库 `xime.db` 里的 `p2p_peers` 表（与 Android Room 对齐） |
//! | Android | Room（界面侧已经在存） |
//! | 鸿蒙 | 宿主自定，经 C ABI 传 JSON 进来 |
//!
//! 因此这里只有 [`PeerBook`] 这个 trait 和一个 [`MemoryPeerBook`]（供测试、
//! 以及「宿主自己管持久化、只在启动时灌一次」的绑定层使用）。
//! 协议层不引入任何数据库、不写任何文件。

use std::collections::BTreeMap;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use crate::error::Error;
use crate::identity::{Did, PublicIdentity};

/// 一个已配对的对端。
///
/// 这是**协议与信任记录**，不是存储格式：谁存、怎么存由宿主决定。
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
    /// 最后一次确认在线的时刻（Unix 秒）。
    ///
    /// 界面在节点刚启动、还没连上任何设备时，靠它显示「上次在线 …」，
    /// 而不是干巴巴一句「离线」。
    #[serde(default)]
    pub last_seen: Option<i64>,
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
            last_seen: None,
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

/// 已配对设备的查询与更新。
///
/// 实现方负责持久化与并发。**方法都取 `&self`**：节点会从多个任务同时调用，
/// 实现内部自己加锁（或直接查库）。返回 owned 值，避免把实现的锁泄漏到协议层。
pub trait PeerBook: Send + Sync {
    /// 按 `did` 取一台设备。
    fn get(&self, did: &str) -> Option<PairedPeer>;

    /// 按 X25519 静态公钥反查。接入方用它把 Noise 握手识别到的密钥映射到设备。
    fn by_x25519(&self, pub_x25519: &[u8; 32]) -> Option<PairedPeer>;

    /// 全部已配对设备。节点用它做重连与状态展示。
    fn all(&self) -> Vec<PairedPeer>;

    /// 插入或更新信任锚（配对完成时调用）。
    ///
    /// **不应覆盖运行时状态**：重配对（换名字、换公钥）不该把学到的地址清掉。
    fn upsert(&self, peer: PairedPeer) -> Result<(), Error>;

    /// 删除一台设备，返回是否确实删掉了。
    fn remove(&self, did: &str) -> Result<bool, Error>;

    /// 记录最近一次成功连接的地址。
    fn set_last_addr(&self, did: &str, addr: &str) -> Result<(), Error>;

    /// 记录最后一次确认在线的时刻。
    fn set_last_seen(&self, did: &str, at: i64) -> Result<(), Error>;
}

/// 纯内存实现。
///
/// 用途有两个：测试；以及绑定层（JNI / NAPI）——那里宿主自己管存储，
/// 启动时把已配对设备灌进来，之后通过 [`crate::Node::status`] 读回运行时状态自行落盘。
#[derive(Debug, Default)]
pub struct MemoryPeerBook {
    peers: Mutex<BTreeMap<String, PairedPeer>>,
}

impl MemoryPeerBook {
    pub fn new() -> Self {
        Self::default()
    }

    /// 由一批设备构造（已有同 `did` 的按后者覆盖）。
    pub fn from_peers(peers: impl IntoIterator<Item = PairedPeer>) -> Self {
        let book = Self::new();
        for peer in peers {
            let _ = book.upsert(peer);
        }
        book
    }

    /// 用一批设备整体替换现有内容（宿主配对/忘记之后同步用）。
    pub fn replace_all(&self, peers: impl IntoIterator<Item = PairedPeer>) {
        if let Ok(mut guard) = self.peers.lock() {
            guard.clear();
            for peer in peers {
                guard.insert(peer.did.clone(), peer);
            }
        }
    }
}

impl PeerBook for MemoryPeerBook {
    fn get(&self, did: &str) -> Option<PairedPeer> {
        self.peers.lock().ok()?.get(did).cloned()
    }

    fn by_x25519(&self, pub_x25519: &[u8; 32]) -> Option<PairedPeer> {
        let want = hex::encode(pub_x25519);
        self.peers
            .lock()
            .ok()?
            .values()
            .find(|p| p.pub_x25519 == want)
            .cloned()
    }

    fn all(&self) -> Vec<PairedPeer> {
        self.peers
            .lock()
            .map(|m| m.values().cloned().collect())
            .unwrap_or_default()
    }

    fn upsert(&self, peer: PairedPeer) -> Result<(), Error> {
        let Ok(mut guard) = self.peers.lock() else {
            return Err(Error::Store("设备表锁不可用".into()));
        };
        // 与持久化实现保持一致：信任锚更新，运行时状态保留。
        let mut merged = peer;
        if let Some(existing) = guard.get(&merged.did) {
            merged.last_addr = merged.last_addr.or_else(|| existing.last_addr.clone());
            merged.last_seen = merged.last_seen.or(existing.last_seen);
        }
        guard.insert(merged.did.clone(), merged);
        Ok(())
    }

    fn remove(&self, did: &str) -> Result<bool, Error> {
        let Ok(mut guard) = self.peers.lock() else {
            return Err(Error::Store("设备表锁不可用".into()));
        };
        Ok(guard.remove(did).is_some())
    }

    fn set_last_addr(&self, did: &str, addr: &str) -> Result<(), Error> {
        let Ok(mut guard) = self.peers.lock() else {
            return Err(Error::Store("设备表锁不可用".into()));
        };
        let Some(peer) = guard.get_mut(did) else {
            return Err(Error::Store(format!("未找到已配对设备 {did}")));
        };
        peer.last_addr = Some(addr.to_string());
        Ok(())
    }

    fn set_last_seen(&self, did: &str, at: i64) -> Result<(), Error> {
        let Ok(mut guard) = self.peers.lock() else {
            return Err(Error::Store("设备表锁不可用".into()));
        };
        let Some(peer) = guard.get_mut(did) else {
            return Err(Error::Store(format!("未找到已配对设备 {did}")));
        };
        if peer.last_seen.is_some_and(|prev| at <= prev) {
            return Ok(());
        }
        peer.last_seen = Some(at);
        Ok(())
    }
}

fn decode32(value: &str, field: &str) -> Result<[u8; 32], Error> {
    let raw = hex::decode(value).map_err(|e| Error::Store(format!("{field} 不是合法 hex: {e}")))?;
    raw.try_into()
        .map_err(|_| Error::Store(format!("{field} 长度应为 32 字节")))
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
    fn 插入后可查且按_x25519_反查() {
        let book = MemoryPeerBook::new();
        let p = peer(1, "MacBook");
        let x: [u8; 32] = hex::decode(&p.pub_x25519).unwrap().try_into().unwrap();
        book.upsert(p.clone()).unwrap();

        assert_eq!(book.get(&p.did).unwrap().name, "MacBook");
        assert_eq!(book.by_x25519(&x).unwrap().did, p.did);
        assert!(book.by_x25519(&[0u8; 32]).is_none());
        assert_eq!(book.all().len(), 1);
    }

    #[test]
    fn 删除后不再出现() {
        let book = MemoryPeerBook::new();
        let p = peer(2, "Old");
        let did = p.did.clone();
        book.upsert(p.clone()).unwrap();
        assert!(book.remove(&did).unwrap());
        assert!(!book.remove(&did).unwrap());
        assert!(book.all().is_empty());
    }

    #[test]
    fn 未配对设备写地址时报错() {
        let book = MemoryPeerBook::new();
        assert!(book.set_last_addr("deadbeef", "1.2.3.4:1").is_err());
    }

    /// 重配对（换名字）不能把学到的地址清掉——地址是运行时状态，不属于信任锚。
    #[test]
    fn 重新配对保留运行时状态() {
        let book = MemoryPeerBook::new();
        let p = peer(3, "Old name");
        let did = p.did.clone();
        book.upsert(p.clone()).unwrap();
        book.set_last_addr(&did, "10.0.0.2:47821").unwrap();
        book.set_last_seen(&did, 100).unwrap();

        let mut renamed = p;
        renamed.name = "New name".to_string();
        book.upsert(renamed).unwrap();

        let got = book.get(&did).unwrap();
        assert_eq!(got.name, "New name");
        assert_eq!(got.last_addr.as_deref(), Some("10.0.0.2:47821"));
        assert_eq!(got.last_seen, Some(100));
    }

    #[test]
    fn 整体替换用于宿主回灌() {
        let book = MemoryPeerBook::from_peers([peer(4, "A"), peer(5, "B")]);
        assert_eq!(book.all().len(), 2);
        book.replace_all([peer(6, "C")]);
        let all = book.all();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].name, "C");
    }

    #[test]
    fn 篡改_did_后身份校验失败() {
        let mut p = peer(7, "Victim");
        p.did = "00".repeat(16);
        assert!(p.public_identity().is_err());
    }
}
