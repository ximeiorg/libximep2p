//! 设备标识与长期密钥（§3）。
//!
//! - `did` = `SHA256(pub_ed)[..16]`，**由公钥派生而非独立存储**。
//!   这样"did 与公钥不匹配"这类伪造在结构上就不可能出现，无需额外校验表。
//! - 长期密钥 = Ed25519（身份签名）+ X25519（Noise IK 静态密钥）。
//! - 两者由同一个 32 字节种子经 HKDF 分离派生，便于以单份种子做备份/恢复。

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

use crate::app::{B64, IdentityPayload};
use crate::error::Error;
use crate::random;

/// `did` 字节长度。
pub const DID_LEN: usize = 16;

/// 设备标识，16 字节，hex 展示为 32 位小写。
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Did([u8; DID_LEN]);

impl Did {
    pub fn from_bytes(bytes: [u8; DID_LEN]) -> Self {
        Self(bytes)
    }

    /// 由 Ed25519 公钥派生：`SHA256(pub_ed)[..16]`。
    pub fn from_ed25519(pub_ed: &[u8; 32]) -> Self {
        let digest = Sha256::digest(pub_ed);
        let mut bytes = [0u8; DID_LEN];
        bytes.copy_from_slice(&digest[..DID_LEN]);
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; DID_LEN] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn from_hex(value: &str) -> Result<Self, Error> {
        let raw = hex::decode(value.trim())
            .map_err(|e| Error::Identity(format!("did 不是合法 hex: {e}")))?;
        if raw.len() != DID_LEN {
            return Err(Error::Identity(format!(
                "did 长度应为 {DID_LEN} 字节，实际 {}",
                raw.len()
            )));
        }
        let mut bytes = [0u8; DID_LEN];
        bytes.copy_from_slice(&raw);
        Ok(Self(bytes))
    }
}

impl std::fmt::Display for Did {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

impl std::fmt::Debug for Did {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Did({})", hex::encode(self.0))
    }
}

/// 本机长期身份。
pub struct Identity {
    ed: SigningKey,
    x: StaticSecret,
}

impl Identity {
    /// 随机生成。系统随机源不可用时返回错误，不做降级（弱随机等于没有身份）。
    pub fn generate() -> Result<Self, Error> {
        let seed = random::array::<32>()?;
        Ok(Self::from_seed(&seed))
    }

    /// 由 32 字节种子确定性派生（备份恢复、测试）。
    ///
    /// 两个私钥用不同 `info` 从同一 IKM 展开，互不相关；
    /// 不要改用 `seed` 直接切片，否则 ed25519 与 x25519 私钥会强相关。
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let hk = Hkdf::<Sha256>::new(Some(b"xime-p2p/identity/v1"), seed);

        let mut ed_seed = [0u8; 32];
        hk.expand(b"ed25519", &mut ed_seed)
            .expect("32 字节输出长度恒定合法");

        let mut x_bytes = [0u8; 32];
        hk.expand(b"x25519", &mut x_bytes)
            .expect("32 字节输出长度恒定合法");

        let ed = SigningKey::from_bytes(&ed_seed);
        let x = StaticSecret::from(x_bytes);

        // 清掉栈上的中间值（两个数组都是 Copy，清零只作用于本地副本）。
        ed_seed.iter_mut().for_each(|b| *b = 0);
        x_bytes.iter_mut().for_each(|b| *b = 0);

        Self { ed, x }
    }

    /// 由 64 字节私钥材料恢复：`ed25519 seed(32) || x25519 secret(32)`。
    pub fn from_bytes(bytes: &[u8; 64]) -> Self {
        let mut ed_seed = [0u8; 32];
        let mut x_bytes = [0u8; 32];
        ed_seed.copy_from_slice(&bytes[..32]);
        x_bytes.copy_from_slice(&bytes[32..]);
        let ed = SigningKey::from_bytes(&ed_seed);
        let x = StaticSecret::from(x_bytes);
        ed_seed.iter_mut().for_each(|b| *b = 0);
        x_bytes.iter_mut().for_each(|b| *b = 0);
        Self { ed, x }
    }

    /// 导出 64 字节私钥材料，调用方负责安全存储（权限 0600 / Android Keystore）。
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(&self.ed.to_bytes());
        out[32..].copy_from_slice(&self.x.to_bytes());
        out
    }

    pub fn did(&self) -> Did {
        Did::from_ed25519(&self.ed.verifying_key().to_bytes())
    }

    /// 本机对外公开信息。
    pub fn public(&self, name: impl Into<String>) -> PublicIdentity {
        PublicIdentity {
            did: self.did(),
            ed: self.ed.verifying_key(),
            x: X25519PublicKey::from(&self.x),
            name: name.into(),
        }
    }

    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        self.ed.sign(msg).to_bytes()
    }

    /// Noise IK 的本地静态密钥对：`(private, public)`。
    pub fn noise_keypair(&self) -> ([u8; 32], [u8; 32]) {
        (self.x.to_bytes(), X25519PublicKey::from(&self.x).to_bytes())
    }
}

/// 对端公开身份。
#[derive(Clone, PartialEq, Eq)]
pub struct PublicIdentity {
    did: Did,
    ed: VerifyingKey,
    x: X25519PublicKey,
    name: String,
}

impl PublicIdentity {
    /// 由公钥重建，并校验 `did` 与公钥一致。
    ///
    /// [`PublicIdentity::did`] 由 `ed` 重新派生，所以传进来的 `did` 只用于比对，
    /// 不一致即拒绝——这是防"配对表被篡改后指向其他设备"的第一道闸。
    pub fn from_parts(
        did: &Did,
        pub_ed: &[u8; 32],
        pub_x: &[u8; 32],
        name: String,
    ) -> Result<Self, Error> {
        let ed = VerifyingKey::from_bytes(pub_ed)
            .map_err(|e| Error::Identity(format!("Ed25519 公钥非法: {e}")))?;
        let derived = Did::from_ed25519(&ed.to_bytes());
        if &derived != did {
            return Err(Error::Identity(format!(
                "did 与公钥不匹配: 声明 {did}, 实为 {derived}"
            )));
        }
        Ok(Self {
            did: derived,
            ed,
            x: X25519PublicKey::from(*pub_x),
            name,
        })
    }

    /// 由公钥直接构造，`did` 自动派生。
    pub fn from_public_keys(
        pub_ed: &[u8; 32],
        pub_x: &[u8; 32],
        name: String,
    ) -> Result<Self, Error> {
        let did = Did::from_ed25519(pub_ed);
        Self::from_parts(&did, pub_ed, pub_x, name)
    }

    pub fn did(&self) -> Did {
        self.did
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn ed_public(&self) -> [u8; 32] {
        self.ed.to_bytes()
    }

    pub fn x_public(&self) -> [u8; 32] {
        self.x.to_bytes()
    }

    pub fn verify(&self, msg: &[u8], signature: &[u8; 64]) -> bool {
        self.ed
            .verify(msg, &Signature::from_bytes(signature))
            .is_ok()
    }

    /// 转为 `IDENTITY` 帧的明文结构。
    pub fn to_payload(&self) -> IdentityPayload {
        IdentityPayload {
            pub_ed: B64::new(self.ed_public().to_vec()),
            pub_x25519: B64::new(self.x_public().to_vec()),
            name: self.name.clone(),
        }
    }

    /// 从 `IDENTITY` 帧明文还原。
    pub fn from_payload(payload: &IdentityPayload) -> Result<Self, Error> {
        let ed = to_array32(payload.pub_ed.as_slice(), "pub_ed")?;
        let x = to_array32(payload.pub_x25519.as_slice(), "pub_x25519")?;
        Self::from_public_keys(&ed, &x, payload.name.clone())
    }
}

impl std::fmt::Debug for PublicIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PublicIdentity")
            .field("did", &self.did)
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

fn to_array32(bytes: &[u8], field: &str) -> Result<[u8; 32], Error> {
    bytes
        .try_into()
        .map_err(|_| Error::Identity(format!("{field} 长度应为 32 字节，实际 {}", bytes.len())))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn 同种子派生同一身份() {
        let seed = [7u8; 32];
        let a = Identity::from_seed(&seed);
        let b = Identity::from_seed(&seed);
        assert_eq!(a.did(), b.did());
        assert_eq!(a.noise_keypair(), b.noise_keypair());
    }

    #[test]
    fn 不同种子派生不同身份() {
        assert_ne!(
            Identity::from_seed(&[1u8; 32]).did(),
            Identity::from_seed(&[2u8; 32]).did()
        );
    }

    #[test]
    fn 私钥导出与恢复等价() {
        let id = Identity::generate().unwrap();
        let bytes = id.to_bytes();
        let back = Identity::from_bytes(&bytes);
        assert_eq!(id.did(), back.did());
        assert_eq!(id.noise_keypair(), back.noise_keypair());
    }

    #[test]
    fn did_是_32_位小写_hex() {
        let id = Identity::generate().unwrap();
        let hex = id.did().to_hex();
        assert_eq!(hex.len(), 32);
        assert!(
            hex.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
        assert_eq!(Did::from_hex(&hex).unwrap(), id.did());
    }

    #[test]
    fn did_与公钥不匹配时拒绝() {
        let a = Identity::generate().unwrap();
        let b = Identity::generate().unwrap();
        let pub_b = b.public("b");
        let err = PublicIdentity::from_parts(
            &a.did(),
            &pub_b.ed_public(),
            &pub_b.x_public(),
            "spoof".into(),
        );
        assert!(matches!(err, Err(Error::Identity(_))));
    }

    #[test]
    fn 身份_payload_往返() {
        let id = Identity::generate().unwrap();
        let public = id.public("我的 MacBook");
        let payload = public.to_payload();
        let back = PublicIdentity::from_payload(&payload).unwrap();
        assert_eq!(back.did(), public.did());
        assert_eq!(back.name(), "我的 MacBook");
        assert_eq!(back.x_public(), public.x_public());
    }

    #[test]
    fn 签名可验且篡改后失败() {
        let id = Identity::generate().unwrap();
        let public = id.public("dev");
        let sig = id.sign(b"hello");
        assert!(public.verify(b"hello", &sig));
        assert!(!public.verify(b"hell0", &sig));
    }

    #[test]
    fn 长度非法的公钥被拒绝() {
        let payload = IdentityPayload {
            pub_ed: B64::new(vec![0u8; 31]),
            pub_x25519: B64::new(vec![0u8; 32]),
            name: "x".into(),
        };
        assert!(PublicIdentity::from_payload(&payload).is_err());
    }
}
