//! SPAKE2 配对（§6.2）。
//!
//! 动态码只有 10^6 熵，直接当 KDF 输入会被离线枚举。这里用 SPAKE2 把
//! 低熵码强化成 32 字节共享密钥 `K`，再由 `K` 经 HKDF 派生出三个用途隔离的密钥：
//!
//! ```text
//! salt = nonce_a || nonce_b                      (16 + 16 字节)
//! PRK  = HKDF-SHA256(salt, IKM = K, info = "xime-p2p/pairing/v1")
//! k_c2s = HKDF-Expand(PRK, "c2s",      32)        Input  → Display
//! k_s2c = HKDF-Expand(PRK, "s2c",      32)        Display → Input
//! k_id  = HKDF-Expand(PRK, "identity", 32)        IDENTITY 帧的 AEAD 密钥
//! ```
//!
//! 方向分离靠**不同密钥**实现（而不是在同一个密钥上换消息前缀）：
//! 这样反射攻击（把 `PAIR_CONFIRM` 原样发回当 `PAIR_OK`）在密钥层面就不可能通过。
//!
//! SPAKE2 的密码字节 = 6 位码的零填充 ASCII（如 `"482719"`），
//! 两侧身份 = 各自的 `did` hex（32 字符），顺序固定为 `(display, input)`。

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use spake2::{Ed25519Group, Identity, Password, Spake2};

use crate::code::PairingCode;
use crate::error::Error;
use crate::identity::Did;

type HmacSha256 = Hmac<Sha256>;

const CONFIRM_LABEL: &[u8] = b"xime-p2p/confirm";
const IDENTITY_AAD_TAG: &[u8] = b"xime-p2p/identity/v1";

/// 配对阶段派生出的三个密钥。
pub struct PairKeys {
    k_c2s: [u8; 32],
    k_s2c: [u8; 32],
    k_id: [u8; 32],
}

impl PairKeys {
    /// 由 SPAKE2 共享密钥与双方 nonce 派生。
    ///
    /// `nonce_a` 来自 Display，`nonce_b` 来自 Input，顺序不可交换：
    /// 交换后两端派生的密钥不同，握手会直接失败（这是有意的，用于固定角色）。
    pub fn derive(shared: &[u8], nonce_a: &[u8], nonce_b: &[u8]) -> Result<Self, Error> {
        if nonce_a.len() < 8 || nonce_b.len() < 8 {
            return Err(Error::internal("nonce 长度不足 8 字节"));
        }
        let mut salt = Vec::with_capacity(nonce_a.len() + nonce_b.len());
        salt.extend_from_slice(nonce_a);
        salt.extend_from_slice(nonce_b);

        let hk = Hkdf::<Sha256>::new(Some(&salt), shared);
        let mut k_c2s = [0u8; 32];
        let mut k_s2c = [0u8; 32];
        let mut k_id = [0u8; 32];
        hk.expand(b"c2s", &mut k_c2s)
            .map_err(|e| Error::internal(format!("HKDF(c2s) 失败: {e}")))?;
        hk.expand(b"s2c", &mut k_s2c)
            .map_err(|e| Error::internal(format!("HKDF(s2c) 失败: {e}")))?;
        hk.expand(b"identity", &mut k_id)
            .map_err(|e| Error::internal(format!("HKDF(identity) 失败: {e}")))?;

        Ok(Self { k_c2s, k_s2c, k_id })
    }

    /// Input 侧应发送的 `PAIR_CONFIRM`。
    pub fn confirm_c2s(&self) -> [u8; 32] {
        hmac(&self.k_c2s)
    }

    /// Display 侧应发送的 `PAIR_OK`。
    pub fn confirm_s2c(&self) -> [u8; 32] {
        hmac(&self.k_s2c)
    }

    /// Display 校验 Input 发来的 `PAIR_CONFIRM`。
    pub fn verify_confirm_c2s(&self, got: &[u8]) -> Result<(), Error> {
        verify_hmac(&self.k_c2s, got)
    }

    /// Input 校验 Display 发来的 `PAIR_OK`。
    pub fn verify_confirm_s2c(&self, got: &[u8]) -> Result<(), Error> {
        verify_hmac(&self.k_s2c, got)
    }

    /// 加密 `IDENTITY` 帧的明文。
    ///
    /// `k_id` 在一次配对中只用于一条消息，所以固定 nonce 全零是安全的；
    /// 若将来复用到多条消息，必须改为每次递增的 nonce。
    pub fn seal_identity(&self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        let cipher = ChaCha20Poly1305::new(&Key::from(self.k_id));
        cipher
            .encrypt(
                &Nonce::from([0u8; 12]),
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| Error::internal("IDENTITY 加密失败"))
    }

    pub fn open_identity(&self, aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
        let cipher = ChaCha20Poly1305::new(&Key::from(self.k_id));
        cipher
            .decrypt(
                &Nonce::from([0u8; 12]),
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map_err(|_| Error::AuthFailed)
    }
}

impl std::fmt::Debug for PairKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PairKeys(<已隐藏>)")
    }
}

impl Drop for PairKeys {
    fn drop(&mut self) {
        // best-effort：密钥不留在内存里等 GC。编译器理论上可优化掉，
        // 真正需要强保证时应换成 zeroize crate；这里不加依赖。
        zero(&mut self.k_c2s);
        zero(&mut self.k_s2c);
        zero(&mut self.k_id);
    }
}

#[inline(never)]
fn zero(buf: &mut [u8; 32]) {
    for b in buf.iter_mut() {
        *b = 0;
    }
}

fn hmac(key: &[u8; 32]) -> [u8; 32] {
    let mut mac =
        <HmacSha256 as hmac::KeyInit>::new_from_slice(key).expect("HMAC 接受任意长度密钥");
    mac.update(CONFIRM_LABEL);
    mac.finalize().into_bytes().into()
}

fn verify_hmac(key: &[u8; 32], got: &[u8]) -> Result<(), Error> {
    let mut mac =
        <HmacSha256 as hmac::KeyInit>::new_from_slice(key).expect("HMAC 接受任意长度密钥");
    mac.update(CONFIRM_LABEL);
    mac.verify_slice(got).map_err(|_| Error::AuthFailed)
}

/// `IDENTITY` 帧的 AAD：绑定双方 `did`，防止密文被搬到另一对设备复用。
pub fn identity_aad(display: &Did, input: &Did) -> Vec<u8> {
    let mut aad = Vec::with_capacity(IDENTITY_AAD_TAG.len() + 32);
    aad.extend_from_slice(IDENTITY_AAD_TAG);
    aad.extend_from_slice(display.as_bytes());
    aad.extend_from_slice(input.as_bytes());
    aad
}

/// 一次 SPAKE2 交互的本地状态。
pub struct SpakeSession {
    inner: Spake2<Ed25519Group>,
    message: Vec<u8>,
}

impl SpakeSession {
    /// Display 侧（SPAKE2 的 A 角色）。
    pub fn display(code: &PairingCode, display_did: &Did, input_did: &Did) -> Result<Self, Error> {
        let (inner, message) = Spake2::<Ed25519Group>::start_a(
            &password(code),
            &identity(display_did),
            &identity(input_did),
        );
        Ok(Self { inner, message })
    }

    /// Input 侧（SPAKE2 的 B 角色）。
    pub fn input(code: &PairingCode, display_did: &Did, input_did: &Did) -> Result<Self, Error> {
        let (inner, message) = Spake2::<Ed25519Group>::start_b(
            &password(code),
            &identity(display_did),
            &identity(input_did),
        );
        Ok(Self { inner, message })
    }

    /// 本端要发出去的公钥消息。
    pub fn message(&self) -> &[u8] {
        &self.message
    }

    /// 消费自身并计算共享密钥，再派生 [`PairKeys`]。
    pub fn finish(
        self,
        peer_message: &[u8],
        nonce_a: &[u8],
        nonce_b: &[u8],
    ) -> Result<PairKeys, Error> {
        let shared = self
            .inner
            .finish(peer_message)
            .map_err(|e| Error::Spake(format!("SPAKE2 finish 失败: {e}")))?;
        PairKeys::derive(&shared, nonce_a, nonce_b)
    }
}

fn password(code: &PairingCode) -> Password {
    Password::new(format!("{:06}", code.digits()).as_bytes())
}

fn identity(did: &Did) -> Identity {
    Identity::new(did.to_hex().as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    fn dids() -> (Did, Did) {
        use crate::identity::Identity as Id;
        let a = Id::from_seed(&[11u8; 32]).did();
        let b = Id::from_seed(&[22u8; 32]).did();
        (a, b)
    }

    fn code(n: u32) -> PairingCode {
        PairingCode::from_digits_at(n, Instant::now()).unwrap()
    }

    #[test]
    fn 同码两端派生出相同密钥() {
        let (display_did, input_did) = dids();
        let c = code(482_719);
        let nonce_a = [1u8; 16];
        let nonce_b = [2u8; 16];

        let display = SpakeSession::display(&c, &display_did, &input_did).unwrap();
        let input = SpakeSession::input(&c, &display_did, &input_did).unwrap();
        let msg_a = display.message().to_vec();
        let msg_b = input.message().to_vec();

        let kd = display.finish(&msg_b, &nonce_a, &nonce_b).unwrap();
        let ki = input.finish(&msg_a, &nonce_a, &nonce_b).unwrap();

        assert_eq!(kd.confirm_c2s(), ki.confirm_c2s());
        assert_eq!(kd.confirm_s2c(), ki.confirm_s2c());
        kd.verify_confirm_c2s(&ki.confirm_c2s()).unwrap();
        ki.verify_confirm_s2c(&kd.confirm_s2c()).unwrap();
    }

    #[test]
    fn 不同码派生不同密钥() {
        let (display_did, input_did) = dids();
        let nonce_a = [1u8; 16];
        let nonce_b = [2u8; 16];

        let display = SpakeSession::display(&code(111_111), &display_did, &input_did).unwrap();
        let input = SpakeSession::input(&code(111_112), &display_did, &input_did).unwrap();
        let msg_a = display.message().to_vec();
        let msg_b = input.message().to_vec();

        let kd = display.finish(&msg_b, &nonce_a, &nonce_b).unwrap();
        let ki = input.finish(&msg_a, &nonce_a, &nonce_b).unwrap();
        assert!(kd.verify_confirm_c2s(&ki.confirm_c2s()).is_err());
        assert!(ki.verify_confirm_s2c(&kd.confirm_s2c()).is_err());
    }

    #[test]
    fn nonce_顺序不可交换() {
        let (display_did, input_did) = dids();
        let c = code(482_719);
        let display = SpakeSession::display(&c, &display_did, &input_did).unwrap();
        let input = SpakeSession::input(&c, &display_did, &input_did).unwrap();
        let msg_a = display.message().to_vec();
        let msg_b = input.message().to_vec();

        let kd = display.finish(&msg_b, &[1u8; 16], &[2u8; 16]).unwrap();
        let ki = input.finish(&msg_a, &[2u8; 16], &[1u8; 16]).unwrap();
        assert!(kd.verify_confirm_c2s(&ki.confirm_c2s()).is_err());
    }

    #[test]
    fn 方向密钥不同因此确认值不同() {
        let (display_did, input_did) = dids();
        let c = code(1_234_567u32 % 1_000_000);
        let display = SpakeSession::display(&c, &display_did, &input_did).unwrap();
        let input = SpakeSession::input(&c, &display_did, &input_did).unwrap();
        let msg_a = display.message().to_vec();
        let msg_b = input.message().to_vec();
        let kd = display.finish(&msg_b, &[9u8; 16], &[8u8; 16]).unwrap();
        let ki = input.finish(&msg_a, &[9u8; 16], &[8u8; 16]).unwrap();

        assert_ne!(kd.confirm_c2s(), kd.confirm_s2c());
        // 反射：把 s2c 的值当作 c2s 提交，必须被拒
        assert!(kd.verify_confirm_c2s(&ki.confirm_s2c()).is_err());
        assert!(ki.verify_confirm_s2c(&kd.confirm_c2s()).is_err());
        // 各自的正确方向仍然通过
        kd.verify_confirm_c2s(&ki.confirm_c2s()).unwrap();
        ki.verify_confirm_s2c(&kd.confirm_s2c()).unwrap();
    }

    #[test]
    fn 身份密文可解密且篡改被拒() {
        let (display_did, input_did) = dids();
        let aad = identity_aad(&display_did, &input_did);
        let c = code(482_719);
        let display = SpakeSession::display(&c, &display_did, &input_did).unwrap();
        let input = SpakeSession::input(&c, &display_did, &input_did).unwrap();
        let msg_a = display.message().to_vec();
        let msg_b = input.message().to_vec();
        let kd = display.finish(&msg_b, &[1u8; 16], &[2u8; 16]).unwrap();
        let ki = input.finish(&msg_a, &[1u8; 16], &[2u8; 16]).unwrap();

        let ct = kd.seal_identity(&aad, b"{\"name\":\"mac\"}").unwrap();
        assert_eq!(ki.open_identity(&aad, &ct).unwrap(), b"{\"name\":\"mac\"}");

        let mut bad = ct.clone();
        *bad.last_mut().unwrap() ^= 0x01;
        assert!(matches!(
            ki.open_identity(&aad, &bad),
            Err(Error::AuthFailed)
        ));

        // AAD 换成另一对设备也必须失败
        let other_aad = identity_aad(&input_did, &display_did);
        assert!(ki.open_identity(&other_aad, &ct).is_err());
    }
}
