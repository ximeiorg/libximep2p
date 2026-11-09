//! Noise IK 会话（§7）。
//!
//! 已配对设备重连时用 `Noise_IK_25519_ChaChaPoly_BLAKE2s`：1-RTT，Initiator
//! 的身份对被动观察者隐藏，Responder 用配对时记录的静态公钥作为目标。
//!
//! `prologue` 固定为 `b"xime-p2p/session/v1" || did_lo(16) || did_hi(16)`，
//! 两端 did 按字节序排序后拼接，因此与谁先连谁无关。这条绑定防止握手消息
//! 被原样重放到另一对设备上。
//!
//! Noise 的传输消息单条上限是 65535 字节（含 16 字节 tag），而剪贴板文本可达
//! 256 KiB，所以明文按 [`MAX_CHUNK`] 切片，每条密文前加 `u16` 大端长度：
//!
//! ```text
//! payload = (u16 be len || ciphertext) * N
//! ```
//!
//! 空明文编码为零条分片，解密结果为空。

use snow::{Builder, HandshakeState, TransportState};

use crate::error::Error;
use crate::identity::{Did, Identity};

/// Noise 参数串。改动它等于改协议版本，必须同步 Android 侧。
pub const NOISE_PARAMS: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";
/// 单个分片的明文上限。65535 - 16(tag) = 65519，留余量取 60000。
pub const MAX_CHUNK: usize = 60_000;
/// prologue 前缀。
pub const PROLOGUE_TAG: &[u8] = b"xime-p2p/session/v1";

/// 构造会话绑定的 prologue。
pub fn prologue(a: &Did, b: &Did) -> Vec<u8> {
    let (lo, hi) = if a.as_bytes() <= b.as_bytes() {
        (a, b)
    } else {
        (b, a)
    };
    let mut out = Vec::with_capacity(PROLOGUE_TAG.len() + 32);
    out.extend_from_slice(PROLOGUE_TAG);
    out.extend_from_slice(lo.as_bytes());
    out.extend_from_slice(hi.as_bytes());
    out
}

fn params() -> snow::params::NoiseParams {
    NOISE_PARAMS
        .parse()
        .expect("NOISE_PARAMS 是编译期常量，必须可解析")
}

/// 握手阶段的包装。
pub struct NoiseHandshake {
    hs: Option<HandshakeState>,
}

impl NoiseHandshake {
    /// 主动连接方（Initiator）。`remote_static` 是配对时记录的 `pub_x25519`。
    pub fn initiator(
        local: &Identity,
        remote_static: &[u8; 32],
        prologue: &[u8],
    ) -> Result<Self, Error> {
        let (private, _) = local.noise_keypair();
        let hs = Builder::new(params())
            .local_private_key(&private)
            .map_err(noise_err)?
            .remote_public_key(remote_static)
            .map_err(noise_err)?
            .prologue(prologue)
            .map_err(noise_err)?
            .build_initiator()
            .map_err(noise_err)?;
        Ok(Self { hs: Some(hs) })
    }

    /// 监听方（Responder）。对端静态公钥在握手中获得。
    pub fn responder(local: &Identity, prologue: &[u8]) -> Result<Self, Error> {
        let (private, _) = local.noise_keypair();
        let hs = Builder::new(params())
            .local_private_key(&private)
            .map_err(noise_err)?
            .prologue(prologue)
            .map_err(noise_err)?
            .build_responder()
            .map_err(noise_err)?;
        Ok(Self { hs: Some(hs) })
    }

    /// 产出一条握手消息。
    pub fn write_message(&mut self, payload: &[u8]) -> Result<Vec<u8>, Error> {
        let hs = self
            .hs
            .as_mut()
            .ok_or_else(|| Error::internal("握手已完成"))?;
        let mut out = vec![0u8; payload.len() + 128];
        let n = hs.write_message(payload, &mut out).map_err(noise_err)?;
        out.truncate(n);
        Ok(out)
    }

    /// 消费一条握手消息，返回其中的 payload。
    pub fn read_message(&mut self, message: &[u8]) -> Result<Vec<u8>, Error> {
        let hs = self
            .hs
            .as_mut()
            .ok_or_else(|| Error::internal("握手已完成"))?;
        let mut out = vec![0u8; message.len()];
        let n = hs.read_message(message, &mut out).map_err(noise_err)?;
        out.truncate(n);
        Ok(out)
    }

    pub fn is_finished(&self) -> bool {
        self.hs
            .as_ref()
            .map(|hs| hs.is_handshake_finished())
            .unwrap_or(true)
    }

    /// 对端静态公钥（Responder 在读到第一条消息后可用）。
    pub fn remote_static(&self) -> Option<[u8; 32]> {
        self.hs
            .as_ref()
            .and_then(|hs| hs.get_remote_static())
            .and_then(|raw| raw.try_into().ok())
    }

    /// 转入传输模式。
    pub fn into_session(mut self) -> Result<Session, Error> {
        let peer_static = self
            .remote_static()
            .ok_or_else(|| Error::internal("握手未获得对端静态公钥"))?;
        let hs = self
            .hs
            .take()
            .ok_or_else(|| Error::internal("握手已完成"))?;
        let transport = hs.into_transport_mode().map_err(noise_err)?;
        Ok(Session {
            transport,
            peer_static,
        })
    }
}

/// 已建立的加密会话。
pub struct Session {
    transport: TransportState,
    peer_static: [u8; 32],
}

impl Session {
    /// 对端 Noise 静态公钥，用于反查已配对表。
    pub fn peer_static(&self) -> [u8; 32] {
        self.peer_static
    }

    /// 加密一段任意长度的明文，产出可分片解密的 payload。
    pub fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        let mut out = Vec::with_capacity(plaintext.len() + 32);
        for chunk in plaintext.chunks(MAX_CHUNK) {
            let mut buf = vec![0u8; chunk.len() + 16];
            let n = self
                .transport
                .write_message(chunk, &mut buf)
                .map_err(noise_err)?;
            let n = u16::try_from(n).map_err(|_| Error::internal("分片长度超出 u16"))?;
            out.extend_from_slice(&n.to_be_bytes());
            out.extend_from_slice(&buf[..n as usize]);
        }
        Ok(out)
    }

    /// 解密 [`Session::seal`] 的产物。
    pub fn open(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
        let mut out = Vec::with_capacity(ciphertext.len());
        let mut rest = ciphertext;
        while !rest.is_empty() {
            if rest.len() < 2 {
                return Err(Error::bad_frame("分片长度字段被截断"));
            }
            let len = u16::from_be_bytes([rest[0], rest[1]]) as usize;
            rest = &rest[2..];
            if rest.len() < len || len < 16 {
                return Err(Error::bad_frame("分片长度非法"));
            }
            let mut buf = vec![0u8; len - 16];
            let n = self
                .transport
                .read_message(&rest[..len], &mut buf)
                .map_err(noise_err)?;
            out.extend_from_slice(&buf[..n]);
            rest = &rest[len..];
        }
        Ok(out)
    }
}

fn noise_err(e: snow::Error) -> Error {
    Error::Noise(e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair_handshake() -> (Session, Session) {
        let initiator_id = Identity::from_seed(&[3u8; 32]);
        let responder_id = Identity::from_seed(&[4u8; 32]);
        let (_, responder_static) = responder_id.noise_keypair();
        let pro = prologue(&initiator_id.did(), &responder_id.did());

        let mut init = NoiseHandshake::initiator(&initiator_id, &responder_static, &pro).unwrap();
        let mut resp = NoiseHandshake::responder(&responder_id, &pro).unwrap();

        let m1 = init.write_message(&[]).unwrap();
        resp.read_message(&m1).unwrap();
        let m2 = resp.write_message(&[]).unwrap();
        init.read_message(&m2).unwrap();
        assert!(init.is_finished());

        (init.into_session().unwrap(), resp.into_session().unwrap())
    }

    #[test]
    fn 握手后双向加解密() {
        let (mut a, mut b) = pair_handshake();

        let ct = a.seal(b"hello").unwrap();
        assert_eq!(b.open(&ct).unwrap(), b"hello");

        let ct = b.seal("反向".as_bytes()).unwrap();
        assert_eq!(a.open(&ct).unwrap(), "反向".as_bytes());
    }

    #[test]
    fn 双方看到对方的静态公钥() {
        let initiator_id = Identity::from_seed(&[5u8; 32]);
        let responder_id = Identity::from_seed(&[6u8; 32]);
        let (init_pub, resp_pub) = (
            initiator_id.noise_keypair().1,
            responder_id.noise_keypair().1,
        );
        let pro = prologue(&initiator_id.did(), &responder_id.did());

        let mut init = NoiseHandshake::initiator(&initiator_id, &resp_pub, &pro).unwrap();
        let mut resp = NoiseHandshake::responder(&responder_id, &pro).unwrap();
        let m1 = init.write_message(&[]).unwrap();
        resp.read_message(&m1).unwrap();
        let m2 = resp.write_message(&[]).unwrap();
        init.read_message(&m2).unwrap();

        assert_eq!(init.remote_static(), Some(resp_pub));
        assert_eq!(resp.remote_static(), Some(init_pub));

        let (a, b) = (init.into_session().unwrap(), resp.into_session().unwrap());
        assert_eq!(a.peer_static(), resp_pub);
        assert_eq!(b.peer_static(), init_pub);
    }

    #[test]
    fn prologue_不一致时握手失败() {
        let initiator_id = Identity::from_seed(&[7u8; 32]);
        let responder_id = Identity::from_seed(&[8u8; 32]);
        let (_, resp_pub) = responder_id.noise_keypair();
        let stranger = Did::from_bytes([0xABu8; 16]);

        let pro_init = prologue(&initiator_id.did(), &responder_id.did());
        let pro_resp = prologue(&initiator_id.did(), &stranger);

        let mut init = NoiseHandshake::initiator(&initiator_id, &resp_pub, &pro_init).unwrap();
        let mut resp = NoiseHandshake::responder(&responder_id, &pro_resp).unwrap();
        let m1 = init.write_message(&[]).unwrap();
        assert!(resp.read_message(&m1).is_err());
    }

    #[test]
    fn prologue_与连接方向无关() {
        let a = Did::from_bytes([1u8; 16]);
        let b = Did::from_bytes([2u8; 16]);
        assert_eq!(prologue(&a, &b), prologue(&b, &a));
        assert_eq!(prologue(&a, &b).len(), PROLOGUE_TAG.len() + 32);
    }

    #[test]
    fn 空明文往返() {
        let (mut a, mut b) = pair_handshake();
        let ct = a.seal(b"").unwrap();
        assert!(ct.is_empty());
        assert_eq!(b.open(&ct).unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn 超过单条上限的明文自动分片() {
        let (mut a, mut b) = pair_handshake();
        // 300 KiB，跨 5 个分片
        let plain: Vec<u8> = (0..300 * 1024).map(|i| (i % 251) as u8).collect();
        let ct = a.seal(&plain).unwrap();
        assert!(ct.len() > plain.len());
        assert_eq!(b.open(&ct).unwrap(), plain);
    }

    #[test]
    fn 密文被篡改时解密失败() {
        let (mut a, mut b) = pair_handshake();
        let mut ct = a.seal(b"payload").unwrap();
        let last = ct.len() - 1;
        ct[last] ^= 0xFF;
        assert!(b.open(&ct).is_err());
    }

    #[test]
    fn 分片长度字段被破坏时拒绝() {
        let (mut a, mut b) = pair_handshake();
        let mut ct = a.seal(b"payload").unwrap();
        ct[0] = 0xFF;
        ct[1] = 0xFF;
        assert!(b.open(&ct).is_err());
    }
}
