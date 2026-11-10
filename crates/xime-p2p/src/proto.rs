//! 握手驱动：把配对与会话流程跑在任意 `AsyncRead + AsyncWrite` 上。
//!
//! 这一层不关心 TCP，也不做发现——调用方先拿到连接（mDNS / UDP 广播 /
//! 上次地址直连），再把流交给这里。这样单测可以用内存管道跑完整流程，
//! 不需要端口和网卡。
//!
//! 配对消息序列见 §6.2；会话握手见 §7（Noise IK，1-RTT）。

use std::time::Duration;

use serde::Serialize;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time::timeout;

use xime_sync_domain::profile::Profile;

use crate::app::{
    B64, Bye, ClipboardSet, Confirm, ErrorMsg, Hello, HelloAck, IdentityPayload, PROTOCOL_VERSION,
    SpakeMsg, TopicMessage,
};
use crate::code::PairingCode;
use crate::error::{Error, ErrorCode};
use crate::frame::{Frame, MsgType, read_frame, write_frame};
use crate::identity::{Did, Identity, PublicIdentity};
use crate::pairing::{PairKeys, SpakeSession, identity_aad};
use crate::session::{NoiseHandshake, Session, prologue};
use crate::store::{PairedPeer, PeerStore};

/// 握手整体超时（§4.2：连接建立后 5 秒内未完成握手即断开）。
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
/// 空闲超时（§4.2）。
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(30);
/// nonce 长度。
pub const NONCE_LEN: usize = 16;
/// Responder 逐个尝试已配对设备的数量上限。
///
/// 会话握手前 Responder 不知道对端是谁，只能按已配对表逐一试解第一条消息
/// （prologue 绑定了双方 did，试错代价是一次 Noise 解析）。
/// 个人设备表通常 1–3 项，8 已是宽松上限。
pub const MAX_PAIRING_CANDIDATES: usize = 8;

fn timeout_err(_: tokio::time::error::Elapsed) -> Error {
    Error::Io(std::io::Error::from(std::io::ErrorKind::TimedOut))
}

// ─────────────────────────── 配对 ───────────────────────────

/// Display 侧：显示动态码的一端。
///
/// 成功返回对端公开身份（调用方据此写入 [`PeerStore`]，并补上已知地址）。
pub async fn pair_as_display<S>(
    stream: &mut S,
    identity: &Identity,
    name: &str,
    code: &PairingCode,
) -> Result<PublicIdentity, Error>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    if code.is_expired() {
        return Err(Error::CodeExpired);
    }
    timeout(
        HANDSHAKE_TIMEOUT,
        pair_display_inner(stream, identity, name, code),
    )
    .await
    .map_err(timeout_err)?
}

async fn pair_display_inner<S>(
    stream: &mut S,
    identity: &Identity,
    name: &str,
    code: &PairingCode,
) -> Result<PublicIdentity, Error>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let my_did = identity.did();

    // 1. HELLO
    let hello: Hello = expect_json(stream, MsgType::Hello).await?;
    if hello.ver != PROTOCOL_VERSION {
        fail(stream, ErrorCode::VersionMismatch).await;
        return Err(Error::VersionMismatch {
            got: hello.ver,
            expected: PROTOCOL_VERSION,
        });
    }
    let peer_did = Did::from_hex(&hello.did)?;
    let nonce_b = hello.nonce.0;
    if nonce_b.len() != NONCE_LEN {
        return Err(Error::bad_frame("nonce 长度非法"));
    }

    // 2. HELLO_ACK（回自己的 nonce）
    let nonce_a = random_nonce()?;
    let ack = HelloAck {
        ver: PROTOCOL_VERSION,
        did: my_did.to_hex(),
        nonce: B64::new(nonce_a.to_vec()),
        ok: true,
    };
    write_frame(stream, &Frame::json(MsgType::HelloAck, &ack)?).await?;

    // 3. SPAKE2：Display 是 A 角色，先收 Input 的消息再回自己的
    let spake = SpakeSession::display(code, &my_did, &peer_did)?;
    let inbound: SpakeMsg = expect_json(stream, MsgType::Spake2A).await?;
    write_frame(
        stream,
        &Frame::json(
            MsgType::Spake2B,
            &SpakeMsg {
                msg: B64::new(spake.message().to_vec()),
            },
        )?,
    )
    .await?;
    let keys = spake.finish(&inbound.msg.0, &nonce_a, &nonce_b)?;

    // 4. PAIR_CONFIRM（Input → Display）
    let confirm: Confirm = expect_json(stream, MsgType::PairConfirm).await?;
    if keys.verify_confirm_c2s(&confirm.hmac.0).is_err() {
        fail(stream, ErrorCode::AuthFailed).await;
        return Err(Error::AuthFailed);
    }
    write_frame(
        stream,
        &Frame::json(
            MsgType::PairOk,
            &Confirm {
                hmac: B64::new(keys.confirm_s2c().to_vec()),
            },
        )?,
    )
    .await?;

    // 5. IDENTITY 交换（AEAD，AAD 绑定双方 did）
    let aad = identity_aad(&my_did, &peer_did);
    exchange_identity(stream, identity, name, &keys, &aad, &peer_did).await
}

/// Input 侧：输入动态码的一端。
pub async fn pair_as_input<S>(
    stream: &mut S,
    identity: &Identity,
    name: &str,
    code: &PairingCode,
) -> Result<PublicIdentity, Error>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    if code.is_expired() {
        return Err(Error::CodeExpired);
    }
    timeout(
        HANDSHAKE_TIMEOUT,
        pair_input_inner(stream, identity, name, code),
    )
    .await
    .map_err(timeout_err)?
}

async fn pair_input_inner<S>(
    stream: &mut S,
    identity: &Identity,
    name: &str,
    code: &PairingCode,
) -> Result<PublicIdentity, Error>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let my_did = identity.did();
    let nonce_b = random_nonce()?;

    // 1. HELLO
    write_frame(
        stream,
        &Frame::json(
            MsgType::Hello,
            &Hello {
                ver: PROTOCOL_VERSION,
                did: my_did.to_hex(),
                nonce: B64::new(nonce_b.to_vec()),
            },
        )?,
    )
    .await?;

    // 2. HELLO_ACK
    let ack: HelloAck = expect_json(stream, MsgType::HelloAck).await?;
    if ack.ver != PROTOCOL_VERSION {
        return Err(Error::VersionMismatch {
            got: ack.ver,
            expected: PROTOCOL_VERSION,
        });
    }
    if !ack.ok {
        return Err(Error::Busy);
    }
    let peer_did = Did::from_hex(&ack.did)?;
    let nonce_a = ack.nonce.0;
    if nonce_a.len() != NONCE_LEN {
        return Err(Error::bad_frame("nonce 长度非法"));
    }

    // 3. SPAKE2：Input 是 B 角色
    let spake = SpakeSession::input(code, &peer_did, &my_did)?;
    write_frame(
        stream,
        &Frame::json(
            MsgType::Spake2A,
            &SpakeMsg {
                msg: B64::new(spake.message().to_vec()),
            },
        )?,
    )
    .await?;
    let inbound: SpakeMsg = expect_json(stream, MsgType::Spake2B).await?;
    let keys = spake.finish(&inbound.msg.0, &nonce_a, &nonce_b)?;

    // 4. PAIR_CONFIRM / PAIR_OK
    write_frame(
        stream,
        &Frame::json(
            MsgType::PairConfirm,
            &Confirm {
                hmac: B64::new(keys.confirm_c2s().to_vec()),
            },
        )?,
    )
    .await?;
    let ok: Confirm = expect_json(stream, MsgType::PairOk).await?;
    if keys.verify_confirm_s2c(&ok.hmac.0).is_err() {
        return Err(Error::AuthFailed);
    }

    // 5. IDENTITY
    let aad = identity_aad(&peer_did, &my_did);
    exchange_identity(stream, identity, name, &keys, &aad, &peer_did).await
}

/// 双向交换 IDENTITY：先写后读，全双工下不会死锁。
async fn exchange_identity<S>(
    stream: &mut S,
    identity: &Identity,
    name: &str,
    keys: &PairKeys,
    aad: &[u8],
    expect_did: &Did,
) -> Result<PublicIdentity, Error>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let my_public = identity.public(name);
    let plaintext = serde_json::to_vec(&my_public.to_payload())?;
    let sealed = keys.seal_identity(aad, &plaintext)?;
    write_frame(stream, &Frame::new(MsgType::Identity, sealed)).await?;

    let frame = expect_frame(stream, MsgType::Identity).await?;
    let plain = keys.open_identity(aad, &frame.payload)?;
    let payload: IdentityPayload = serde_json::from_slice(&plain)?;
    let peer = PublicIdentity::from_payload(&payload)?;

    // HELLO/HELLO_ACK 里声明的 did 必须与 IDENTITY 里的公钥一致，
    // 否则可以拿别人的 did 认领自己的公钥，污染对端配对表。
    if peer.did() != *expect_did {
        return Err(Error::Identity(format!(
            "IDENTITY 的 did({}) 与握手中声明的 did({expect_did}) 不一致",
            peer.did()
        )));
    }
    Ok(peer)
}

// ─────────────────────────── 会话 ───────────────────────────

/// 一条已建立加密会话的连接。
pub struct Connection<S> {
    stream: S,
    session: Session,
    local_did: String,
    peer_did: String,
    peer_name: String,
    seq: u64,
}

impl<S> Connection<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    fn new(stream: S, session: Session, local_did: Did, peer: &PairedPeer) -> Self {
        Self {
            stream,
            session,
            local_did: local_did.to_hex(),
            peer_did: peer.did.clone(),
            peer_name: peer.name.clone(),
            seq: 0,
        }
    }

    pub fn peer_did(&self) -> &str {
        &self.peer_did
    }

    pub fn peer_name(&self) -> &str {
        &self.peer_name
    }

    /// 本机 did（写入 `Profile.source`）。
    pub fn local_did(&self) -> &str {
        &self.local_did
    }

    /// 发送一条加密消息。`payload` 传明文，加密由会话负责。
    pub async fn send(&mut self, msg: MsgType, payload: &[u8]) -> Result<(), Error> {
        let sealed = self.session.seal(payload)?;
        let mut frame = Frame::new(msg, sealed);
        frame.set_encrypted(true);
        write_frame(&mut self.stream, &frame).await
    }

    pub async fn send_json<T: Serialize>(&mut self, msg: MsgType, value: &T) -> Result<(), Error> {
        let payload = serde_json::to_vec(value)?;
        self.send(msg, &payload).await
    }

    /// 接收一条消息，返回解密后的明文帧。
    ///
    /// 收到 `ERROR` 帧直接转成本地错误（调用方只需处理 `Err`）；
    /// 收到 `BYE` 报 [`Error::Closed`]。
    pub async fn recv(&mut self) -> Result<Frame, Error> {
        let frame = timeout(IDLE_TIMEOUT, read_frame(&mut self.stream))
            .await
            .map_err(timeout_err)??;

        match frame.msg {
            MsgType::Error => {
                let body: ErrorMsg = frame.parse_json()?;
                Err(body.to_error())
            }
            MsgType::Bye => Err(Error::Closed),
            _ if frame.is_encrypted() => {
                let plain = self.session.open(&frame.payload)?;
                Ok(Frame::new(frame.msg, plain))
            }
            _ => Err(Error::bad_frame("会话中的明文帧被拒绝")),
        }
    }

    /// 发送当前剪贴板。
    ///
    /// `source` 强制改写为本机 did：这个字段是对端的回环判断依据（§8.2），
    /// 不能由调用方随意指定，否则会造成自我回环或冒充其他设备。
    pub async fn send_clipboard(&mut self, mut profile: Profile) -> Result<(), Error> {
        profile.source = Some(self.local_did.clone());
        self.seq += 1;
        let body = ClipboardSet {
            profile,
            seq: self.seq,
        };
        self.send_json(MsgType::ClipboardSet, &body).await
    }

    /// 发送一条业务无关的 topic 消息。
    ///
    /// 剪贴板走同一入口（`topic = "clipboard"`，负载是 `Profile` 的 JSON），
    /// 以后新增同步功能只需定义新的 topic，不必扩展帧层。
    pub async fn send_message(&mut self, topic: &str, payload: Vec<u8>) -> Result<(), Error> {
        let body = TopicMessage {
            topic: topic.to_string(),
            payload: B64::new(payload),
        };
        self.send_json(MsgType::Message, &body).await
    }

    pub async fn ping(&mut self) -> Result<(), Error> {
        self.send(MsgType::Ping, b"{}").await
    }

    pub async fn bye(&mut self, reason: &str) -> Result<(), Error> {
        self.send_json(
            MsgType::Bye,
            &Bye {
                reason: reason.to_string(),
            },
        )
        .await
    }
}

/// 主动连接：`peer` 来自已配对表，`stream` 是已建立的 TCP 连接。
pub async fn session_initiate<S>(
    stream: S,
    identity: &Identity,
    peer: &PairedPeer,
) -> Result<Connection<S>, Error>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let mut stream = stream;
    let remote = peer.public_identity()?;
    let remote_static = remote.x_public();
    let pro = prologue(&identity.did(), &remote.did());

    let (hs, peer_static) = timeout(HANDSHAKE_TIMEOUT, async {
        let mut hs = NoiseHandshake::initiator(identity, &remote_static, &pro)?;
        let m1 = hs.write_message(&[])?;
        write_frame(&mut stream, &Frame::new(MsgType::Noise, m1)).await?;

        let reply = expect_frame(&mut stream, MsgType::Noise).await?;
        hs.read_message(&reply.payload)?;
        if !hs.is_finished() {
            return Err(Error::internal("IK 握手未在 1-RTT 内完成"));
        }
        let seen = hs
            .remote_static()
            .ok_or_else(|| Error::internal("握手未获得对端静态公钥"))?;
        Ok::<_, Error>((hs, seen))
    })
    .await
    .map_err(timeout_err)??;

    // 对方出示的静态公钥必须与配对表一致；Noise IK 已用该公钥加密，
    // 这里再比一次是为了防"配对表被改坏"这类本地故障。
    if peer_static != remote_static {
        return Err(Error::Identity("对端静态公钥与已配对表不一致".to_string()));
    }

    let session = hs.into_session()?;
    Ok(Connection::new(stream, session, identity.did(), peer))
}

/// 监听方：收下握手，按对端静态公钥在已配对表里找设备。
///
/// Noise IK 的 Responder 在收到第一条消息前不知道对端是谁，而 `prologue`
/// 绑定了双方 did，因此只能对已配对表逐项试解。表为空时直接拒绝，
/// 不会走到这里（调用方应先判断）。
pub async fn session_accept<S>(
    stream: S,
    identity: &Identity,
    store: &PeerStore,
) -> Result<Connection<S>, Error>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let mut stream = stream;
    let my_did = identity.did();

    let (peer, hs) = timeout(HANDSHAKE_TIMEOUT, async {
        let first = expect_frame(&mut stream, MsgType::Noise).await?;

        let mut matched: Option<(PairedPeer, NoiseHandshake)> = None;
        for peer in store.all().take(MAX_PAIRING_CANDIDATES) {
            let Ok(peer_did) = peer.did() else { continue };
            let pro = prologue(&peer_did, &my_did);
            let Ok(mut hs) = NoiseHandshake::responder(identity, &pro) else {
                continue;
            };
            if hs.read_message(&first.payload).is_ok() {
                matched = Some((peer.clone(), hs));
                break;
            }
        }

        let Some((peer, mut hs)) = matched else {
            fail(&mut stream, ErrorCode::NoPairedSession).await;
            return Err(Error::NotPaired);
        };

        let m2 = hs.write_message(&[])?;
        write_frame(&mut stream, &Frame::new(MsgType::Noise, m2)).await?;

        if !hs.is_finished() {
            return Err(Error::internal("IK 握手未在 1-RTT 内完成"));
        }
        Ok::<_, Error>((peer, hs))
    })
    .await
    .map_err(timeout_err)??;

    // 握手解出的静态公钥必须确实是这条配对记录的公钥。
    // （prologue 里已含该 did，这一步是二次确认，防配对表内部不一致。）
    let seen = hs
        .remote_static()
        .ok_or_else(|| Error::internal("握手未获得对端静态公钥"))?;
    let expect: [u8; 32] = hex::decode(&peer.pub_x25519)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or_else(|| Error::Store("配对表里的 pub_x25519 非法".to_string()))?;
    if seen != expect {
        return Err(Error::Identity("对端静态公钥与配对记录不一致".to_string()));
    }

    let session = hs.into_session()?;
    Ok(Connection::new(stream, session, my_did, &peer))
}

// ─────────────────────────── 工具 ───────────────────────────

fn random_nonce() -> Result<[u8; NONCE_LEN], Error> {
    crate::random::array::<NONCE_LEN>()
}

async fn expect_frame<S>(stream: &mut S, expected: MsgType) -> Result<Frame, Error>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let frame = read_frame(stream).await?;
    match frame.msg {
        MsgType::Error => {
            let body: ErrorMsg = frame.parse_json()?;
            Err(body.to_error())
        }
        msg if msg == expected => Ok(frame),
        other => Err(Error::bad_frame(format!(
            "期望消息 0x{:02X}，收到 0x{:02X}",
            expected.as_u8(),
            other.as_u8()
        ))),
    }
}

async fn expect_json<S, T>(stream: &mut S, expected: MsgType) -> Result<T, Error>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
    T: serde::de::DeserializeOwned,
{
    let frame = expect_frame(stream, expected).await?;
    Ok(serde_json::from_slice(&frame.payload)?)
}

/// 尽力发一条 ERROR（对端可能已断开，失败无所谓）。
async fn fail<S>(stream: &mut S, code: ErrorCode)
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let _ = write_frame(stream, &Frame::error(code)).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    fn code(n: u32) -> PairingCode {
        PairingCode::from_digits_at(n, Instant::now()).unwrap()
    }

    fn identity(seed: u8) -> Identity {
        Identity::from_seed(&[seed; 32])
    }

    /// 配对一对设备，返回各自的配对记录。
    async fn pair_both(
        display_id: &Identity,
        input_id: &Identity,
        display_code: u32,
        input_code: u32,
    ) -> (Result<PublicIdentity, Error>, Result<PublicIdentity, Error>) {
        let (mut a, mut b) = tokio::io::duplex(256 * 1024);
        let c1 = code(display_code);
        let c2 = code(input_code);

        let display = async move { pair_as_display(&mut a, display_id, "Mac", &c1).await };
        let input = async move { pair_as_input(&mut b, input_id, "Phone", &c2).await };
        tokio::join!(display, input)
    }

    #[tokio::test]
    async fn 同码配对成功且双方互见身份() {
        let display_id = identity(1);
        let input_id = identity(2);
        let (d, i) = pair_both(&display_id, &input_id, 482_719, 482_719).await;

        let d = d.unwrap();
        let i = i.unwrap();
        assert_eq!(d.did(), input_id.did());
        assert_eq!(d.name(), "Phone");
        assert_eq!(i.did(), display_id.did());
        assert_eq!(i.name(), "Mac");
    }

    #[tokio::test]
    async fn 码不一致时双方都认证失败() {
        let display_id = identity(3);
        let input_id = identity(4);
        let (d, i) = pair_both(&display_id, &input_id, 111_111, 222_222).await;

        assert!(matches!(d, Err(Error::AuthFailed)));
        assert!(matches!(i, Err(Error::AuthFailed)));
    }

    #[tokio::test]
    async fn 过期的码直接拒绝() {
        let display_id = identity(5);
        let input_id = identity(6);
        let stale = PairingCode::from_digits_at(482_719, Instant::now() - crate::CODE_TTL).unwrap();
        let (mut a, mut b) = tokio::io::duplex(4096);

        assert!(matches!(
            pair_as_display(&mut a, &display_id, "Mac", &stale).await,
            Err(Error::CodeExpired)
        ));
        assert!(matches!(
            pair_as_input(&mut b, &input_id, "Phone", &stale).await,
            Err(Error::CodeExpired)
        ));
    }

    /// 构造一条已配对的记录，用于会话测试。
    fn paired(seed: u8, name: &str) -> (Identity, PairedPeer) {
        let id = identity(seed);
        let peer = PairedPeer::from_public(&id.public(name), None);
        (id, peer)
    }

    #[tokio::test]
    async fn 会话建立后双向收发剪贴板() {
        let (server_id, server_peer) = paired(7, "Mac");
        let (client_id, client_peer) = paired(8, "Phone");

        let mut store =
            PeerStore::load(tempfile::tempdir().unwrap().path().join("peers.json")).unwrap();
        store.upsert(client_peer.clone()).unwrap();

        let (a, b) = tokio::io::duplex(256 * 1024);
        let server = async {
            let mut conn = session_accept(a, &server_id, &store).await?;
            let frame = conn.recv().await?;
            let body: ClipboardSet = frame.parse_json()?;
            Ok::<_, Error>((conn, body))
        };
        let client = async {
            let mut conn = session_initiate(b, &client_id, &server_peer).await?;
            conn.send_clipboard(Profile::from_text("家里剪贴板", None))
                .await?;
            Ok::<_, Error>(conn)
        };
        let (server_res, client_res) = tokio::join!(server, client);

        let (_conn, body) = server_res.unwrap();
        assert_eq!(body.profile.text, "家里剪贴板");
        assert_eq!(body.seq, 1);
        // source 被强制改写为发送方 did
        assert_eq!(
            body.profile.source.as_deref(),
            Some(client_id.did().to_hex().as_str())
        );
        client_res.unwrap();
    }

    #[tokio::test]
    async fn 未配对设备被拒绝() {
        let (server_id, _) = paired(9, "Mac");
        let (stranger_id, stranger_peer) = paired(11, "Stranger");

        // 服务端配对表里没有 11 号设备
        let mut store =
            PeerStore::load(tempfile::tempdir().unwrap().path().join("peers.json")).unwrap();
        store
            .upsert(PairedPeer::from_public(&identity(12).public("other"), None))
            .unwrap();

        let (a, b) = tokio::io::duplex(64 * 1024);
        let server = async { session_accept(a, &server_id, &store).await };
        let client = async { session_initiate(b, &stranger_id, &stranger_peer).await };
        let (s, c) = tokio::join!(server, client);

        assert!(matches!(s, Err(Error::NotPaired)));
        // 客户端收到 ERROR 帧，映射为同一错误
        assert!(c.is_err());
    }

    #[tokio::test]
    async fn 会话中明文帧被拒绝() {
        let (server_id, server_peer) = paired(13, "Mac");
        let (client_id, client_peer) = paired(14, "Phone");
        let mut store =
            PeerStore::load(tempfile::tempdir().unwrap().path().join("peers.json")).unwrap();
        store.upsert(client_peer).unwrap();

        let (a, b) = tokio::io::duplex(64 * 1024);
        let server = async {
            let mut conn = session_accept(a, &server_id, &store).await?;
            conn.recv().await
        };
        let client = async {
            let mut conn = session_initiate(b, &client_id, &server_peer).await?;
            // 绕过会话加密，直接写一个明文 Ping
            write_frame(&mut conn.stream, &Frame::json_empty(MsgType::Ping)).await?;
            Ok::<_, Error>(())
        };
        let (s, c) = tokio::join!(server, client);
        c.unwrap();
        assert!(matches!(s, Err(Error::BadFrame(_))));
    }
}
