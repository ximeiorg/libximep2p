//! Xime 跨设备剪贴板 P2P 传输层。
//!
//! 设计文档：`docs/clipboard-p2p-protocol.md`（本 crate 的唯一契约来源）。
//!
//! 分层：
//!
//! | 模块 | 职责 |
//! |---|---|
//! | [`frame`] | 9 字节帧头编解码（§4.2） |
//! | [`identity`] | 设备标识 `did` 与长期密钥（§3） |
//! | [`code`] | 6 位动态码的生成、分组显示与过期（§6.1） |
//! | [`pairing`] | SPAKE2 配对与方向分离的确认（§6.2） |
//! | [`session`] | Noise IK 会话与分片加解密（§7） |
//! | [`app`] | 应用层 payload 结构（§8.1） |
//! | [`store`] | 已配对设备表持久化（§6.2） |
//! | [`proto`] | 配对 / 会话握手的异步驱动（跑在任意 `AsyncRead + AsyncWrite` 上） |
//!
//! 约定：
//!
//! - 本 crate **不依赖任何平台 API**，Android 侧只经由 JNI 调用，桌面端直接 `use`。
//! - 所有错误都映射到协议错误码（§10），便于对端统一处理。
//! - 不写日志到 stdout，统一走 `tracing`，由宿主决定订阅方式。

#![forbid(unsafe_code)]

pub mod app;
pub mod code;
pub mod error;
pub mod frame;
pub mod identity;
pub mod node;
pub mod pair_session;
pub mod pairing;
pub mod proto;
pub mod random;
pub mod session;
pub mod store;
pub mod transport;

pub use code::{CODE_TTL, MAX_ATTEMPTS, PairingCode};
pub use error::{Error, ErrorCode};
pub use frame::{FLAG_ENCRYPTED, Frame, MAX_PAYLOAD, MsgType};
pub use identity::{Did, Identity, PublicIdentity};
pub use node::{Event, Node, NodeConfig, now_secs};
pub use pair_session::{DisplaySession, StopHandle, join, join_at, load_or_create_identity};
pub use pairing::PairKeys;
pub use proto::{Connection, pair_as_display, pair_as_input, session_accept, session_initiate};
pub use session::{NoiseHandshake, Session};
pub use store::{PairedPeer, PeerStore};
// 供宿主构造剪贴板条目，省得它们再单独依赖 xime-sync-domain。
pub use transport::{
    Announce, Broadcaster, Listener, PAIR_PORT, TCP_PORT, UDP_PORT, Watcher, connect,
};
pub use xime_sync_domain::profile::{Profile, ProfileType};
