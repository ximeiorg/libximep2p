//! TCP 传输与局域网发现（§4.1、§5）。
//!
//! 这一层只负责「把字节送到对端」和「找到对端在哪」，不碰协议语义。
//! 上层的 [`crate::proto`] 接收任意 `AsyncRead + AsyncWrite`，因此这里返回的
//! [`TcpStream`] 可以直接喂进去，测试里也能用 `tokio::io::duplex` 替代。

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

use crate::error::Error;

/// TCP 监听端口（§4.1）。
pub const TCP_PORT: u16 = 47821;
/// 发现用的 UDP 端口（§5.2）。
pub const UDP_PORT: u16 = 47822;
/// 配对专用端口。
///
/// 与同步端口分开的理由：配对是一次性、低频、且要独占连接直到双方交换完身份；
/// 混在同一端口上就得在 accept 处按首帧类型分流，而两条流程对「首帧」的
/// 期待不同（Noise vs HELLO），分流代码容易出错且难测。分开后互不影响。
pub const PAIR_PORT: u16 = 47823;
/// 端口被占用时顺延的最大次数。
const PORT_PROBE_LIMIT: u16 = 16;
/// 公告的固定标识，用于过滤同端口上的无关流量。
const ANNOUNCE_MAGIC: &str = "xime-clip";
/// 公告版本。
const ANNOUNCE_VERSION: u8 = 1;
/// 单条公告的字节上限。超长直接丢弃，避免被畸形包拖住。
const MAX_ANNOUNCE_BYTES: usize = 512;

// ─────────────────────────── 公告 ───────────────────────────

/// 公告声明的角色：这个端口上是常驻同步节点，还是正在显示配对码的会话。
///
/// 加这个字段的理由：两种角色共用同一个 UDP 广播频道，且同一台设备可能两者同时在跑。
/// 只报端口时，接收方无法判断「连上去会不会讲配对协议」，只能连一次试——试错会
/// 让多设备环境下的配对变慢，也让配对的错误信息失真。
///
/// 兼容性：字段可省。旧版对端不发它（解码成 [`AnnKind::Unknown`]），新版对端收到
/// 旧公告时照旧「连上再试」，因此混跑新旧版本不会失效。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AnnKind {
    /// 常驻同步节点，端口讲 Noise 会话。
    Node,
    /// 配对会话，端口讲配对协议。
    Pair,
    /// 旧版公告没有该字段。
    #[default]
    Unknown,
}

impl AnnKind {
    fn is_unknown(&self) -> bool {
        *self == AnnKind::Unknown
    }
}

/// 局域网公告（§5.2）。
///
/// 注意：**不含任何配对码或密钥**。同网段任何人可见，因此只能放公开信息。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Announce {
    /// 固定为 [`ANNOUNCE_MAGIC`]。
    pub s: String,
    /// 协议版本。
    pub v: u8,
    /// 设备标识（32 位小写 hex）。匹配一律用它，不用主机名。
    pub did: String,
    /// 实际 TCP 端口（可能因占用而顺延，不能假定等于 [`TCP_PORT`]）。
    pub pt: u16,
    /// 端口角色；旧版公告没有该字段。
    #[serde(default, skip_serializing_if = "AnnKind::is_unknown")]
    pub k: AnnKind,
}

impl Announce {
    pub fn new(did: impl Into<String>, tcp_port: u16, kind: AnnKind) -> Self {
        Self {
            s: ANNOUNCE_MAGIC.to_string(),
            v: ANNOUNCE_VERSION,
            did: did.into(),
            pt: tcp_port,
            k: kind,
        }
    }

    /// 是否为可接受的公告（标识与版本都对，`did` 形如 32 位 hex）。
    pub fn is_acceptable(&self) -> bool {
        self.s == ANNOUNCE_MAGIC
            && self.v == ANNOUNCE_VERSION
            && self.did.len() == 32
            && self.did.bytes().all(|b| b.is_ascii_hexdigit())
    }

    fn encode(&self) -> Result<Vec<u8>, Error> {
        let bytes = serde_json::to_vec(self)?;
        if bytes.len() > MAX_ANNOUNCE_BYTES {
            return Err(Error::Internal("公告超出长度上限".into()));
        }
        Ok(bytes)
    }

    fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() > MAX_ANNOUNCE_BYTES {
            return None;
        }
        let ann: Self = serde_json::from_slice(bytes).ok()?;
        ann.is_acceptable().then_some(ann)
    }
}

// ─────────────────────────── TCP ───────────────────────────

/// 监听器：绑一个端口，逐个 accept。
///
/// 端口被占用时顺延（最多 [`PORT_PROBE_LIMIT`] 次）。真实端口必须通过
/// [`Listener::local_port`] 取，并写进公告——调用方不得假定是 [`TCP_PORT`]。
pub struct Listener {
    inner: TcpListener,
}

impl Listener {
    /// 绑定 `0.0.0.0:preferred`，占用则顺延。
    pub async fn bind(preferred: u16) -> Result<Self, Error> {
        let mut last_err = None;
        for offset in 0..PORT_PROBE_LIMIT {
            let Some(port) = preferred.checked_add(offset) else {
                break;
            };
            match TcpListener::bind((Ipv4Addr::UNSPECIFIED, port)).await {
                Ok(inner) => return Ok(Self { inner }),
                Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => last_err = Some(e),
                Err(e) => return Err(Error::Io(e)),
            }
        }
        Err(Error::Io(last_err.unwrap_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::AddrInUse, "无可用端口")
        })))
    }

    /// 实际绑定的端口。
    pub fn local_port(&self) -> Result<u16, Error> {
        Ok(self.inner.local_addr()?.port())
    }

    /// 接受一个连接。
    ///
    /// 启用 `TCP_NODELAY`：剪贴板条目都很小，等 Nagle 合并只会平白增加延迟。
    pub async fn accept(&self) -> Result<(TcpStream, SocketAddr), Error> {
        let (stream, addr) = self.inner.accept().await?;
        let _ = stream.set_nodelay(true);
        Ok((stream, addr))
    }
}

/// 连接到对端，带超时。
///
/// 局域网内直连不需要 NAT 穿透，失败基本只有三种原因：对端没开、AP 隔离、
/// 防火墙拦截。超时设短一些，好让上层快速降级到下一个地址。
pub async fn connect(addr: SocketAddr, timeout: Duration) -> Result<TcpStream, Error> {
    let stream = tokio::time::timeout(timeout, TcpStream::connect(addr))
        .await
        .map_err(|_| {
            Error::Io(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "连接超时",
            ))
        })??;
    let _ = stream.set_nodelay(true);
    Ok(stream)
}

// ─────────────────────────── 发现 ───────────────────────────

/// 公告发送端：周期性把自身公告广播出去。
pub struct Broadcaster {
    sock: UdpSocket,
}

impl Broadcaster {
    pub async fn bind() -> Result<Self, Error> {
        let sock = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await?;
        sock.set_broadcast(true)?;
        Ok(Self { sock })
    }

    /// 广播一条公告。
    ///
    /// 目前只发受限广播（`255.255.255.255`）。定向广播需要枚举各接口的子网地址，
    /// 在多网卡（Docker / VMware / VPN）机器上能提高到达率，但要引入网卡枚举依赖，
    /// 留到发现层完善时再补。
    ///
    /// 返回是否发送成功。广播失败不是致命错误（可能没有可用网卡），
    /// 所以调用方只需要记日志，不必中断同步。
    pub async fn send(&self, ann: &Announce) -> Result<(), Error> {
        let bytes = ann.encode()?;
        let target = SocketAddrV4::new(Ipv4Addr::BROADCAST, UDP_PORT);
        self.sock.send_to(&bytes, target).await?;
        Ok(())
    }

    /// 单播回应：收到别人的公告后，把自身公告回给对方（§5.2）。
    pub async fn reply(&self, ann: &Announce, to: SocketAddr) -> Result<(), Error> {
        let bytes = ann.encode()?;
        self.sock.send_to(&bytes, to).await?;
        Ok(())
    }
}

/// 公告接收端。
pub struct Watcher {
    sock: UdpSocket,
}

impl Watcher {
    /// 绑定公告端口。
    ///
    /// 多实例（如输入法与设置应用同时运行）会撞端口。这里用 `SO_REUSEADDR` 语义的
    /// 做法受限于 tokio 未暴露该选项，因此失败时返回错误，由上层决定是否降级为
    /// 「只发不收」——发现是尽力而为，不因为它失败就阻断已配对设备的重连。
    pub async fn bind() -> Result<Self, Error> {
        let sock = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, UDP_PORT)).await?;
        Ok(Self { sock })
    }

    /// 等待一条公告，超时返回 `Ok(None)`。
    ///
    /// 畸形包、他人流量、自身回环都会被静默丢弃，只有通过
    /// [`Announce::is_acceptable`] 的才返回。
    pub async fn recv(&self, timeout: Duration) -> Result<Option<(Announce, SocketAddr)>, Error> {
        let deadline = tokio::time::Instant::now() + timeout;
        let mut buf = [0u8; MAX_ANNOUNCE_BYTES];
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Ok(None);
            }
            let recv = tokio::time::timeout(remaining, self.sock.recv_from(&mut buf)).await;
            let Ok(Ok((len, from))) = recv else {
                return Ok(None);
            };
            if let Some(ann) = Announce::decode(&buf[..len]) {
                return Ok(Some((ann, from)));
            }
            // 不是我们的包，继续等（不消耗调用方的超时预算之外的时间）。
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn 公告编解码往返() {
        let ann = Announce::new("0123456789abcdef0123456789abcdef", TCP_PORT, AnnKind::Node);
        let bytes = ann.encode().unwrap();
        let back = Announce::decode(&bytes).unwrap();
        assert_eq!(ann, back);
    }

    #[test]
    fn 拒绝非法公告() {
        // 标识不对
        let mut ann = Announce::new("0123456789abcdef0123456789abcdef", TCP_PORT, AnnKind::Node);
        ann.s = "other".into();
        assert!(Announce::decode(&serde_json::to_vec(&ann).unwrap()).is_none());

        // 版本不对
        let mut ann = Announce::new("0123456789abcdef0123456789abcdef", TCP_PORT, AnnKind::Node);
        ann.v = 9;
        assert!(Announce::decode(&serde_json::to_vec(&ann).unwrap()).is_none());

        // did 长度不对
        let mut ann = Announce::new("0123456789abcdef0123456789abcdef", TCP_PORT, AnnKind::Node);
        ann.did = "abc".into();
        assert!(Announce::decode(&serde_json::to_vec(&ann).unwrap()).is_none());

        // 非 hex
        let mut ann = Announce::new("0123456789abcdef0123456789abcdef", TCP_PORT, AnnKind::Node);
        ann.did = "zzzz456789abcdef0123456789abcdef".into();
        assert!(Announce::decode(&serde_json::to_vec(&ann).unwrap()).is_none());
    }

    /// 角色字段可省：旧版公告解码成 Unknown，新版对端仍会「连上再试」。
    #[test]
    fn 公告角色缺省为未知() {
        let legacy = br#"{"s":"xime-clip","v":1,"did":"0123456789abcdef0123456789abcdef","pt":47821}"#;
        let ann = Announce::decode(legacy).unwrap();
        assert_eq!(ann.k, AnnKind::Unknown);

        let pair = Announce::new("0123456789abcdef0123456789abcdef", 47823, AnnKind::Pair);
        let back = Announce::decode(&pair.encode().unwrap()).unwrap();
        assert_eq!(back.k, AnnKind::Pair);

        // 未知角色不写入报文，保持与旧版的字节兼容。
        let unknown = Announce::new("0123456789abcdef0123456789abcdef", 47821, AnnKind::Unknown);
        let json = String::from_utf8(unknown.encode().unwrap()).unwrap();
        assert!(!json.contains("\"k\""), "未知角色不应出现在报文里：{json}");
    }

    #[test]
    fn 拒绝超长公告() {
        let ann = Announce::new("0".repeat(32), TCP_PORT, AnnKind::Node);
        let mut bytes = serde_json::to_vec(&ann).unwrap();
        bytes.resize(MAX_ANNOUNCE_BYTES + 1, b' ');
        assert!(Announce::decode(&bytes).is_none());
    }

    #[tokio::test]
    async fn 端口占用时顺延() {
        let first = Listener::bind(0).await.unwrap();
        let port = first.local_port().unwrap();
        // first 仍存活，占着 port，因此第二次绑定必须落到更大的端口。
        // 不断言恰好 +1：端口空间是全局共享的，并发测试可能已占掉相邻端口。
        let second = Listener::bind(port).await.unwrap();
        let second_port = second.local_port().unwrap();
        assert_ne!(port, second_port, "顺延后端口必须不同");
        assert!(
            second_port > port,
            "顺延方向必须向上：{port} → {second_port}"
        );
    }

    #[tokio::test]
    async fn 监听与连接可建立() {
        let listener = Listener::bind(0).await.unwrap();
        let port = listener.local_port().unwrap();
        let accept = tokio::spawn(async move { listener.accept().await });
        let conn = connect(
            SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
            Duration::from_secs(3),
        )
        .await
        .unwrap();
        let (_server, _peer) = accept.await.unwrap().unwrap();
        // 客户端看到的对端端口即监听端口。
        assert_eq!(conn.peer_addr().unwrap().port(), port);
    }

    #[tokio::test]
    async fn 连接不存在端口会失败() {
        // 先占一个端口再释放，拿一个大概率无人监听的端口号。
        let l = Listener::bind(0).await.unwrap();
        let port = l.local_port().unwrap();
        drop(l);
        let result = connect(
            SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
            Duration::from_millis(500),
        )
        .await;
        assert!(result.is_err());
    }
}
