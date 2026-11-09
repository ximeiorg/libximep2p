//! 同步外观层：把异步的连接管理收成一个同步接口。
//!
//! 存在的理由：桌面端（XimeYi）的同步循环是 `std::thread` + 每 2 秒一次 tick 的
//! 同步代码，Android 的 JNI 桥也只能轮询。而连接、握手、收发本身是异步的。
//! 与其让每个宿主自己建 runtime、管生命周期，不如在这里收口：
//!
//! - 内部持有一个 tokio runtime 与后台任务（监听、广播、发现、连接维护）
//! - 对外只暴露 `set_clipboard` / `poll_event` 两个同步方法
//!
//! 这条「轮询而非回调」的边界是刻意划定的：它让 JNI 侧不需要处理线程附着，
//! 也让桌面端不必改造成异步。

use std::path::PathBuf;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::mpsc as std_mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::net::TcpStream;
use tokio::runtime::Runtime;
use tokio::sync::mpsc as tokio_mpsc;
use xime_sync_domain::profile::Profile;

use crate::app::ClipboardSet;
use crate::error::Error;
use crate::frame::{Frame, MsgType};
use crate::identity::Identity;
use crate::proto::{Connection, session_accept, session_initiate};
use crate::store::{PairedPeer, PeerStore};
use crate::transport::{Announce, Broadcaster, Listener, TCP_PORT, Watcher, connect};

/// 广播间隔。局域网内设备少，3 秒足够让对端在可感知的时间内发现。
const ANNOUNCE_INTERVAL: Duration = Duration::from_secs(3);
/// 单次等待公告的时长，决定发现循环的响应粒度。
const WATCH_SLICE: Duration = Duration::from_secs(2);
/// 默认连接超时。局域网直连要么很快成功，要么就是不通，等太久没有意义。
const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(3);

/// 节点对外事件。
#[derive(Debug, Clone)]
pub enum Event {
    /// 收到远端剪贴板条目。
    Clipboard(Profile),
    /// 对端连接状态变化。
    Peer {
        did: String,
        name: String,
        connected: bool,
    },
    /// 非致命错误，调用方记日志即可，不需要中断同步。
    Warning(String),
}

/// 节点配置。
#[derive(Clone)]
pub struct NodeConfig {
    /// 本机长期身份。多处共享使用，故用 `Arc`。
    pub identity: Arc<Identity>,
    /// 已配对表路径。
    pub store_path: PathBuf,
    /// 是否监听入站连接。桌面端通常 `true`；手机端可设 `false` 只主动连。
    pub listen: bool,
    /// 是否周期广播 + 监听公告。关闭后只能靠「上次地址」重连。
    pub discover: bool,
    /// 监听端口，被占用会自动顺延。
    pub port: u16,
    pub connect_timeout: Duration,
}

impl NodeConfig {
    pub fn new(identity: Arc<Identity>, store_path: impl Into<PathBuf>) -> Self {
        Self {
            identity,
            store_path: store_path.into(),
            listen: true,
            discover: true,
            port: TCP_PORT,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
        }
    }
}

/// 发往后台的指令。
enum Cmd {
    Clipboard(Profile),
    Stop,
}

/// 发往某条连接的指令。
enum Outbound {
    Clipboard(Profile),
    Close,
}

/// 当前活跃连接。剪贴板是单值资源，因此同一时刻只维护一条。
struct Link {
    did: String,
    tx: tokio_mpsc::UnboundedSender<Outbound>,
}

/// 同步外观。
///
/// 创建后后台立即开始工作（监听 / 广播 / 重连已配对设备）。
/// 调用方每轮 `poll_event()` 取事件，用 `set_clipboard()` 投递本地变更。
pub struct Node {
    rt: Option<Runtime>,
    cmd_tx: tokio_mpsc::UnboundedSender<Cmd>,
    events: Mutex<std_mpsc::Receiver<Event>>,
    did: String,
    port: Arc<AtomicU16>,
}

impl Node {
    /// 启动节点。
    ///
    /// 端口在返回前已绑定完成（`block_on`，毫秒级），因此 `local_port()`
    /// 立刻可用——UI 要显示端口、测试要连过来，都依赖这一点。
    /// 网络收发仍全部在后台，不会阻塞调用方。
    pub fn start(cfg: NodeConfig) -> Result<Self, Error> {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .thread_name("xime-p2p")
            .build()?;

        // 监听器在这里同步建好：失败要在 start 阶段暴露，而不是悄悄在后台失败。
        let listener = if cfg.listen {
            Some(rt.block_on(Listener::bind(cfg.port))?)
        } else {
            None
        };
        let actual_port = listener
            .as_ref()
            .and_then(|l| l.local_port().ok())
            .unwrap_or(cfg.port);

        let (cmd_tx, cmd_rx) = tokio_mpsc::unbounded_channel();
        let (event_tx, event_rx) = std_mpsc::channel();
        let did = cfg.identity.did().to_hex();
        let port = Arc::new(AtomicU16::new(actual_port));

        let task_port = Arc::clone(&port);
        rt.spawn(async move {
            run(cfg, listener, actual_port, cmd_rx, event_tx, task_port).await;
        });

        Ok(Self {
            rt: Some(rt),
            cmd_tx,
            events: Mutex::new(event_rx),
            did,
            port,
        })
    }

    /// 本机设备标识。
    pub fn did(&self) -> &str {
        &self.did
    }

    /// 实际监听端口（`listen = false` 时为配置值）。
    pub fn local_port(&self) -> u16 {
        self.port.load(Ordering::Relaxed)
    }

    /// 投递一条本地剪贴板变更。
    ///
    /// 返回 `true` 表示指令已入队；`false` 表示节点已关闭。
    /// **无连接时不会报错**——剪贴板只关心最新值，对端连上后的推送由调用方
    /// 下一次 `set_clipboard` 自然带出，不需要在这里排队回溯。
    /// 本方法不阻塞，可以在同步循环里直接调。
    pub fn set_clipboard(&self, profile: Profile) -> bool {
        self.cmd_tx.send(Cmd::Clipboard(profile)).is_ok()
    }

    /// 取一个事件，非阻塞。无事件返回 `None`。
    pub fn poll_event(&self) -> Option<Event> {
        self.events.lock().ok()?.try_recv().ok()
    }

    /// 等一个事件，最多等 `timeout`。超时返回 `None`。
    ///
    /// 会短暂阻塞调用线程，因此不要放在 async 上下文里调用。
    pub fn wait_event(&self, timeout: Duration) -> Option<Event> {
        self.events.lock().ok()?.recv_timeout(timeout).ok()
    }

    /// 关闭节点，等待后台任务收尾。
    ///
    /// 用 `shutdown_timeout` 而不是直接 drop：后者会取消正在写的任务，
    /// 可能留下半截写入的配对表。
    pub fn shutdown(mut self) {
        let _ = self.cmd_tx.send(Cmd::Stop);
        if let Some(rt) = self.rt.take() {
            rt.shutdown_timeout(Duration::from_secs(2));
        }
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.cmd_tx.send(Cmd::Stop);
        if let Some(rt) = self.rt.take() {
            rt.shutdown_timeout(Duration::from_secs(1));
        }
    }
}

// ─────────────────────────── 后台 ───────────────────────────

async fn run(
    cfg: NodeConfig,
    listener: Option<Listener>,
    port: u16,
    mut cmd_rx: tokio_mpsc::UnboundedReceiver<Cmd>,
    events: std_mpsc::Sender<Event>,
    _port_slot: Arc<AtomicU16>,
) {
    let store = match PeerStore::load(&cfg.store_path) {
        Ok(s) => Arc::new(Mutex::new(s)),
        Err(e) => {
            warn(&events, format!("配对表加载失败，同步不可用：{e}"));
            return;
        }
    };
    let link: Arc<Mutex<Option<Link>>> = Arc::new(Mutex::new(None));

    // ── 监听 ──
    let can_accept = listener.is_some();
    if let Some(listener) = listener {
        tokio::spawn(accept_loop(
            Arc::clone(&cfg.identity),
            Arc::clone(&store),
            Arc::clone(&link),
            events.clone(),
            listener,
        ));
    }

    // ── 发现 + 广播 ──
    if cfg.discover {
        // 不监听就不广播：别人即使收到公告也连不进来，广播只会造成无效连接尝试。
        if can_accept {
            tokio::spawn(announce_loop(Arc::clone(&cfg.identity), port));
        }
        tokio::spawn(discover_loop(
            cfg.clone(),
            Arc::clone(&store),
            Arc::clone(&link),
            events.clone(),
        ));
    }

    // ── 启动时先按「上次地址」直连一次 ──
    let known: Vec<PairedPeer> = store
        .lock()
        .map(|s| s.all().cloned().collect())
        .unwrap_or_default();
    for peer in known {
        tokio::spawn(connect_peer(
            peer,
            cfg.clone(),
            Arc::clone(&store),
            Arc::clone(&link),
            events.clone(),
        ));
    }

    // ── 指令循环 ──
    while let Some(cmd) = cmd_rx.recv().await {
        match cmd {
            Cmd::Clipboard(profile) => {
                let sent = link
                    .lock()
                    .ok()
                    .and_then(|guard| {
                        guard
                            .as_ref()
                            .map(|l| l.tx.send(Outbound::Clipboard(profile)).is_ok())
                    })
                    .unwrap_or(false);
                if !sent {
                    tracing::debug!("无活跃连接，本次剪贴板变更未发送");
                }
            }
            Cmd::Stop => break,
        }
    }
}

async fn accept_loop(
    identity: Arc<Identity>,
    store: Arc<Mutex<PeerStore>>,
    link: Arc<Mutex<Option<Link>>>,
    events: std_mpsc::Sender<Event>,
    listener: Listener,
) {
    loop {
        let Ok((stream, addr)) = listener.accept().await else {
            continue;
        };
        // 握手期间用快照，避免与配对写入争锁；配对表只有几项，克隆成本可忽略。
        // 每次 accept 前重读一次磁盘：新配对是在设置应用（另一个进程）里写入的，
        // 常驻的输入法进程不重读就会一直认为对方未配对。
        let snapshot = match store.lock() {
            Ok(mut s) => {
                let _ = s.reload();
                s.clone()
            }
            Err(_) => continue,
        };
        let identity = Arc::clone(&identity);
        let link = Arc::clone(&link);
        let events = events.clone();
        let store = Arc::clone(&store);
        tokio::spawn(async move {
            match session_accept(stream, &identity, &snapshot).await {
                Ok(conn) => {
                    let peer_did = conn.peer_did().to_string();
                    remember_addr(&store, &peer_did, addr);
                    serve(conn, link, events).await;
                }
                Err(e) => {
                    // 未配对设备连上来是常见情况（对面还在配对阶段），不当错误刷屏。
                    tracing::debug!("入站握手未完成：{e}");
                }
            }
        });
    }
}

/// 按「上次地址」连接一个已配对设备。
async fn connect_peer(
    peer: PairedPeer,
    cfg: NodeConfig,
    store: Arc<Mutex<PeerStore>>,
    link: Arc<Mutex<Option<Link>>>,
    events: std_mpsc::Sender<Event>,
) {
    let Some(last) = peer.last_addr.clone() else {
        return;
    };
    let Ok(addr) = last.parse::<std::net::SocketAddr>() else {
        return;
    };
    connect_peer_at(peer, addr, cfg, store, link, events).await;
}

/// 连指定地址。成功后回写 `last_addr`，下次可直接复用。
async fn connect_peer_at(
    peer: PairedPeer,
    addr: std::net::SocketAddr,
    cfg: NodeConfig,
    store: Arc<Mutex<PeerStore>>,
    link: Arc<Mutex<Option<Link>>>,
    events: std_mpsc::Sender<Event>,
) {
    // 已有连接时不再叠加：局域网内同一对端两条连接只会互相顶掉。
    if link.lock().map(|l| l.is_some()).unwrap_or(false) {
        return;
    }
    let stream = match connect(addr, cfg.connect_timeout).await {
        Ok(s) => s,
        Err(e) => {
            tracing::debug!("连接 {addr} 失败：{e}");
            return;
        }
    };
    match session_initiate(stream, &cfg.identity, &peer).await {
        Ok(conn) => {
            remember_addr(&store, &peer.did, addr);
            serve(conn, link, events).await;
        }
        Err(e) => tracing::debug!("{} 握手失败：{e}", peer.name),
    }
}

/// 注册为当前连接并跑收发循环，返回即表示断开。
async fn serve(
    mut conn: Connection<TcpStream>,
    link: Arc<Mutex<Option<Link>>>,
    events: std_mpsc::Sender<Event>,
) {
    let did = conn.peer_did().to_string();
    let name = conn.peer_name().to_string();
    let (tx, mut rx) = tokio_mpsc::unbounded_channel();

    // 顶掉旧连接。
    if let Ok(mut guard) = link.lock() {
        if let Some(old) = guard.take() {
            let _ = old.tx.send(Outbound::Close);
        }
        *guard = Some(Link {
            did: did.clone(),
            tx,
        });
    }
    emit(
        &events,
        Event::Peer {
            did: did.clone(),
            name: name.clone(),
            connected: true,
        },
    );

    // select 的结果先落到 `step`，等 select 结束再操作 conn——
    // 否则两个分支会同时借用 `conn`，借用检查过不去。
    loop {
        let step = tokio::select! {
            incoming = conn.recv() => Step::Incoming(incoming),
            out = rx.recv() => Step::Outbound(out),
        };
        match step {
            Step::Incoming(Ok(frame)) => {
                if frame.msg == MsgType::ClipboardSet {
                    match frame.parse_json::<ClipboardSet>() {
                        Ok(body) => emit(&events, Event::Clipboard(body.profile)),
                        Err(e) => warn(&events, format!("剪贴板帧解析失败：{e}")),
                    }
                } else if frame.msg == MsgType::Ping {
                    // 协议要求对 PING 回 PONG；失败说明连接已坏，直接结束。
                    if conn.send(MsgType::Pong, b"{}").await.is_err() {
                        break;
                    }
                }
            }
            Step::Incoming(Err(e)) => {
                tracing::debug!("{name} 连接结束：{e}");
                break;
            }
            Step::Outbound(Some(Outbound::Clipboard(p))) => {
                if let Err(e) = conn.send_clipboard(p).await {
                    tracing::debug!("向 {name} 发送失败：{e}");
                    break;
                }
            }
            Step::Outbound(Some(Outbound::Close) | None) => {
                let _ = conn.bye("peer replaced").await;
                break;
            }
        }
    }

    // 只有自己仍是当前连接时才清空，避免把新连接误标为断开。
    if let Ok(mut guard) = link.lock()
        && guard.as_ref().is_some_and(|l| l.did == did)
    {
        *guard = None;
    }
    emit(
        &events,
        Event::Peer {
            did,
            name,
            connected: false,
        },
    );
}

enum Step {
    Incoming(Result<Frame, Error>),
    Outbound(Option<Outbound>),
}

async fn announce_loop(identity: Arc<Identity>, port: u16) {
    let Ok(broadcaster) = Broadcaster::bind().await else {
        return;
    };
    let ann = Announce::new(identity.did().to_hex(), port);
    loop {
        // 广播失败不是致命问题（可能暂时没有可用网卡），下一轮再试。
        let _ = broadcaster.send(&ann).await;
        tokio::time::sleep(ANNOUNCE_INTERVAL).await;
    }
}

/// 监听公告：发现已配对设备就主动连过去。
async fn discover_loop(
    cfg: NodeConfig,
    store: Arc<Mutex<PeerStore>>,
    link: Arc<Mutex<Option<Link>>>,
    events: std_mpsc::Sender<Event>,
) {
    let Ok(watcher) = Watcher::bind().await else {
        // 端口被占（另一个实例在收）时不影响已配对设备用 last_addr 重连。
        tracing::debug!("公告端口被占用，本次不参与发现");
        return;
    };
    let my_did = cfg.identity.did().to_hex();
    loop {
        let Ok(Some((ann, from))) = watcher.recv(WATCH_SLICE).await else {
            continue;
        };
        if ann.did == my_did {
            continue;
        }
        let Some(peer) = store.lock().ok().and_then(|s| s.get(&ann.did).cloned()) else {
            continue;
        };
        // 公告里带的是对端真实端口（可能已顺延），不能假定为固定端口。
        let addr = std::net::SocketAddr::new(from.ip(), ann.pt);
        tracing::debug!("从公告发现 {} @ {addr}", peer.name);
        tokio::spawn(connect_peer_at(
            peer,
            addr,
            cfg.clone(),
            Arc::clone(&store),
            Arc::clone(&link),
            events.clone(),
        ));
    }
}

// ─────────────────────────── 工具 ───────────────────────────

/// 记录对端的可达地址，供发现失败时直连。
fn remember_addr(store: &Arc<Mutex<PeerStore>>, did: &str, addr: std::net::SocketAddr) {
    if let Ok(mut s) = store.lock()
        && s.set_last_addr(did, addr.to_string()).is_ok()
    {
        let _ = s.save();
    }
}

fn emit(events: &std_mpsc::Sender<Event>, event: Event) {
    // 接收端已关闭说明宿主不再需要通知，可以安全忽略。
    let _ = events.send(event);
}

fn warn(events: &std_mpsc::Sender<Event>, message: impl Into<String>) {
    let message = message.into();
    tracing::warn!("{message}");
    emit(events, Event::Warning(message));
}

/// 当前时间（Unix 秒），构造 `PairedPeer` 时用。
pub fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn temp_store() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("peers.json");
        (dir, path)
    }

    /// 等到满足条件的事件，超时返回 None。
    fn wait_for(node: &Node, timeout: Duration, pred: impl Fn(&Event) -> bool) -> Option<Event> {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            if left.is_zero() {
                return None;
            }
            if let Some(ev) = node.wait_event(left)
                && pred(&ev)
            {
                return Some(ev);
            }
        }
    }

    #[test]
    fn 无对端时投递不阻塞且能正常关闭() {
        let (_dir, path) = temp_store();
        let identity = Arc::new(Identity::generate().unwrap());
        let node = Node::start(NodeConfig {
            listen: false,
            discover: false,
            ..NodeConfig::new(identity, path)
        })
        .unwrap();
        assert!(!node.did().is_empty());
        assert!(node.set_clipboard(Profile::from_text("hello", None)));
        assert!(node.poll_event().is_none());
        node.shutdown();
    }

    #[test]
    fn 绑定端口后对外可见() {
        let (_dir, path) = temp_store();
        let identity = Arc::new(Identity::generate().unwrap());
        let node = Node::start(NodeConfig {
            discover: false,
            port: 0,
            ..NodeConfig::new(identity, path)
        })
        .unwrap();
        assert_ne!(node.local_port(), 0, "实际端口必须可读");
        node.shutdown();
    }

    #[test]
    fn 两节点可完成握手并互发剪贴板() {
        let (_d1, p1) = temp_store();
        let (_d2, p2) = temp_store();

        let id1 = Arc::new(Identity::generate().unwrap());
        let id2 = Arc::new(Identity::generate().unwrap());

        // 模拟「配对已完成」：互相写进对方表里。
        let mut s1 = PeerStore::load(&p1).unwrap();
        s1.upsert(PairedPeer::from_public(&id2.public("B"), None))
            .unwrap();
        s1.save().unwrap();
        let mut s2 = PeerStore::load(&p2).unwrap();
        // 先把 A 写进来，地址稍后补（要等 A 真的绑好端口）。
        s2.upsert(PairedPeer::from_public(&id1.public("A"), None))
            .unwrap();
        s2.save().unwrap();

        let a = Node::start(NodeConfig {
            discover: false,
            port: 0,
            ..NodeConfig::new(Arc::clone(&id1), p1)
        })
        .unwrap();

        // A 的端口已知后，补进 B 的对端表，B 启动即会自动连过来。
        let mut s2 = PeerStore::load(&p2).unwrap();
        s2.set_last_addr(&id1.did().to_hex(), format!("127.0.0.1:{}", a.local_port()))
            .unwrap();
        s2.save().unwrap();

        let b = Node::start(NodeConfig {
            discover: false,
            port: 0,
            ..NodeConfig::new(Arc::clone(&id2), p2)
        })
        .unwrap();

        // B 应看到已连接；A 也应看到对端上线。
        assert!(
            wait_for(&b, Duration::from_secs(10), |e| matches!(
                e,
                Event::Peer {
                    connected: true,
                    ..
                }
            ))
            .is_some(),
            "B 未观察到连接建立"
        );
        assert!(
            wait_for(&a, Duration::from_secs(10), |e| matches!(
                e,
                Event::Peer {
                    connected: true,
                    ..
                }
            ))
            .is_some(),
            "A 未观察到连接建立"
        );

        // B → A 方向。
        assert!(b.set_clipboard(Profile::from_text("from-b", None)));
        let got = wait_for(
            &a,
            Duration::from_secs(10),
            |e| matches!(e, Event::Clipboard(p) if p.text == "from-b"),
        );
        assert!(got.is_some(), "A 未收到 B 的剪贴板");

        // A → B 方向。
        assert!(a.set_clipboard(Profile::from_text("from-a", None)));
        let got = wait_for(
            &b,
            Duration::from_secs(10),
            |e| matches!(e, Event::Clipboard(p) if p.text == "from-a"),
        );
        assert!(got.is_some(), "B 未收到 A 的剪贴板");

        // 对端 did / source 应为本机设置，用于回环抑制。
        if let Some(Event::Clipboard(p)) = wait_for(&a, Duration::from_millis(1), |_| false) {
            let _ = p;
        }

        a.shutdown();
        b.shutdown();
        let _ = Ipv4Addr::LOCALHOST;
    }
}
