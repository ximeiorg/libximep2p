//! 同步外观层：把异步的连接管理收成一个同步接口。
//!
//! 存在的理由：桌面端（XimeYi）的同步循环是 `std::thread` + 每 2 秒一次 tick 的
//! 同步代码，Android 的 JNI 桥也只能轮询。而连接、握手、收发本身是异步的。
//! 与其让每个宿主自己建 runtime、管生命周期，不如在这里收口：
//!
//! - 内部持有一个 tokio runtime 与后台任务（监听、广播、发现、连接维护）
//! - 对外只暴露 `set_clipboard` / `poll_event` / `status` 三个同步方法
//!
//! 这条「轮询而非回调」的边界是刻意划定的：它让 JNI 侧不需要处理线程附着，
//! 也让桌面端不必改造成异步。
//!
//! ## 多连接
//!
//! 每条已配对设备各持一条独立会话（`HashMap<did, Link>`）。剪贴板是单值资源，
//! 老实现只维护一条连接，导致「三台设备最多只有一台在线」——这既丢同步，
//! 也让界面无法按设备显示状态。
//!
//! ## 在线状态
//!
//! 状态有两个正交来源，不能混成一个布尔量：
//!
//! - **连接**（[`PeerState::Online`]）：本机与对端有活跃加密会话，能立刻同步；
//! - **在场**（[`PeerState::Nearby`]）：最近 [`PRESENCE_TTL`] 内收到过对端公告，
//!   但它当前没有连本机（可能在连别的设备，或本机正在退回重试）。
//!
//! 只有两者都没有才是 [`PeerState::Offline`]。把它们合成一个「在线/离线」会让
//! 界面说谎：设备明明开着，只是没连上，却显示成离线。

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU16, AtomicU64, Ordering};
use std::sync::mpsc as std_mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

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
use crate::transport::{AnnKind, Announce, Broadcaster, Listener, TCP_PORT, Watcher, connect};

/// 广播间隔。局域网内设备少，3 秒足够让对端在可感知的时间内发现。
const ANNOUNCE_INTERVAL: Duration = Duration::from_secs(3);
/// 单次等待公告的时长，决定发现循环的响应粒度。
const WATCH_SLICE: Duration = Duration::from_secs(2);
/// 默认连接超时。局域网直连要么很快成功，要么就是不通，等太久没有意义。
const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
/// 心跳间隔。
///
/// **必须明显小于 [`crate::proto::IDLE_TIMEOUT`]（30 秒）**：`Connection::recv`
/// 自带 30 秒读超时，而协议里没有任何一方会主动发帧。两端都沉默时，空闲连接
/// 会被对端判成断开——表现为「连上 30 秒后自己掉线，过一会儿又连上」。
/// 心跳顺带把死连接检测从 TCP 重传级（分钟级）压到秒级。
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(10);
/// 在场判定窗口：公告周期 3 秒，容忍连丢三次。
const PRESENCE_TTL: Duration = Duration::from_secs(12);
/// 已配对但未连接时的重试间隔。
///
/// 发现循环只在收到公告时才发起连接；公告被广播域、AP 隔离或多网卡挡住时，
/// 没有这条重试就再也连不上了。
const RETRY_INTERVAL: Duration = Duration::from_secs(5);

/// 会话令牌计数器。进程内单调递增，用于区分同一台设备的先后会话。
static TOKEN: AtomicU64 = AtomicU64::new(1);

fn next_token() -> u64 {
    TOKEN.fetch_add(1, Ordering::Relaxed)
}

/// 节点对外事件。
#[derive(Debug, Clone)]
pub enum Event {
    /// 收到远端剪贴板条目。
    Clipboard(Profile),
    /// 收到某个 topic 的业务消息（剪贴板以外的新功能走这里）。
    Message { topic: String, payload: Vec<u8> },
    /// 对端连接状态变化。
    Peer {
        did: String,
        name: String,
        connected: bool,
    },
    /// 非致命错误，调用方记日志即可，不需要中断同步。
    Warning(String),
}

/// 对端在场状态。
///
/// 序列化用 `lowercase`，C ABI / JNI / NAPI 三端共用同一份字面量，
/// 不要在各自的宿主里再翻译一遍。
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PeerState {
    /// 有活跃会话，能立刻同步。
    Online,
    /// 最近收到过公告，但没有会话（对端在跑，只是没连上本机）。
    Nearby,
    /// 既没会话也没公告——不等于关机，见 [`NodeStatus`] 的说明。
    Offline,
}

/// 单台设备的即时状态。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PeerStatus {
    pub did: String,
    pub name: String,
    pub state: PeerState,
    /// 当前会话建立时间（Unix 秒），仅 [`PeerState::Online`] 有值。
    pub since: Option<i64>,
    /// 最后一次确认对端存在的时间（Unix 秒）：会话建立/心跳，或收到公告。
    /// 从已配对表读出的历史值也在这里，界面可以显示「上次在线 …」。
    pub last_seen: Option<i64>,
    /// 当前会话的对端地址，或上次成功连接的地址。
    pub addr: Option<String>,
}

/// 节点快照。
///
/// 为什么不只发事件：宿主界面按秒轮询，而事件是边沿的。断线重连会连发
/// 「断开→连上」两条，界面按事件改灯就会闪；重启后更是拿不到任何状态。
/// 快照给的是**水平值**，界面直接渲染即可。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct NodeStatus {
    pub did: String,
    /// 监听端口（`listen = false` 时为配置值）。
    pub port: u16,
    /// 与已配对表顺序一致；未配对的公告不在这里出现。
    pub peers: Vec<PeerStatus>,
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
    Message { topic: String, payload: Vec<u8> },
    Stop,
}

/// 发往某条连接的指令。
enum Outbound {
    Clipboard(Profile),
    Message { topic: String, payload: Vec<u8> },
    Close,
}

/// 各 topic 的最近一条消息，供新连接建立后补发。
#[derive(Default)]
struct Cache {
    clipboard: Option<Profile>,
    topics: HashMap<String, Vec<u8>>,
}

/// 当前活跃连接：一台设备一条，按 `did` 索引。
struct Link {
    did: String,
    tx: tokio_mpsc::UnboundedSender<Outbound>,
    /// 会话令牌，每次建连递增。
    ///
    /// 收尾时只能按令牌比对，**不能按 `did`**：同一台设备重连（两端同时拨号、
    /// 或掉线后立刻重连）时，旧会话的收尾会把新会话的登记一起清掉，表现为
    /// 「明明连着却显示离线，剪贴板也不再推送」。
    token: u64,
    /// 这次会话的拨号方 `did`。
    ///
    /// 两端都存了对方地址时，启动会互相拨号，得到两条方向相反、互为镜像的连接。
    /// 若两边按各自看到的「最新」去留，可能各留一条**不同的** TCP 连接，随后互相
    /// 关掉对方保留的那条，双双清零再重连——实测会掉一次连接（见
    /// `双端同时拨号后保持稳定单连接`）。改用拨号方 `did` 的字典序裁决：
    /// 保留「较小 did 拨出的那条」。两端算出的赢家是同一条连接，不会互相拆台。
    dialer: String,
    since: i64,
    addr: SocketAddr,
}

type Links = Arc<Mutex<HashMap<String, Link>>>;
/// 最近一次收到某设备公告的时刻：`(单调时钟, Unix 秒)`。
type Presence = Arc<Mutex<HashMap<String, (Instant, i64)>>>;
/// 正在拨号的设备，用于避免发现循环与重试循环重复连同一台。
type Connecting = Arc<Mutex<HashSet<String>>>;

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
    /// 与后台任务共用：界面读状态、后台改状态。
    links: Links,
    presence: Presence,
    store: Arc<Mutex<PeerStore>>,
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

        // 配对表在这里加载：状态查询要读它，不能等后台任务起来才有。
        // 加载失败直接报错——表里是用户的信任关系，静默降级成空表等于把所有
        // 设备退回未配对，用户只会看到「设备都不见了」。
        let store = Arc::new(Mutex::new(PeerStore::load(&cfg.store_path)?));

        let (cmd_tx, cmd_rx) = tokio_mpsc::unbounded_channel();
        let (event_tx, event_rx) = std_mpsc::channel();
        let did = cfg.identity.did().to_hex();
        let port = Arc::new(AtomicU16::new(actual_port));
        let links: Links = Arc::new(Mutex::new(HashMap::new()));
        let presence: Presence = Arc::new(Mutex::new(HashMap::new()));

        let task_port = Arc::clone(&port);
        let task_presence = Arc::clone(&presence);
        let hub = Hub {
            cfg,
            store: Arc::clone(&store),
            links: Arc::clone(&links),
            // 各 topic 的最近一条：无连接时投递的变更没有队列，靠它在新连接建立后补发。
            // 剪贴板是单值资源，只保留最新一条即可（与协议「只关心最新值」一致）。
            cache: Arc::new(Mutex::new(Cache::default())),
            connecting: Arc::new(Mutex::new(HashSet::new())),
            events: event_tx,
        };
        rt.spawn(async move {
            run(hub, listener, actual_port, cmd_rx, task_port, task_presence).await;
        });

        Ok(Self {
            rt: Some(rt),
            cmd_tx,
            events: Mutex::new(event_rx),
            did,
            port,
            links,
            presence,
            store,
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

    /// 当前状态快照（水平值，非事件）。
    ///
    /// 界面按秒轮询它即可，不需要自己维护状态机——事件是边沿的，
    /// 断线重连时会连发两条，按事件改灯就会闪。
    pub fn status(&self) -> NodeStatus {
        // 先取出已配对表快照并释放锁：三把锁不能嵌套，否则与后台上锁顺序
        // 不一致时会死锁。
        let known: Vec<PairedPeer> = self
            .store
            .lock()
            .map(|s| s.all().cloned().collect())
            .unwrap_or_default();
        let links = self.links.lock().ok();
        let presence = self.presence.lock().ok();
        let now = Instant::now();

        let peers = known
            .into_iter()
            .map(|peer| {
                let link = links.as_ref().and_then(|m| m.get(&peer.did));
                let seen = presence
                    .as_ref()
                    .and_then(|m| m.get(&peer.did))
                    .filter(|(at, _)| now.duration_since(*at) <= PRESENCE_TTL)
                    .map(|(_, unix)| *unix);
                let (state, since, addr) = match link {
                    Some(l) => (PeerState::Online, Some(l.since), Some(l.addr.to_string())),
                    None if seen.is_some() => (PeerState::Nearby, None, peer.last_addr.clone()),
                    None => (PeerState::Offline, None, peer.last_addr.clone()),
                };
                PeerStatus {
                    did: peer.did.clone(),
                    name: peer.name.clone(),
                    state,
                    since,
                    last_seen: match state {
                        PeerState::Online => Some(now_secs()),
                        _ => seen.or(peer.last_seen),
                    },
                    addr,
                }
            })
            .collect();

        NodeStatus {
            did: self.did.clone(),
            port: self.local_port(),
            peers,
        }
    }

    /// 投递一条本地剪贴板变更。
    ///
    /// 返回 `true` 表示指令已入队；`false` 表示节点已关闭。
    /// **无连接时不会报错**：节点会记住最近一条，等连接建立后补发一次
    /// （剪贴板只关心最新值，不需要排队回溯历史变更）。
    /// 本方法不阻塞，可以在同步循环里直接调。
    pub fn set_clipboard(&self, profile: Profile) -> bool {
        self.cmd_tx.send(Cmd::Clipboard(profile)).is_ok()
    }

    /// 投递一条业务无关的 topic 消息。
    ///
    /// 与 [`Self::set_clipboard`] 同理：无连接时节点会记住每 topic 的最新一条，
    /// 等连接建立后补发。
    pub fn send_message(&self, topic: impl Into<String>, payload: Vec<u8>) -> bool {
        self.cmd_tx
            .send(Cmd::Message {
                topic: topic.into(),
                payload,
            })
            .is_ok()
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

/// 后台四条任务（监听 / 发现 / 重试 / 收发）共享的上下文。
///
/// 收成一个结构体而不是逐个传参：这些字段每条任务都要用，散着传既容易漏，
/// 也会让各处上锁顺序悄悄分叉——状态查询一旦和后台的顺序不一致就是死锁。
#[derive(Clone)]
struct Hub {
    cfg: NodeConfig,
    store: Arc<Mutex<PeerStore>>,
    links: Links,
    connecting: Connecting,
    cache: Arc<Mutex<Cache>>,
    events: std_mpsc::Sender<Event>,
}

async fn run(
    hub: Hub,
    listener: Option<Listener>,
    port: u16,
    mut cmd_rx: tokio_mpsc::UnboundedReceiver<Cmd>,
    _port_slot: Arc<AtomicU16>,
    presence: Presence,
) {
    // ── 监听 ──
    let can_accept = listener.is_some();
    if let Some(listener) = listener {
        tokio::spawn(accept_loop(
            Arc::clone(&hub.cfg.identity),
            hub.clone(),
            listener,
        ));
    }

    // ── 发现 + 广播 ──
    if hub.cfg.discover {
        // 不监听就不广播：别人即使收到公告也连不进来，广播只会造成无效连接尝试。
        if can_accept {
            tokio::spawn(announce_loop(Arc::clone(&hub.cfg.identity), port));
        }
        tokio::spawn(discover_loop(hub.clone(), presence));
    }

    // 重试与发现是两件事：公告可能根本到不了（跨网段、AP 隔离、多网卡发错口），
    // 没有这条重试，一次断开就是永久失联——用户看到的是「一直离线」。
    // 即使关了广播（`discover = false`），仍应按「上次地址」把设备连回来。
    tokio::spawn(retry_loop(hub.clone()));

    // ── 启动时先按「上次地址」直连一次 ──
    let known: Vec<PairedPeer> = hub
        .store
        .lock()
        .map(|s| s.all().cloned().collect())
        .unwrap_or_default();
    for peer in known {
        tokio::spawn(connect_peer(hub.clone(), peer));
    }

    // ── 指令循环 ──
    while let Some(cmd) = cmd_rx.recv().await {
        match cmd {
            Cmd::Clipboard(profile) => {
                // 先记下来：手机端是「按需上线」，投递时往往还没连接，
                // 只丢弃会让对端连上后收不到最近一次复制（见 P2P-DEVICE-LINK §4）。
                if let Ok(mut cache) = hub.cache.lock() {
                    cache.clipboard = Some(profile.clone());
                }
                // 多连接：同一份内容发给所有在线设备。对端按 hash 去重，
                // 重复内容不会重复写系统剪贴板。
                let targets = link_targets(&hub.links);
                let mut sent = 0usize;
                for (_, tx) in &targets {
                    if tx.send(Outbound::Clipboard(profile.clone())).is_ok() {
                        sent += 1;
                    }
                }
                if sent == 0 {
                    tracing::debug!("无活跃连接，本次剪贴板变更留待连接后补发");
                }
            }
            Cmd::Message { topic, payload } => {
                if let Ok(mut cache) = hub.cache.lock() {
                    cache.topics.insert(topic.clone(), payload.clone());
                }
                let targets = link_targets(&hub.links);
                let mut sent = 0usize;
                for (_, tx) in &targets {
                    if tx
                        .send(Outbound::Message {
                            topic: topic.clone(),
                            payload: payload.clone(),
                        })
                        .is_ok()
                    {
                        sent += 1;
                    }
                }
                if sent == 0 {
                    tracing::debug!("无活跃连接，消息 {topic} 留待连接后补发");
                }
            }
            Cmd::Stop => break,
        }
    }
}

/// 取当前所有连接的发送端快照。
///
/// 不在持锁状态下发送：发送端是无界队列，入队失败意味着对端任务已结束，
/// 逐条处理比整表加锁更不容易阻塞后台。
fn link_targets(links: &Links) -> Vec<(String, tokio_mpsc::UnboundedSender<Outbound>)> {
    links
        .lock()
        .map(|m| m.values().map(|l| (l.did.clone(), l.tx.clone())).collect())
        .unwrap_or_default()
}

/// 注销某次会话的登记；返回是否确实删掉了。
///
/// 按令牌比对而非 `did`：同一台设备可能已经有更新的会话占了槽位，
/// 旧会话收尾时不能把新会话一起带走。
fn unregister(links: &Links, did: &str, token: u64) -> bool {
    links
        .lock()
        .map(|mut m| {
            if m.get(did).is_some_and(|l| l.token == token) {
                m.remove(did);
                true
            } else {
                false
            }
        })
        .unwrap_or(false)
}

async fn accept_loop(identity: Arc<Identity>, hub: Hub, listener: Listener) {
    loop {
        let Ok((stream, addr)) = listener.accept().await else {
            continue;
        };
        // 握手期间用快照，避免与配对写入争锁；配对表只有几项，克隆成本可忽略。
        // 每次 accept 前重读一次磁盘：新配对是在设置应用（另一个进程）里写入的，
        // 常驻的输入法进程不重读就会一直认为对方未配对。
        let snapshot = match hub.store.lock() {
            Ok(mut s) => {
                let _ = s.reload();
                s.clone()
            }
            Err(_) => continue,
        };
        let identity = Arc::clone(&identity);
        let hub = hub.clone();
        tokio::spawn(async move {
            match session_accept(stream, &identity, &snapshot).await {
                Ok(conn) => {
                    let peer_did = conn.peer_did().to_string();
                    remember_addr(&hub.store, &peer_did, addr);
                    // 入站：这条连接是对方拨过来的。
                    serve(conn, addr, hub, true).await;
                }
                Err(e) => {
                    // 未配对设备连上来是常见情况（对面还在配对阶段），不当错误刷屏。
                    tracing::debug!("入站握手未完成：{e}");
                }
            }
        });
    }
}

/// 拨号中的设备集合守卫：离开作用域即释放，避免握手失败后该设备被永久标记为「正在拨号」。
struct DialGuard {
    set: Connecting,
    did: String,
}

impl Drop for DialGuard {
    fn drop(&mut self) {
        if let Ok(mut set) = self.set.lock() {
            set.remove(&self.did);
        }
    }
}

/// 按「上次地址」连接一个已配对设备。
async fn connect_peer(hub: Hub, peer: PairedPeer) {
    let Some(last_addr) = peer.last_addr.clone() else {
        return;
    };
    let Ok(addr) = last_addr.parse::<SocketAddr>() else {
        return;
    };
    connect_peer_at(hub, peer, addr).await;
}

/// 连指定地址。成功后回写 `last_addr`，下次可直接复用。
async fn connect_peer_at(hub: Hub, peer: PairedPeer, addr: SocketAddr) {
    // 已有连接就不再叠加：同一台设备两条会话只会互相顶掉，界面还会闪一下。
    // 注意只检查这一台——别的设备在线不影响本台重连。
    if hub
        .links
        .lock()
        .map(|m| m.contains_key(&peer.did))
        .unwrap_or(false)
    {
        return;
    }
    // 发现循环和重试循环可能同时挑中同一台，只让先到的拨号。
    {
        let Ok(mut set) = hub.connecting.lock() else {
            return;
        };
        if !set.insert(peer.did.clone()) {
            return;
        }
    }
    let _guard = DialGuard {
        set: Arc::clone(&hub.connecting),
        did: peer.did.clone(),
    };

    let stream = match connect(addr, hub.cfg.connect_timeout).await {
        Ok(s) => s,
        Err(e) => {
            tracing::debug!("连接 {addr} 失败：{e}");
            return;
        }
    };
    match session_initiate(stream, &hub.cfg.identity, &peer).await {
        Ok(conn) => {
            remember_addr(&hub.store, &peer.did, addr);
            // 出站：这条连接由本机拨出。
            serve(conn, addr, hub, false).await;
        }
        Err(e) => tracing::debug!("{} 握手失败：{e}", peer.name),
    }
}

/// 注册为当前连接并跑收发循环，返回即表示断开。
async fn serve(mut conn: Connection<TcpStream>, addr: SocketAddr, hub: Hub, inbound: bool) {
    let did = conn.peer_did().to_string();
    let name = conn.peer_name().to_string();
    let my_did = hub.cfg.identity.did().to_hex();
    let token = next_token();
    let (tx, mut rx) = tokio_mpsc::unbounded_channel();
    // 这条连接是谁拨的：入站就是对方，出站就是自己。两端据此算出同一个赢家。
    let dialer = if inbound { did.clone() } else { my_did };

    // 同一台设备只留一条会话。保留规则按拨号方 did 裁决，见 `Link::dialer`。
    // 旧连接被顶掉时不发 `Peer{connected:false}`：设备状态没变，界面不该闪。
    let keep_existing;
    let previous;
    {
        // 锁必须在 await 之前释放：spawn 出去的任务要 Send，跨 await 持锁过不去。
        let Ok(mut m) = hub.links.lock() else {
            return;
        };
        keep_existing = m
            .get(&did)
            .is_some_and(|existing| existing.dialer.as_str() <= dialer.as_str());
        previous = if keep_existing {
            None
        } else {
            m.insert(
                did.clone(),
                Link {
                    did: did.clone(),
                    tx,
                    token,
                    dialer,
                    since: now_secs(),
                    addr,
                },
            )
        };
    }
    if keep_existing {
        // 对方拨出的那条更优先：回一句 BYE，别让对端干等。
        let _ = conn.bye("duplicate").await;
        return;
    }
    let first_link = previous.is_none();
    if let Some(old) = previous {
        let _ = old.tx.send(Outbound::Close);
    }
    if first_link {
        emit(
            &hub.events,
            Event::Peer {
                did: did.clone(),
                name: name.clone(),
                connected: true,
            },
        );
    }

    // 连上即同步：把缓存里最近一次本地剪贴板补发给对端。
    // 对端按 hash 去重，重复内容不会写系统剪贴板，因此不会造成回声。
    let (cached_clipboard, cached_topics) = hub
        .cache
        .lock()
        .map(|c| (c.clipboard.clone(), c.topics.clone()))
        .unwrap_or_default();
    if let Some(profile) = cached_clipboard
        && let Err(e) = conn.send_clipboard(profile).await
    {
        tracing::debug!("向 {name} 补发剪贴板失败：{e}");
    }
    for (topic, payload) in cached_topics {
        if let Err(e) = conn.send_message(&topic, payload).await {
            tracing::debug!("向 {name} 补发 {topic} 失败：{e}");
        }
    }

    // 心跳：`Connection::recv` 自带 30 秒读超时，而协议里没人主动发帧，
    // 两端都沉默时空闲连接会被自己判死（表现为连上 30 秒后掉线再重连）。
    // 顺带把死连接检测压到秒级：对端拔网线时不会再有十几分钟的假在线。
    let mut beat = tokio::time::interval_at(
        tokio::time::Instant::now() + HEARTBEAT_INTERVAL,
        HEARTBEAT_INTERVAL,
    );
    beat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    // select 的结果先落到 `step`，等 select 结束再操作 conn——
    // 否则两个分支会同时借用 `conn`，借用检查过不去。
    loop {
        let step = tokio::select! {
            incoming = conn.recv() => Step::Incoming(incoming),
            out = rx.recv() => Step::Outbound(out),
            _ = beat.tick() => Step::Beat,
        };
        match step {
            Step::Incoming(Ok(frame)) => {
                if frame.msg == MsgType::ClipboardSet {
                    match frame.parse_json::<ClipboardSet>() {
                        Ok(body) => emit(&hub.events, Event::Clipboard(body.profile)),
                        Err(e) => warn(&hub.events, format!("剪贴板帧解析失败：{e}")),
                    }
                } else if frame.msg == MsgType::Message {
                    match frame.parse_json::<crate::app::TopicMessage>() {
                        Ok(body) => emit(
                            &hub.events,
                            Event::Message {
                                topic: body.topic,
                                payload: body.payload.0,
                            },
                        ),
                        Err(e) => warn(&hub.events, format!("消息帧解析失败：{e}")),
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
            Step::Beat => {
                if let Err(e) = conn.ping().await {
                    tracing::debug!("{name} 心跳发送失败：{e}");
                    break;
                }
            }
            Step::Outbound(Some(Outbound::Clipboard(p))) => {
                if let Err(e) = conn.send_clipboard(p).await {
                    tracing::debug!("向 {name} 发送失败：{e}");
                    break;
                }
            }
            Step::Outbound(Some(Outbound::Message { topic, payload })) => {
                if let Err(e) = conn.send_message(&topic, payload).await {
                    tracing::debug!("向 {name} 发送 {topic} 失败：{e}");
                    break;
                }
            }
            Step::Outbound(Some(Outbound::Close) | None) => {
                let _ = conn.bye("peer replaced").await;
                break;
            }
        }
    }

    // 只清理自己的登记。
    //
    // 这里**不能**按 `did` 比对：同一台设备重连时，新会话已经占了这个槽位，
    // 旧会话按 did 判断会把它一起清掉，于是「明明连着却显示离线、剪贴板也不动了」。
    // 令牌（token）是每次建连唯一递增的，只有仍指向自己时才删。
    let removed = unregister(&hub.links, &did, token);
    if removed {
        if let Ok(mut s) = hub.store.lock() {
            // 记下最后一次确认在线的时间，重启后界面能显示「上次在线 …」。
            let _ = s.set_last_seen(&did, now_secs());
        }
        emit(
            &hub.events,
            Event::Peer {
                did,
                name,
                connected: false,
            },
        );
    }
}

enum Step {
    Incoming(Result<Frame, Error>),
    Outbound(Option<Outbound>),
    /// 心跳定时器：发一条 PING 让对端与自己的读超时都重置。
    Beat,
}

/// 已配对但当前没连上的设备，定期按 `last_addr` 重试。
///
/// 发现循环依赖公告；公告到不了时（跨网段、AP 隔离、多网卡发错口），
/// 没有这条重试就再也连不上——这正是「设备明明开着却一直离线」的成因。
async fn retry_loop(hub: Hub) {
    let mut ticker = tokio::time::interval(RETRY_INTERVAL);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        ticker.tick().await;
        // 每轮重读磁盘：新配对在另一个进程里完成，不重读就永远不知道。
        let known: Vec<PairedPeer> = hub
            .store
            .lock()
            .map(|mut s| {
                let _ = s.reload();
                s.all().cloned().collect()
            })
            .unwrap_or_default();
        for peer in known {
            if peer.last_addr.is_none() {
                continue;
            }
            if hub
                .links
                .lock()
                .map(|m| m.contains_key(&peer.did))
                .unwrap_or(false)
            {
                continue;
            }
            tokio::spawn(connect_peer(hub.clone(), peer));
        }
    }
}

async fn announce_loop(identity: Arc<Identity>, port: u16) {
    let Ok(broadcaster) = Broadcaster::bind().await else {
        return;
    };
    let ann = Announce::new(identity.did().to_hex(), port, AnnKind::Node);
    loop {
        // 广播失败不是致命问题（可能暂时没有可用网卡），下一轮再试。
        let _ = broadcaster.send(&ann).await;
        tokio::time::sleep(ANNOUNCE_INTERVAL).await;
    }
}

/// 监听公告：记录在场信息，并对已配对设备主动连过去。
async fn discover_loop(hub: Hub, presence: Presence) {
    let Ok(watcher) = Watcher::bind().await else {
        // 端口被占（另一个实例在收）时不影响已配对设备用 last_addr 重连。
        tracing::debug!("公告端口被占用，本次不参与发现");
        return;
    };
    let my_did = hub.cfg.identity.did().to_hex();
    loop {
        let Ok(Some((ann, from))) = watcher.recv(WATCH_SLICE).await else {
            continue;
        };
        if ann.did == my_did {
            continue;
        }
        // 收到公告就是「在场」，与连没连上无关。这条记录是界面能显示
        // 「附近但未连接」的唯一来源，所以必须记在过滤之前。
        if let Ok(mut p) = presence.lock() {
            p.insert(ann.did.clone(), (Instant::now(), now_secs()));
        }
        // 配对会话的端口讲的是配对协议，拿来跑同步会话只会握手失败。
        if ann.k == AnnKind::Pair {
            continue;
        }
        // 每轮重新读盘：新配对是在设置进程里写进表的，常驻节点不重读就会一直
        // 认为对方未配对——表现为「配完了，但要重启键盘才连上」。
        let Some(peer) = hub.store.lock().ok().and_then(|mut s| {
            let _ = s.reload();
            s.get(&ann.did).cloned()
        }) else {
            continue;
        };
        // 公告里带的是对端真实端口（可能已顺延），不能假定为固定端口。
        let addr = SocketAddr::new(from.ip(), ann.pt);
        tracing::debug!("从公告发现 {} @ {addr}", peer.name);
        tokio::spawn(connect_peer_at(hub.clone(), peer, addr));
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

    /// 手机端是「按需上线」：投递剪贴板时往往还没有连接。这类变更不能丢，
    /// 对端连上后必须补发一次，否则表现为「键盘开了、连上了，但刚复制的内容收不到」。
    #[test]
    fn 无连接时投递的剪贴板会在连上后补发() {
        let (_d1, p1) = temp_store();
        let (_d2, p2) = temp_store();
        let id1 = Arc::new(Identity::generate().unwrap());
        let id2 = Arc::new(Identity::generate().unwrap());

        let mut s1 = PeerStore::load(&p1).unwrap();
        s1.upsert(PairedPeer::from_public(&id2.public("B"), None))
            .unwrap();
        s1.save().unwrap();

        let a = Node::start(NodeConfig {
            discover: false,
            port: 0,
            ..NodeConfig::new(Arc::clone(&id1), p1)
        })
        .unwrap();
        // 此刻还没有任何连接：这条必须有缓存，否则测试拿不到。
        assert!(a.set_clipboard(Profile::from_text("early", None)));

        let mut s2 = PeerStore::load(&p2).unwrap();
        s2.upsert(PairedPeer::from_public(&id1.public("A"), None))
            .unwrap();
        s2.set_last_addr(&id1.did().to_hex(), format!("127.0.0.1:{}", a.local_port()))
            .unwrap();
        s2.save().unwrap();

        let b = Node::start(NodeConfig {
            discover: false,
            port: 0,
            ..NodeConfig::new(Arc::clone(&id2), p2)
        })
        .unwrap();

        let got = wait_for(
            &b,
            Duration::from_secs(10),
            |e| matches!(e, Event::Clipboard(p) if p.text == "early"),
        );
        assert!(got.is_some(), "连上后未收到缓存的剪贴板");

        a.shutdown();
        b.shutdown();
    }

    /// topic 消息是与剪贴板平行的通用入口：新功能（词库/主题等）以后只加 topic，
    /// 不再动帧层与 Node 的结构。
    #[test]
    fn 两节点可互发_topic_消息() {
        let (_d1, p1) = temp_store();
        let (_d2, p2) = temp_store();
        let id1 = Arc::new(Identity::generate().unwrap());
        let id2 = Arc::new(Identity::generate().unwrap());

        let mut s1 = PeerStore::load(&p1).unwrap();
        s1.upsert(PairedPeer::from_public(&id2.public("B"), None))
            .unwrap();
        s1.save().unwrap();

        let a = Node::start(NodeConfig {
            discover: false,
            port: 0,
            ..NodeConfig::new(Arc::clone(&id1), p1)
        })
        .unwrap();

        let mut s2 = PeerStore::load(&p2).unwrap();
        s2.upsert(PairedPeer::from_public(&id1.public("A"), None))
            .unwrap();
        s2.set_last_addr(&id1.did().to_hex(), format!("127.0.0.1:{}", a.local_port()))
            .unwrap();
        s2.save().unwrap();

        let b = Node::start(NodeConfig {
            discover: false,
            port: 0,
            ..NodeConfig::new(Arc::clone(&id2), p2)
        })
        .unwrap();

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

        assert!(b.send_message("theme", b"theme-bytes".to_vec()));
        let got = wait_for(
            &a,
            Duration::from_secs(10),
            |e| matches!(e, Event::Message { topic, payload } if topic == "theme" && payload == b"theme-bytes"),
        );
        assert!(got.is_some(), "A 未收到 topic 消息");

        a.shutdown();
        b.shutdown();
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

    /// 轮询到期望状态，超时返回 `false`。
    fn wait_state(node: &Node, did: &str, want: PeerState, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        loop {
            if node
                .status()
                .peers
                .iter()
                .any(|p| p.did == did && p.state == want)
            {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// 三台设备（一台桌面 + 两台手机）应同时保持会话，剪贴板发给所有在线设备。
    ///
    /// 老实现只有单个连接槽位，第二台连上来就把第一台顶掉——表现为
    /// 「列表里永远只有一台在线」，且复制内容只会到其中一台。
    #[test]
    fn 三台设备可同时在线且剪贴板广播到全部() {
        let (_d1, p1) = temp_store();
        let (_d2, p2) = temp_store();
        let (_d3, p3) = temp_store();
        let id1 = Arc::new(Identity::generate().unwrap());
        let id2 = Arc::new(Identity::generate().unwrap());
        let id3 = Arc::new(Identity::generate().unwrap());
        let did1 = id1.did().to_hex();
        let did2 = id2.did().to_hex();
        let did3 = id3.did().to_hex();

        // A 的配对表里有两台设备。
        let mut s1 = PeerStore::load(&p1).unwrap();
        s1.upsert(PairedPeer::from_public(&id2.public("B"), None))
            .unwrap();
        s1.upsert(PairedPeer::from_public(&id3.public("C"), None))
            .unwrap();
        s1.save().unwrap();

        let a = Node::start(NodeConfig {
            discover: false,
            port: 0,
            ..NodeConfig::new(Arc::clone(&id1), p1)
        })
        .unwrap();
        let port = a.local_port();

        for (id, path, name) in [(&id2, &p2, "B"), (&id3, &p3, "C")] {
            let mut s = PeerStore::load(path).unwrap();
            s.upsert(PairedPeer::from_public(&id1.public("A"), None))
                .unwrap();
            s.set_last_addr(&did1, format!("127.0.0.1:{port}")).unwrap();
            s.save().unwrap();
            let _ = (id, name);
        }

        let b = Node::start(NodeConfig {
            discover: false,
            port: 0,
            ..NodeConfig::new(Arc::clone(&id2), p2)
        })
        .unwrap();
        let c = Node::start(NodeConfig {
            discover: false,
            port: 0,
            ..NodeConfig::new(Arc::clone(&id3), p3)
        })
        .unwrap();

        assert!(
            wait_state(&a, &did2, PeerState::Online, Duration::from_secs(10)),
            "B 未连上 A"
        );
        assert!(
            wait_state(&a, &did3, PeerState::Online, Duration::from_secs(10)),
            "C 未连上 A；多条连接没有同时保持"
        );
        assert_eq!(
            a.status()
                .peers
                .iter()
                .filter(|p| p.state == PeerState::Online)
                .count(),
            2,
            "A 应同时对两台设备在线"
        );

        // 两台手机 → A。
        assert!(b.set_clipboard(Profile::from_text("from-b", None)));
        assert!(
            wait_for(
                &a,
                Duration::from_secs(10),
                |e| matches!(e, Event::Clipboard(p) if p.text == "from-b")
            )
            .is_some(),
            "A 未收到 B 的剪贴板"
        );
        assert!(c.set_clipboard(Profile::from_text("from-c", None)));
        assert!(
            wait_for(
                &a,
                Duration::from_secs(10),
                |e| matches!(e, Event::Clipboard(p) if p.text == "from-c")
            )
            .is_some(),
            "A 未收到 C 的剪贴板"
        );

        // A → 两台手机（广播）。
        assert!(a.set_clipboard(Profile::from_text("from-a", None)));
        for node in [&b, &c] {
            assert!(
                wait_for(
                    node,
                    Duration::from_secs(10),
                    |e| matches!(e, Event::Clipboard(p) if p.text == "from-a")
                )
                .is_some(),
                "剪贴板没有广播到所有在线设备"
            );
        }

        a.shutdown();
        b.shutdown();
        c.shutdown();
    }

    /// 状态快照必须区分三种情况：有会话 / 只收到公告 / 什么都没有。
    ///
    /// 合成一个布尔量会让界面说谎：设备明明开着、只是没连上，却显示成离线。
    #[test]
    fn 状态快照区分在线_附近与离线() {
        let (_dir, path) = temp_store();
        let id1 = Arc::new(Identity::generate().unwrap());
        let id2 = Arc::new(Identity::generate().unwrap());
        let did2 = id2.did().to_hex();

        let mut s1 = PeerStore::load(&path).unwrap();
        s1.upsert(PairedPeer::from_public(&id2.public("B"), None))
            .unwrap();
        s1.save().unwrap();

        let a = Node::start(NodeConfig {
            discover: false,
            port: 0,
            ..NodeConfig::new(Arc::clone(&id1), path)
        })
        .unwrap();

        let state = || a.status().peers[0].state;
        assert_eq!(state(), PeerState::Offline, "还没任何联系时应为离线");

        // 模拟收到公告：在场但没有会话。
        a.presence
            .lock()
            .unwrap()
            .insert(did2.clone(), (Instant::now(), now_secs()));
        assert_eq!(state(), PeerState::Nearby, "收到公告应为「附近」");

        // 公告过期（超过窗口）回到离线。
        a.presence.lock().unwrap().insert(
            did2.clone(),
            (
                Instant::now() - PRESENCE_TTL - Duration::from_secs(1),
                now_secs(),
            ),
        );
        assert_eq!(state(), PeerState::Offline, "公告过期应回到离线");

        a.shutdown();
    }

    /// 同一台设备重连时，旧会话的收尾不能把新会话的登记清掉。
    ///
    /// 这正是「明明连着却显示离线、剪贴板也不动」的成因：按 `did` 比对时，
    /// 旧任务看到槽位上还是这台设备，就把新任务刚写进去的连接删了。
    #[test]
    fn 过期会话的收尾不会清掉新会话() {
        let links: Links = Arc::new(Mutex::new(HashMap::new()));
        let (tx, _rx) = tokio_mpsc::unbounded_channel();
        links.lock().unwrap().insert(
            "peer".to_string(),
            Link {
                did: "peer".to_string(),
                tx,
                token: 1,
                dialer: "peer".to_string(),
                since: 0,
                addr: "127.0.0.1:1".parse().unwrap(),
            },
        );

        // 令牌 2 是新会话：旧会话（令牌 1）收尾时必须什么都不做。
        assert!(!unregister(&links, "peer", 2), "旧令牌不应删除新会话");
        assert!(
            links.lock().unwrap().contains_key("peer"),
            "新会话的登记被误删"
        );

        // 令牌 1 才是自己，删得掉。
        assert!(unregister(&links, "peer", 1));
        assert!(links.lock().unwrap().is_empty());
    }

    /// 关掉广播后，未连接的已配对设备仍应被「上次地址」重试连回来。
    ///
    /// 公告到不了的网络（跨网段、AP 隔离、多网卡）里，重试是唯一的自愈手段。
    #[test]
    fn 未连接时按上次地址重试() {
        // 先占一个端口再释放，当作「对端稍后才监听的端口」。
        let port = {
            let l = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
            l.local_addr().unwrap().port()
        };
        let (_d1, p1) = temp_store();
        let id1 = Arc::new(Identity::generate().unwrap());
        let id2 = Arc::new(Identity::generate().unwrap());
        let did2 = id2.did().to_hex();

        let mut s1 = PeerStore::load(&p1).unwrap();
        let mut peer = PairedPeer::from_public(&id2.public("B"), None);
        peer.last_addr = Some(format!("127.0.0.1:{port}"));
        s1.upsert(peer).unwrap();
        s1.save().unwrap();

        let a = Node::start(NodeConfig {
            discover: false,
            port: 0,
            ..NodeConfig::new(Arc::clone(&id1), p1)
        })
        .unwrap();
        // 此刻 B 还没起，首次连接必然失败。
        assert!(
            !wait_state(&a, &did2, PeerState::Online, Duration::from_millis(300)),
            "B 还没启动，不该已经连上"
        );

        let (_d2, p2) = temp_store();
        let mut s2 = PeerStore::load(&p2).unwrap();
        s2.upsert(PairedPeer::from_public(&id1.public("A"), None))
            .unwrap();
        s2.save().unwrap();
        let b = Node::start(NodeConfig {
            discover: false,
            port,
            ..NodeConfig::new(Arc::clone(&id2), p2)
        })
        .unwrap();

        assert!(
            wait_state(&a, &did2, PeerState::Online, Duration::from_secs(15)),
            "重试循环没有把设备连回来"
        );

        a.shutdown();
        b.shutdown();
    }

    /// 统计窗口内收到的「断开」事件数。
    fn count_disconnects(node: &Node, window: Duration) -> usize {
        let deadline = Instant::now() + window;
        let mut count = 0;
        while Instant::now() < deadline {
            match node.poll_event() {
                Some(Event::Peer {
                    connected: false, ..
                }) => count += 1,
                Some(_) => {}
                None => std::thread::sleep(Duration::from_millis(20)),
            }
        }
        count
    }

    /// 两端同时拨号（都存了对方地址时必然发生）必须收敛成一条连接，且之后不抖。
    ///
    /// 替换策略刻意与旧版一致（保留最新）：旧版收到新连接就顶掉旧的。
    /// 若新版按别的规则裁决，两端各自保留的连接可能不是同一条，随后互相踢断，
    /// 表现为升级过渡期连接周期性抖动。
    #[test]
    fn 双端同时拨号后保持稳定单连接() {
        // 先各占一个端口再释放，好让两端「一开始就互相知道地址」。
        let port = || {
            let l = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
            l.local_addr().unwrap().port()
        };
        let (pa, pb) = (port(), port());
        let (_da, sa) = temp_store();
        let (_db, sb) = temp_store();
        let ida = Arc::new(Identity::generate().unwrap());
        let idb = Arc::new(Identity::generate().unwrap());
        let did_a = ida.did().to_hex();
        let did_b = idb.did().to_hex();

        for (path, me, peer, peer_addr) in [
            (&sa, &ida, &idb, format!("127.0.0.1:{pb}")),
            (&sb, &idb, &ida, format!("127.0.0.1:{pa}")),
        ] {
            let mut s = PeerStore::load(path).unwrap();
            s.upsert(PairedPeer::from_public(&peer.public("x"), None))
                .unwrap();
            s.set_last_addr(&peer.did().to_hex(), peer_addr).unwrap();
            s.save().unwrap();
            let _ = me;
        }

        let a = Node::start(NodeConfig {
            discover: false,
            port: pa,
            ..NodeConfig::new(Arc::clone(&ida), sa)
        })
        .unwrap();
        let b = Node::start(NodeConfig {
            discover: false,
            port: pb,
            ..NodeConfig::new(Arc::clone(&idb), sb)
        })
        .unwrap();

        assert!(
            wait_state(&a, &did_b, PeerState::Online, Duration::from_secs(10))
                && wait_state(&b, &did_a, PeerState::Online, Duration::from_secs(10)),
            "双端未能建连"
        );

        // 稳定期：不应出现任何断开事件（顶掉旧连接不算断开）。
        assert_eq!(
            count_disconnects(&a, Duration::from_secs(4)),
            0,
            "A 侧连接抖动"
        );
        assert_eq!(
            count_disconnects(&b, Duration::from_secs(4)),
            0,
            "B 侧连接抖动"
        );
        assert_eq!(a.status().peers[0].state, PeerState::Online);
        assert_eq!(b.status().peers[0].state, PeerState::Online);

        a.shutdown();
        b.shutdown();
    }

    /// 空闲连接不能因为 `Connection::recv` 的 30 秒读超时被自己判死。
    ///
    /// 需要跑满 35 秒，默认不执行：`cargo test -p xime-p2p -- --ignored`。
    #[test]
    #[ignore = "需 35 秒，验证心跳维持空闲连接"]
    fn 心跳维持空闲连接() {
        let (_d1, p1) = temp_store();
        let (_d2, p2) = temp_store();
        let id1 = Arc::new(Identity::generate().unwrap());
        let id2 = Arc::new(Identity::generate().unwrap());
        let did1 = id1.did().to_hex();
        let did2 = id2.did().to_hex();

        let mut s1 = PeerStore::load(&p1).unwrap();
        s1.upsert(PairedPeer::from_public(&id2.public("B"), None))
            .unwrap();
        s1.save().unwrap();
        let a = Node::start(NodeConfig {
            discover: false,
            port: 0,
            ..NodeConfig::new(Arc::clone(&id1), p1)
        })
        .unwrap();

        let mut s2 = PeerStore::load(&p2).unwrap();
        s2.upsert(PairedPeer::from_public(&id1.public("A"), None))
            .unwrap();
        s2.set_last_addr(&did1, format!("127.0.0.1:{}", a.local_port()))
            .unwrap();
        s2.save().unwrap();
        let b = Node::start(NodeConfig {
            discover: false,
            port: 0,
            ..NodeConfig::new(Arc::clone(&id2), p2)
        })
        .unwrap();

        assert!(wait_state(
            &a,
            &did2,
            PeerState::Online,
            Duration::from_secs(10)
        ));
        // 超过 proto::IDLE_TIMEOUT（30 秒）仍应在线。
        std::thread::sleep(Duration::from_secs(35));
        assert_eq!(
            a.status().peers[0].state,
            PeerState::Online,
            "空闲 35 秒后连接被断开，心跳没有生效"
        );

        a.shutdown();
        b.shutdown();
    }
}
