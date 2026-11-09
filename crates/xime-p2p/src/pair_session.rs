//! 配对会话的阻塞封装。
//!
//! 分层的理由：配对流程要建 runtime、跑超时、驱动异步握手，这些是协议层的事。
//! 如果把 `Runtime` 暴露给宿主，桌面端要依赖 tokio，Android 的 JNI 侧更是没法用
//! （它只能调阻塞函数）。所以这里对外只给同步接口，tokio 留在 crate 内部。
//!
//! 路径策略（身份存哪、配对表存哪）不在这里决定，由宿主传入，四端各自适配。

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::code::PairingCode;
use crate::error::Error;
use crate::identity::{Identity, PublicIdentity};
use crate::proto::{pair_as_display, pair_as_input};
use crate::store::{PairedPeer, PeerStore};
use crate::transport::{Announce, Broadcaster, Listener, PAIR_PORT, Watcher, connect};

/// 加载或生成长期身份，落盘到 `dir/identity.bin`。
///
/// 私钥文件权限必须 0600：同机其他用户读到就等于能冒充本设备完成配对，
/// 而配对一旦被冒充，后续所有剪贴板内容都会流向攻击者。
#[cfg(unix)]
pub fn load_or_create_identity(dir: &Path) -> Option<Arc<Identity>> {
    use std::os::unix::fs::PermissionsExt;

    let path = dir.join("identity.bin");
    if let Ok(bytes) = std::fs::read(&path)
        && let Ok(arr) = <[u8; 64]>::try_from(bytes.as_slice())
    {
        return Some(Arc::new(Identity::from_bytes(&arr)));
    }

    let identity = Identity::generate().ok()?;
    std::fs::write(&path, identity.to_bytes()).ok()?;
    let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    Some(Arc::new(identity))
}

/// 非 Unix 平台（Windows）：不做 POSIX 权限位，依赖用户目录的默认 ACL。
#[cfg(not(unix))]
pub fn load_or_create_identity(dir: &Path) -> Option<Arc<Identity>> {
    let path = dir.join("identity.bin");
    if let Ok(bytes) = std::fs::read(&path)
        && let Ok(arr) = <[u8; 64]>::try_from(bytes.as_slice())
    {
        return Some(Arc::new(Identity::from_bytes(&arr)));
    }
    let identity = Identity::generate().ok()?;
    std::fs::write(&path, identity.to_bytes()).ok()?;
    Some(Arc::new(identity))
}

fn one_shot_runtime() -> Result<tokio::runtime::Runtime, Error> {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .thread_name("xime-p2p-pair")
        .build()
        .map_err(Error::Io)
}

fn save_peer(store_path: &Path, public: &PublicIdentity) -> Result<(), Error> {
    let mut store = PeerStore::load(store_path)?;
    // 不写 last_addr：显示端此时并不知道自己的同步端口（可能已顺延），
    // 写一个猜测值会让下次重连指向错误端口。真实地址在首次连接成功后回写。
    store.upsert(PairedPeer::from_public(public, None))?;
    store.save()
}

/// 显示端会话的取消句柄。
///
/// 会话本体被 `wait` 独占（它要阻塞），界面线程只能通过这个句柄叫停。
#[derive(Clone)]
pub struct StopHandle(Arc<std::sync::atomic::AtomicBool>);

impl StopHandle {
    pub fn cancel(&self) {
        self.0.store(true, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn is_cancelled(&self) -> bool {
        self.0.load(std::sync::atomic::Ordering::Relaxed)
    }
}

/// 显示端会话：先拿到码给用户看，再阻塞等待对端连入。
pub struct DisplaySession {
    rt: tokio::runtime::Runtime,
    listener: Listener,
    broadcaster: Broadcaster,
    identity: Arc<Identity>,
    code: PairingCode,
    name: String,
    store_path: PathBuf,
    /// 取消标志。用户在界面上点「取消」或重新生成码时置位，
    /// 让阻塞在 [`Self::wait`] 里的线程退出并及时释放配对端口。
    stop: Arc<std::sync::atomic::AtomicBool>,
}

impl DisplaySession {
    /// 生成动态码并开始监听 + 广播。
    ///
    /// 返回后立刻可以用 [`Self::code_text`] 把码显示给用户。
    pub fn start(
        identity: Arc<Identity>,
        store_path: PathBuf,
        name: impl Into<String>,
    ) -> Result<Self, Error> {
        let code = PairingCode::generate()?;
        let rt = one_shot_runtime()?;
        let listener = rt.block_on(Listener::bind(PAIR_PORT))?;
        let broadcaster = rt.block_on(Broadcaster::bind())?;
        Ok(Self {
            rt,
            listener,
            broadcaster,
            identity,
            code,
            name: name.into(),
            store_path,
            stop: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        })
    }

    /// 显示用的码，形如 `482 719`。
    pub fn code_text(&self) -> String {
        self.code.grouped()
    }

    /// 实际监听端口。端口被占时会顺延，所以不能假定等于 `PAIR_PORT`。
    ///
    /// 输入端靠公告里的 IP 找到本机，但若公告不可达（AP 隔离、多网卡），
    /// 用户也可以手工把这个端口填到二维码里。
    pub fn local_port(&self) -> Result<u16, Error> {
        self.listener.local_port()
    }

    /// 码是否已过期。过期后必须重新 [`Self::start`]，不能续用。
    pub fn is_expired(&self) -> bool {
        self.code.is_expired()
    }

    /// 请求结束等待。可从其他线程调用：`wait` 会在下一次循环跳出。
    ///
    /// 必须提供这个口子——否则用户点「取消」或重新生成码时，旧会话还占着
    /// 配对端口，新会话只能顺延，公告与监听端口就对不上了。
    pub fn cancel(&self) {
        self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
    }

    /// 取一个可跨线程使用的取消句柄（会话被移进等待线程后，界面只剩它）。
    pub fn stop_handle(&self) -> StopHandle {
        StopHandle(Arc::clone(&self.stop))
    }

    /// 阻塞等待对端连入并完成配对。
    ///
    /// 期间持续广播公告让输入端能发现本机。单个连接配对失败（例如对面输错码）
    /// 不会中断整个流程，会继续等下一个——用户手滑是常态。
    pub fn wait(&mut self, timeout: Duration) -> Result<PublicIdentity, Error> {
        let identity = Arc::clone(&self.identity);
        let code = self.code;
        let name = self.name.clone();
        let store_path = self.store_path.clone();
        let listener = &self.listener;
        let broadcaster = &self.broadcaster;
        let stop = Arc::clone(&self.stop);
        // 端口可能因占用顺延，公告必须写真实端口；写死 PAIR_PORT 会让
        // 输入端连到一个没人监听的端口，表现为「一直找不到设备」。
        let ann = Announce::new(identity.did().to_hex(), self.listener.local_port()?);

        self.rt.block_on(async move {
            let deadline = Instant::now() + timeout;
            loop {
                if stop.load(std::sync::atomic::Ordering::Relaxed) {
                    return Err(Error::Internal("已取消配对".into()));
                }
                if code.is_expired() {
                    return Err(Error::CodeExpired);
                }
                let _ = broadcaster.send(&ann).await;

                let left = deadline.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    return Err(Error::Internal("等待配对超时".into()));
                }
                let slice = left.min(Duration::from_secs(1));
                let Ok(Ok((mut stream, _addr))) =
                    tokio::time::timeout(slice, listener.accept()).await
                else {
                    continue;
                };

                match pair_as_display(&mut stream, &identity, &name, &code).await {
                    Ok(public) => {
                        save_peer(&store_path, &public)?;
                        return Ok(public);
                    }
                    // 输错码 / 版本不符 / 对端中途断开都归到这里，继续等下一个。
                    Err(_) => continue,
                }
            }
        })
    }
}

/// 输入端：用动态码连接显示端完成配对。
///
/// 地址来自局域网公告——用户不需要填 IP。若发现端口被占用（通常意味着
/// 另一个实例正在做发现），返回明确的错误而不是静默超时。
pub fn join(
    identity: Arc<Identity>,
    store_path: PathBuf,
    code_input: &str,
    name: impl Into<String>,
    timeout: Duration,
) -> Result<PublicIdentity, Error> {
    let name = name.into();
    let code = parse_code(code_input)?;

    let rt = one_shot_runtime()?;
    rt.block_on(async move {
        let watcher = Watcher::bind()
            .await
            .map_err(|e| Error::Internal(format!("发现端口 {PAIR_PORT} 不可用：{e}")))?;
        let deadline = Instant::now() + timeout;

        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(Error::Internal("未发现在线设备".into()));
            }
            let Ok(Some((ann, from))) = watcher.recv(left.min(Duration::from_secs(1))).await
            else {
                continue;
            };

            // 端口取公告里的实际值：对端配对端口可能已被别的进程占走而顺延，
            // 用常量 PAIR_PORT 会连到空端口上。
            let addr = std::net::SocketAddr::new(from.ip(), ann.pt);
            let Ok(mut stream) = connect(addr, Duration::from_secs(2)).await else {
                continue;
            };
            match pair_as_input(&mut stream, &identity, &name, &code).await {
                Ok(public) => {
                    save_peer(&store_path, &public)?;
                    return Ok(public);
                }
                // 码错了就直接失败：对同一台设备反复试同一个错码没有意义，
                // 而且会白白消耗协议里的尝试次数。
                Err(e) => return Err(e),
            }
        }
    })
}

/// 输入端：已知地址时直接连（二维码带 IP、或用户手工输入 IP）。
///
/// 这条路径不依赖 UDP 广播，因此在 AP 隔离、多网卡环境或广播被防火墙拦掉时
/// 仍然可用——它是发现失败时的兜底。
pub fn join_at(
    identity: Arc<Identity>,
    store_path: PathBuf,
    code_input: &str,
    name: impl Into<String>,
    addr: std::net::SocketAddr,
    timeout: Duration,
) -> Result<PublicIdentity, Error> {
    let name = name.into();
    let code = parse_code(code_input)?;

    let rt = one_shot_runtime()?;
    rt.block_on(async move {
        let mut stream = connect(addr, timeout).await?;
        let public = pair_as_input(&mut stream, &identity, &name, &code).await?;
        save_peer(&store_path, &public)?;
        Ok(public)
    })
}

/// 解析用户输入的码。界面上显示的是 `482 719`，粘贴进来常带空格或全角空格。
fn parse_code(code_input: &str) -> Result<PairingCode, Error> {
    let cleaned: String = code_input.chars().filter(|c| c.is_ascii_digit()).collect();
    let digits = PairingCode::parse(&cleaned)?;
    PairingCode::from_digits(digits)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn temp_dir() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    #[test]
    fn 身份首次生成后再次加载一致() {
        let dir = temp_dir();
        let a = load_or_create_identity(dir.path()).unwrap();
        let b = load_or_create_identity(dir.path()).unwrap();
        assert_eq!(a.did().to_hex(), b.did().to_hex());
    }

    #[cfg(unix)]
    #[test]
    fn 身份文件权限为_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = temp_dir();
        load_or_create_identity(dir.path()).unwrap();
        let meta = std::fs::metadata(dir.path().join("identity.bin")).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
    }

    #[test]
    fn 动态码解析容忍空格() {
        let cleaned: String = "482 719".chars().filter(|c| c.is_ascii_digit()).collect();
        assert_eq!(PairingCode::parse(&cleaned).unwrap(), 482_719);
    }

    #[test]
    fn 非法码被拒绝() {
        let cleaned: String = "abc".chars().filter(|c| c.is_ascii_digit()).collect();
        assert!(PairingCode::parse(&cleaned).is_err());
    }

    /// 两端跑完整配对流程：显示端出码，输入端用同一个码连上去。
    ///
    /// 走真实 TCP（`join_at` 直连），不走 UDP 广播——单机测试里广播回环
    /// 在部分平台/防火墙配置下并不可靠，那会让这条测试变成随机失败的噪声。
    /// 广播路径由 `transport` 里的编解码测试覆盖，配对语义由这里覆盖。
    #[test]
    fn 双端可完成配对() {
        let dir_a = temp_dir();
        let dir_b = temp_dir();
        let store_a = dir_a.path().join("peers.json");
        let store_b = dir_b.path().join("peers.json");
        let id_a = load_or_create_identity(dir_a.path()).unwrap();
        let id_b = load_or_create_identity(dir_b.path()).unwrap();

        let mut display = DisplaySession::start(Arc::clone(&id_a), store_a.clone(), "Mac")
            .expect("显示端启动失败");
        let code = display.code_text();
        let port = display.local_port().unwrap();

        let wait_handle = std::thread::spawn(move || display.wait(Duration::from_secs(20)));

        let joined = join_at(
            Arc::clone(&id_b),
            store_b.clone(),
            &code,
            "Phone",
            std::net::SocketAddr::from(([127, 0, 0, 1], port)),
            Duration::from_secs(20),
        );

        let shown = wait_handle.join().expect("等待线程崩溃");
        let joined = joined.expect("输入端配对失败");
        let shown = shown.expect("显示端配对失败");

        // 两端拿到的对端身份必须互相指向。
        assert_eq!(shown.did().to_hex(), id_b.did().to_hex());
        assert_eq!(joined.did().to_hex(), id_a.did().to_hex());

        // 配对表两侧都应写入对端。
        let a = PeerStore::load(&store_a).unwrap();
        let b = PeerStore::load(&store_b).unwrap();
        assert_eq!(a.len(), 1);
        assert_eq!(b.len(), 1);
        assert!(a.get(&id_b.did().to_hex()).is_some());
        assert!(b.get(&id_a.did().to_hex()).is_some());
    }

    /// 码不对时必须失败，且不能把对端写进配对表。
    #[test]
    fn 错误动态码配对失败() {
        let dir_a = temp_dir();
        let dir_b = temp_dir();
        let store_a = dir_a.path().join("peers.json");
        let store_b = dir_b.path().join("peers.json");
        let id_a = load_or_create_identity(dir_a.path()).unwrap();
        let id_b = load_or_create_identity(dir_b.path()).unwrap();

        let mut display = DisplaySession::start(Arc::clone(&id_a), store_a.clone(), "Mac")
            .expect("显示端启动失败");
        let port = display.local_port().unwrap();
        let right = display.code_text();

        // 换一个必然不同的码。
        let wrong = if right.starts_with("000") {
            "111111"
        } else {
            "000000"
        };

        // 显示端只需等到「确认没有配对成功」，3 秒足够——这条路径不该有等待。
        let wait_handle = std::thread::spawn(move || display.wait(Duration::from_secs(3)));
        let joined = join_at(
            Arc::clone(&id_b),
            store_b.clone(),
            wrong,
            "Phone",
            std::net::SocketAddr::from(([127, 0, 0, 1], port)),
            Duration::from_secs(5),
        );

        assert!(joined.is_err(), "错误码不应配对成功");
        // 输入端不能留下对端记录。
        let b = PeerStore::load(&store_b).unwrap();
        assert!(b.is_empty(), "失败配对不应写入配对表");
        // 显示端仍在等下一个连接，超时后返回错误（不是 panic）。
        let _ = wait_handle.join();
    }
}
