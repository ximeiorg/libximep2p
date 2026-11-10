//! `xime-p2p` 的 C ABI 薄层，面向非 Rust 宿主（鸿蒙 NAPI）。
//!
//! 约定：
//!
//! - 参数是 UTF-8 C 字符串；路径由宿主给出（各端沙箱不同，本层不猜）。
//! - 返回是 JSON 字符串，形如 `{"ok":true,...}` 或 `{"ok":false,"error":"..."}`，
//!   调用方用 [`xime_p2p_free`] 释放；不用静态缓冲区，NAPI 是多线程的。
//! - 内部持有一个全局 `Node` 与一个配对任务，宿主按「单线程串行调用」使用。
//! - 每个入口都包了 `catch_unwind`：panic 不得跨 FFI 边界。

use std::ffi::{CStr, CString, c_char};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::Serialize;
use serde_json::{Value, json};
use xime_p2p::{DisplaySession, Event, Identity, Node, NodeConfig, PeerStore, Profile};

/// 常驻同步节点（同一进程只有一个）。
static NODE: Mutex<Option<Node>> = Mutex::new(None);
/// 当前配对任务。
static PAIR: Mutex<Option<PairJob>> = Mutex::new(None);

struct PairJob {
    state: Arc<Mutex<PairState>>,
    /// 仅显示端有取消句柄；输入端阻塞在连接里，靠超时退出。
    stop: Option<xime_p2p::StopHandle>,
}

#[derive(Clone, Default)]
struct PairState {
    phase: String,
    code: Option<String>,
    port: u16,
    peer: Option<PeerInfo>,
    error: Option<String>,
}

#[derive(Clone, Serialize)]
struct PeerInfo {
    did: String,
    name: String,
}

// ─────────────────────────── 公共脚手架 ───────────────────────────

fn out(v: Value) -> *mut c_char {
    let text = v.to_string();
    match CString::new(text) {
        Ok(c) => c.into_raw(),
        // JSON 里不会出现裸 NUL，走到这里说明上游数据异常，返回一个固定错误即可。
        Err(_) => CString::new(r#"{"ok":false,"error":"返回内容含非法字符"}"#)
            .expect("字面量无 NUL")
            .into_raw(),
    }
}

fn err(msg: impl ToString) -> *mut c_char {
    out(json!({ "ok": false, "error": msg.to_string() }))
}

/// 统一入口：捕获 panic 并把错误压成 JSON。
fn guard<F>(f: F) -> *mut c_char
where
    F: FnOnce() -> Result<Value, String>,
{
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(Ok(v)) => out(v),
        Ok(Err(e)) => err(e),
        Err(_) => err("内部错误：native panic"),
    }
}

/// 读取 C 字符串参数。空指针与非法 UTF-8 都返回 `None`。
unsafe fn arg(p: *const c_char) -> Option<String> {
    if p.is_null() {
        return None;
    }
    unsafe { CStr::from_ptr(p) }
        .to_str()
        .ok()
        .map(|v| v.to_owned())
}

fn identity_for(dir: &str) -> Result<Arc<Identity>, String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("目录创建失败：{e}"))?;
    xime_p2p::load_or_create_identity(Path::new(dir))
        .ok_or_else(|| "身份不可用（系统随机源异常）".to_string())
}

fn store_path(dir: &str) -> PathBuf {
    Path::new(dir).join("peers.json")
}

fn event_json(e: Event) -> Value {
    match e {
        Event::Clipboard(profile) => json!({ "type": "clipboard", "profile": profile }),
        Event::Peer {
            did,
            name,
            connected,
        } => json!({ "type": "peer", "did": did, "name": name, "connected": connected }),
        Event::Message { topic, payload } => {
            // 负载是任意字节，用 base64 交给宿主（JS/ArkTS 侧再决定怎么解）。
            let data = b64_encode(&payload);
            json!({ "type": "message", "topic": topic, "data": data })
        }
        Event::Warning(message) => json!({ "type": "warning", "message": message }),
    }
}

fn cancel_pair_locked() {
    let Ok(mut guard) = PAIR.lock() else {
        return;
    };
    if let Some(job) = guard.take()
        && let Some(stop) = job.stop
    {
        stop.cancel();
    }
}

// ─────────────────────────── 身份 ───────────────────────────

/// 加载或生成本机身份，返回 `{ok,did}`。
#[unsafe(no_mangle)]
pub extern "C" fn xime_p2p_identity(dir: *const c_char) -> *mut c_char {
    guard(|| {
        let dir = unsafe { arg(dir) }.ok_or("缺少目录参数")?;
        let identity = identity_for(&dir)?;
        Ok(json!({ "ok": true, "did": identity.did().to_hex() }))
    })
}

// ─────────────────────────── 节点 ───────────────────────────

/// 启动同步节点。`listen`/`discover` 传 0 表示关闭；`port` 传 0 用协议默认。
#[unsafe(no_mangle)]
pub extern "C" fn xime_p2p_start(
    dir: *const c_char,
    listen: i32,
    discover: i32,
    port: i32,
) -> *mut c_char {
    guard(|| {
        let dir = unsafe { arg(dir) }.ok_or("缺少目录参数")?;
        let identity = identity_for(&dir)?;

        let mut cfg = NodeConfig::new(identity, store_path(&dir));
        cfg.listen = listen != 0;
        cfg.discover = discover != 0;
        if port > 0 {
            cfg.port = port as u16;
        }

        // 重复启动时先收掉旧节点，避免两个实例抢同一端口。
        if let Ok(mut guard) = NODE.lock()
            && let Some(old) = guard.take()
        {
            old.shutdown();
        }

        let node = Node::start(cfg).map_err(|e| format!("节点启动失败：{e}"))?;
        let info = json!({
            "ok": true,
            "did": node.did(),
            "port": node.local_port(),
        });
        if let Ok(mut guard) = NODE.lock() {
            *guard = Some(node);
        }
        Ok(info)
    })
}

/// 关闭同步节点。返回 1 表示原本在运行。
#[unsafe(no_mangle)]
pub extern "C" fn xime_p2p_stop() -> i32 {
    match catch_unwind(AssertUnwindSafe(|| {
        NODE.lock().ok().and_then(|mut g| g.take())
    })) {
        Ok(Some(node)) => {
            node.shutdown();
            1
        }
        _ => 0,
    }
}

/// base64 编解码（C ABI 层用，避免宿主再引依赖）。
fn b64_encode(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// 投递一条业务无关的 topic 消息。返回 1 表示已入队（无连接时也会在连上后补发）。
///
/// 剪贴板也走同一入口（`topic = "clipboard"`），以后新增同步功能不必再加 C 函数。
#[unsafe(no_mangle)]
pub extern "C" fn xime_p2p_send_message(topic: *const c_char, payload: *const c_char) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| -> Result<bool, String> {
        let topic = unsafe { arg(topic) }.ok_or("缺少 topic")?;
        let payload = unsafe { arg(payload) }.ok_or("缺少 payload")?;
        let guard = NODE.lock().map_err(|_| "状态锁不可用")?;
        let node = guard.as_ref().ok_or("节点未启动")?;
        Ok(node.send_message(topic, payload.into_bytes()))
    }));
    match result {
        Ok(Ok(true)) => 1,
        _ => 0,
    }
}

/// 投递一条文本剪贴板条目。返回 1 表示已入队（无连接时也返回 1，由对端连上后补发）。
#[unsafe(no_mangle)]
pub extern "C" fn xime_p2p_set_clipboard(text: *const c_char, source: *const c_char) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| -> Result<bool, String> {
        let text = unsafe { arg(text) }.ok_or("缺少文本参数")?;
        if text.is_empty() {
            return Ok(false);
        }
        let source = unsafe { arg(source) }.filter(|v| !v.is_empty());
        let guard = NODE.lock().map_err(|_| "状态锁不可用")?;
        let node = guard.as_ref().ok_or("节点未启动")?;
        // 缺省用本机 did 作为来源，接收端据此丢弃回环。
        let source = source.or_else(|| Some(node.did().to_string()));
        Ok(node.set_clipboard(Profile::from_text(text, source)))
    }));
    match result {
        Ok(Ok(true)) => 1,
        _ => 0,
    }
}

/// 取事件（非阻塞）。返回 `{ok,events:[...]}`，无事件时 `events` 为空数组。
#[unsafe(no_mangle)]
pub extern "C" fn xime_p2p_poll(max: i32) -> *mut c_char {
    guard(|| {
        let limit = max.clamp(1, 256) as usize;
        let guard = NODE.lock().map_err(|_| "状态锁不可用")?;
        let mut events = Vec::new();
        if let Some(node) = guard.as_ref() {
            while events.len() < limit {
                match node.poll_event() {
                    Some(e) => events.push(event_json(e)),
                    None => break,
                }
            }
        }
        Ok(json!({ "ok": true, "events": events }))
    })
}

/// 节点状态：`{ok,running,did,port}`。
#[unsafe(no_mangle)]
pub extern "C" fn xime_p2p_status() -> *mut c_char {
    guard(|| {
        let guard = NODE.lock().map_err(|_| "状态锁不可用")?;
        match guard.as_ref() {
            Some(node) => Ok(json!({
                "ok": true,
                "running": true,
                "did": node.did(),
                "port": node.local_port(),
            })),
            None => Ok(json!({ "ok": true, "running": false })),
        }
    })
}

// ─────────────────────────── 配对 ───────────────────────────

/// 显示端：生成动态码并等待对端连入。返回 `{ok,code,port}`，进度用 [`xime_p2p_pair_poll`] 取。
#[unsafe(no_mangle)]
pub extern "C" fn xime_p2p_pair_display(
    dir: *const c_char,
    name: *const c_char,
    timeout_sec: i32,
) -> *mut c_char {
    guard(|| {
        let dir = unsafe { arg(dir) }.ok_or("缺少目录参数")?;
        let name = unsafe { arg(name) }.unwrap_or_else(|| "HarmonyOS".to_string());
        let identity = identity_for(&dir)?;

        cancel_pair_locked();

        let mut session = DisplaySession::start(identity, store_path(&dir), name)
            .map_err(|e| format!("配对启动失败：{e}"))?;
        let code = session.code_text();
        let port = session.local_port().map_err(|e| e.to_string())?;
        let stop = session.stop_handle();

        let state = Arc::new(Mutex::new(PairState {
            phase: "waiting".to_string(),
            code: Some(code.clone()),
            port,
            peer: None,
            error: None,
        }));

        let thread_state = Arc::clone(&state);
        let thread_stop = stop.clone();
        let timeout = timeout_sec.clamp(10, 300) as u64;
        std::thread::spawn(move || {
            let result = session.wait(Duration::from_secs(timeout));
            if let Ok(mut s) = thread_state.lock() {
                match result {
                    Ok(public) => {
                        s.phase = "done".to_string();
                        s.peer = Some(PeerInfo {
                            did: public.did().to_hex(),
                            name: public.name().to_string(),
                        });
                    }
                    Err(e) => {
                        s.phase = if thread_stop.is_cancelled() {
                            "cancelled".to_string()
                        } else {
                            "failed".to_string()
                        };
                        s.error = Some(e.to_string());
                    }
                }
            }
        });

        if let Ok(mut guard) = PAIR.lock() {
            *guard = Some(PairJob {
                state,
                stop: Some(stop),
            });
        }
        Ok(json!({ "ok": true, "code": code, "port": port }))
    })
}

/// 输入端：用动态码配对。`addr` 为空时走局域网发现，否则直连 `ip:port`。
#[unsafe(no_mangle)]
pub extern "C" fn xime_p2p_pair_input(
    dir: *const c_char,
    name: *const c_char,
    code: *const c_char,
    addr: *const c_char,
    timeout_sec: i32,
) -> *mut c_char {
    guard(|| {
        let dir = unsafe { arg(dir) }.ok_or("缺少目录参数")?;
        let name = unsafe { arg(name) }.unwrap_or_else(|| "HarmonyOS".to_string());
        let code = unsafe { arg(code) }.ok_or("缺少动态码")?;
        let addr = unsafe { arg(addr) }.filter(|v| !v.is_empty());
        let identity = identity_for(&dir)?;

        cancel_pair_locked();

        let state = Arc::new(Mutex::new(PairState {
            phase: "waiting".to_string(),
            code: None,
            port: 0,
            peer: None,
            error: None,
        }));

        let thread_state = Arc::clone(&state);
        let store = store_path(&dir);
        let timeout = timeout_sec.clamp(10, 300) as u64;
        std::thread::spawn(move || {
            let result = match addr {
                Some(addr) => match addr.parse::<std::net::SocketAddr>() {
                    Ok(socket) => xime_p2p::join_at(
                        identity,
                        store,
                        &code,
                        name,
                        socket,
                        Duration::from_secs(timeout),
                    ),
                    Err(e) => Err(xime_p2p::Error::Internal(format!("地址格式错误：{e}"))),
                },
                None => xime_p2p::join(identity, store, &code, name, Duration::from_secs(timeout)),
            };
            if let Ok(mut s) = thread_state.lock() {
                match result {
                    Ok(public) => {
                        s.phase = "done".to_string();
                        s.peer = Some(PeerInfo {
                            did: public.did().to_hex(),
                            name: public.name().to_string(),
                        });
                    }
                    Err(e) => {
                        s.phase = "failed".to_string();
                        s.error = Some(e.to_string());
                    }
                }
            }
        });

        if let Ok(mut guard) = PAIR.lock() {
            *guard = Some(PairJob { state, stop: None });
        }
        Ok(json!({ "ok": true }))
    })
}

/// 配对进度：`{ok,phase,code,port,peer,error}`，`phase` 为 idle/waiting/done/failed/cancelled。
#[unsafe(no_mangle)]
pub extern "C" fn xime_p2p_pair_poll() -> *mut c_char {
    guard(|| {
        let state = PAIR
            .lock()
            .ok()
            .and_then(|g| g.as_ref().map(|j| Arc::clone(&j.state)));
        let Some(state) = state else {
            return Ok(json!({ "ok": true, "phase": "idle" }));
        };
        let s = state.lock().map_err(|_| "配对状态锁不可用")?.clone();
        Ok(json!({
            "ok": true,
            "phase": s.phase,
            "code": s.code,
            "port": s.port,
            "peer": s.peer,
            "error": s.error,
        }))
    })
}

/// 取消当前配对（仅显示端能立刻打断，输入端靠超时）。
#[unsafe(no_mangle)]
pub extern "C" fn xime_p2p_pair_cancel() -> i32 {
    match catch_unwind(AssertUnwindSafe(|| {
        let Ok(guard) = PAIR.lock() else {
            return false;
        };
        // 保留任务：poll 要能读到「cancelled」，而不是任务消失后回到 idle。
        let Some(job) = guard.as_ref() else {
            return false;
        };
        let Some(stop) = job.stop.as_ref() else {
            return false;
        };
        stop.cancel();
        if let Ok(mut state) = job.state.lock()
            && state.phase == "waiting"
        {
            state.phase = "cancelled".to_string();
        }
        true
    })) {
        Ok(true) => 1,
        _ => 0,
    }
}

// ─────────────────────────── 已配对设备 ───────────────────────────

/// 已配对设备列表：`{ok,peers:[{did,name,last_addr,paired_at}]}`。
#[unsafe(no_mangle)]
pub extern "C" fn xime_p2p_peers(dir: *const c_char) -> *mut c_char {
    guard(|| {
        let dir = unsafe { arg(dir) }.ok_or("缺少目录参数")?;
        let store = PeerStore::load(store_path(&dir)).map_err(|e| e.to_string())?;
        let peers: Vec<Value> = store
            .all()
            .map(|p| {
                json!({
                    "did": p.did,
                    "name": p.name,
                    "last_addr": p.last_addr,
                    "paired_at": p.paired_at,
                })
            })
            .collect();
        Ok(json!({ "ok": true, "peers": peers }))
    })
}

/// 删除一个已配对设备。返回 1 表示确实删掉了。
#[unsafe(no_mangle)]
pub extern "C" fn xime_p2p_forget(dir: *const c_char, did: *const c_char) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| -> Result<bool, String> {
        let dir = unsafe { arg(dir) }.ok_or("缺少目录参数")?;
        let did = unsafe { arg(did) }.ok_or("缺少 did")?;
        let mut store = PeerStore::load(store_path(&dir)).map_err(|e| e.to_string())?;
        let removed = store.remove(&did).map_err(|e| e.to_string())?;
        if removed {
            store.save().map_err(|e| e.to_string())?;
        }
        Ok(removed)
    }));
    match result {
        Ok(Ok(true)) => 1,
        _ => 0,
    }
}

// ─────────────────────────── 内存 ───────────────────────────

/// 释放本层返回的字符串。
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xime_p2p_free(p: *mut c_char) {
    if !p.is_null() {
        unsafe { drop(CString::from_raw(p)) };
    }
}

#[cfg(test)]
mod tests {
    //! C ABI 层的自测：验证 JSON 形状与单例状态机，不涉及跨进程互通
    //! （那由 `xime-p2p` 的 Node 端到端测试覆盖）。
    //!
    //! 全局单例决定了这些用例必须串行，故用一把锁把所有用例排开。

    use super::*;
    use std::sync::{Mutex, MutexGuard};

    static SERIAL: Mutex<()> = Mutex::new(());

    fn lock() -> MutexGuard<'static, ()> {
        SERIAL.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn call_json(raw: *mut c_char) -> Value {
        assert!(!raw.is_null(), "返回了空指针");
        let text = unsafe { CStr::from_ptr(raw) }
            .to_str()
            .expect("返回值不是合法 UTF-8")
            .to_owned();
        unsafe { xime_p2p_free(raw) };
        serde_json::from_str(&text).expect("返回值不是合法 JSON")
    }

    fn c(text: &str) -> CString {
        CString::new(text).unwrap()
    }

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("xime-p2p-c-{}-{}", tag, std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn 身份可重复读取且一致() {
        let _guard = lock();
        let dir = temp_dir("identity");
        let dir_c = c(dir.to_str().unwrap());

        let first = call_json(xime_p2p_identity(dir_c.as_ptr()));
        let second = call_json(xime_p2p_identity(dir_c.as_ptr()));

        assert_eq!(first["ok"], true);
        let did = first["did"].as_str().expect("缺少 did");
        assert_eq!(did.len(), 32, "did 应为 32 位 hex");
        assert_eq!(did, second["did"].as_str().unwrap());
        assert!(dir.join("identity.bin").exists());
    }

    #[test]
    fn 节点可启动查询并停止() {
        let _guard = lock();
        let dir = temp_dir("node");
        let dir_c = c(dir.to_str().unwrap());

        let started = call_json(xime_p2p_start(dir_c.as_ptr(), 1, 0, 0));
        assert_eq!(started["ok"], true, "启动失败：{started}");
        assert_eq!(started["port"].as_u64().unwrap(), 47821);
        assert_eq!(xime_p2p_status().is_null(), false);

        // 投递文本：无连接时也算入队成功（对端连上后补发）。
        let text = c("hello xime");
        assert_eq!(xime_p2p_set_clipboard(text.as_ptr(), std::ptr::null()), 1);

        let polled = call_json(xime_p2p_poll(8));
        assert_eq!(polled["ok"], true);
        assert_eq!(polled["events"].as_array().unwrap().len(), 0);

        assert_eq!(xime_p2p_stop(), 1);
        assert_eq!(xime_p2p_stop(), 0, "重复停止应返回 0");
    }

    #[test]
    fn 配对表为空且可删除不存在的设备() {
        let _guard = lock();
        let dir = temp_dir("peers");
        let dir_c = c(dir.to_str().unwrap());

        let peers = call_json(xime_p2p_peers(dir_c.as_ptr()));
        assert_eq!(peers["ok"], true);
        assert!(peers["peers"].as_array().unwrap().is_empty());

        let did = c("00000000000000000000000000000000");
        assert_eq!(xime_p2p_forget(dir_c.as_ptr(), did.as_ptr()), 0);
    }

    #[test]
    fn 显示端配对可出码并可取消() {
        let _guard = lock();
        let dir = temp_dir("pair");
        let dir_c = c(dir.to_str().unwrap());
        let name = c("HarmonyOS 测试机");

        let started = call_json(xime_p2p_pair_display(dir_c.as_ptr(), name.as_ptr(), 30));
        assert_eq!(started["ok"], true, "配对启动失败：{started}");
        let code = started["code"].as_str().expect("缺少配对码");
        assert_eq!(
            code.matches(char::is_numeric).count(),
            6,
            "配对码应为 6 位数字"
        );

        let waiting = call_json(xime_p2p_pair_poll());
        assert_eq!(waiting["phase"], "waiting");

        assert_eq!(xime_p2p_pair_cancel(), 1);
        // 取消后线程需要一点时间收尾，轮询到 cancelled 为止。
        let mut phase = String::new();
        for _ in 0..50 {
            phase = call_json(xime_p2p_pair_poll())["phase"]
                .as_str()
                .unwrap_or("")
                .to_string();
            if phase != "waiting" {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(phase, "cancelled", "取消后状态未收敛");
    }
}
