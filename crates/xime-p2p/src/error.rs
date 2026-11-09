//! 错误类型与协议错误码。
//!
//! 每个 [`Error`] 都能映射到一个 [`ErrorCode`]（§10），
//! 对端收到的 `ERROR` 帧只携带码值与该码的固定文案，不泄露内部细节。

use std::fmt;

/// 协议错误码（§10）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ErrorCode {
    Ok = 0,
    VersionMismatch = 1,
    AuthFailed = 2,
    NoPairedSession = 3,
    Busy = 4,
    PayloadTooLarge = 5,
    BadFrame = 6,
    RateLimited = 7,
    Internal = 8,
}

impl ErrorCode {
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// 该码的固定英文标识，用于 `ERROR` 帧的 `msg` 字段。
    pub const fn as_str(self) -> &'static str {
        match self {
            ErrorCode::Ok => "OK",
            ErrorCode::VersionMismatch => "VERSION_MISMATCH",
            ErrorCode::AuthFailed => "AUTH_FAILED",
            ErrorCode::NoPairedSession => "NO_PAIRED_SESSION",
            ErrorCode::Busy => "BUSY",
            ErrorCode::PayloadTooLarge => "PAYLOAD_TOO_LARGE",
            ErrorCode::BadFrame => "BAD_FRAME",
            ErrorCode::RateLimited => "RATE_LIMITED",
            ErrorCode::Internal => "INTERNAL",
        }
    }

    pub const fn from_u8(value: u8) -> Option<Self> {
        Some(match value {
            0 => ErrorCode::Ok,
            1 => ErrorCode::VersionMismatch,
            2 => ErrorCode::AuthFailed,
            3 => ErrorCode::NoPairedSession,
            4 => ErrorCode::Busy,
            5 => ErrorCode::PayloadTooLarge,
            6 => ErrorCode::BadFrame,
            7 => ErrorCode::RateLimited,
            8 => ErrorCode::Internal,
            _ => return None,
        })
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// xime-p2p 的错误。
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// 对端正常关闭连接（读到 EOF）。
    #[error("连接已关闭")]
    Closed,

    #[error("io 错误: {0}")]
    Io(#[from] std::io::Error),

    #[error("魔数不匹配: {0:02X?}")]
    BadMagic([u8; 2]),

    #[error("协议版本不兼容: 收到 {got}, 期望 {expected}")]
    VersionMismatch { got: u8, expected: u8 },

    #[error("payload 超过上限: {0} 字节")]
    PayloadTooLarge(u32),

    #[error("未知消息类型: 0x{0:02X}")]
    UnknownMsgType(u8),

    #[error("帧格式错误: {0}")]
    BadFrame(String),

    #[error("JSON 编解码失败: {0}")]
    Json(#[from] serde_json::Error),

    /// 配对码错误，或 PAIR_CONFIRM / PAIR_OK 校验失败。
    #[error("认证失败")]
    AuthFailed,

    #[error("未配对的设备尝试建立会话")]
    NotPaired,

    #[error("已有配对或连接进行中")]
    Busy,

    #[error("配对码已过期")]
    CodeExpired,

    #[error("配对失败次数过多")]
    TooManyAttempts,

    #[error("Noise 握手失败: {0}")]
    Noise(String),

    #[error("PAKE 失败: {0}")]
    Spake(String),

    #[error("身份校验失败: {0}")]
    Identity(String),

    #[error("存储错误: {0}")]
    Store(String),

    #[error("内部错误: {0}")]
    Internal(String),
}

impl Error {
    /// 映射到协议错误码。
    pub fn code(&self) -> ErrorCode {
        match self {
            Error::Closed | Error::Io(_) => ErrorCode::Internal,
            Error::BadMagic(_) | Error::UnknownMsgType(_) | Error::BadFrame(_) => {
                ErrorCode::BadFrame
            }
            Error::VersionMismatch { .. } => ErrorCode::VersionMismatch,
            Error::PayloadTooLarge(_) => ErrorCode::PayloadTooLarge,
            Error::Json(_) => ErrorCode::BadFrame,
            Error::AuthFailed | Error::CodeExpired | Error::TooManyAttempts => {
                ErrorCode::AuthFailed
            }
            Error::NotPaired => ErrorCode::NoPairedSession,
            Error::Busy => ErrorCode::Busy,
            Error::Noise(_)
            | Error::Spake(_)
            | Error::Identity(_)
            | Error::Store(_)
            | Error::Internal(_) => ErrorCode::Internal,
        }
    }

    /// 是否属于"对端不可信 / 认证失败"，这类错误不应重试同一次握手。
    pub fn is_auth_failure(&self) -> bool {
        matches!(self, Error::AuthFailed | Error::TooManyAttempts)
    }

    /// 面向用户的说明：告诉他下一步该做什么。
    ///
    /// 与 `Display` 的分工：`Display` 追求把错误描述准确（给日志看），
    /// 这里追求让用户能自己解决（给界面看）。放在协议层是因为四个宿主
    /// 都要用——各自维护一份映射，文案迟早分叉。
    pub fn user_hint(&self) -> String {
        match self {
            // `Internal` 里装的多是本层写好的可读文案（「等待配对超时」之类），
            // 再套一层「内部错误:」只会把有用信息埋掉。
            Error::Internal(msg) => msg.clone(),
            Error::CodeExpired => "动态码已过期，请让对方重新生成".to_string(),
            Error::TooManyAttempts => "尝试次数过多，请重新生成动态码".to_string(),
            Error::AuthFailed => "动态码不正确".to_string(),
            Error::VersionMismatch { got, expected } => {
                format!("两端版本不兼容（对端 {got}，本机 {expected}），请更新到同一版本")
            }
            Error::Io(e) if e.kind() == std::io::ErrorKind::TimedOut => {
                "连接超时，请确认两端在同一 WiFi，且路由器未开启 AP 隔离".to_string()
            }
            Error::Io(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
                "对方未在等待配对，请让其重新生成动态码".to_string()
            }
            other => other.to_string(),
        }
    }

    pub fn internal(msg: impl Into<String>) -> Self {
        Error::Internal(msg.into())
    }

    pub fn bad_frame(msg: impl Into<String>) -> Self {
        Error::BadFrame(msg.into())
    }
}
