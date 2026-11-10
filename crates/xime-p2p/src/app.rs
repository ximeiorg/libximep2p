//! 应用层 payload 结构（§8.1）。
//!
//! 字段名与文档表格严格一致（全小写 snake_case），Android 侧的 Kotlin 实现
//! 按同一份 JSON 结构反序列化。二进制字段一律 base64（标准字母表，含 padding）。

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64_ENGINE;
use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use xime_sync_domain::profile::Profile;

/// 协议版本号，出现在 `HELLO` / `HELLO_ACK` 的 `ver` 字段。
///
/// 只在**对外发布后出现不兼容变更**时才加一，作用是让新旧两端在握手阶段就明确拒绝，
/// 而不是走到一半才失败。发布之前字段增删（如 `Profile.ts`、新的 `MsgType`）直接沿用 1，
/// 不用版本号标记——否则会出现「同一个未发布协议，两台机器版本号不一样」的假不兼容。
pub const PROTOCOL_VERSION: u8 = 1;

/// base64 包装：JSON 里是字符串，内存里是字节。
#[derive(Clone, PartialEq, Eq, Default)]
pub struct B64(pub Vec<u8>);

impl B64 {
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Self(bytes.into())
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8]> for B64 {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<Vec<u8>> for B64 {
    fn from(value: Vec<u8>) -> Self {
        Self(value)
    }
}

impl std::fmt::Debug for B64 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // 不打印完整字节：nonce / hmac / 公钥都会进日志。
        write!(f, "B64({} bytes)", self.0.len())
    }
}

impl Serialize for B64 {
    fn serialize<S: Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(&B64_ENGINE.encode(&self.0))
    }
}

impl<'de> Deserialize<'de> for B64 {
    fn deserialize<D: Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        struct B64Visitor;
        impl Visitor<'_> for B64Visitor {
            type Value = B64;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("base64 字符串")
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<B64, E> {
                B64_ENGINE
                    .decode(v)
                    .map(B64)
                    .map_err(|e| E::custom(format!("base64 解码失败: {e}")))
            }
        }
        de.deserialize_str(B64Visitor)
    }
}

/// `HELLO`（0x01）：Input 侧发起，携带自身 `did` 与 16 字节 `nonce_b`。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hello {
    pub ver: u8,
    pub did: String,
    pub nonce: B64,
}

/// `HELLO_ACK`（0x02）：Display 侧回应，携带 16 字节 `nonce_a`。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HelloAck {
    pub ver: u8,
    pub did: String,
    pub nonce: B64,
    pub ok: bool,
}

/// `SPAKE2_A` / `SPAKE2_B`（0x03 / 0x04）：PAKE 公钥消息。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpakeMsg {
    pub msg: B64,
}

/// `PAIR_CONFIRM` / `PAIR_OK`（0x05 / 0x06）：方向分离的确认值。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Confirm {
    pub hmac: B64,
}

/// `IDENTITY`（0x07）加密后的明文内容。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityPayload {
    pub pub_ed: B64,
    pub pub_x25519: B64,
    pub name: String,
}

/// `CLIPBOARD_SET` / `CLIPBOARD_CHANGED`（0x08 / 0x09）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClipboardSet {
    pub profile: Profile,
    pub seq: u64,
}

/// `MESSAGE`（0x20）：业务无关的 topic 消息。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TopicMessage {
    /// 业务标识，例如 `"clipboard"`。
    pub topic: String,
    /// 业务负载，序列化时 base64。
    pub payload: B64,
}

/// `ERROR`（0x0C）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorMsg {
    pub code: u8,
    pub msg: String,
}

impl ErrorMsg {
    /// 把对端错误还原成本地错误类型。
    pub fn to_error(&self) -> crate::error::Error {
        use crate::error::{Error, ErrorCode};
        match ErrorCode::from_u8(self.code) {
            Some(ErrorCode::AuthFailed) => Error::AuthFailed,
            Some(ErrorCode::NoPairedSession) => Error::NotPaired,
            Some(ErrorCode::Busy) => Error::Busy,
            Some(ErrorCode::PayloadTooLarge) => Error::PayloadTooLarge(0),
            Some(ErrorCode::VersionMismatch) => Error::VersionMismatch {
                got: self.code,
                expected: PROTOCOL_VERSION,
            },
            Some(ErrorCode::BadFrame) => Error::bad_frame(self.msg.clone()),
            other => Error::Internal(match other {
                Some(code) => format!("对端错误 {}: {}", code, self.msg),
                None => format!("对端错误码 {}: {}", self.code, self.msg),
            }),
        }
    }
}

/// `BYE`（0x0D）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bye {
    pub reason: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_字段以字符串出现() {
        let hello = Hello {
            ver: 1,
            did: "00112233445566778899aabbccddeeff".into(),
            nonce: B64::new(vec![1, 2, 3]),
        };
        let json = serde_json::to_value(&hello).unwrap();
        assert_eq!(json["nonce"], "AQID");
        let back: Hello = serde_json::from_value(json).unwrap();
        assert_eq!(back, hello);
    }

    #[test]
    fn 非法_base64_被拒绝() {
        let raw = r#"{"ver":1,"did":"aa","nonce":"!!!"}"#;
        assert!(serde_json::from_str::<Hello>(raw).is_err());
    }

    #[test]
    fn 剪贴板消息携带_profile_与_seq() {
        let profile = Profile::from_text("hello", Some("device-a".into()));
        let msg = ClipboardSet {
            profile: profile.clone(),
            seq: 7,
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"seq\":7"));
        assert!(json.contains("\"source\":\"device-a\""));
        let back: ClipboardSet = serde_json::from_str(&json).unwrap();
        assert_eq!(back, msg);
    }

    #[test]
    fn 错误帧的_msg_是固定标识() {
        let frame = crate::frame::Frame::error(crate::error::ErrorCode::AuthFailed);
        let body: ErrorMsg = frame.parse_json().unwrap();
        assert_eq!(body.code, 2);
        assert_eq!(body.msg, "AUTH_FAILED");
        assert!(matches!(body.to_error(), crate::error::Error::AuthFailed));
    }
}
