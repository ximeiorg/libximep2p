//! 帧编解码（§4.2）。
//!
//! 所有帧都是「9 字节头 + payload」：
//!
//! ```text
//! offset  size  field
//! 0       2     magic     0x58 0x50（ASCII "XP"）
//! 2       1     version   0x01
//! 3       1     type      见 MsgType
//! 4       1     flags     bit0 = ENCRYPTED
//! 5       4     length    big-endian u32
//! 9       N     payload
//! ```
//!
//! 手写解析是为了跨语言逐字节一致：Kotlin 侧按同一份定义实现，
//! 两侧共用 `tests/vectors/frames.json` 做回归。

use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::{Error, ErrorCode};

/// 魔数 `"XP"`。
pub const MAGIC: [u8; 2] = [0x58, 0x50];
/// 协议版本。
pub const VERSION: u8 = 0x01;
/// 帧头长度。
pub const HEADER_LEN: usize = 9;
/// payload 上限：1 MiB。
pub const MAX_PAYLOAD: u32 = 1024 * 1024;
/// `flags` 的加密位。
pub const FLAG_ENCRYPTED: u8 = 0b0000_0001;

/// 消息类型（§8.1）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum MsgType {
    Hello = 0x01,
    HelloAck = 0x02,
    Spake2A = 0x03,
    Spake2B = 0x04,
    PairConfirm = 0x05,
    PairOk = 0x06,
    Identity = 0x07,
    ClipboardSet = 0x08,
    ClipboardChanged = 0x09,
    Ping = 0x0A,
    Pong = 0x0B,
    Error = 0x0C,
    Bye = 0x0D,
    /// Noise 握手消息载体（会话阶段，明文，payload 同样是 `{"msg": base64}`）。
    Noise = 0x0E,
    /// 业务无关的 topic 消息：`{"topic": "...", "payload": base64}`。
    ///
    /// 剪贴板只是 `topic = "clipboard"` 的一个订阅者；以后新增同步功能不需要再动帧层。
    Message = 0x20,
}

impl MsgType {
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    pub const fn from_u8(value: u8) -> Result<Self, Error> {
        Ok(match value {
            0x01 => MsgType::Hello,
            0x02 => MsgType::HelloAck,
            0x03 => MsgType::Spake2A,
            0x04 => MsgType::Spake2B,
            0x05 => MsgType::PairConfirm,
            0x06 => MsgType::PairOk,
            0x07 => MsgType::Identity,
            0x08 => MsgType::ClipboardSet,
            0x09 => MsgType::ClipboardChanged,
            0x0A => MsgType::Ping,
            0x0B => MsgType::Pong,
            0x0C => MsgType::Error,
            0x0D => MsgType::Bye,
            0x0E => MsgType::Noise,
            0x20 => MsgType::Message,
            other => return Err(Error::UnknownMsgType(other)),
        })
    }

    /// 是否需要加密（§8.1 的"阶段"列中的会话消息）。
    pub const fn is_session_msg(self) -> bool {
        matches!(
            self,
            MsgType::ClipboardSet
                | MsgType::ClipboardChanged
                | MsgType::Ping
                | MsgType::Pong
                | MsgType::Bye
                | MsgType::Error
                | MsgType::Identity
        )
    }
}

/// 一个协议帧。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub msg: MsgType,
    pub flags: u8,
    pub payload: Vec<u8>,
}

impl Frame {
    pub fn new(msg: MsgType, payload: impl Into<Vec<u8>>) -> Self {
        Self {
            msg,
            flags: 0,
            payload: payload.into(),
        }
    }

    /// 由可序列化值构造明文 JSON 帧。
    pub fn json<T: Serialize>(msg: MsgType, value: &T) -> Result<Self, Error> {
        Ok(Self::new(msg, serde_json::to_vec(value)?))
    }

    pub fn json_empty(msg: MsgType) -> Self {
        Self::new(msg, b"{}".to_vec())
    }

    pub fn error(code: ErrorCode) -> Self {
        let body = crate::app::ErrorMsg {
            code: code.as_u8(),
            msg: code.as_str().to_string(),
        };
        // ErrorMsg 必然可序列化（无 Option 以外的复杂类型），
        // 序列化失败时退化为空对象，保证错误路径本身不会 panic。
        let payload = serde_json::to_vec(&body).unwrap_or_else(|_| b"{}".to_vec());
        Self::new(MsgType::Error, payload)
    }

    pub fn bye(reason: impl Into<String>) -> Self {
        let body = crate::app::Bye {
            reason: reason.into(),
        };
        let payload = serde_json::to_vec(&body).unwrap_or_else(|_| b"{}".to_vec());
        Self::new(MsgType::Bye, payload)
    }

    pub fn is_encrypted(&self) -> bool {
        self.flags & FLAG_ENCRYPTED != 0
    }

    pub fn set_encrypted(&mut self, yes: bool) {
        if yes {
            self.flags |= FLAG_ENCRYPTED;
        } else {
            self.flags &= !FLAG_ENCRYPTED;
        }
    }

    /// 解析 payload 为 JSON。
    pub fn parse_json<T: DeserializeOwned>(&self) -> Result<T, Error> {
        Ok(serde_json::from_slice(&self.payload)?)
    }

    /// 编码为完整帧字节。
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let mut out = Vec::with_capacity(HEADER_LEN + self.payload.len());
        self.encode_into(&mut out)?;
        Ok(out)
    }

    pub fn encode_into(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        let len =
            u32::try_from(self.payload.len()).map_err(|_| Error::PayloadTooLarge(u32::MAX))?;
        if len > MAX_PAYLOAD {
            return Err(Error::PayloadTooLarge(len));
        }
        out.reserve(HEADER_LEN + self.payload.len());
        out.extend_from_slice(&MAGIC);
        out.push(VERSION);
        out.push(self.msg.as_u8());
        out.push(self.flags);
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(&self.payload);
        Ok(())
    }

    /// 解析帧头，返回 `(type, flags, length)`。
    pub fn decode_header(header: &[u8; HEADER_LEN]) -> Result<(MsgType, u8, u32), Error> {
        if header[0..2] != MAGIC {
            return Err(Error::BadMagic([header[0], header[1]]));
        }
        if header[2] != VERSION {
            return Err(Error::VersionMismatch {
                got: header[2],
                expected: VERSION,
            });
        }
        let msg = MsgType::from_u8(header[3])?;
        let flags = header[4];
        let len = u32::from_be_bytes([header[5], header[6], header[7], header[8]]);
        if len > MAX_PAYLOAD {
            return Err(Error::PayloadTooLarge(len));
        }
        Ok((msg, flags, len))
    }

    /// 解析完整帧字节（必须严格等于 `HEADER_LEN + length`）。
    pub fn decode(buf: &[u8]) -> Result<Self, Error> {
        if buf.len() < HEADER_LEN {
            return Err(Error::bad_frame("缓冲区不足一个帧头"));
        }
        let header: [u8; HEADER_LEN] = buf[..HEADER_LEN]
            .try_into()
            .map_err(|_| Error::bad_frame("帧头长度异常"))?;
        let (msg, flags, len) = Self::decode_header(&header)?;
        let len = len as usize;
        if buf.len() != HEADER_LEN + len {
            return Err(Error::bad_frame(format!(
                "长度字段 {} 与实际 payload {} 不符",
                len,
                buf.len() - HEADER_LEN
            )));
        }
        Ok(Self {
            msg,
            flags,
            payload: buf[HEADER_LEN..].to_vec(),
        })
    }
}

/// 从流中读一个完整帧。
///
/// 读到 0 字节（对端正常关闭）返回 [`Error::Closed`]，区别于中途截断的 io 错误。
pub async fn read_frame<R>(reader: &mut R) -> Result<Frame, Error>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0u8; HEADER_LEN];
    match reader.read_exact(&mut header).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Err(Error::Closed),
        Err(e) => return Err(Error::Io(e)),
    }
    let (msg, flags, len) = Frame::decode_header(&header)?;
    let mut payload = vec![0u8; len as usize];
    if len > 0 {
        reader.read_exact(&mut payload).await?;
    }
    Ok(Frame {
        msg,
        flags,
        payload,
    })
}

/// 向流中写一个完整帧。
pub async fn write_frame<W>(writer: &mut W, frame: &Frame) -> Result<(), Error>
where
    W: AsyncWrite + Unpin,
{
    let bytes = frame.encode()?;
    writer.write_all(&bytes).await?;
    writer.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        hex::encode_upper(bytes)
    }

    /// §11.1 的三个向量：必须逐字节一致。
    #[test]
    fn 帧向量与文档一致() {
        let ping = Frame::json_empty(MsgType::Ping);
        assert_eq!(hex(&ping.encode().unwrap()), "5850010A00000000027B7D");

        let err = Frame::new(MsgType::Error, br#"{"code":2}"#.to_vec());
        assert_eq!(
            hex(&err.encode().unwrap()),
            "5850010C000000000A7B22636F6465223A327D"
        );

        let empty = Frame::new(MsgType::Pong, Vec::new());
        assert_eq!(hex(&empty.encode().unwrap()), "5850010B0000000000");
    }

    #[test]
    fn 帧向量可被解码回原值() {
        let raw = hex::decode("5850010A00000000027B7D").unwrap();
        let frame = Frame::decode(&raw).unwrap();
        assert_eq!(frame.msg, MsgType::Ping);
        assert_eq!(frame.flags, 0);
        assert_eq!(frame.payload, b"{}");
        assert!(!frame.is_encrypted());
    }

    #[test]
    fn 超限长度被拒绝() {
        // length = 1048577
        let mut raw = vec![0x58, 0x50, 0x01, 0x0A, 0x00];
        raw.extend_from_slice(&1_048_577u32.to_be_bytes());
        let err = Frame::decode(&raw).unwrap_err();
        assert!(matches!(err, Error::PayloadTooLarge(1_048_577)));
    }

    #[test]
    fn 魔数与版本错误被区分() {
        let mut raw = [0u8; HEADER_LEN];
        raw[..2].copy_from_slice(b"XY");
        raw[2] = VERSION;
        assert!(matches!(
            Frame::decode_header(&raw),
            Err(Error::BadMagic(_))
        ));

        raw[..2].copy_from_slice(&MAGIC);
        raw[2] = 2;
        assert!(matches!(
            Frame::decode_header(&raw),
            Err(Error::VersionMismatch { got: 2, .. })
        ));
    }

    #[test]
    fn 长度字段与实际不一致时拒绝() {
        let mut raw = Frame::new(MsgType::Hello, b"{}".to_vec()).encode().unwrap();
        raw.push(0x00);
        assert!(matches!(Frame::decode(&raw), Err(Error::BadFrame(_))));
    }

    #[test]
    fn 加密位可独立切换() {
        let mut f = Frame::json_empty(MsgType::Ping);
        f.set_encrypted(true);
        assert!(f.is_encrypted());
        assert_eq!(f.flags, FLAG_ENCRYPTED);
        let decoded = Frame::decode(&f.encode().unwrap()).unwrap();
        assert!(decoded.is_encrypted());
        f.set_encrypted(false);
        assert_eq!(f.flags, 0);
    }

    #[tokio::test]
    async fn 流式读写往返() {
        let (mut a, mut b) = tokio::io::duplex(4096);
        let original = Frame::new(MsgType::Hello, br#"{"ver":1}"#.to_vec());
        write_frame(&mut a, &original).await.unwrap();
        let got = read_frame(&mut b).await.unwrap();
        assert_eq!(got, original);
    }

    #[tokio::test]
    async fn 对端关闭时返回_closed() {
        let (a, mut b) = tokio::io::duplex(64);
        drop(a);
        assert!(matches!(read_frame(&mut b).await, Err(Error::Closed)));
    }
}
