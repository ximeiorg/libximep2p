//! 6 位动态码（§6.1）。
//!
//! 硬约束：**码只经人眼与手指传递，不得出现在任何网络报文中**。
//! 本模块只负责生成、分组显示、过期判断与本地比对，不参与任何序列化。

use std::fmt;
use std::time::{Duration, Instant};

use subtle::ConstantTimeEq;

use crate::random;

use crate::error::Error;

/// 动态码有效期。
pub const CODE_TTL: Duration = Duration::from_secs(60);
/// 单个码允许的错误次数，超过即作废。
pub const MAX_ATTEMPTS: u32 = 3;
/// 码空间：10^6。
pub const CODE_SPACE: u32 = 1_000_000;

/// 一个 6 位十进制动态码及其签发时刻。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PairingCode {
    digits: u32,
    issued: Instant,
}

impl PairingCode {
    /// 生成新码（当前时刻签发）。
    ///
    /// 系统随机源不可用时返回错误：配对码的强度完全依赖随机性，
    /// 这里不做任何降级（退化成时间戳等于把动态码变成可预测序列）。
    pub fn generate() -> Result<Self, Error> {
        Self::generate_at(Instant::now())
    }

    /// 生成新码，并指定签发时刻（便于测试过期逻辑）。
    pub fn generate_at(now: Instant) -> Result<Self, Error> {
        let digits = random::u32_below(CODE_SPACE)?;
        Ok(Self {
            digits,
            issued: now,
        })
    }

    /// 由已知数值构造（测试与"重新输入上次的码"场景使用）。
    pub fn from_digits(digits: u32) -> Result<Self, Error> {
        Self::from_digits_at(digits, Instant::now())
    }

    pub fn from_digits_at(digits: u32, now: Instant) -> Result<Self, Error> {
        if digits >= CODE_SPACE {
            return Err(Error::bad_frame(format!("码值超出范围: {digits}")));
        }
        Ok(Self {
            digits,
            issued: now,
        })
    }

    /// 六位数值，左侧补零。
    pub fn digits(&self) -> u32 {
        self.digits
    }

    /// 展示形式：`482 719`。分两组是因为 6 位连读容易念错、听错。
    pub fn grouped(&self) -> String {
        let s = format!("{:06}", self.digits);
        format!("{} {}", &s[..3], &s[3..])
    }

    /// 解析用户输入，容忍空格与连字符，其余字符一律拒绝。
    pub fn parse(input: &str) -> Result<u32, Error> {
        let mut value: u32 = 0;
        let mut count = 0usize;
        for ch in input.chars() {
            match ch {
                ' ' | '-' | '\t' => continue,
                '0'..='9' => {
                    value = value * 10 + (ch as u32 - '0' as u32);
                    count += 1;
                    if count > 6 {
                        return Err(Error::bad_frame("动态码超过 6 位"));
                    }
                }
                _ => return Err(Error::bad_frame(format!("动态码含非法字符: {ch:?}"))),
            }
        }
        if count != 6 {
            return Err(Error::bad_frame(format!(
                "动态码必须是 6 位，实际 {count} 位"
            )));
        }
        Ok(value)
    }

    pub fn is_expired(&self) -> bool {
        self.is_expired_at(Instant::now())
    }

    pub fn is_expired_at(&self, now: Instant) -> bool {
        now.duration_since(self.issued) >= CODE_TTL
    }

    /// 剩余有效期，已过期返回零。
    pub fn remaining(&self) -> Duration {
        self.remaining_at(Instant::now())
    }

    pub fn remaining_at(&self, now: Instant) -> Duration {
        CODE_TTL.saturating_sub(now.duration_since(self.issued))
    }

    /// 常量时间比较，避免比较耗时泄露前几位。
    pub fn matches(&self, other: &Self) -> bool {
        self.digits
            .to_be_bytes()
            .ct_eq(&other.digits.to_be_bytes())
            .into()
    }
}

impl fmt::Display for PairingCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.grouped())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn 分组显示补零且分两段() {
        let code = PairingCode::from_digits(482_719).unwrap();
        assert_eq!(code.grouped(), "482 719");
        assert_eq!(code.to_string(), "482 719");

        let small = PairingCode::from_digits(42).unwrap();
        assert_eq!(small.grouped(), "000 042");
    }

    #[test]
    fn 解析容忍空格与连字符() {
        assert_eq!(PairingCode::parse("482 719").unwrap(), 482_719);
        assert_eq!(PairingCode::parse("482719").unwrap(), 482_719);
        assert_eq!(PairingCode::parse(" 482-719 ").unwrap(), 482_719);
        assert_eq!(PairingCode::parse("000042").unwrap(), 42);
    }

    #[test]
    fn 解析拒绝长度与字符错误() {
        assert!(PairingCode::parse("48271").is_err());
        assert!(PairingCode::parse("4827190").is_err());
        assert!(PairingCode::parse("4827l9").is_err());
        assert!(PairingCode::parse("").is_err());
    }

    #[test]
    fn 码值越界被拒绝() {
        assert!(PairingCode::from_digits(1_000_000).is_err());
        assert!(PairingCode::from_digits(999_999).is_ok());
    }

    #[test]
    fn 过期按签发时刻计算() {
        let start = Instant::now();
        let code = PairingCode::from_digits_at(123_456, start).unwrap();
        assert!(!code.is_expired_at(start));
        assert!(!code.is_expired_at(start + Duration::from_secs(59)));
        assert!(code.is_expired_at(start + CODE_TTL));
        assert_eq!(
            code.remaining_at(start + Duration::from_secs(20)),
            Duration::from_secs(40)
        );
        assert_eq!(
            code.remaining_at(start + Duration::from_secs(120)),
            Duration::ZERO
        );
    }

    #[test]
    fn 比较不受前导零影响() {
        let a = PairingCode::from_digits(42).unwrap();
        let b = PairingCode::from_digits(42).unwrap();
        let c = PairingCode::from_digits(43).unwrap();
        assert!(a.matches(&b));
        assert!(!a.matches(&c));
    }

    #[test]
    fn 生成的码总在空间内() {
        for _ in 0..200 {
            let code = PairingCode::generate().unwrap();
            assert!(code.digits() < CODE_SPACE);
            assert!(!code.is_expired());
        }
    }
}
