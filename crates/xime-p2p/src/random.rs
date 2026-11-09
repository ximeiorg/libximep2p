//! 系统随机源。
//!
//! 直接用 `getrandom` 而不引 `rand`：本 crate 只需要「取 N 个字节」和
//! 「取 [0, bound) 的整数」两件事，`rand` 的 API 在 0.9 / 0.10 两代之间反复改名
//! （`thread_rng` → `rng`、`gen_range` → `random_range`、`OsRng` 挪位），
//! 对密码学库来说是不必要的升级负担。
//!
//! 取整数用拒绝采样，不做 `% bound` 直接取模：后者会让小数值出现概率偏高，
//! 对 6 位配对码来说虽然偏差极小，但没有理由留这种瑕疵。

use crate::error::Error;

/// 填充随机字节。
pub fn fill(buf: &mut [u8]) -> Result<(), Error> {
    getrandom::fill(buf).map_err(|e| Error::internal(format!("系统随机源不可用: {e}")))
}

/// 取 N 字节随机数组。
pub fn array<const N: usize>() -> Result<[u8; N], Error> {
    let mut out = [0u8; N];
    fill(&mut out)?;
    Ok(out)
}

/// 无模偏差地取 `[0, bound)` 的整数。
///
/// # Panics
/// `bound == 0` 时 panic：这是调用方的编程错误，不是运行时故障。
pub fn u32_below(bound: u32) -> Result<u32, Error> {
    assert!(bound > 0, "bound 必须大于 0");
    let bound64 = u64::from(bound);
    // 2^32 内能被 bound 整除的最大区间；落在区间外则重采样。
    let limit = (1u64 << 32) - ((1u64 << 32) % bound64);
    loop {
        let v = u64::from(u32::from_le_bytes(array::<4>()?));
        if v < limit {
            return Ok((v % bound64) as u32);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn 取到的整数总在范围内() {
        for bound in [1u32, 2, 7, 1_000_000, u32::MAX] {
            for _ in 0..50 {
                assert!(u32_below(bound).unwrap() < bound);
            }
        }
    }

    #[test]
    fn 随机字节不全为零() {
        let a = array::<32>().unwrap();
        assert!(a.iter().any(|b| *b != 0));
        let b = array::<32>().unwrap();
        assert_ne!(a, b);
    }
}
