use std::path::{Component, Path};

use async_trait::async_trait;

/// 存储错误。
#[derive(Debug)]
pub enum StorageError {
    /// 非法 key（路径穿越、空 key、绝对路径等）。
    InvalidKey(String),
    /// 底层 IO 错误。
    Io(std::io::Error),
}

impl std::fmt::Display for StorageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StorageError::InvalidKey(key) => write!(f, "invalid storage key: {key}"),
            StorageError::Io(e) => write!(f, "io error: {e}"),
        }
    }
}

impl std::error::Error for StorageError {}

impl From<std::io::Error> for StorageError {
    fn from(e: std::io::Error) -> Self {
        StorageError::Io(e)
    }
}

pub type Result<T> = std::result::Result<T, StorageError>;

/// 键值 Blob 存储抽象。所有后端（本地文件 / WebDAV / S3 / Turso）实现同一 trait。
///
/// 键空间约定（后端无关）：
/// ```text
/// clipboard/current.json   # 当前剪贴板 profile（三通道共享的唯一事实源）
/// files/{data_name}        # 附件数据（后续图片/文件）
/// history/{id}.json        # 历史记录（P7）
/// ```
#[async_trait]
// 新版 clippy：async_trait 给每个方法生成 #[must_use] 的 boxed Future，
// 而 Result 本身已是 must_use，触发 double_must_use——宏展开问题，非代码缺陷。
#[allow(clippy::double_must_use)]
pub trait Storage: Send + Sync {
    /// 写入 key → blob（覆盖）。
    async fn put(&self, key: &str, data: &[u8]) -> Result<()>;
    /// 读取 key，不存在返回 None。
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>>;
    /// 删除 key（幂等）。
    async fn delete(&self, key: &str) -> Result<()>;
    /// 列出 prefix 下的 key。
    async fn list(&self, prefix: &str) -> Result<Vec<String>>;
}

/// 校验 key 合法性：拒绝空 key、绝对路径、`..`/`.` 组件、反斜杠与 NUL 字符。
pub fn validate_key(key: &str) -> Result<()> {
    if key.is_empty() {
        return Err(StorageError::InvalidKey(key.to_string()));
    }
    if key.contains('\\') || key.contains('\0') {
        return Err(StorageError::InvalidKey(key.to_string()));
    }
    let path = Path::new(key);
    if path.is_absolute() {
        return Err(StorageError::InvalidKey(key.to_string()));
    }
    for comp in path.components() {
        match comp {
            Component::ParentDir => return Err(StorageError::InvalidKey(key.to_string())),
            Component::CurDir => return Err(StorageError::InvalidKey(key.to_string())),
            Component::RootDir => return Err(StorageError::InvalidKey(key.to_string())),
            _ => {}
        }
    }
    Ok(())
}

/// 校验附件文件名（data_name）：仅允许文件名（不含路径分隔符），
/// 拒绝 `\` `/` `..` 与不可见控制字符，防路径穿越（设计文档 3.1 安全要求）。
pub fn validate_file_name(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(StorageError::InvalidKey(name.to_string()));
    }
    if name.contains('/') || name.contains('\\') || name.contains('\0') {
        return Err(StorageError::InvalidKey(name.to_string()));
    }
    if name == "." || name == ".." || name.starts_with('.') {
        return Err(StorageError::InvalidKey(name.to_string()));
    }
    // 拒绝控制字符（C0 与 DEL）
    if name.chars().any(|c| c.is_control()) {
        return Err(StorageError::InvalidKey(name.to_string()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_keys_rejected() {
        for bad in ["", "..", "../evil", "a/../../b", "/abs", "a\\b", "a\0b"] {
            assert!(validate_key(bad).is_err(), "key {bad:?} should be rejected");
        }
    }

    #[test]
    fn valid_keys_accepted() {
        for good in [
            "clipboard/current.json",
            "history/1.json",
            "files/a.txt",
            "a",
            "dir/a.b.c",
            ".hidden",
        ] {
            assert!(
                validate_key(good).is_ok(),
                "key {good:?} should be accepted"
            );
        }
    }

    #[test]
    fn file_name_validation() {
        // 合法
        for good in [
            "a.txt",
            "photo.jpg",
            "archive.tar.gz",
            "文件-1.png",
            "a_b_c.d",
        ] {
            assert!(
                validate_file_name(good).is_ok(),
                "file {good:?} should be accepted"
            );
        }
        // 非法：路径分隔符 / 穿越 / 隐藏 / 控制字符
        for bad in [
            "", "..", ".", "../evil", "a/b", "a\\b", ".hidden", "a\0b", "a\nb",
        ] {
            assert!(
                validate_file_name(bad).is_err(),
                "file {bad:?} should be rejected"
            );
        }
    }
}
