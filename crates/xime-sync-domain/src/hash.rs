use sha2::{Digest, Sha256};

/// SHA256(data) 的 hex 表示（小写）。
pub fn sha256_hex(data: &[u8]) -> String {
    let digest = Sha256::digest(data);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

/// 剪贴板文本 hash：SHA256(utf8(text)) 的 hex（小写）。
/// 算法对齐 SyncClipboard Hash.md：text → SHA256(utf8(text))。
pub fn text_hash(text: &str) -> String {
    sha256_hex(text.as_bytes())
}

/// 附件文件 hash：SHA256(utf8("filename|" + SHA256(content) hex)) 的 hex（小写）。
/// 算法对齐 SyncClipboard Hash.md：file → SHA256(utf8("FileName|" + SHA256(content)))。后续图片/文件同步使用。
pub fn file_hash(filename: &str, content: &[u8]) -> String {
    let content_hash = sha256_hex(content);
    let input = format!("{filename}|{content_hash}");
    sha256_hex(input.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_hex_nist_vectors() {
        // NIST SHA-256 标准测试向量
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"hello"),
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn sha256_hex_is_lowercase() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert!(
            sha256_hex(b"abc")
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        );
    }

    #[test]
    fn text_hash_matches_sha256_of_utf8() {
        // "你好" 的 SHA256（独立计算验证，对齐 SyncClipboard 算法）
        assert_eq!(
            text_hash("你好"),
            "670d9743542cae3ea7ebe36af56bd53648b0a1126162e78d81a32934a711302e"
        );
        // 通用性验证：text_hash == sha256_hex(utf8 bytes)
        assert_eq!(text_hash("hello"), sha256_hex(b"hello"));
        assert_eq!(text_hash(""), sha256_hex(b""));
        assert_eq!(text_hash("你好"), sha256_hex("你好".as_bytes()));
    }

    #[test]
    fn file_hash_format() {
        // file_hash("a.txt", content) 与 sha256_hex("a.txt|" + sha256_hex(content)) 一致
        let content = b"file-content";
        let content_hash = sha256_hex(content);
        let expected = sha256_hex(format!("a.txt|{content_hash}").as_bytes());
        assert_eq!(file_hash("a.txt", content), expected);
        // 不同文件名 -> 不同 hash
        assert_ne!(file_hash("a.txt", content), file_hash("b.txt", content));
    }
}
