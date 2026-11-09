use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// 剪贴板数据类型。枚举值序列化为小写（`"type": "text"`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProfileType {
    Text,
    File,
    Image,
    Group,
    None,
}

/// 图片数据字段的 base64 序列化：`Option<Vec<u8>>` 在 JSON 中以字符串形式传输，
/// 避免 serde 默认把字节序列化为数字数组。
mod base64_bytes {
    use super::*;
    use base64::Engine;

    pub fn serialize<S>(bytes: &Option<Vec<u8>>, ser: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match bytes {
            None => ser.serialize_none(),
            Some(b) => {
                ser.serialize_some(base64::engine::general_purpose::STANDARD.encode(b).as_str())
            }
        }
    }

    pub fn deserialize<'de, D>(de: D) -> Result<Option<Vec<u8>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s: Option<String> = Option::deserialize(de)?;
        s.map(|s| {
            base64::engine::general_purpose::STANDARD
                .decode(s)
                .map_err(serde::de::Error::custom)
        })
        .transpose()
    }
}

/// 剪贴板条目（Profile）。所有字段一律小写 snake_case。
///
/// JSON 示例（文本）：
/// ```json
/// {
///   "type": "text",
///   "hash": "9f86d081884c7d65...",
///   "text": "完整文本内容",
///   "has_data": false,
///   "data_name": null,
///   "size": 12,
///   "source": "device-a"
/// }
/// ```
///
/// 图片类型额外携带 `data`（RGBA8 裸字节，base64 字符串）、`width`、`height`；
/// 文本/文件类型这三个字段为 `null`（序列化时省略，保持向后兼容）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Profile {
    pub r#type: ProfileType,
    /// 小写 hex SHA256。text 类型 = SHA256(utf8(text))；image 类型 = SHA256(data)。
    pub hash: String,
    /// 文本内容或预览。
    pub text: String,
    /// 是否有附件数据（图片/文件）。
    pub has_data: bool,
    /// 附件文件名（文件同步使用）。
    pub data_name: Option<String>,
    /// 内容字节大小。
    pub size: usize,
    /// 来源设备标识。
    pub source: Option<String>,
    /// 图片 RGBA8 裸字节（仅 image 类型携带，base64 序列化）。
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "base64_bytes"
    )]
    pub data: Option<Vec<u8>>,
    /// 图片宽（像素，仅 image 类型携带）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub width: Option<u32>,
    /// 图片高（像素，仅 image 类型携带）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub height: Option<u32>,
}

impl Profile {
    /// 由文本构造一个 text 类型 profile，自动计算 hash 与 size。
    pub fn from_text(text: impl Into<String>, source: Option<String>) -> Self {
        let text = text.into();
        let hash = crate::hash::text_hash(&text);
        let size = text.len();
        Self {
            r#type: ProfileType::Text,
            hash,
            text,
            has_data: false,
            data_name: None,
            size,
            source,
            data: None,
            width: None,
            height: None,
        }
    }

    /// 由 RGBA8 像素数据构造 image 类型 profile，自动计算 hash（SHA256(data)）与 size。
    pub fn from_image(data: Vec<u8>, width: u32, height: u32, source: Option<String>) -> Self {
        let hash = crate::hash::sha256_hex(&data);
        let size = data.len();
        Self {
            r#type: ProfileType::Image,
            hash,
            text: String::new(),
            has_data: true,
            data_name: None,
            size,
            source,
            data: Some(data),
            width: Some(width),
            height: Some(height),
        }
    }

    /// 空剪贴板初始值（配置 `clipboard.default_profile` 语义）。
    pub fn empty(source: Option<String>) -> Self {
        Self {
            r#type: ProfileType::Text,
            hash: String::new(),
            text: String::new(),
            has_data: false,
            data_name: None,
            size: 0,
            source,
            data: None,
            width: None,
            height: None,
        }
    }
}

impl Default for Profile {
    fn default() -> Self {
        Self::empty(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialize_lowercase_fields() {
        let p = Profile::from_text("你好", Some("device-a".to_string()));
        let json = serde_json::to_string(&p).unwrap();
        // 字段一律小写：type / has_data / data_name / source，不允许大写开头
        for field in [
            "type",
            "hash",
            "text",
            "has_data",
            "data_name",
            "size",
            "source",
        ] {
            assert!(
                json.contains(&format!("\"{field}\"")),
                "missing field {field}: {json}"
            );
        }
        for bad in ["Type", "HasData", "DataName", "Source"] {
            assert!(!json.contains(bad), "uppercase field {bad} in {json}");
        }
        assert!(
            json.contains("\"type\":\"text\""),
            "enum should serialize lowercase: {json}"
        );
    }

    #[test]
    fn deserialize_lowercase_fields() {
        let json = r#"{
            "type": "text",
            "hash": "abc",
            "text": "hi",
            "has_data": false,
            "data_name": null,
            "size": 2,
            "source": "device-a"
        }"#;
        let p: Profile = serde_json::from_str(json).unwrap();
        assert_eq!(p.r#type, ProfileType::Text);
        assert_eq!(p.text, "hi");
        assert_eq!(p.size, 2);
        assert_eq!(p.source.as_deref(), Some("device-a"));
        assert!(!p.has_data);
    }

    #[test]
    fn from_text_computes_hash_and_size() {
        let p = Profile::from_text("hello", None);
        assert_eq!(p.r#type, ProfileType::Text);
        assert_eq!(p.hash, crate::hash::text_hash("hello"));
        assert_eq!(p.size, 5);
        assert!(!p.has_data);
        assert_eq!(p.data_name, None);
    }

    #[test]
    fn profile_type_roundtrip_all_variants() {
        for (ty, s) in [
            (ProfileType::Text, "text"),
            (ProfileType::File, "file"),
            (ProfileType::Image, "image"),
            (ProfileType::Group, "group"),
            (ProfileType::None, "none"),
        ] {
            let json = serde_json::to_string(&ty).unwrap();
            assert_eq!(
                json,
                format!("\"{s}\""),
                "variant {s} should serialize lowercase"
            );
            let back: ProfileType = serde_json::from_str(&json).unwrap();
            assert_eq!(back, ty);
        }
    }

    #[test]
    fn empty_profile() {
        let p = Profile::empty(None);
        assert_eq!(p.hash, "");
        assert_eq!(p.text, "");
        assert_eq!(p.size, 0);
        assert!(!p.has_data);
        assert_eq!(Profile::default(), p);
    }

    #[test]
    fn from_image_computes_hash_size_and_bounds() {
        let data = vec![0u8; 16];
        let p = Profile::from_image(data.clone(), 4, 4, Some("dev-a".to_string()));
        assert_eq!(p.r#type, ProfileType::Image);
        assert_eq!(p.hash, crate::hash::sha256_hex(&data));
        assert_eq!(p.size, 16);
        assert!(p.has_data);
        assert_eq!(p.data.as_deref(), Some(data.as_slice()));
        assert_eq!(p.width, Some(4));
        assert_eq!(p.height, Some(4));
        assert_eq!(p.source.as_deref(), Some("dev-a"));
        assert_eq!(p.text, "");
    }

    #[test]
    fn image_data_roundtrip_base64() {
        let data: Vec<u8> = (0..64).map(|i| (i % 251) as u8).collect();
        let p = Profile::from_image(data.clone(), 8, 8, Some("dev-a".to_string()));
        let json = serde_json::to_string(&p).unwrap();
        // data 以 base64 字符串传输，而不是数字数组
        assert!(json.contains("\"data\":\""), "data must be base64: {json}");
        assert!(!json.contains("\"data\":["), "data must not be array");
        let back: Profile = serde_json::from_str(&json).unwrap();
        assert_eq!(back, p);
        assert_eq!(back.data.as_deref(), Some(data.as_slice()));
        assert_eq!(back.width, Some(8));
        assert_eq!(back.height, Some(8));
    }

    #[test]
    fn text_profile_omits_image_fields() {
        let p = Profile::from_text("hello", None);
        let json = serde_json::to_string(&p).unwrap();
        assert!(
            !json.contains("\"data\""),
            "text profile must omit data: {json}"
        );
        assert!(
            !json.contains("\"width\""),
            "text profile must omit width: {json}"
        );
        // 兼容旧数据：缺失 image 字段也能反序列化
        let old = r#"{"type":"text","hash":"abc","text":"hi","has_data":false,"data_name":null,"size":2,"source":null}"#;
        let back: Profile = serde_json::from_str(old).unwrap();
        assert_eq!(back.text, "hi");
        assert_eq!(back.data, None);
        assert_eq!(back.width, None);
        assert_eq!(back.height, None);
    }
}
