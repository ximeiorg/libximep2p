//! 跨语言测试向量。
//!
//! 这些断言读的是 `tests/vectors/*.json`，**Android（Kotlin）侧要实现同一份
//! 解析逻辑并读同一份文件**。协议改动时两个仓库同时变红，才算真正改对了。
//!
//! 这里只断言"可观测输出"（帧字节、确认值、prologue 字节），
//! 不把派生过程中的中间量固化成语义契约。

use serde_json::Value;
use xime_p2p::frame::{Frame, MsgType};
use xime_p2p::identity::Did;
use xime_p2p::pairing::PairKeys;
use xime_p2p::session::prologue;

fn load(name: &str) -> Value {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/vectors")
        .join(name);
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("读取向量文件 {} 失败: {e}", path.display()));
    serde_json::from_str(&raw).expect("向量文件必须是合法 JSON")
}

fn bytes(v: &Value, key: &str) -> Vec<u8> {
    let s = v[key].as_str().unwrap_or_else(|| panic!("缺少字段 {key}"));
    hex::decode(s).unwrap_or_else(|e| panic!("字段 {key} 不是合法 hex: {e}"))
}

#[test]
fn 帧编码与向量逐字节一致() {
    let doc = load("frames.json");
    let frames = doc["frames"].as_array().expect("frames 必须是数组");
    assert!(!frames.is_empty());

    for case in frames {
        let name = case["name"].as_str().unwrap();
        let ty = MsgType::from_u8(case["type"].as_u64().unwrap() as u8).unwrap();
        let flags = case["flags"].as_u64().unwrap() as u8;
        let payload = bytes(case, "payload_hex");
        let expect = bytes(case, "frame_hex");

        let frame = Frame {
            msg: ty,
            flags,
            payload: payload.clone(),
        };
        assert_eq!(
            frame.encode().unwrap(),
            expect,
            "[{name}] 编码结果与向量不一致"
        );

        // 反向：向量必须能解回同样的字段
        let decoded = Frame::decode(&expect).unwrap_or_else(|e| panic!("[{name}] 解码失败: {e}"));
        assert_eq!(decoded.msg, ty, "[{name}] 消息类型不符");
        assert_eq!(decoded.flags, flags, "[{name}] flags 不符");
        assert_eq!(decoded.payload, payload, "[{name}] payload 不符");
    }
}

#[test]
fn 非法帧必须被拒绝() {
    let doc = load("frames.json");
    let cases = doc["reject"].as_array().expect("reject 必须是数组");

    for case in cases {
        let name = case["name"].as_str().unwrap();
        let header = bytes(case, "header_hex");
        assert_eq!(header.len(), 9, "[{name}] 拒绝用例必须给满 9 字节帧头");
        let arr: [u8; 9] = header.try_into().unwrap();

        let result = Frame::decode_header(&arr);
        assert!(result.is_err(), "[{name}] 本应被拒绝，却解析成功了");
    }
}

#[test]
fn 配对_kdf_与向量一致() {
    let doc = load("pairing.json");
    let v = &doc["pairing_kdf"];

    let shared = bytes(v, "shared_hex");
    let nonce_a = bytes(v, "nonce_a_hex");
    let nonce_b = bytes(v, "nonce_b_hex");

    let keys = PairKeys::derive(&shared, &nonce_a, &nonce_b).unwrap();

    assert_eq!(
        hex::encode(keys.confirm_c2s()),
        v["confirm_c2s_hex"].as_str().unwrap(),
        "PAIR_CONFIRM 与向量不一致：两侧会因此互相拒绝"
    );
    assert_eq!(
        hex::encode(keys.confirm_s2c()),
        v["confirm_s2c_hex"].as_str().unwrap(),
        "PAIR_OK 与向量不一致"
    );
}

#[test]
fn prologue_与向量一致() {
    let doc = load("pairing.json");
    let v = &doc["prologue"];

    let tag = v["tag"].as_str().unwrap();
    assert_eq!(tag.as_bytes(), xime_p2p::session::PROLOGUE_TAG);

    let lo = Did::from_hex(v["did_lo_hex"].as_str().unwrap()).unwrap();
    let hi = Did::from_hex(v["did_hi_hex"].as_str().unwrap()).unwrap();
    let expect = bytes(v, "expect_hex");

    // 两个方向都必须得到同一串字节
    assert_eq!(prologue(&lo, &hi), expect);
    assert_eq!(prologue(&hi, &lo), expect);
}
