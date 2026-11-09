# libximep2p

曦码（Xime）跨设备剪贴板 P2P 传输层，从 [libximecore](https://github.com/ximeiorg/libximecore)
拆出的独立仓库（GPL-3.0-or-later），供桌面端、鸿蒙端与安卓端共同使用。

协议定义见 libximecore 的
[docs/clipboard-p2p-protocol.md](https://github.com/ximeiorg/libximecore/blob/main/docs/clipboard-p2p-protocol.md)。

## 组成

| crate | 内容 |
|---|---|
| `xime-sync-domain` | `Profile` 条目模型与 `text_hash`（与云端同步共用，`text_hash` 必须逐字节一致） |
| `xime-p2p` | 帧编解码、身份、SPAKE2 配对、Noise IK 会话、分片、TCP/UDP 传输、`Node` |
| `xime-p2p-c` | C ABI 薄层（JSON 入参/返回），鸿蒙 NAPI 使用 |

各平台绑定不在本仓：

- 安卓 JNI：`Xime/app/src/main/rust/xime-p2p-jni`
- 鸿蒙 NAPI：`ximeharmony/entry/src/main/cpp/p2p_napi.cpp`

## 构建与测试

```bash
cargo test
cargo build -p xime-p2p-c --release
```

安卓交叉编译由 Xime 仓的 `scripts/build-p2p-android.sh` 负责（只编本仓三个 crate）。

## 许可证

GPL-3.0-or-later，与 libximecore 一致；完整文本见 [LICENSE](LICENSE)。
