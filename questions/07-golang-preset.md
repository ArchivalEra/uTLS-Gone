# 07: `Golang` 预设的语义

**Status:** resolved

结案日期：2026-10-01。

## 结论

**`HelloGolang` 在本架构里没有对应的 spec，而且这不是待实现项 —— 它是明确的不适用项。**

uTLS 的 `HelloGolang` 意思是「用 **Go 标准库自己的** ClientHello」：不是一份 spec，而是
让引擎按自己的默认值构建。在 uTLS 里那就是 `crypto/tls` 的产出。

在我们的分层里，与之对应的是「用 **rustls 自己的** ClientHello」—— 也就是
**不使用本 crate 的指纹层**（不设 `ClientConfig::fork_client_hello`）。所以：

- 它不该被列进 `ClientHelloId::implemented()`（那是「能用 `from_preset` 静态拿到的预设」）；
- 它也不该报 `PresetUnavailable`（那是在说「我还欠着」）；
- 它报的是一个专门的变体 [`SpecError::EngineDefined`]，其 `Display` 文案把这个结论写全。

这个区分不是文字游戏：`PresetUnavailable` 会被读成一张待办，而这张单的结论是
**没有待办** —— 想「用引擎默认」，正确做法就是别用这个库的指纹层。

## 复跑

```sh
cargo test -p utls --lib preset::tests::unimplemented_presets_error_instead_of_falling_back
```

**Settling:** crates/utls/src/hello/preset.rs —— `spec_of(Golang)` 返回 `EngineDefined` ⇒ 结论成立；返回 `PresetUnavailable` ⇒ 结论被改回「待实现」

**Type:** question

- [x] 定下语义（不适用，而非待实现）
- [x] 用专门的错误变体把它写进代码，并让测试钉住
- [x] 结论回填，`Status:` 改 `resolved`
