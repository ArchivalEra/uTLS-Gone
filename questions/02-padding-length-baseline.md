# 02: 填充长度的基准含不含 5 字节 record 头

**Status:** resolved

结案日期：2026-10-01。

## 结论

**基准是「整条握手消息」（含 4 字节握手头），不含 TLS record 的 5 字节头。**

两条独立证据，一条来自源码、一条来自观测：

1. **源码**：uTLS `u_conn.go:611` 把 `paddingExt.Update(headerLength + 4 + extensionsLen + 2)`
   传给 `BoringPaddingStyle`。其中 `headerLength`（`u_conn.go:589`）是「扩展区之前的 ClientHello 体」，
   那个 `+ 4` 正是握手头（`type(1) + u24长度`），`+ 2` 是扩展区的 u16 长度字段。
   所以传进去的就是「**不含本填充扩展**的整条握手消息长」。
2. **观测**：`tests/utls_conformance.rs` 用参照实现（Go 版 uTLS）实际产出的总长集合对账，
   全部预设通过。若基准差 5 字节，填充量会整体偏移，总长集合必然对不上。

本仓的实现因此是 `unpadded = body_len(含握手头) - 4`（那 4 是填充扩展自身的头），
见 `encode.rs` 的 `Padding::BoringStyle`。**不是** `- 5`，也不是不含握手头的 `body_len`。

## 仍然开放的残余

「uTLS 这么算」不等于「真实 Chrome 这么算」。后者是**保真基准**问题，
归 `questions/03-preset-fidelity-baseline.md` —— 本单只负责把基准钉在参照实现上，
而这正是本期目标（复刻 uTLS）所需要的口径。

**Settling:** crates/utls/tests/utls_conformance.rs —— 总长集合对账全过 ⇒ 填充算术与参照一致；任一对不上 ⇒ 基准或算术有偏差

**Type:** task

- [x] 从 uTLS 源码确认 `Update()` 收到的到底是什么长度
- [x] 用参照实现的实际产出交叉验证（总长集合）
- [x] 结论回填，`Status:` 改 `resolved`
