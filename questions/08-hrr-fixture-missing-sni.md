# 08: `HelloRetryRequest` 那条录音为什么缺 SNI

**Status:** resolved

结案日期：2026-10-01。

## 问题

上一轮会话末尾，用 uTLS 自带 `testdata/` 做对账时出现**唯一一条**不一致：

```
夹具: 65281-23-35-13-5-18-16-30032-11-51-45-43-10-27-21        （无类型 0 = server_name）
我们: 65281-0-23-35-13-5-18-16-30032-11-51-45-43-10-27-21
```

那条夹具叫 `Client-TLSv13-UTLS-HelloRetryRequest-Chrome-70`。同目录还有显式的
`-OmitSNI` / `-ServerNameIP` / `-EmptyServerName` 后缀夹具，而这条**名字里没有后缀却缺 SNI**，
所以当时把它标成「provenance 不明，需要判断而不是猜」，没有改代码。

## 结论

**是我们错，夹具对。** 而且原因不在 HRR，在 SNI 的编码规则。

`TestUTLSHelloRetryRequest`（`u_conn_test.go:174-188`）用的配置是
`testConfig.Clone()`，而 `testConfig`（`handshake_test.go:458`）**根本不设 `ServerName`**。
于是：

- `ApplyPreset`（`u_parrots.go:3116-3118`）里 `if ext.ServerName == "" { ext.ServerName = config.ServerName }`
  ⇒ 仍然是空串；
- 写字节时 `SNIExtension.Read` 先过 `hostnameInSNI(handshake_client.go:1365)`，
  空串返回空 ⇒ `Len()` 为 0 ⇒ **线上零字节**；
- 但那个槽位**仍在扩展列表里**：Go 的写循环照常遍历它（`Read` 返回 `(0, io.EOF)`），
  所以它照占洗牌的那一次抽取。

顺带同证的三条夹具（都缺类型 0）：`…-Chrome-70-EmptyServerName`（`config.ServerName = ""`）、
`…-Chrome-70-ServerNameIP`（`config.ServerName = "1.1.1.1"` —— IP 字面量同样被
`hostnameInSNI` 判空）、以及这条 HRR。而同预设的正常夹具里类型 0 在。

## 我们错在哪

`crates/utls/src/hello/encode.rs` 的 `Extension::ServerName` 分支：
`sni = None` 直接报 `SpecError::MissingServerName`，`sni = Some("")` 发出 4 字节空体。
两条都与 uTLS 不符。

修法：新增 `hostname_in_sni()`（逐行对应 `hostnameInSNI`，含三处「照抄而不是改好」的怪癖），
空结果走 `emit = false`（**零字节但保留槽位**，与本仓处理窗口外填充、空 PSK 用的是同一个机制），
并删掉 `SpecError::MissingServerName`（uTLS 里它不是错误）。

## 判据（可复跑、可证伪）

- `crates/utls/tests/utls_testdata.rs`：三条 SNI 家族夹具 + HRR 那条现在都逐字节相同；
  另有 `omitting_the_sni_slot_equals_an_empty_sni_only_when_stable` 钉住
  「删槽位」与「空名字」在 `Stable` 预设上等价、在 `Shuffled` 预设上**必须不同**。
- `crates/utls/src/hello/tests.rs`：`hostname_in_sni_is_utls_byte_for_byte`（17 个样例，
  含方括号、zone、尾点、近似 IP 的怪癖）。
- **证伪已实测**：把修好的分支**回退**成旧行为后重跑，`utls_testdata` 立刻变红，
  且第一条失败就指名 `…-Chrome-70-EmptyServerName` 与「扩展类型序列」。
  一处修好、一处回退就一处红 —— 这条判据不是自证。

## 教训（比这个 bug 本身值钱）

上一轮为什么会把它标成「provenance 不明」：我只看了夹具名与同目录的后缀命名，
**没去读那条测试用的配置**（`testConfig` 与 `getUTLSTestConfig` 是两个不同的配置，
前者不设 ServerName）。名字里的后缀是**显式线索**，而「没有后缀」不等于「用默认值」。
所以：**对账不一致时，先去读产出它的那段测试代码，再谈「夹具是不是错的」。**

**Settling:** `cargo test -p utls --test utls_testdata -- --nocapture` —— rc=0 ⇒ 三条 SNI 家族夹具与那条 HRR 逐字节相同；把 `crates/utls/src/hello/encode.rs` 的 `hostname_in_sni` 分支回退成旧行为 ⇒ rc≠0，且失败信息指名 `…-Chrome-70-EmptyServerName`（已实测）

**Type:** question

- [x] 读产出那条夹具的测试与配置，而不是只看名字
- [x] 定位到 `hostnameInSNI` + `SNIExtension.Len()` 这条规则，并用另外两条夹具交叉验证
- [x] 修 `encode.rs` 并删掉 `SpecError::MissingServerName`
- [x] 把对账固化成入库工具（`utls_testdata.rs` + `fixtures/utls-testdata/`）
- [x] 回退验证判据会红（证伪），结论回填，`Status:` 改 `resolved`
