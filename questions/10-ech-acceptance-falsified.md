# 10: 真实 ECH 服务器拒绝我们的提议（已解决：三族服务器都接受了）

**Status:** resolved

**Settling:** `cargo test -p utls-engine --test ech_inner_utls our_inner && cargo test -p utls-engine --test ech_utls_server -- --ignored && cargo test -p utls-engine --test ech_e2e -- --ignored` —— 全绿 ⇒ 结论成立（内层与 uTLS 逐字节相同，且三族 ECH 服务器都**接受**我们的提议）；任一条红（`IllegalParameter` / `ServerRejectedEncryptedClientHello` / `Rejected`）⇒ 本悬案重新成立。三条判据分列如下（两离线一在线）：

```bash
cd /mnt/hdd/zcode-projects/uTLS-rs
# ① 离线·逐字节：我们的内层 == uTLS 自己产出的内层（探针取回的原始字节）
cargo test -p utls-engine --test ech_inner_utls our_inner
# ② 离线·参照实现服务端：让**我们的客户端**与 **uTLS 自己的 ECH 服务端**完整握手
#    （要 go 与 uTLS 源码树，默认 /tmp/utls-ref/utls-master）
cargo test -p utls-engine --test ech_utls_server -- --ignored
# ③ 在线：打真实端点，断言 EchStatus::Accepted
cargo test -p utls-engine --test ech_e2e -- --ignored
```

②③ 的通过形状：服务端 `ech_accepted=true` 且 `server_name` 是**内层**那个真名，
客户端 `ech_status == Accepted`；任一条报 `IllegalParameter` /
`ServerRejectedEncryptedClientHello` / `Rejected` ⇒ 本悬案重新成立。

## 教训链（按发现顺序；每条都指名出处，防止后人「再解释」）

1. **AAD 是 ClientHello 的体**，不是整条握手消息（含 4 字节头）。
   能通的参照（rustls）用 `ClientHelloPayload::get_encoding()`；
   uTLS 的 `computeAndUpdateOuterECHExtension` 也是 `serializedOuter[4:]`。
   修完后 Cloudflare 的反应从「回 retry configs」（解不开）变成 `IllegalParameter`
   （解开了、内容不合规）—— 错误变了，就是修掉的证据。
2. **内层不是「外层的过滤版」**。这是本悬案最大的一个弯路：第一版内层是
   「Chrome-70 spec 去掉几条扩展」（那是 **rustls** 的 `encode_inner_hello` 做法），
   而 uTLS 的内层是 `UConn.makeClientHello()` 造的**诚实的 hello**
   （cipher suites / supported_versions / ALPN / 扩展集合都来自引擎真实能力），
   只把**四个字段**从预设抄进去（`u_conn.go:564-568`：keyShares、
   supportedSignatureAlgorithms、sessionId、supportedCurves）。
   出处：`ech_inner_probe_test.go` 打出的 `echCtx.encodedInner`（128 字节：
   SNI、SCT、ECH[1]、supported_versions=[0304]、0xfd00 marker、补零）。
   现在的判据是**逐字节**：`ech_inner_utls.rs::our_inner_hello_is_byte_identical_to_utls_chrome70`。
3. **内层转录里的 session id 必须是外层线上的那个**（fork 的 bug）。
   `EchState::from_supplied` 曾拿到 `input.session_id` —— 那是引擎在
   `ClientHelloInput::new` 里自造的值；而「我们的值」要到**之后**解析外层字节才学到。
   服务端重建内层时插的是**外层**的 session id（Go：`recon.AddBytes(outer.sessionId)`），
   两边哈希的内层转录差 32 字节 ⇒ 接受确认对不上 ⇒ 服务端按接受走、我们判
   `Rejected` ⇒ 密钥调度分叉 ⇒ `cannot decrypt peer's message`。
   离线定位法：把我们的字节喂给 uTLS 自己的解码器（`ech_decoder_probe_test.go`），
   它的重建与我们差的那 32 字节就是它。
4. **内层的内联扩展按 Go 的字段顺序排**（SNI, SCT, ECH, ALPN, versions, marker），
   与 uTLS 的产出**逐字节**相同 —— 包括顺序。
   ⚠️ 排查记录（防重推）：OpenSSL 系拒我们时曾怀疑「内层要按**外层**线序保序」，
   并单独改过顺序 —— **无效**（test.defo.ie 仍拒）。那个假设被证伪了；
   真正的元凶是下一条（GREASE keyshare）。二分把它钉死后，顺序改回了 uTLS 的原序。
5. **ECH 时外层要去掉 GREASE key share**（OpenSSL 系 `illegal_parameter` 的元凶）。
   Chrome-70 那代指纹在 `key_share` 里第一个放 `{GREASE, [0]}`；服务器重建内层时
   被压缩的 `key_share` 由**外层**真身填回 ⇒ GREASE keyshare 进了内层 ⇒ OpenSSL 系拒。
   逐变量实测（`ech_e2e.rs::bisect_3_which_grease_codepoint_offends`）：只去 key_share
   里的 GREASE ⇒ Accepted；只去 supported_groups / supported_versions 的 ⇒ 仍被拒。
   真实 ECH 客户端（Chrome 117+ / Firefox）本来就不发 GREASE keyshare，
   所以这只在 **ECH 路径**上 scrub，非 ECH 指纹一字节不动
   （`utls-engine/src/lib.rs::scrub_grease_key_share`）。
6. **新预设自带 GREASE 形态的 `0xfe0d`**（Chrome 133+ / Firefox 120+）：
   真 ECH 模式下要**替换**它而不是再叠一条（marshaller 会因扩展类型重复拒绝；
   `utls-engine/src/lib.rs::put_or_replace_ech_ext`）。

## 三个服务器家族的对照（谁把什么当判据）

| 检查 | Go 系（uTLS 服务端 / Cloudflare） | OpenSSL 系（DEfO：defo.ie / test.defo.ie） |
|---|---|---|
| marker 类型沿外层**单调查找** | 是（找不到 ⇒ illegal_parameter） | 是 |
| 内层 `supported_versions` ≥ 1.3（GREASE 除外） | 是 | 是 |
| 内层里的 GREASE **keyshare** | 容忍 | **拒**（illegal_parameter） |
| 内层是「诚实的 hello」还是「外层过滤版」 | 都接受 | 都接受（形状对的前提下） |

rustls 自带客户端（`ech_e2e.rs::stock_rustls_ech_client_is_the_control`）在两个真实
端点都被接受 —— 它是「同一客户端实现、只换内层构造」的对照组，用来把变量缩到一个。

## 修完之后的验收状态（本机实测）

- ② uTLS 自家服务端：完整握手成功，`ech_accepted=true`、`server_name="secret.example"`
  （内层真名）、ALPN `h2`；客户端 `EchStatus::Accepted`。
- ③ 真实端点：`crypto.cloudflare.com` ⇒ Accepted；`test.defo.ie` 与 `defo.ie` ⇒
  Accepted（三条 config 逐条试也都 Accepted）；chrome-70 / chrome-133 / firefox-120 /
  minimal 四种外层指纹 ⇒ 全部 Accepted。

## 历史注记（诚实起见）

旧实现（外层过滤版内层）下 defo.ie 曾有一次 `Accepted`、其余全是 `IllegalParameter`，
那次「通过」未能复现也无法归因（当时混着第 3/4/5 条三个缺陷，且端点配置在轮换）。
修完 3/4/5 之后三个端点稳定 Accepted，那条孤例不再有意义。
