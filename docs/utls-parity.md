# uTLS 等价物：上游每个测试族，我们判到了哪一步

这份文件回答一句话：**「离真 uTLS 等价物还差哪些测试」**。
它是「完全等价」这句声明的**可核对形式** —— 每一行都能顺着 `file:line` 去查，
而不是一份印象。

## 口径（贯穿全表的那条线）

**uTLS 自己写的那一层，我们必须有、必须有判据；`crypto/tls` 提供的东西（引擎），
由 rustls 提供。** uTLS 的本质就是「fork 掉 TLS 引擎、在它上面搭一层指纹」，
所以「等价」在架构上就等于这条线；照它切，QUIC 会自动分成两半：
`u_quic_transport_parameters.go` / `u_quic_grease_version` 是 **uTLS 的**（要做），
`quic.go` 的连接状态机是 **crypto/tls 的**（rustls 有 `pub mod quic`，不重写）。

四种判定：

| 判定 | 意思 |
|---|---|
| **已判** | 本仓有可复跑的判据，且判据取「服务端给的结论 / 上游产出的字节」 |
| **rustls 领地** | 上游那部分测的是 Go 引擎的行为；我们的引擎是 rustls，不重写，也不假装判过 |
| **无 oracle** | 上游**自己没测**，所以不存在可移植的判据（我们的自有判据已是上限） |
| **未做** | uTLS 有、我们还没有 —— **这是真正的缺口**，逐条列在下面 |

---

## 一、指纹构造与 ClientHello（uTLS 的核心那一层）

| 上游 | 判定 | 我们的判据 / 说明 |
|---|---|---|
| `u_parrots_test.go` 全族的 spec 深拷贝、每家族扩展序列 | 已判 | `crates/utls/src/hello/preset.rs`（36 条自测：每家族的扩展类型、PSK 位置、填充带、无重复、只有 Chrome 是乱序） |
| `u_conn_test.go` 的 parrot 握手族 + `testdata/Client-TLSv*-UTLS-*`（55 个） | 已判 | `crates/utls/tests/utls_testdata.rs`：**39 个逐字节对账**（含 `Flow 1` 与 HRR 的 `Flow 3`）；16 个有理由地跳过，逐条写在 `fixtures/utls-testdata/README.md` |
| `u_clienthello_json_test.go` + `testdata/ClientHello-JSON-*.json`（4 个） | **已判** | `crates/utls/src/json.rs`（feature `json`，默认关；serde_json 变 optional）+ `tests/utls_json_golden.rs`：四份 golden 反解出的 spec 与 `from_preset` **逐字段相同**（模型级 PartialEq，GREASE 两边都是占位符）。为这份 golden 补了 **`Ios(14)` 预设**，其指纹事实（`fp_ios_14_*`）已入台账，且 conformance 那条对账判它对着上游**实时输出**逐字段一致 |
| `u_common_test.go`（`isGREASEUint16`） | 已判 | `crates/utls/src/ja3.rs`、`src/hello/stream.rs` 的 GREASE 判据 |
| `u_ech_test.go`（`TestGREASEECHWrite`，对 inline raw vector） | **已判** | `src/hello/tests.rs` 的 `grease_ech_matches_the_upstream_inline_vector_fields`：把上游那条 254 字节向量**逐字段**移植（先判向量自洽，再判我们编出来的体长度与每个结构字段相同）。上游那条判据本身也不比载荷字节（它是每连接的随机量），所以这就是它的等价形式 |
| `u_parrots_test.go` 的 `ReuseHybridAndClassicalKeyShares`（`:63` + 互补 `:96`） | **本轮已补** | `crates/utls-engine/tests/key_share_reuse.rs`（4 条）：Firefox 148 线上末 32 字节相同 + 只认经典组时 `Full`、Chrome 133 必须独立、声明后选混合组仍 `Full`、`from_bytes` 不凭空补这个声明。实现：`KeyShare::reuse` + 引擎按 `hybrid_component()` 只交一把 |
| `u_fingerprinter_test.go` 的**解析**半边（4 个 golden spec、内联的真实捕获） | **已判**（三条捕获；JSON 除外） | 三条内联捕获全部逐字节回放：Google（`utls_testdata.rs`）、Slack 的 KeepPSK 与 curl 的 dump-larger-than-extensions（`real_world_captures.rs`）。BluntMimicry 的口径差异见下 |

## 二、握手行为（引擎那半边，但判据必须是「服务端给的结论」）

| 上游 | 判定 | 我们的判据 / 说明 |
|---|---|---|
| `TestUTLSHelloRetryRequest`（`u_conn_test.go:176`） | 已判 | `tests/hello_retry.rs`、`tests/hello_retry_e2e.rs`、`tests/hello_retry.rs::*` 的第二飞逐字节 + `fixtures/utls-testdata` 里上游录的第二飞 |
| 多 key share 的完成 | 已判 | `tests/multi_key_share.rs`（服务端选**第二个**组也谈成）、`tests/p256_handshake.rs`、`tests/mixed_group_handshake.rs`、`tests/pq_key_share.rs` |
| `TestResumption` / `TestLRUClientSessionCache` / `TestCrossVersionResume`（引擎的 ticket 机制） | 部分已判 | **PSK 接线**已判：`tests/resumption.rs`（服务端第二条连接说 `Resumed`、HRR 后仍复用）。**ticket 加解密本身**是引擎领地（rustls） |
| `TestRealResumption`（真外网 `yahoo.com`） | 已判（换域名） | `run-upstream-suite.sh`：目标域名换成直连可达、判据等价者，全量 222 PASS / 0 FAIL / 1 SKIP。**代理跑未改动树那条已退役**（`questions/09` 留历史） |
| `TestVerifyHostname`（真外网 `www.google.com`） | 已判（换域名） | 同上 |
| `TestECH` / `TestTLS13ECHRejectionCallbacks` / `TestUTLSECH` | 已判 | `tests/ech.rs`、`tests/ech_offer.rs`、`tests/ech_inner_utls.rs`（内层与 uTLS 逐字节）、`tests/ech_e2e.rs`（三族真服务器 `Accepted`）、`tests/ech_utls_server.rs`（过 uTLS 自己的服务端）；证据链在 `questions/10` |

## 三、**未做**（真缺口，逐条）

1. **QUIC 指纹层 —— 编码层已移植，连接那半边未接**。
   `u_quic_transport_parameters.go` 已移植为 `crates/utls/src/quic.rs`，上游三条判据
   都有了 Rust 版：`TestMarshal`（Firefox 参数集 **golden bytes 逐字节**）、
   `TestGetGREASEVersion`（4096 次抽样全是 `0x?a?a?a?a` 且高位不全同）、
   `TestVersionInformationGREASESubstitution`（哨兵逐次替换、非哨兵原样、结构里仍是哨兵）。
   **一处刻意的差别**（写在模块头）：上游每次 `Value()` 从系统熵新抽，我们由**每连接的
   seed** 驱动（与 hello 分域）—— 跨连接照样每条不同，**同连接可复现**（HRR 第二飞需要）。
   **仍缺**：(a) `u_quic.go` 的 `UQUICConn` 那层接缝（rustls 有 `pub mod quic`，
   但我们的外供 ClientHello 还没接上 QUIC 连接）；(b) 真握手判据
   （服务端看到的传输参数扩展与我们算的一致）。
2. **`AllowBluntMimicry` 的口径差异（已写死在案，不是默默不同）**：
   上游 `FromRaw` 默认（blunt=false）会**丢掉**不认识的扩展；我们是**恒 blunt**
   （`crates/utls/src/hello/parse.rs:20`，未知扩展一律留成 `Opaque`、字节原样保留）。
   理由：本仓的逐字节回放判据（Google / Slack / curl 三条捕获）只有在「什么都不丢」时
   才可能成立；上游自己的 curl 那条判据也是显式开 `AllowBluntMimicry: true` 才吃下的。
   若日后要补 blunt=false 那个开关，判据就是「反解-回放**不再**逐字节」—— 那是与本仓
   全部回放判据相斥的另一条路，做之前要想清楚。
3. **一条被 `from_bytes` 挡住的等价性**：`parse.rs` 把 `key_share` 归成 `Opaque`
   （这正是回放能逐字节相同的原因），代价是**反解出来的 spec 没有「组」**，
   于是它走不了引擎 —— 而 uTLS 那边可以：它在写出时**总是**用引擎新生成的密钥覆盖
   spec 里的 keyshare 数据（`handshake_client_tls13.go:391`，
   `// new ks seems to be generated either way`），所以一份 `Fingerprinter` 出的 spec
   照样能握手。这是「Fingerprinter 一族」的根，见 `tests/key_share_reuse.rs` 第四条里
   钉住的那条已知边界。
4. **early data（0-RTT）**：上游 `quic_test.go` 里有 declined-early-data 的判据；
   我们一行没有。uTLS 的早期实现同样不支持（`u_conn.go` 的注释），但这属于「未做」，
   不写成「上游也没有」。

## 四、**rustls 领地**（不重写，也不假装判过）

上游这些测试判的是 **Go `crypto/tls` 引擎**的行为，我们的引擎是 rustls ——
重写它们等于重写一个 TLS 栈，而那不是本项目的目标（`README.md` 的「为什么必须 fork」
一节说明了我们与 uTLS 的**同一形态**：fork 引擎 + 搭指纹层）。

| 上游 | 为什么不是我们的 |
|---|---|
| `handshake_server_test.go`（60 个 `Server-*` 录制）、`TestClientAuth`、`TestGetConfigForClient` 等 | 服务端状态机 —— 我们不提供 TLS 服务端；uTLS 也不提供（它靠 Go 的 `tls.Server`） |
| `handshake_messages_test.go`、`key_schedule_test.go`、`prf_test.go`、`auth_test.go`、`conn_test.go`（record 层） | 消息编解码 / 密钥计划 / PRF / 记录层 —— 全是引擎内部 |
| `tls_test.go` 的 `X509KeyPair` / `DialTimeout` / `ConnectionState` / `TestClone*` | Go 的证书与 API 形状 |
| `quic_test.go`（17 条，`QUICConn` 传输 API） | QUIC 连接状态机（rustls 有 `pub mod quic`）；**注意**：`u_quic*.go` 那两半不在此列，见「三」 |
| `fipsonly_test.go`、`TestHandshakeMLKEM` 的 FIPS 分支、各 `skipFIPS` | 要 `GOEXPERIMENT=boringcrypto` 的构建 |
| `testdata/` 里的 `Server-*`、`Client-TLSv10/11-*`、OpenSSL 重录（`-update`） | 要么是服务端录制，要么要 OpenSSL 1.1.1 的特定构建 |

**`bogo`**：上游**已经把它拆掉了** —— `handshake_test.go:419-425` 的 `[uTLS section]` 里
`bogoShim()` 调用被注释掉，只剩几个 flag（`-bogo-mode` 只改 `flag.Usage`）。
所以「跑 BoringSSL 的 bogo 套件」在**上游**就不是一项在跑的东西，不构成缺口。

## 五、**无 oracle**

| 上游 | 说明 |
|---|---|
| `u_roller.go`（`Roller` / `NewRoller` / `RollerConfig`） | 上游**没有任何测试**引用它（在 `*_test.go` 里 grep 为空）。它要拨真主机，天然不可回放。本仓的 `tests/roller.rs`（候选顺序、记住赢家、TCP 失败立刻返回）已是**上限** —— 因为没有可移植的判据 |

---

## 本轮（2026-10）动过的地方

- **已补**：Firefox 148 的混合/经典 key_share 复用（上表「一」），顺带炸出并修掉
  fork 缺陷第 8 条（`OfferedKeyShares::take_for` 的匹配顺序，见
  `crates/rustls-fork/README.md`）。
- **完整性**：两个 upstream job 原先**只断言「没有意外的跳过」** —— 于是一条都没跑也是绿的；
  现在都断言「顶层 PASS 非零」+「跳过集恰如预期」。死判据 `tests/ech_control.rs`
  （无引用、无理由地 `#[ignore]`、不断言）已删。
- **代理路径退役**：`socks5fwd.py` 已删，`questions/09` 的配方降为历史记录。
  **代价写明**：失去了「完全未改动的上游树」那条路的可复跑性。
- **过时文档**：`utls-engine/src/lib.rs` 的能力清单、`utls/src/hello/preset.rs` 的
  `_PSK_` 段、`rustls-fork/README.md` 的 §三/§六/`rustls_pin` 段、
  `README.md` 的 QUIC 非目标句 —— 都已对齐现状（它们此前在**低估**自己）。
