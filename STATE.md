# uTLS-rs · 活状态

本文件是**活状态**：正文只写「现在是什么」，数字一律引用台账键（`[[键名]]`），
不手抄。机器维护的块在文件末尾。判定规则见 `zreflect/living.py`。

## 这个项目是什么

纯 Rust 复刻 [`refraction-networking/utls`](https://github.com/refraction-networking/utls)：
把 ClientHello 做成**可命名、可复现、可验证**的指纹。目标形态与 uTLS 一致 ——
fork 掉 TLS 引擎、在上面搭 `u_*` 层；唯一的区别是引擎从 Go 的 `crypto/tls` 换成 rustls。

## 架构定位

**「用上游 rustls 加一个扩展列表就能实现」是错的**，见 `retractions.json` 的 R-001。
两个硬约束：rustls 没有公开的 ClientHello 定制 API，且自 0.23.0 起**每连接随机化扩展顺序**。
所以必须 fork —— 这是前提，不是选择。

我方那一层（ClientHello 数据模型 / 序列化 / GREASE / 填充 / 预设表 / 从原始字节反解）
**不引用任何 rustls 类型**。理由是实测的：rustls 在两年内两次重构内部扩展表示
（0.23.4 改成 `ClientExtensions{order_seed, ..}`，0.24-dev 又拆了 `client/`）。
把易变的部分关进一个薄适配层，补丁的 delta 才只剩插桩点，rebase 的成本才从「重写」降为「对行」。

## 现在是什么

- **预设表已覆盖 uTLS 的绝大多数家族**：Chrome（含 PQ 变体）、Firefox、iOS、Android、
  Edge、Safari、360、QQ 共三十余条，全部逐条抄自 Go 的 `u_parrots.go`。
  已实现与未实现的由 `ClientHelloId::implemented()` 明列；**未实现的返回错误，
  不静默降级到「最近的版本」**（那会让调用方以为在模仿 Chrome 120，实际发出去的是
  Chrome 133 —— 这种错在指纹上看得见、在代码里看不见）。
- **逐条与参照实现对过账**：`crates/utls/tests/utls_conformance.rs` 拿
  `tests/fixtures/utls-reference.json`（**Go 版 uTLS 的实际产出**，不是我们转写的）
  比 `legacy_version`、密码套件序、支持组序、点格式、扩展多重集、逐扩展体长、总长的集合、
  以及两条稳定性指标。这是本仓唯一一条**外部**验证 —— 仓内其它测试都是自证，
  预设抄错了编码器和解码器会一起错，往返照样绿。
- **指纹事实已在台账里**：每档预设若干条（`[[fp_chrome_133_ja3_md5]]`、
  `[[fp_chrome_133_hello_len]]` 等），由 `examples/reflect-facts.rs` 跑出来。
  文档里的指纹值**只来自这里**，不手抄。
- **一条已登记的缺口**：`fp_chrome_133_len_stable` 是 `NO` —— 而参照实现**也是** `False`
  （同一个预设跑多次得到多个总长）。所以我们与 uTLS 一致；剩下的问题是**真实 Chrome**
  是否也如此（见 `questions/06-*.md`）。
- **原版全量测试已跑通（无跳过）**：干净检出上 `go test -count=1 -timeout 480s ./...`
  ⇒ `ok`，**222 PASS / 0 FAIL / 1 SKIP**（那条 SKIP 是上游自己跳的）。
  现在只有**一条**推荐路径：`sh crates/utls/tests/fixtures/gen-reference/run-upstream-suite.sh`
  —— 无代理，只把那两条 egress 测试拨号的目标域名换成直连可达、判据等价者，
  用 `go -overlay` 在构建期替换（上游树磁盘不动）。
  **经代理跑「完全未改动的上游树」那条已退役**（2026-10-01：它要 sudo 改 `/etc/hosts`
  再手工收尾，把跑判据变成会留系统改动的事），配方与已删的转发器留在
  `questions/09-*.md` 作历史记录；**代价**是失去了那条路的可复跑性（已写明）。
  两条路为什么是**两个**判据写在 `gen-reference/README.md`。
- **CI 在跑本仓自己的判据**（`.github/workflows/ci.yml`，六个 job）：
  `rust`（fmt / clippy -D warnings / 全部测试）、`gates`（五道闸门 + 自证 + 机器块一致）、
  `patch-repro`（一条命令：补丁打到原始 rustls 上要与 vendored 树逐文件相同，两条判据）、
  `ech-offline`（内层逐字节 + 过 uTLS 自己的 ECH 服务端）、`upstream`（原版套件，
  不联网那两条 `-skip`）、`upstream-no-skip`（原版套件**全量**，靠 `-overlay` 换目标域名）。
  两个 upstream job 现在都断言「**顶层 PASS 非零**」+「跳过集恰如预期」——
  原先只断言「没有意外的跳过」，于是**一条都没跑**也是绿的。
  联网判据**不在 CI 里**，理由与本地跑法写在 workflow 文件头。
- **事实系统**：[[gate_count]] 个闸门（**发现式**名录，见 `gates-selftest.sh`），
  [[question_count]] 条悬案（未结案 [[open_questions]] 条），[[retraction_count]] 条翻案，
  台账 [[rs_files]] 个 `.rs` 文件 / [[rs_lines]] 行的规模。
  采集器与闸门共 [[py_files]] 个 Python 文件，纯脚本 + 退出码，不联网、不依赖模型。

## `_PSK_` 变体已复刻：位置约束 + 空 PSK

uTLS 有四个 `_PSK_` 预设（Chrome 100 / 112 / 114 / 115 的 PSK 变体）。它们的实测形状是
「对应兄弟 spec + 末尾一条**空 PSK 标记**」，其中 100/112 **不含填充扩展**、114 含（且在 PSK
之前）、115_PQ 本来就没有。

- **位置约束**：`pre_shared_key` 必须**最后**（RFC 8446 §4.2.11）。这条在**声明层**校验
  （`SpecError::PreSharedKeyNotLast`），不等到组装 —— 那时错误已经离原因很远了。
- **空 PSK 怎么办**：实测 uTLS 在**没有会话时直接报错**
  （`tls: empty psk detected; remove the psk extension for this connection or set OmitEmptyPsk`）。
  错误信息自己给了两条出路，本层取较弱的那条：**不发**（等价 `OmitEmptyPsk`）。
  理由是一个纯序列化器没有「拒绝服务」的立场；带 identities 与 binders 的**真 PSK 支持**
  属于 session/resumption 那一块，仍未做。
- ⚠️ 那个标记**仍然参与乱序的那次抽取**（uTLS 把它当位置固定的元素，照抽不误），
  所以编码器把它留在列表里、只是**不写字节**。

## 结构化扩展集：`Opaque` 的常见扩展已升级成有类型的变体

`crates/utls/src/hello/extensions.rs`：把常见扩展从 `Extension::Opaque`（类型 + 原始体）
升级成有类型的变体，共十五种（`status_request`、`extended_master_secret`、
`renegotiation_info`、`session_ticket`、`ec_point_formats`、`compress_certificate`、
ALPS 的两个码点、`sct`、`psk_key_exchange_modes`、`record_size_limit`、
`signature_algorithms_cert`、`delegated_credentials`、NPN、ChannelID 的两个码点），
预设里 **241 处** `Opaque` 全部换成了它们。

两条自律：

1. **`classify()` 必须是 `body()` 的逆** —— 反解器只在「重新编码可证明逐字节相同」时才
   产出有类型的变体，其余一律回落 `Opaque`（宁可不可编辑，也不能不可靠）。
   有一条**表驱动测试**把这条钉住：每个变体走一遍「声明 → 字节 → 反解 → 字节」，
   外加一组**非规范形状**（带 responder id 的 `status_request`、长度前缀不符的
   `renegotiation_info`……）断言它们确实回落到 `Opaque`。
2. **体内容必须与 uTLS 逐字节一致** —— 见下。

**收益**：三个临时的体构造函数（`alps_body` / `cert_compression_body` /
`delegated_credentials_body`）被删掉了，它们的逻辑进了有类型的编码器；而且有类型之后
每个变体都能**校验自己的长度字段**（如 `renegotiation_info` 的连接串必须装得进 u8），
`Opaque` 做不到这件事。

## 对账被加强到「逐字节比体内容」

这次顺带把 uTLS 一致性对账从「逐扩展**体长**」加强到「逐扩展**体内容**」：
夹具现在带每个扩展体的十六进制，测试逐字节比。

**为什么必须加强**：只比长度会漏掉「长度一样、内容错了」—— 而那正是「把 `Opaque` 升级成
有类型的变体」最容易犯的错（体的生成方式换了，长度却不变）。**这次重构的守门人就是它。**

不可比的部分被**规范化**掉（只折真正每连接变化的东西）：GREASE 值（`supported_groups` /
`supported_versions` / `key_share` 的组）、`key_share` 的**公钥字节**（参照实现给真密钥、
本仓给等长哑字节）、以及 GREASE-ECH 的整个体。折完之后仍能抓到的就是**结构、长度、顺序、
以及一切非随机的字节**。这条规范化第一次跑就抓到了真实的 GREASE/密钥差异 —— 可见它可证伪。

## `ApplyPreset`：uTLS 形状的连接级 API

uTLS 的用法是「建一条 `UConn` → `ApplyPreset(spec)` → `Handshake()`」。本仓在
`crates/utls-engine` 里给出了等价物：

- `UClient::apply_preset(spec)` —— 对应 `(*UConn).ApplyPreset(p)`；
- `UClient::apply_preset_by_id(id)` —— 对应 `applyPresetByID`，并**照 uTLS 的做法**
  对随机化 ID 现取一个种子（`ClientHelloSpec::randomized_os`），所以每次调用产出不同指纹；
- `UClient::set_sni` / `set_alpn` / `connect` → `UConn`（`read` / `write_all` / `http_get`）。

spec 层另有两个 uTLS 同名的方法：`always_add_padding`（`AlwaysAddPadding` —— 有 PSK 时
**插在它前面**，因为 PSK 必须最后）与 `always_add_psk`（`Config.AlwaysIncludePSK` 在
`ApplyPreset` 里做的那个变更）。两条都有测试钉住「幂等」与「位置」。

**一处架构差异，明写在文档里**：uTLS 的 `UConn` 是**可变**的，`ApplyPreset` 可以在
**建连之后、握手之前**调用；而 rustls 的连接在创建时就消耗掉 `ClientConfig`，外供
ClientHello 的接缝就挂在 config 上 —— 所以「往一条已存在的连接上施加预设」在 rustls 的
形状里没有位置。于是本仓把它挪到**建连之前**：`UClient` 攒配置，`connect()` 才建连握手。

**顺带修掉一个从未被测到的缺陷**：旧的 `connect` 用「读一个字节来推动握手」，
而在阻塞 socket 上那会一直等到服务器发应用数据（它不会 —— 它在等我们的请求），
整条连接卡死。换成 `complete_io`（只驱动握手、不吞应用数据）之后，三条联网对账
从 45 秒超时变成不到一秒通过。旧代码之所以没暴露，只是因为它没被任何**会通过**的
测试走到过 —— 这正是「能编过 ≠ 能用了」。

## 保真度：一处「乱序抽取」的缺陷（只有推理 + 一条新测试能抓到）

uTLS 里「长度 0 的扩展」**在列表里、但不占字节**（`Len()` 返回 0）—— 窗口外的填充、空 PSK
都是这样。它们仍参与洗牌的那次抽取（洗牌按列表长度抽，只是跳过与它们相关的交换）。

本仓原来做错了：窗口外的填充是**从列表里删掉**的 ⇒ 列表长度变了 ⇒ 洗牌结果变了 ⇒
同一个预设在不同 SNI 长度下，其余扩展的相对顺序**不一样**。

**这类错对账对不出来**：乱序预设不比顺序（本来每次就不同），而 0 字节不影响长度，
所以「多重集 + 逐扩展体长 + 总长集合」三关全过。是被推理找出来的，并配了一条**能红的**
测试（`padding_decision_does_not_disturb_the_shuffle`：填充发不发，不该改变其余扩展的相对顺序
—— 已验证它在修复前的实现上确实变红）。修完之后 `chrome_115_pq` 与 `chrome_120` 的 JA3
立刻改口，那正是修复生效的证据。

## 随机化族已复刻（且与参照实现逐位一致）

uTLS 的 `HelloRandomized` / `HelloRandomizedALPN` / `HelloRandomizedNoALPN` **不是固定数据，
而是一串加权掷币的结果**。它的复刻难点全在「取随机的次序」上，所以对账口径也最严。

- 实现：`crates/utls/src/hello/randomized.rs`。PRNG 是 uTLS 那条 **SHAKE256 流** +
  Go `math/rand` 的方法（逐字移植，含两个**不同**的 `int31n`）；权重表与密文套件表逐条抄录，
  后者由 `tests/fixtures/gen-reference/extract-cipher-tables.py` **生成**（可复跑）。
- 对账：`crates/utls/tests/utls_randomized.rs` 拿 `tests/fixtures/utls-randomized.json`
  （参照实现在**固定种子**下的产出，3 个 id × 8 个种子）逐字段比 ——
  legacy_version、密码套件序、扩展类型序、支持组、点格式、JA3 的 MD5、逐扩展体长、总长。
  **全部逐字相同**。随机化 spec 完全不含 GREASE，所以顺序也可以逐字比。
- 为什么这条比对静态预设更有说服力：它能对上，说明的不是「某几张表抄对了」，而是
  **整条取随机的流逐次对齐** —— 包括 Go 里「掷币是 `||`/`&&` 的左侧所以总会发生」这种
  求值顺序、两个 `int31n` 的区别、以及 ALPS 那次掷币走的是 HKDF 派生的**另一条流**。
  移植时这三处**都被踩到过**，每一处的症状都是「前面全对、后面全错」。
- 语义：这三个 ID **不能**走 `from_preset`（随机化指纹由种子定义 —— 没有种子就没有指纹），
  它们报 [`SpecError::RandomizedNeedsSeed`]，用 `ClientHelloSpec::randomized(id, seed, alpn)`。

## `Golang` 预设：结论是「不适用」，不是「待实现」

uTLS 的 `HelloGolang` 意思是「用**引擎自己**的 ClientHello」——在 uTLS 里那是 Go 标准库的产出，
在我们的分层里对应「用 **rustls 自己**的 ClientHello」，也就是**不使用本 crate 的指纹层**。
所以它没有 spec，也**没有待办**；它报的是一个专门的变体 `SpecError::EngineDefined`，
而不是 `PresetUnavailable`（后者会被读成一张欠条）。见 `questions/07-*.md`。

## 引擎已接通（里程碑 2）

**指纹层的字节真的上了线，而且服务器看到的与我们发出的完全一致。**

- 被 fork 的 rustls **已 vendor 进 workspace**（[[fork_rs_files]] 个 `.rs` 文件，
  其中**只有 [[fork_rs_modified]] 个**带 `FORK(utls-rs)` 标记 —— 这就是那个「delta 越小越好」
  的落点）。补丁的产地是 `crates/rustls-fork/patch.diff`，并且**可复现**：
  应用到原始 tarball 上得到的树与仓库里 vendored 的**逐文件相同**。
- 引擎侧在 `crates/utls-engine`：它向 rustls 的密码学提供者要密钥交换（于是 `utls`
  里一行密码学都没有），把公钥交给指纹层，再把产出的字节**原样**塞进 fork 的接缝。
- **端到端对账**（要联网，默认不跑）：
  `cargo test -p utls-engine --test end_to_end -- --ignored`。
  它断言的是**服务器观察到的 JA3 == 我们从自己记录的发出去的字节算出的 JA3**；
  对 `Stable` 预设还要再等于**台账里的黄金事实** —— 于是三方一致：
  离线黄金值（`examples/reflect-facts.rs` 产出）= 我们发出去的字节 = 外部观察者所见。
  实测 `firefox_148` 三方相同，`chrome_133`（乱序）两次连接的 JA3 不同而每次都与服务器一致。
- **接进引擎时又抓到缺陷，全是「只有运行才会暴露」的那种**：编译期一条、真实握手两条、
  把真实的 HelloRetryRequest 喂进第二飞路径时一条（引擎把自己生成的 `legacy_session_id`
  拿去校验服务器回显，而线上那个值是调用方写进字节里的）。症状、根因与修法记在
  `crates/rustls-fork/README.md` 的「跑通之后才暴露的缺陷」。
- **HelloRetryRequest 的第二飞已接通**（fork 的第六处能力）：
  `SuppliesClientHello::retry_plan` 的**默认实现是拒绝**（只供一条 hello 的调用方仍然
  完全惰性），实现了它的一方接管第二飞。两侧都有判据：指纹层与 uTLS 自带的 `Flow 3`
  录音**逐字节**相同；引擎层有 4 条离线测试 + 1 条端到端（手写的 HRR 服务端走回环，
  见 `crates/utls-engine/tests/hello_retry_e2e.rs`）。
- **本地服务端装置**（`crates/utls-engine/tests/common/mod.rs`）：一台完全离线、**握手能跑完**
  的 rustls 服务端（自签证书 vendor 在 `tests/fixtures/`，生成命令记在同目录 README）。
  它是唯一「可控 + 跑得完」的服务端 —— 打 browserleaks 不可控，手写的假服务端跑不完。
  实测它已经证掉一件之前写明的残留：**服务端要求 P-384、Chrome-70 只给 X25519 ⇒ 强制 HRR，
  我们回第二飞，会话谈成 TLS 1.3**，而 `HandshakeKind::FullWithHelloRetryRequest`
  是**服务端**给的判断，不是我们自报的。
- **PSK 的线格式已就位**（`Extension::PreSharedKey`）：identities + binders 按 RFC 8446 §4.2.11
  编码，并有 `ClientHello::psk_transcript_len()` 给出 §4.2.11.2 的截断点
  （**连 binders 向量自己的 u16 长度字段都不要** —— 差这 2 字节 binder 就永远验不过）。
  「没有会话」不再是单独一个变体：它就是 identities/binders 都空的那个形态，零字节但占位。
  真正的 resumption（session 缓存 + binder 计算）还差：fork 得把会话交出来。
- **会话复用（resumption）已跑通**（fork 的第七处能力）：引擎把会话当**数据**交给调用方
  （ticket / 混淆年龄 / binder 长度），调用方写 `pre_shared_key` 并**报告 binder 该写在哪**，
  真 binder 由引擎在拿到字节后只改写那几十个字节 —— **密钥不出引擎**。
  判据是**服务端**给的：本地服务端装置上第二次连接 `handshake_kind == Resumed`，
  且第二条 ClientHello 里的 PSK identity 就是服务端发的 ticket、binder 不是全零。
  顺带查清一个会让复用**静默**失效的坑：rustls 用 `Weak::ptr_eq` 比验签器，
  所以「每条连接新建一个 config」永远复用不了（票还被 take 走了）—— 症状看起来像 PSK 写错了。
- **HRR 不作废会话**（uTLS 的 `UpdateOnHRR`）：会话活到第二飞，binder 在新转录
  （`message_hash || HRR || Truncate(ClientHello2)`）上重算；重试套件的哈希与会话不同时
  按 RFC 丢掉 PSK。判据同样是服务端给的：`Resumed` **且** 那条连接真的发了两条 ClientHello
  （`HandshakeKind` 里没有「带 HRR 的复用」这个取值，所以「发了两条」才是 HRR 的直接证据）。
- **真实 ECH 已跑通：三族服务器都接受了我们的提议**（完整链条与教训在
  `questions/10-*.md`，已 resolved）。
  ① 配置面用 **uTLS 自己的 `ech_test.go` 向量**判（条数 1/3、逐字段、`TestSkipBadConfigs` 全对）；
  ② 封装面用 **rustls 的 `Hpke::open`** 独立解回来判（外加反面：改一个字节的 AAD/info/密钥都解不开）；
  ③ **内层按 uTLS 的模型造**（这是本条最大的弯路）：不是「外层的过滤版」（那是 rustls 的做法），
  而是 `makeClientHello` 的**诚实 hello** + 四个抄自预设的字段
  （`u_conn.go:564-568`：keyShares / supportedSignatureAlgorithms / sessionId / supportedCurves）；
  判据是**逐字节**：`ech_inner_utls.rs` 把探针取回的 uTLS 原始输出 vendor 进来逐字节比；
  ④ fork 第八处能力：外供的 `0xfe0d` 可被**声明为真提议**（差分判据：只带扩展 ⇒ `Grease`；
  交出 offer ⇒ 走完接受/拒绝判定）。
  **这一轮用真服务器判又修掉两处**：**内层转录里的 session id 该是外层线上的那个**
  （fork 曾把引擎自造的值交给 `EchState::from_supplied` —— 两边哈希的内层差 32 字节 ⇒
  服务端接受而我们判 `Rejected` ⇒ 密钥调度分叉 ⇒ `cannot decrypt peer's message`）；
  **ECH 时外层要去掉 GREASE keyshare**（Chrome-70 那代的摆设；服务器重建内层时它随
  `key_share` 真身进了内层，OpenSSL 系（DEfO）据此 `illegal_parameter` —— 逐变量二分钉死，
  只去 key_share 的 ⇒ Accepted，只去 supported_groups / supported_versions 的 ⇒ 仍拒；
  真实 ECH 客户端本来就不发它，所以只 scrub ECH 路径，非 ECH 指纹一字节不动）。
  判据三层：**离线**（内层逐字节 == uTLS 产出；uTLS 自家 ECH 服务端上完整握手、
  服务端 `ech_accepted=true` 且认证的是内层真名 —— `ech_utls_server.rs`，要 go + uTLS 源码树）
  与**在线**（`crypto.cloudflare.com` / `defo.ie` / `test.defo.ie` 全部 `Accepted`；
  对照组：rustls 自带 ECH 客户端在这两个端点同样 Accepted，用于把变量缩到一个；
  chrome-70 / chrome-133 / firefox-120 / minimal 四种外层指纹全部 Accepted）。
  参照树是可再取回的（`codeload` 的 master tarball；取回命令、本轮那份的 sha256、
  以及「别改用 v1.8.2 —— 它把 ALPN 收进了 `0xfd00` 标记」这条差异，都记在
  `crates/utls/tests/fixtures/gen-reference/README.md`）。

- **多组 `key_share` 的完整握手已修**：这道缝原来只收**一把**外部交换（引擎也只交出
  `key_share` 里的第一把），于是服务器选中另一个**我们声明过**的组就死
  （`WrongGroupForKeyShare`）。现在 `key_exchanges` 是一张表，按服务器选中的组（混合组按
  经典分量）挑对应那把，并把 `kx_state` 校正成实际用到的组。判据是本地服务端：
  只认 P-384 而客户端第二项才是 P-384 ⇒ **直接**谈成（`Full` 而非 `FullWithHelloRetryRequest`），
  外加一条「只发 X25519 ⇒ 被要求 HRR」的对照，证明前者确实意味着服务端用了我们发的共享密钥。

## 对账抓到、并已修掉的四处编码错

前两处**不会让任何 JA3 对账变红** —— 因为 JA3 只覆盖扩展**类型**，不覆盖**体长**。
是「逐扩展体长 + 总长集合」这条更细的对账把它们逼出来的。它们的形状值得记住：

1. **`status_request` 的体少了一个 u16**（写了三个字节，该五个）—— 每个报 OCSP 的预设都少两字节。
2. **第二个 GREASE 扩展的体应为 `[0]`**，我们给两个都写了空体 —— 少一字节。
   规则在 uTLS `u_parrots.go` 的 `ApplyPreset` 里：第 1 个空、第 2 个 `[0]`、第 3 个报错。
3. **ALPS 的体多算了一个 u16** —— 那两字节是**扩展自己的长度字段**，由编码器提供，
   我们又在体里算了一遍。每个用 ALPS 的预设有都多两字节。
4. **SNI 的「空」与「IP 字面量」都是零字节扩展，而不是错误或空体**（由 uTLS 自带录音抓到）。
   uTLS 的 `hostnameInSNI()` 在名字为空、或为 IP 字面量时返回空串，`SNIExtension.Len()` 随之返回 0 ⇒
   **线上零字节、但槽位仍留在列表里参与洗牌抽取**。我们原先两处都错：
   `sni = None` 直接报错（`SpecError::MissingServerName`）、`sni = Some("")` 发出 4 字节空体。
   修法与判据见下一节与 `crates/utls/src/hello/encode.rs` 的 `hostname_in_sni`。

教训不是「仔细点」，而是：**一条只覆盖部分的判据会把不覆盖的那部分变成盲区**。
JA3 是最常用的指纹对账方式，而它对体长完全无感 —— 所以「JA3 全绿」从来不是保真的证据。
第 4 处更狠：它连**体长**对账都躲得过去（多出的那 4 字节会被 `BoringPaddingStyle` 的填充
吃掉，总长照样落在观测集合里），只有**上游自己录下的字节**才抓得到它。

## 外部判据之二：uTLS 自带的 `testdata/` 录音

`crates/utls/tests/utls_testdata.rs` —— 拿上游仓库 `testdata/` 里的 ClientHello 录音判我们。
它与 `utls_conformance.rs` 的分工是**权威不同**：那边判据是我写的 Go 参照生成器
（它只调用了 uTLS 的一部分公开 API），这边是 uTLS **测试套件自己录下的完整连接输出**，
会经过 `ApplyConfig` / `SetTLSVers` / `SetClientRandom` / `RemoveSNIExtension` 这些
只有走一遍握手才碰得到的步骤 —— 第 4 处编码错就是这么抓到的。

- 夹具出处、格式（Go 的转储每行**两组 8 字节**，只读前一组会丢一半）、对账口径、
  以及 16 条跳过的**逐条理由**：`crates/utls/tests/fixtures/utls-testdata/README.md`。
- 同一份录音里还内联着一条**真实世界捕获**（真浏览器发往 `people-pa.clients6.google.com`
  的握手）：反解再重发必须逐字节相同 —— 那是唯一一条输入形状不是我们自己造的测试。
- 「跳过」全部带理由并打印（`-- --nocapture`）：安静的跳过看起来像通过。

本节数字不写死：条数由测试自己的遍历与断言守着（「比过的必须占多数」「每一类都必须还有」），
而不是由一个会漂的魔法数守着。

## 指纹值的写法

正文里**只写键名引用**（形如 `[[fp_<预设>_<算法>]]`），不写哈希本身。两条理由：
手抄的数字从写下那刻开始腐烂；而陈旧断言闸门的「出处」判据把 **sha / hash / 校验 / 指纹**
当敏感词，正文里的哈希一律要求有出处 —— 直接引用台账键最省事，也永远不会过期。

## 配置：为什么本仓一个旋钮都没改

机制与名字是分开的，本仓**沿用全部默认名字**（`FACTS.json` / `STATE.md` / `retractions.json` /
`questions/`），所以不需要任何环境变量。两个旋钮刻意留空：

- `REFLECT_RETIRED`（退役名）**未配置** —— 本仓还没有任何「用过又退役」的组件，
  配一个空名单等于假装查过。闸门会**明说本条未启用**，这比一个安静的绿更诚实。
- `REFLECT_HISTORY_SECS`（append-only 历史章节）为空 —— 本仓还没有历史章节。
  第一次把某节标记为「当时如此」时再配，不要提前豁免。

## 已知缺口（写明的，不是忘掉的）

- 悬案闸门对 `Settling:` 的路径存在性**只查第一个词**（当它像路径时）。所以
  「跑一下 scripts/missing.sh」这种把路径藏在句子中间的写法查不出来。这是上游标定过的
  已知限制，理由是：**会误报的严判据最后会被人一律 `--accept` 掉，那比有缺口更糟。**
  宁可留一个写明的缺口，不要一个会误报的判据。
- 机器块由 pre-commit 重渲染，但产物可能在提交之后又变；pre-push 用 `--check` 拒推不新鲜的块
  （**不自动改文件、不动历史**）。
- ⚠️ **pre-commit 只重渲染，不重新测量** —— 所以事实会在没人手动跑 `zreflect/facts.py`
  的情况下静默过期，而 pre-commit / pre-push / 四个闸门在那个状态下**全是绿的**（本仓实测）。
  这是上游的机制缺口，详情与复跑方式见 `docs/upstream-issues-zcode-reflect.md` 第 3 条。
  本仓的应对：把 `facts.py`（无参数）当作与 `render-doc` 不同的一条命令，改动能影响事实时手动跑它。

## 下一步

按「离『跑通 uTLS 原版测试』的距离」排序，而不是按喜好：

1. **判据全绿，且没有一条靠跳过**：指纹层、预设对账（39 夹具逐字节）、随机化族、
   HRR / 会话复用 / Roller / 多组 key_share、**真实 ECH**（三族服务器都接受）——
   `cargo test --workspace` 全绿 + clippy 0 警告。
2. **原版 `go test` 全量（无 `-skip`）通过**：干净检出上
   `go test -count=1 -timeout 480s ./...` ⇒ `ok`，**222 PASS / 0 FAIL / 1 SKIP**
   （那条 SKIP 是上游自己跳的）。那两条要真外网的测试现在只有**一条**推荐路径：
   **无代理** —— 只换它们拨号的目标域名（`www.baidu.com`，判据等价：证书 SAN 与自身
   主机名一致 + 支持 TLS 1.3 票据），`go -overlay` 构建期替换，上游树磁盘不动
   （`sh crates/utls/tests/fixtures/gen-reference/run-upstream-suite.sh <参照树>`）。
   **经代理跑未改动树的配方已退役**（转发器已删，历史见 `questions/09-*.md`；
   那次「本机不可达」的误判记为 `R-005`）。
3. **悬案清零**：`questions/` 10 条**全部结案**（未结案 0）。本轮结掉的三条：
   04（两道守卫在真实台账上 rc=2 且拒绝写盘）、
   05（新增第 5 个闸门 `zreflect/check_cmds.py`：321 条 `cmd` 全部产出记录值）、
   06（BoringSSL 源码证实 GREASE-ECH 载荷**也是四选一随机** ⇒ uTLS 保真、预设不动）。

- **引擎那条路现在覆盖 40 档里的 39 档**（复跑：`cargo run --release --example plan-cost`
  会打能建的与被拒的两份名单，被拒的带原因）。唯一被拒的是 `HelloCustom` = 空 spec，
  理由是「没有密码套件」—— 空 spec 不是合法的 ClientHello。
  两处曾经发不出去的形态已在 `docs/` 的两个新测试里钉住：
  - **TLS 1.2 时代的老预设**（8 档：Chrome 58/62、Firefox 55/56、Ios 11/12、Android 11、
    360 7）：没有 `key_share` ⇒ 引擎允许「零交换」的 plan，fork 也不再背着调用方造一个。
    判据在 `crates/utls-engine/tests/tls12_presets.rs`：**7 档真谈成 `TLSv1_2`**；
    第 8 档 `360_7` 与服务端的 TLS 1.2 套件**交集为 0**（它 20 个套件全是 CBC/RC4/3DES），
    于是服务端回 `HandshakeFailure` —— 那是密码套件的性质，不是引擎的缺陷（Go/uTLS 默认也不实现那些）。
    ⚠️ 用这一档时 **config 的版本范围要设成 1.2**，否则降级哨兵会被判成降级攻击。
  - **PQ 预设**（3 档：ChromePq 115/120、ChromePsk 115）：`X25519Kyber768Draft00` 是草案组，
    提供者没有它 ⇒ 引擎给**长度正确**的占位公钥（形状与 Chrome 一致），真交换只交 X25519。
    判据在 `crates/utls-engine/tests/pq_key_share.rs`：形状（草案组 1216 字节 + 总长对台账）、
    真握手（服务端只认 X25519 时 `Full`）、以及「不声称能完成草案组」。
    **与 uTLS 的语义差异**：uTLS 自己实现了那个草案组，我们只能在 X25519 上完成；
    服务器若认它并选中它，会**响亮失败**而不是静默换组。
  - **密钥交换组：会被真实预设发出去的每一个组都有正向结论**。服务端把 `kx_groups`
    滤成只认那一个组 ⇒ 「谈成了」本身就等于「用的是它」。P-256 三条在
    `crates/utls-engine/tests/p256_handshake.rs`、混合组 `X25519MLKEM768(4588)` 三条在
    `crates/utls-engine/tests/mixed_group_handshake.rs`；两种情形都覆盖（第一飞被选中、
    `key_share` 里只给它一把、服务端强要它时的 HRR 第二飞带**新的**共享 1216 字节）。

## 上游 issue 草稿

`docs/upstream-issues-zcode-reflect.md` —— 接入本系统时实测出的三条**上游**机制缺口。
`gh` token 失效（GraphQL 端点 401），等修好后提。本仓相关的规避已经落地，
所以那三条是上游的待办，不是本仓的。

<!-- AUTO:FACTS -->
> 本区块由 `zreflect/facts.py --render-doc` 从 `FACTS.json` 渲染，**不要手改**（pre-commit 会重算并 `git add`）。
> 正文里的「测出来的数字」只在这里生产：要引用就写 `[[键名]]`，不要手抄数字。

| 键 | 值 | 复跑命令 |
|---|---|---|
| `cargo_version` | **cargo 1.98.1 (797e8a9bc 2026-08-05)** | `cargo --version` |
| `fork_patch_files` | **9** | `grep -c '^diff --git' crates/rustls-fork/patch.diff` |
| `fork_patch_hunks` | **39** | `grep -c '^@@' crates/rustls-fork/patch.diff` |
| `fork_patch_matches_markers` | **yes** | `[ "$(grep -c '^diff --git' crates/rustls-fork/patch.diff)" = "$(grep -rl 'FORK(utls-rs)' crates/rustls/src --include='*.rs' | wc -l)" ] && echo yes || echo NO` |
| `fork_patch_minus` | **39** | `grep '^-' crates/rustls-fork/patch.diff | grep -vc '^---'` |
| `fork_patch_plus` | **1383** | `grep '^+' crates/rustls-fork/patch.diff | grep -vc '^+++'` |
| `fork_rs_files` | **111** | `find crates/rustls -name '*.rs' | wc -l` |
| `fork_rs_lines` | **49942** | `find crates/rustls -name '*.rs' -exec cat {} + | wc -l` |
| `fork_rs_modified` | **9** | `grep -rc 'FORK(utls-rs)' crates/rustls/src --include='*.rs' | grep -v ':0' | wc -l` |
| `fp_360_11_cipher_count` | **16** | `cargo run --quiet --example reflect-facts | grep '^360_11_cipher_count='` |
| `fp_360_11_ext_count` | **16** | `cargo run --quiet --example reflect-facts | grep '^360_11_ext_count='` |
| `fp_360_11_hello_len` | **512** | `cargo run --quiet --example reflect-facts | grep '^360_11_hello_len='` |
| `fp_360_11_ja3_md5` | **2b3a40903395f08c297cd63b9734cb75** | `cargo run --quiet --example reflect-facts | grep '^360_11_ja3_md5='` |
| `fp_360_11_ja3_stable` | **yes** | `cargo run --quiet --example reflect-facts | grep '^360_11_ja3_stable='` |
| `fp_360_11_ja3_text` | **771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53-10,0-23-65281-10-11-35-16-5-13-18-30032-51-45-43-27-21,29-23-24,0** | `cargo run --quiet --example reflect-facts | grep '^360_11_ja3_text='` |
| `fp_360_11_len_stable` | **yes** | `cargo run --quiet --example reflect-facts | grep '^360_11_len_stable='` |
| `fp_360_7_cipher_count` | **20** | `cargo run --quiet --example reflect-facts | grep '^360_7_cipher_count='` |
| `fp_360_7_ext_count` | **10** | `cargo run --quiet --example reflect-facts | grep '^360_7_ext_count='` |
| `fp_360_7_hello_len` | **241** | `cargo run --quiet --example reflect-facts | grep '^360_7_hello_len='` |
| `fp_360_7_ja3_md5` | **c405bbbe31c0e53ac4c8448355b2af5b** | `cargo run --quiet --example reflect-facts | grep '^360_7_ja3_md5='` |
| `fp_360_7_ja3_stable` | **yes** | `cargo run --quiet --example reflect-facts | grep '^360_7_ja3_stable='` |
| `fp_360_7_ja3_text` | **771,49162-49172-57-107-53-61-49159-49161-49187-49169-49171-49191-51-103-50-5-4-47-60-10,0-65281-10-11-35-13172-16-30031-5-13,23-24-25,0** | `cargo run --quiet --example reflect-facts | grep '^360_7_ja3_text='` |
| `fp_360_7_len_stable` | **yes** | `cargo run --quiet --example reflect-facts | grep '^360_7_len_stable='` |
| `fp_android_11_cipher_count` | **12** | `cargo run --quiet --example reflect-facts | grep '^android_11_cipher_count='` |
| `fp_android_11_ext_count` | **7** | `cargo run --quiet --example reflect-facts | grep '^android_11_ext_count='` |
| `fp_android_11_hello_len` | **181** | `cargo run --quiet --example reflect-facts | grep '^android_11_hello_len='` |
| `fp_android_11_ja3_md5` | **6c0f0a346dcd84cb4b97a0d9382c53fd** | `cargo run --quiet --example reflect-facts | grep '^android_11_ja3_md5='` |
| `fp_android_11_ja3_stable` | **yes** | `cargo run --quiet --example reflect-facts | grep '^android_11_ja3_stable='` |
| `fp_android_11_ja3_text` | **771,49195-49196-52393-49199-49200-52392-49171-49172-156-157-47-53,0-23-65281-10-11-5-13,29-23-24,0** | `cargo run --quiet --example reflect-facts | grep '^android_11_ja3_text='` |
| `fp_android_11_len_stable` | **yes** | `cargo run --quiet --example reflect-facts | grep '^android_11_len_stable='` |
| `fp_chrome_100_cipher_count` | **15** | `cargo run --quiet --example reflect-facts | grep '^chrome_100_cipher_count='` |
| `fp_chrome_100_ext_count` | **16** | `cargo run --quiet --example reflect-facts | grep '^chrome_100_ext_count='` |
| `fp_chrome_100_hello_len` | **512** | `cargo run --quiet --example reflect-facts | grep '^chrome_100_hello_len='` |
| `fp_chrome_100_ja3_md5` | **cd08e31494f9531f560d64c695473da9** | `cargo run --quiet --example reflect-facts | grep '^chrome_100_ja3_md5='` |
| `fp_chrome_100_ja3_stable` | **yes** | `cargo run --quiet --example reflect-facts | grep '^chrome_100_ja3_stable='` |
| `fp_chrome_100_ja3_text` | **771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0** | `cargo run --quiet --example reflect-facts | grep '^chrome_100_ja3_text='` |
| `fp_chrome_100_len_stable` | **yes** | `cargo run --quiet --example reflect-facts | grep '^chrome_100_len_stable='` |
| `fp_chrome_100_psk_cipher_count` | **15** | `cargo run --quiet --example reflect-facts | grep '^chrome_100_psk_cipher_count='` |
| `fp_chrome_100_psk_ext_count` | **15** | `cargo run --quiet --example reflect-facts | grep '^chrome_100_psk_ext_count='` |
| `fp_chrome_100_psk_hello_len` | **304** | `cargo run --quiet --example reflect-facts | grep '^chrome_100_psk_hello_len='` |
| `fp_chrome_100_psk_ja3_md5` | **e1d8b04eeb8ef3954ec4f49267a783ef** | `cargo run --quiet --example reflect-facts | grep '^chrome_100_psk_ja3_md5='` |
| `fp_chrome_100_psk_ja3_stable` | **yes** | `cargo run --quiet --example reflect-facts | grep '^chrome_100_psk_ja3_stable='` |
| `fp_chrome_100_psk_ja3_text` | **771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513,29-23-24,0** | `cargo run --quiet --example reflect-facts | grep '^chrome_100_psk_ja3_text='` |
| `fp_chrome_100_psk_len_stable` | **yes** | `cargo run --quiet --example reflect-facts | grep '^chrome_100_psk_len_stable='` |
| `fp_chrome_102_cipher_count` | **15** | `cargo run --quiet --example reflect-facts | grep '^chrome_102_cipher_count='` |
| `fp_chrome_102_ext_count` | **16** | `cargo run --quiet --example reflect-facts | grep '^chrome_102_ext_count='` |
| `fp_chrome_102_hello_len` | **512** | `cargo run --quiet --example reflect-facts | grep '^chrome_102_hello_len='` |
| `fp_chrome_102_ja3_md5` | **cd08e31494f9531f560d64c695473da9** | `cargo run --quiet --example reflect-facts | grep '^chrome_102_ja3_md5='` |
| `fp_chrome_102_ja3_stable` | **yes** | `cargo run --quiet --example reflect-facts | grep '^chrome_102_ja3_stable='` |
| `fp_chrome_102_ja3_text` | **771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0** | `cargo run --quiet --example reflect-facts | grep '^chrome_102_ja3_text='` |
| `fp_chrome_102_len_stable` | **yes** | `cargo run --quiet --example reflect-facts | grep '^chrome_102_len_stable='` |
| `fp_chrome_106_cipher_count` | **15** | `cargo run --quiet --example reflect-facts | grep '^chrome_106_cipher_count='` |
| `fp_chrome_106_ext_count` | **16** | `cargo run --quiet --example reflect-facts | grep '^chrome_106_ext_count='` |
| `fp_chrome_106_hello_len` | **512** | `cargo run --quiet --example reflect-facts | grep '^chrome_106_hello_len='` |
| `fp_chrome_106_ja3_md5` | **def317a12dc7ed05a1b27f43af514602** | `cargo run --quiet --example reflect-facts | grep '^chrome_106_ja3_md5='` |
| `fp_chrome_106_ja3_stable` | **no** | `cargo run --quiet --example reflect-facts | grep '^chrome_106_ja3_stable='` |
| `fp_chrome_106_ja3_text` | **771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,17513-5-11-16-10-43-27-51-13-23-65281-45-35-18-0-21,29-23-24,0** | `cargo run --quiet --example reflect-facts | grep '^chrome_106_ja3_text='` |
| `fp_chrome_106_len_stable` | **yes** | `cargo run --quiet --example reflect-facts | grep '^chrome_106_len_stable='` |
| `fp_chrome_112_psk_cipher_count` | **15** | `cargo run --quiet --example reflect-facts | grep '^chrome_112_psk_cipher_count='` |
| `fp_chrome_112_psk_ext_count` | **15** | `cargo run --quiet --example reflect-facts | grep '^chrome_112_psk_ext_count='` |
| `fp_chrome_112_psk_hello_len` | **304** | `cargo run --quiet --example reflect-facts | grep '^chrome_112_psk_hello_len='` |
| `fp_chrome_112_psk_ja3_md5` | **3f9ed491ea677a123655db3560fe9dc5** | `cargo run --quiet --example reflect-facts | grep '^chrome_112_psk_ja3_md5='` |
| `fp_chrome_112_psk_ja3_stable` | **no** | `cargo run --quiet --example reflect-facts | grep '^chrome_112_psk_ja3_stable='` |
| `fp_chrome_112_psk_ja3_text` | **771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,17513-5-11-16-10-43-27-51-13-23-65281-45-35-18-0,29-23-24,0** | `cargo run --quiet --example reflect-facts | grep '^chrome_112_psk_ja3_text='` |
| `fp_chrome_112_psk_len_stable` | **yes** | `cargo run --quiet --example reflect-facts | grep '^chrome_112_psk_len_stable='` |
| `fp_chrome_114_psk_cipher_count` | **15** | `cargo run --quiet --example reflect-facts | grep '^chrome_114_psk_cipher_count='` |
| `fp_chrome_114_psk_ext_count` | **16** | `cargo run --quiet --example reflect-facts | grep '^chrome_114_psk_ext_count='` |
| `fp_chrome_114_psk_hello_len` | **512** | `cargo run --quiet --example reflect-facts | grep '^chrome_114_psk_hello_len='` |
| `fp_chrome_114_psk_ja3_md5` | **6d720efbfea20c5396c1e146b3686ae4** | `cargo run --quiet --example reflect-facts | grep '^chrome_114_psk_ja3_md5='` |
| `fp_chrome_114_psk_ja3_stable` | **no** | `cargo run --quiet --example reflect-facts | grep '^chrome_114_psk_ja3_stable='` |
| `fp_chrome_114_psk_ja3_text` | **771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,13-23-35-65281-11-27-45-0-5-17513-16-10-43-18-51-21,29-23-24,0** | `cargo run --quiet --example reflect-facts | grep '^chrome_114_psk_ja3_text='` |
| `fp_chrome_114_psk_len_stable` | **yes** | `cargo run --quiet --example reflect-facts | grep '^chrome_114_psk_len_stable='` |
| `fp_chrome_115_pq_cipher_count` | **15** | `cargo run --quiet --example reflect-facts | grep '^chrome_115_pq_cipher_count='` |
| `fp_chrome_115_pq_ext_count` | **15** | `cargo run --quiet --example reflect-facts | grep '^chrome_115_pq_ext_count='` |
| `fp_chrome_115_pq_hello_len` | **1526** | `cargo run --quiet --example reflect-facts | grep '^chrome_115_pq_hello_len='` |
| `fp_chrome_115_pq_ja3_md5` | **0e56ea8d7576172d3325596634e6c05f** | `cargo run --quiet --example reflect-facts | grep '^chrome_115_pq_ja3_md5='` |
| `fp_chrome_115_pq_ja3_stable` | **no** | `cargo run --quiet --example reflect-facts | grep '^chrome_115_pq_ja3_stable='` |
| `fp_chrome_115_pq_ja3_text` | **771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,17513-5-11-16-10-43-27-51-13-23-65281-45-35-18-0,25497-29-23-24,0** | `cargo run --quiet --example reflect-facts | grep '^chrome_115_pq_ja3_text='` |
| `fp_chrome_115_pq_len_stable` | **yes** | `cargo run --quiet --example reflect-facts | grep '^chrome_115_pq_len_stable='` |
| `fp_chrome_115_psk_cipher_count` | **15** | `cargo run --quiet --example reflect-facts | grep '^chrome_115_psk_cipher_count='` |
| `fp_chrome_115_psk_ext_count` | **15** | `cargo run --quiet --example reflect-facts | grep '^chrome_115_psk_ext_count='` |
| `fp_chrome_115_psk_hello_len` | **1526** | `cargo run --quiet --example reflect-facts | grep '^chrome_115_psk_hello_len='` |
| `fp_chrome_115_psk_ja3_md5` | **8813703eeb522d2179bea34fb7b29c05** | `cargo run --quiet --example reflect-facts | grep '^chrome_115_psk_ja3_md5='` |
| `fp_chrome_115_psk_ja3_stable` | **no** | `cargo run --quiet --example reflect-facts | grep '^chrome_115_psk_ja3_stable='` |
| `fp_chrome_115_psk_ja3_text` | **771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,13-23-35-65281-11-27-45-0-5-17513-16-10-43-18-51,25497-29-23-24,0** | `cargo run --quiet --example reflect-facts | grep '^chrome_115_psk_ja3_text='` |
| `fp_chrome_115_psk_len_stable` | **yes** | `cargo run --quiet --example reflect-facts | grep '^chrome_115_psk_len_stable='` |
| `fp_chrome_120_cipher_count` | **15** | `cargo run --quiet --example reflect-facts | grep '^chrome_120_cipher_count='` |
| `fp_chrome_120_ext_count` | **16** | `cargo run --quiet --example reflect-facts | grep '^chrome_120_ext_count='` |
| `fp_chrome_120_hello_len` | **558** | `cargo run --quiet --example reflect-facts | grep '^chrome_120_hello_len='` |
| `fp_chrome_120_ja3_md5` | **4e9f1c0a7ee4ceec80faed41334e1dcf** | `cargo run --quiet --example reflect-facts | grep '^chrome_120_ja3_md5='` |
| `fp_chrome_120_ja3_stable` | **no** | `cargo run --quiet --example reflect-facts | grep '^chrome_120_ja3_stable='` |
| `fp_chrome_120_ja3_text` | **771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,43-18-5-10-0-45-16-13-27-11-51-17513-23-65281-35-65037,29-23-24,0** | `cargo run --quiet --example reflect-facts | grep '^chrome_120_ja3_text='` |
| `fp_chrome_120_len_stable` | **NO** | `cargo run --quiet --example reflect-facts | grep '^chrome_120_len_stable='` |
| `fp_chrome_120_pq_cipher_count` | **15** | `cargo run --quiet --example reflect-facts | grep '^chrome_120_pq_cipher_count='` |
| `fp_chrome_120_pq_ext_count` | **16** | `cargo run --quiet --example reflect-facts | grep '^chrome_120_pq_ext_count='` |
| `fp_chrome_120_pq_hello_len` | **1780** | `cargo run --quiet --example reflect-facts | grep '^chrome_120_pq_hello_len='` |
| `fp_chrome_120_pq_ja3_md5` | **c99b8581a3e59b0bae7aef14a6e5e3bf** | `cargo run --quiet --example reflect-facts | grep '^chrome_120_pq_ja3_md5='` |
| `fp_chrome_120_pq_ja3_stable` | **no** | `cargo run --quiet --example reflect-facts | grep '^chrome_120_pq_ja3_stable='` |
| `fp_chrome_120_pq_ja3_text` | **771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,10-13-23-45-65037-35-17513-51-27-11-18-16-0-65281-5-43,25497-29-23-24,0** | `cargo run --quiet --example reflect-facts | grep '^chrome_120_pq_ja3_text='` |
| `fp_chrome_120_pq_len_stable` | **NO** | `cargo run --quiet --example reflect-facts | grep '^chrome_120_pq_len_stable='` |
| `fp_chrome_131_cipher_count` | **15** | `cargo run --quiet --example reflect-facts | grep '^chrome_131_cipher_count='` |
| `fp_chrome_131_ext_count` | **16** | `cargo run --quiet --example reflect-facts | grep '^chrome_131_ext_count='` |
| `fp_chrome_131_hello_len` | **1780** | `cargo run --quiet --example reflect-facts | grep '^chrome_131_hello_len='` |
| `fp_chrome_131_ja3_md5` | **8e494a6419f08a68d438dc930b4f951b** | `cargo run --quiet --example reflect-facts | grep '^chrome_131_ja3_md5='` |
| `fp_chrome_131_ja3_stable` | **no** | `cargo run --quiet --example reflect-facts | grep '^chrome_131_ja3_stable='` |
| `fp_chrome_131_ja3_text` | **771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,10-13-23-45-65037-35-17513-51-27-11-18-16-0-65281-5-43,4588-29-23-24,0** | `cargo run --quiet --example reflect-facts | grep '^chrome_131_ja3_text='` |
| `fp_chrome_131_len_stable` | **NO** | `cargo run --quiet --example reflect-facts | grep '^chrome_131_len_stable='` |
| `fp_chrome_133_cipher_count` | **15** | `cargo run --quiet --example reflect-facts | grep '^chrome_133_cipher_count='` |
| `fp_chrome_133_ext_count` | **16** | `cargo run --quiet --example reflect-facts | grep '^chrome_133_ext_count='` |
| `fp_chrome_133_hello_len` | **1780** | `cargo run --quiet --example reflect-facts | grep '^chrome_133_hello_len='` |
| `fp_chrome_133_ja3_md5` | **41a1630b19c58de694b977cc0d783dd7** | `cargo run --quiet --example reflect-facts | grep '^chrome_133_ja3_md5='` |
| `fp_chrome_133_ja3_stable` | **no** | `cargo run --quiet --example reflect-facts | grep '^chrome_133_ja3_stable='` |
| `fp_chrome_133_ja3_text` | **771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,10-13-23-45-65037-35-17613-51-27-11-18-16-0-65281-5-43,4588-29-23-24,0** | `cargo run --quiet --example reflect-facts | grep '^chrome_133_ja3_text='` |
| `fp_chrome_133_len_stable` | **NO** | `cargo run --quiet --example reflect-facts | grep '^chrome_133_len_stable='` |
| `fp_chrome_58_cipher_count` | **13** | `cargo run --quiet --example reflect-facts | grep '^chrome_58_cipher_count='` |
| `fp_chrome_58_ext_count` | **11** | `cargo run --quiet --example reflect-facts | grep '^chrome_58_ext_count='` |
| `fp_chrome_58_hello_len` | **226** | `cargo run --quiet --example reflect-facts | grep '^chrome_58_hello_len='` |
| `fp_chrome_58_ja3_md5` | **94c485bca29d5392be53f2b8cf7f4304** | `cargo run --quiet --example reflect-facts | grep '^chrome_58_ja3_md5='` |
| `fp_chrome_58_ja3_stable` | **yes** | `cargo run --quiet --example reflect-facts | grep '^chrome_58_ja3_stable='` |
| `fp_chrome_58_ja3_text` | **771,49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53-10,65281-0-23-35-13-5-18-16-30032-11-10,29-23-24,0** | `cargo run --quiet --example reflect-facts | grep '^chrome_58_ja3_text='` |
| `fp_chrome_58_len_stable` | **yes** | `cargo run --quiet --example reflect-facts | grep '^chrome_58_len_stable='` |
| `fp_chrome_62_cipher_count` | **13** | `cargo run --quiet --example reflect-facts | grep '^chrome_62_cipher_count='` |
| `fp_chrome_62_ext_count` | **11** | `cargo run --quiet --example reflect-facts | grep '^chrome_62_ext_count='` |
| `fp_chrome_62_hello_len` | **226** | `cargo run --quiet --example reflect-facts | grep '^chrome_62_hello_len='` |
| `fp_chrome_62_ja3_md5` | **94c485bca29d5392be53f2b8cf7f4304** | `cargo run --quiet --example reflect-facts | grep '^chrome_62_ja3_md5='` |
| `fp_chrome_62_ja3_stable` | **yes** | `cargo run --quiet --example reflect-facts | grep '^chrome_62_ja3_stable='` |
| `fp_chrome_62_ja3_text` | **771,49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53-10,65281-0-23-35-13-5-18-16-30032-11-10,29-23-24,0** | `cargo run --quiet --example reflect-facts | grep '^chrome_62_ja3_text='` |
| `fp_chrome_62_len_stable` | **yes** | `cargo run --quiet --example reflect-facts | grep '^chrome_62_len_stable='` |
| `fp_chrome_70_cipher_count` | **16** | `cargo run --quiet --example reflect-facts | grep '^chrome_70_cipher_count='` |
| `fp_chrome_70_ext_count` | **16** | `cargo run --quiet --example reflect-facts | grep '^chrome_70_ext_count='` |
| `fp_chrome_70_hello_len` | **512** | `cargo run --quiet --example reflect-facts | grep '^chrome_70_hello_len='` |
| `fp_chrome_70_ja3_md5` | **6a958df291c3f2ee216e80434750d4e1** | `cargo run --quiet --example reflect-facts | grep '^chrome_70_ja3_md5='` |
| `fp_chrome_70_ja3_stable` | **yes** | `cargo run --quiet --example reflect-facts | grep '^chrome_70_ja3_stable='` |
| `fp_chrome_70_ja3_text` | **771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53-10,65281-0-23-35-13-5-18-16-30032-11-51-45-43-10-27-21,29-23-24,0** | `cargo run --quiet --example reflect-facts | grep '^chrome_70_ja3_text='` |
| `fp_chrome_70_len_stable` | **yes** | `cargo run --quiet --example reflect-facts | grep '^chrome_70_len_stable='` |
| `fp_chrome_72_cipher_count` | **16** | `cargo run --quiet --example reflect-facts | grep '^chrome_72_cipher_count='` |
| `fp_chrome_72_ext_count` | **15** | `cargo run --quiet --example reflect-facts | grep '^chrome_72_ext_count='` |
| `fp_chrome_72_hello_len` | **512** | `cargo run --quiet --example reflect-facts | grep '^chrome_72_hello_len='` |
| `fp_chrome_72_ja3_md5` | **66918128f1b9b03303d77c6f2eefd128** | `cargo run --quiet --example reflect-facts | grep '^chrome_72_ja3_md5='` |
| `fp_chrome_72_ja3_stable` | **yes** | `cargo run --quiet --example reflect-facts | grep '^chrome_72_ja3_stable='` |
| `fp_chrome_72_ja3_text` | **771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53-10,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,29-23-24,0** | `cargo run --quiet --example reflect-facts | grep '^chrome_72_ja3_text='` |
| `fp_chrome_72_len_stable` | **yes** | `cargo run --quiet --example reflect-facts | grep '^chrome_72_len_stable='` |
| `fp_chrome_83_cipher_count` | **15** | `cargo run --quiet --example reflect-facts | grep '^chrome_83_cipher_count='` |
| `fp_chrome_83_ext_count` | **15** | `cargo run --quiet --example reflect-facts | grep '^chrome_83_ext_count='` |
| `fp_chrome_83_hello_len` | **512** | `cargo run --quiet --example reflect-facts | grep '^chrome_83_hello_len='` |
| `fp_chrome_83_ja3_md5` | **b32309a26951912be7dba376398abc3b** | `cargo run --quiet --example reflect-facts | grep '^chrome_83_ja3_md5='` |
| `fp_chrome_83_ja3_stable` | **yes** | `cargo run --quiet --example reflect-facts | grep '^chrome_83_ja3_stable='` |
| `fp_chrome_83_ja3_text` | **771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,29-23-24,0** | `cargo run --quiet --example reflect-facts | grep '^chrome_83_ja3_text='` |
| `fp_chrome_83_len_stable` | **yes** | `cargo run --quiet --example reflect-facts | grep '^chrome_83_len_stable='` |
| `fp_chrome_87_cipher_count` | **15** | `cargo run --quiet --example reflect-facts | grep '^chrome_87_cipher_count='` |
| `fp_chrome_87_ext_count` | **15** | `cargo run --quiet --example reflect-facts | grep '^chrome_87_ext_count='` |
| `fp_chrome_87_hello_len` | **512** | `cargo run --quiet --example reflect-facts | grep '^chrome_87_hello_len='` |
| `fp_chrome_87_ja3_md5` | **b32309a26951912be7dba376398abc3b** | `cargo run --quiet --example reflect-facts | grep '^chrome_87_ja3_md5='` |
| `fp_chrome_87_ja3_stable` | **yes** | `cargo run --quiet --example reflect-facts | grep '^chrome_87_ja3_stable='` |
| `fp_chrome_87_ja3_text` | **771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,29-23-24,0** | `cargo run --quiet --example reflect-facts | grep '^chrome_87_ja3_text='` |
| `fp_chrome_87_len_stable` | **yes** | `cargo run --quiet --example reflect-facts | grep '^chrome_87_len_stable='` |
| `fp_chrome_96_cipher_count` | **15** | `cargo run --quiet --example reflect-facts | grep '^chrome_96_cipher_count='` |
| `fp_chrome_96_ext_count` | **16** | `cargo run --quiet --example reflect-facts | grep '^chrome_96_ext_count='` |
| `fp_chrome_96_hello_len` | **512** | `cargo run --quiet --example reflect-facts | grep '^chrome_96_hello_len='` |
| `fp_chrome_96_ja3_md5` | **cd08e31494f9531f560d64c695473da9** | `cargo run --quiet --example reflect-facts | grep '^chrome_96_ja3_md5='` |
| `fp_chrome_96_ja3_stable` | **yes** | `cargo run --quiet --example reflect-facts | grep '^chrome_96_ja3_stable='` |
| `fp_chrome_96_ja3_text` | **771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0** | `cargo run --quiet --example reflect-facts | grep '^chrome_96_ja3_text='` |
| `fp_chrome_96_len_stable` | **yes** | `cargo run --quiet --example reflect-facts | grep '^chrome_96_len_stable='` |
| `fp_edge_106_cipher_count` | **15** | `cargo run --quiet --example reflect-facts | grep '^edge_106_cipher_count='` |
| `fp_edge_106_ext_count` | **16** | `cargo run --quiet --example reflect-facts | grep '^edge_106_ext_count='` |
| `fp_edge_106_hello_len` | **512** | `cargo run --quiet --example reflect-facts | grep '^edge_106_hello_len='` |
| `fp_edge_106_ja3_md5` | **cd08e31494f9531f560d64c695473da9** | `cargo run --quiet --example reflect-facts | grep '^edge_106_ja3_md5='` |
| `fp_edge_106_ja3_stable` | **yes** | `cargo run --quiet --example reflect-facts | grep '^edge_106_ja3_stable='` |
| `fp_edge_106_ja3_text` | **771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0** | `cargo run --quiet --example reflect-facts | grep '^edge_106_ja3_text='` |
| `fp_edge_106_len_stable` | **yes** | `cargo run --quiet --example reflect-facts | grep '^edge_106_len_stable='` |
| `fp_edge_85_cipher_count` | **15** | `cargo run --quiet --example reflect-facts | grep '^edge_85_cipher_count='` |
| `fp_edge_85_ext_count` | **15** | `cargo run --quiet --example reflect-facts | grep '^edge_85_ext_count='` |
| `fp_edge_85_hello_len` | **512** | `cargo run --quiet --example reflect-facts | grep '^edge_85_hello_len='` |
| `fp_edge_85_ja3_md5` | **b32309a26951912be7dba376398abc3b** | `cargo run --quiet --example reflect-facts | grep '^edge_85_ja3_md5='` |
| `fp_edge_85_ja3_stable` | **yes** | `cargo run --quiet --example reflect-facts | grep '^edge_85_ja3_stable='` |
| `fp_edge_85_ja3_text` | **771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,29-23-24,0** | `cargo run --quiet --example reflect-facts | grep '^edge_85_ja3_text='` |
| `fp_edge_85_len_stable` | **yes** | `cargo run --quiet --example reflect-facts | grep '^edge_85_len_stable='` |
| `fp_firefox_102_cipher_count` | **17** | `cargo run --quiet --example reflect-facts | grep '^firefox_102_cipher_count='` |
| `fp_firefox_102_ext_count` | **15** | `cargo run --quiet --example reflect-facts | grep '^firefox_102_ext_count='` |
| `fp_firefox_102_hello_len` | **512** | `cargo run --quiet --example reflect-facts | grep '^firefox_102_hello_len='` |
| `fp_firefox_102_ja3_md5` | **579ccef312d18482fc42e2b822ca2430** | `cargo run --quiet --example reflect-facts | grep '^firefox_102_ja3_md5='` |
| `fp_firefox_102_ja3_stable` | **yes** | `cargo run --quiet --example reflect-facts | grep '^firefox_102_ja3_stable='` |
| `fp_firefox_102_ja3_text` | **771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-34-51-43-13-45-28-21,29-23-24-25-256-257,0** | `cargo run --quiet --example reflect-facts | grep '^firefox_102_ja3_text='` |
| `fp_firefox_102_len_stable` | **yes** | `cargo run --quiet --example reflect-facts | grep '^firefox_102_len_stable='` |
| `fp_firefox_105_cipher_count` | **17** | `cargo run --quiet --example reflect-facts | grep '^firefox_105_cipher_count='` |
| `fp_firefox_105_ext_count` | **15** | `cargo run --quiet --example reflect-facts | grep '^firefox_105_ext_count='` |
| `fp_firefox_105_hello_len` | **512** | `cargo run --quiet --example reflect-facts | grep '^firefox_105_hello_len='` |
| `fp_firefox_105_ja3_md5` | **579ccef312d18482fc42e2b822ca2430** | `cargo run --quiet --example reflect-facts | grep '^firefox_105_ja3_md5='` |
| `fp_firefox_105_ja3_stable` | **yes** | `cargo run --quiet --example reflect-facts | grep '^firefox_105_ja3_stable='` |
| `fp_firefox_105_ja3_text` | **771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-34-51-43-13-45-28-21,29-23-24-25-256-257,0** | `cargo run --quiet --example reflect-facts | grep '^firefox_105_ja3_text='` |
| `fp_firefox_105_len_stable` | **yes** | `cargo run --quiet --example reflect-facts | grep '^firefox_105_len_stable='` |
| `fp_firefox_120_cipher_count` | **17** | `cargo run --quiet --example reflect-facts | grep '^firefox_120_cipher_count='` |
| `fp_firefox_120_ext_count` | **15** | `cargo run --quiet --example reflect-facts | grep '^firefox_120_ext_count='` |
| `fp_firefox_120_hello_len` | **654** | `cargo run --quiet --example reflect-facts | grep '^firefox_120_hello_len='` |
| `fp_firefox_120_ja3_md5` | **b5001237acdf006056b409cc433726b0** | `cargo run --quiet --example reflect-facts | grep '^firefox_120_ja3_md5='` |
| `fp_firefox_120_ja3_stable` | **yes** | `cargo run --quiet --example reflect-facts | grep '^firefox_120_ja3_stable='` |
| `fp_firefox_120_ja3_text` | **771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-34-51-43-13-45-28-65037,29-23-24-25-256-257,0** | `cargo run --quiet --example reflect-facts | grep '^firefox_120_ja3_text='` |
| `fp_firefox_120_len_stable` | **yes** | `cargo run --quiet --example reflect-facts | grep '^firefox_120_len_stable='` |
| `fp_firefox_148_cipher_count` | **17** | `cargo run --quiet --example reflect-facts | grep '^firefox_148_cipher_count='` |
| `fp_firefox_148_ext_count` | **15** | `cargo run --quiet --example reflect-facts | grep '^firefox_148_ext_count='` |
| `fp_firefox_148_hello_len` | **1881** | `cargo run --quiet --example reflect-facts | grep '^firefox_148_hello_len='` |
| `fp_firefox_148_ja3_md5` | **7704a11cf87dfcf33080b90ce11d5527** | `cargo run --quiet --example reflect-facts | grep '^firefox_148_ja3_md5='` |
| `fp_firefox_148_ja3_stable` | **yes** | `cargo run --quiet --example reflect-facts | grep '^firefox_148_ja3_stable='` |
| `fp_firefox_148_ja3_text` | **771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-16-5-34-18-51-43-13-28-27-65037,4588-29-23-24-25-256-257,0** | `cargo run --quiet --example reflect-facts | grep '^firefox_148_ja3_text='` |
| `fp_firefox_148_len_stable` | **yes** | `cargo run --quiet --example reflect-facts | grep '^firefox_148_len_stable='` |
| `fp_firefox_55_cipher_count` | **15** | `cargo run --quiet --example reflect-facts | grep '^firefox_55_cipher_count='` |
| `fp_firefox_55_ext_count` | **9** | `cargo run --quiet --example reflect-facts | grep '^firefox_55_ext_count='` |
| `fp_firefox_55_hello_len` | **215** | `cargo run --quiet --example reflect-facts | grep '^firefox_55_hello_len='` |
| `fp_firefox_55_ja3_md5` | **0ffee3ba8e615ad22535e7f771690a28** | `cargo run --quiet --example reflect-facts | grep '^firefox_55_ja3_md5='` |
| `fp_firefox_55_ja3_stable` | **yes** | `cargo run --quiet --example reflect-facts | grep '^firefox_55_ja3_stable='` |
| `fp_firefox_55_ja3_text` | **771,49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-51-57-47-53-10,0-23-65281-10-11-35-16-5-13,29-23-24-25,0** | `cargo run --quiet --example reflect-facts | grep '^firefox_55_ja3_text='` |
| `fp_firefox_55_len_stable` | **yes** | `cargo run --quiet --example reflect-facts | grep '^firefox_55_len_stable='` |
| `fp_firefox_56_cipher_count` | **15** | `cargo run --quiet --example reflect-facts | grep '^firefox_56_cipher_count='` |
| `fp_firefox_56_ext_count` | **9** | `cargo run --quiet --example reflect-facts | grep '^firefox_56_ext_count='` |
| `fp_firefox_56_hello_len` | **215** | `cargo run --quiet --example reflect-facts | grep '^firefox_56_hello_len='` |
| `fp_firefox_56_ja3_md5` | **0ffee3ba8e615ad22535e7f771690a28** | `cargo run --quiet --example reflect-facts | grep '^firefox_56_ja3_md5='` |
| `fp_firefox_56_ja3_stable` | **yes** | `cargo run --quiet --example reflect-facts | grep '^firefox_56_ja3_stable='` |
| `fp_firefox_56_ja3_text` | **771,49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-51-57-47-53-10,0-23-65281-10-11-35-16-5-13,29-23-24-25,0** | `cargo run --quiet --example reflect-facts | grep '^firefox_56_ja3_text='` |
| `fp_firefox_56_len_stable` | **yes** | `cargo run --quiet --example reflect-facts | grep '^firefox_56_len_stable='` |
| `fp_firefox_63_cipher_count` | **18** | `cargo run --quiet --example reflect-facts | grep '^firefox_63_cipher_count='` |
| `fp_firefox_63_ext_count` | **14** | `cargo run --quiet --example reflect-facts | grep '^firefox_63_ext_count='` |
| `fp_firefox_63_hello_len` | **512** | `cargo run --quiet --example reflect-facts | grep '^firefox_63_hello_len='` |
| `fp_firefox_63_ja3_md5` | **b20b44b18b853ef29ab773e921b03422** | `cargo run --quiet --example reflect-facts | grep '^firefox_63_ja3_md5='` |
| `fp_firefox_63_ja3_stable` | **yes** | `cargo run --quiet --example reflect-facts | grep '^firefox_63_ja3_stable='` |
| `fp_firefox_63_ja3_text` | **771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-51-57-47-53-10,0-23-65281-10-11-35-16-5-51-43-13-45-28-21,29-23-24-25-256-257,0** | `cargo run --quiet --example reflect-facts | grep '^firefox_63_ja3_text='` |
| `fp_firefox_63_len_stable` | **yes** | `cargo run --quiet --example reflect-facts | grep '^firefox_63_len_stable='` |
| `fp_firefox_65_cipher_count` | **18** | `cargo run --quiet --example reflect-facts | grep '^firefox_65_cipher_count='` |
| `fp_firefox_65_ext_count` | **14** | `cargo run --quiet --example reflect-facts | grep '^firefox_65_ext_count='` |
| `fp_firefox_65_hello_len` | **512** | `cargo run --quiet --example reflect-facts | grep '^firefox_65_hello_len='` |
| `fp_firefox_65_ja3_md5` | **b20b44b18b853ef29ab773e921b03422** | `cargo run --quiet --example reflect-facts | grep '^firefox_65_ja3_md5='` |
| `fp_firefox_65_ja3_stable` | **yes** | `cargo run --quiet --example reflect-facts | grep '^firefox_65_ja3_stable='` |
| `fp_firefox_65_ja3_text` | **771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-51-57-47-53-10,0-23-65281-10-11-35-16-5-51-43-13-45-28-21,29-23-24-25-256-257,0** | `cargo run --quiet --example reflect-facts | grep '^firefox_65_ja3_text='` |
| `fp_firefox_65_len_stable` | **yes** | `cargo run --quiet --example reflect-facts | grep '^firefox_65_len_stable='` |
| `fp_firefox_99_cipher_count` | **18** | `cargo run --quiet --example reflect-facts | grep '^firefox_99_cipher_count='` |
| `fp_firefox_99_ext_count` | **15** | `cargo run --quiet --example reflect-facts | grep '^firefox_99_ext_count='` |
| `fp_firefox_99_hello_len` | **512** | `cargo run --quiet --example reflect-facts | grep '^firefox_99_hello_len='` |
| `fp_firefox_99_ja3_md5` | **6b5e0cfe988c723ee71faf54f8460684** | `cargo run --quiet --example reflect-facts | grep '^firefox_99_ja3_md5='` |
| `fp_firefox_99_ja3_stable` | **yes** | `cargo run --quiet --example reflect-facts | grep '^firefox_99_ja3_stable='` |
| `fp_firefox_99_ja3_text` | **771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53-10,0-23-65281-10-11-35-16-5-34-51-43-13-45-28-21,29-23-24-25-256-257,0** | `cargo run --quiet --example reflect-facts | grep '^firefox_99_ja3_text='` |
| `fp_firefox_99_len_stable` | **yes** | `cargo run --quiet --example reflect-facts | grep '^firefox_99_len_stable='` |
| `fp_ios_11_cipher_count` | **20** | `cargo run --quiet --example reflect-facts | grep '^ios_11_cipher_count='` |
| `fp_ios_11_ext_count` | **10** | `cargo run --quiet --example reflect-facts | grep '^ios_11_ext_count='` |
| `fp_ios_11_hello_len` | **259** | `cargo run --quiet --example reflect-facts | grep '^ios_11_hello_len='` |
| `fp_ios_11_ja3_md5` | **a69708a64f853c3bcc214c2c5faf84f3** | `cargo run --quiet --example reflect-facts | grep '^ios_11_ja3_md5='` |
| `fp_ios_11_ja3_stable` | **yes** | `cargo run --quiet --example reflect-facts | grep '^ios_11_ja3_stable='` |
| `fp_ios_11_ja3_text` | **771,49196-49195-49188-49187-49162-49161-52393-49200-49199-49192-49191-49172-49171-52392-157-156-61-60-53-47,65281-0-23-13-5-13172-18-16-11-10,29-23-24-25,0** | `cargo run --quiet --example reflect-facts | grep '^ios_11_ja3_text='` |
| `fp_ios_11_len_stable` | **yes** | `cargo run --quiet --example reflect-facts | grep '^ios_11_len_stable='` |
| `fp_ios_12_cipher_count` | **23** | `cargo run --quiet --example reflect-facts | grep '^ios_12_cipher_count='` |
| `fp_ios_12_ext_count` | **10** | `cargo run --quiet --example reflect-facts | grep '^ios_12_ext_count='` |
| `fp_ios_12_hello_len` | **269** | `cargo run --quiet --example reflect-facts | grep '^ios_12_hello_len='` |
| `fp_ios_12_ja3_md5` | **5c118da645babe52f060d0754256a73c** | `cargo run --quiet --example reflect-facts | grep '^ios_12_ja3_md5='` |
| `fp_ios_12_ja3_stable` | **yes** | `cargo run --quiet --example reflect-facts | grep '^ios_12_ja3_stable='` |
| `fp_ios_12_ja3_text` | **771,49196-49195-49188-49187-49162-49161-52393-49200-49199-49192-49191-49172-49171-52392-157-156-61-60-53-47-49160-49170-10,65281-0-23-13-5-13172-18-16-11-10,29-23-24-25,0** | `cargo run --quiet --example reflect-facts | grep '^ios_12_ja3_text='` |
| `fp_ios_12_len_stable` | **yes** | `cargo run --quiet --example reflect-facts | grep '^ios_12_len_stable='` |
| `fp_ios_13_cipher_count` | **26** | `cargo run --quiet --example reflect-facts | grep '^ios_13_cipher_count='` |
| `fp_ios_13_ext_count` | **13** | `cargo run --quiet --example reflect-facts | grep '^ios_13_ext_count='` |
| `fp_ios_13_hello_len` | **512** | `cargo run --quiet --example reflect-facts | grep '^ios_13_hello_len='` |
| `fp_ios_13_ja3_md5` | **6fa3244afc6bb6f9fad207b6b52af26b** | `cargo run --quiet --example reflect-facts | grep '^ios_13_ja3_md5='` |
| `fp_ios_13_ja3_stable` | **yes** | `cargo run --quiet --example reflect-facts | grep '^ios_13_ja3_stable='` |
| `fp_ios_13_ja3_text` | **771,4865-4866-4867-49196-49195-49188-49187-49162-49161-52393-49200-49199-49192-49191-49172-49171-52392-157-156-61-60-53-47-49160-49170-10,65281-0-23-13-5-18-16-11-51-45-43-10-21,29-23-24-25,0** | `cargo run --quiet --example reflect-facts | grep '^ios_13_ja3_text='` |
| `fp_ios_13_len_stable` | **yes** | `cargo run --quiet --example reflect-facts | grep '^ios_13_len_stable='` |
| `fp_qq_11_cipher_count` | **15** | `cargo run --quiet --example reflect-facts | grep '^qq_11_cipher_count='` |
| `fp_qq_11_ext_count` | **16** | `cargo run --quiet --example reflect-facts | grep '^qq_11_ext_count='` |
| `fp_qq_11_hello_len` | **512** | `cargo run --quiet --example reflect-facts | grep '^qq_11_hello_len='` |
| `fp_qq_11_ja3_md5` | **cd08e31494f9531f560d64c695473da9** | `cargo run --quiet --example reflect-facts | grep '^qq_11_ja3_md5='` |
| `fp_qq_11_ja3_stable` | **yes** | `cargo run --quiet --example reflect-facts | grep '^qq_11_ja3_stable='` |
| `fp_qq_11_ja3_text` | **771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0** | `cargo run --quiet --example reflect-facts | grep '^qq_11_ja3_text='` |
| `fp_qq_11_len_stable` | **yes** | `cargo run --quiet --example reflect-facts | grep '^qq_11_len_stable='` |
| `fp_randomized_alpn_seed0_hello_len` | **217** | `cargo run --quiet --example reflect-facts | grep '^randomized_alpn_seed0_hello_len='` |
| `fp_randomized_alpn_seed0_ja3_md5` | **c7d630f6535ab1f5b0e3950db6554ac9** | `cargo run --quiet --example reflect-facts | grep '^randomized_alpn_seed0_ja3_md5='` |
| `fp_randomized_alpn_seed0_ja3_text` | **771,49187-60-49199-157-49196-52392-49195-156-49200-49191-49171-10-5-53-47-49162-49169-49172-49161-49159-49170,0-11-13-10-65281-5-35-16-23,23-24-25,0** | `cargo run --quiet --example reflect-facts | grep '^randomized_alpn_seed0_ja3_text='` |
| `fp_randomized_alpn_seed1_hello_len` | **1502** | `cargo run --quiet --example reflect-facts | grep '^randomized_alpn_seed1_hello_len='` |
| `fp_randomized_alpn_seed1_ja3_md5` | **5f11d9abc52a689b81a758517df394f1** | `cargo run --quiet --example reflect-facts | grep '^randomized_alpn_seed1_ja3_md5='` |
| `fp_randomized_alpn_seed1_ja3_text` | **771,4866-4865-60-52393-49187-49196-52392-49195-49199-157-49171-10-53-49161-49162,11-5-23-43-17513-16-10-18-13-51-0-45-35,4588-29-23-24,0** | `cargo run --quiet --example reflect-facts | grep '^randomized_alpn_seed1_ja3_text='` |
| `fp_randomized_alpn_seed2_hello_len` | **512** | `cargo run --quiet --example reflect-facts | grep '^randomized_alpn_seed2_hello_len='` |
| `fp_randomized_alpn_seed2_ja3_md5` | **7b9f787da5094b8ecf46b874d60de39a** | `cargo run --quiet --example reflect-facts | grep '^randomized_alpn_seed2_ja3_md5='` |
| `fp_randomized_alpn_seed2_ja3_text` | **771,4866-4867-4865-49199-157-156-49191-49200-49196-49195-52393-53-49170-49172-10-49162-49161,65281-13-21-43-18-16-11-10-5-51-17513-45-0-35,4588-29-23-24,0** | `cargo run --quiet --example reflect-facts | grep '^randomized_alpn_seed2_ja3_text='` |
| `fp_randomized_no_alpn_seed0_hello_len` | **199** | `cargo run --quiet --example reflect-facts | grep '^randomized_no_alpn_seed0_hello_len='` |
| `fp_randomized_no_alpn_seed0_ja3_md5` | **419a0067df283e172dbe1515f4a9fef1** | `cargo run --quiet --example reflect-facts | grep '^randomized_no_alpn_seed0_ja3_md5='` |
| `fp_randomized_no_alpn_seed0_ja3_text` | **771,49187-60-49199-157-49196-52392-49195-156-49200-49191-49171-10-5-53-47-49162-49169-49172-49161-49159-49170,13-11-65281-5-0-35-10-23,23-24-25,0** | `cargo run --quiet --example reflect-facts | grep '^randomized_no_alpn_seed0_ja3_text='` |
| `fp_randomized_no_alpn_seed1_hello_len` | **1475** | `cargo run --quiet --example reflect-facts | grep '^randomized_no_alpn_seed1_hello_len='` |
| `fp_randomized_no_alpn_seed1_ja3_md5` | **ad82954779f6fe28886c6b619a5ac5da** | `cargo run --quiet --example reflect-facts | grep '^randomized_no_alpn_seed1_ja3_md5='` |
| `fp_randomized_no_alpn_seed1_ja3_text` | **771,4866-4865-60-52393-49187-49196-52392-49195-49199-157-49171-10-53-49161-49162,13-18-45-10-11-5-43-23-0-51-35,4588-29-23-24,0** | `cargo run --quiet --example reflect-facts | grep '^randomized_no_alpn_seed1_ja3_text='` |
| `fp_randomized_no_alpn_seed2_hello_len` | **512** | `cargo run --quiet --example reflect-facts | grep '^randomized_no_alpn_seed2_hello_len='` |
| `fp_randomized_no_alpn_seed2_ja3_md5` | **78d307ab74c1728c434cfd9779b584d3** | `cargo run --quiet --example reflect-facts | grep '^randomized_no_alpn_seed2_ja3_md5='` |
| `fp_randomized_no_alpn_seed2_ja3_text` | **771,4866-4867-4865-49199-157-156-49191-49200-49196-49195-52393-53-49170-49172-10-49162-49161,65281-18-10-21-13-11-5-45-43-51-0-35,4588-29-23-24,0** | `cargo run --quiet --example reflect-facts | grep '^randomized_no_alpn_seed2_ja3_text='` |
| `fp_randomized_seed0_hello_len` | **1566** | `cargo run --quiet --example reflect-facts | grep '^randomized_seed0_hello_len='` |
| `fp_randomized_seed0_ja3_md5` | **26822966929f842a4c55ff33436e7d67** | `cargo run --quiet --example reflect-facts | grep '^randomized_seed0_ja3_md5='` |
| `fp_randomized_seed0_ja3_text` | **771,4866-4865-4867-52393-157-60-156-49199-49196-52392-49191-49187-49200-49195-49172-47-49162-49171-49161-49170-10,13-16-0-11-10-51-43-35-23-65281-45,4588-29-23-24-25,0** | `cargo run --quiet --example reflect-facts | grep '^randomized_seed0_ja3_text='` |
| `fp_randomized_seed1_hello_len` | **512** | `cargo run --quiet --example reflect-facts | grep '^randomized_seed1_hello_len='` |
| `fp_randomized_seed1_ja3_md5` | **815d092461846a85bfe28245cd4d5f75** | `cargo run --quiet --example reflect-facts | grep '^randomized_seed1_ja3_md5='` |
| `fp_randomized_seed1_ja3_text` | **771,4867-49200-157-52393-49187-52392-49195-156-60-49191-47-53-49170-10-49162,65281-51-10-5-11-0-17513-21-16-23-13-45-35-43,4588-29-23-24-25,0** | `cargo run --quiet --example reflect-facts | grep '^randomized_seed1_ja3_text='` |
| `fp_randomized_seed2_hello_len` | **192** | `cargo run --quiet --example reflect-facts | grep '^randomized_seed2_hello_len='` |
| `fp_randomized_seed2_ja3_md5` | **0de39d583d9385cc981e62f0437c940f** | `cargo run --quiet --example reflect-facts | grep '^randomized_seed2_ja3_md5='` |
| `fp_randomized_seed2_ja3_text` | **771,49187-49195-52392-157-52393-49196-60-49191-49171-10-47-49169-49161-49159-53-49170-49172,5-13-11-35-0-10-23,23-24-25,0** | `cargo run --quiet --example reflect-facts | grep '^randomized_seed2_ja3_text='` |
| `fp_safari_16_cipher_count` | **20** | `cargo run --quiet --example reflect-facts | grep '^safari_16_cipher_count='` |
| `fp_safari_16_ext_count` | **14** | `cargo run --quiet --example reflect-facts | grep '^safari_16_ext_count='` |
| `fp_safari_16_hello_len` | **512** | `cargo run --quiet --example reflect-facts | grep '^safari_16_hello_len='` |
| `fp_safari_16_ja3_md5` | **773906b0efdefa24a7f2b8eb6985bf37** | `cargo run --quiet --example reflect-facts | grep '^safari_16_ja3_md5='` |
| `fp_safari_16_ja3_stable` | **yes** | `cargo run --quiet --example reflect-facts | grep '^safari_16_ja3_stable='` |
| `fp_safari_16_ja3_text` | **771,4865-4866-4867-49196-49195-52393-49200-49199-52392-49162-49161-49172-49171-157-156-53-47-49160-49170-10,0-23-65281-10-11-16-5-13-18-51-45-43-27-21,29-23-24-25,0** | `cargo run --quiet --example reflect-facts | grep '^safari_16_ja3_text='` |
| `fp_safari_16_len_stable` | **yes** | `cargo run --quiet --example reflect-facts | grep '^safari_16_len_stable='` |
| `fp_safari_26_cipher_count` | **20** | `cargo run --quiet --example reflect-facts | grep '^safari_26_cipher_count='` |
| `fp_safari_26_ext_count` | **13** | `cargo run --quiet --example reflect-facts | grep '^safari_26_ext_count='` |
| `fp_safari_26_hello_len` | **1529** | `cargo run --quiet --example reflect-facts | grep '^safari_26_hello_len='` |
| `fp_safari_26_ja3_md5` | **ecdf4f49dd59effc439639da29186671** | `cargo run --quiet --example reflect-facts | grep '^safari_26_ja3_md5='` |
| `fp_safari_26_ja3_stable` | **yes** | `cargo run --quiet --example reflect-facts | grep '^safari_26_ja3_stable='` |
| `fp_safari_26_ja3_text` | **771,4866-4867-4865-49196-49195-52393-49200-49199-52392-49162-49161-49172-49171-157-156-53-47-49160-49170-10,0-23-65281-10-11-16-5-13-18-51-45-43-27,4588-29-23-24-25,0** | `cargo run --quiet --example reflect-facts | grep '^safari_26_ja3_text='` |
| `fp_safari_26_len_stable` | **yes** | `cargo run --quiet --example reflect-facts | grep '^safari_26_len_stable='` |
| `gate_count` | **5** | `ls zreflect/check_*.py | wc -l` |
| `md_files` | **22** | `find . -name '*.md' -not -path './.git/*' -not -path './target/*' -not -path '*/__pycache__/*' -not -path './crates/rustls/*' | wc -l` |
| `md_lines` | **2845** | `find . -name '*.md' -not -path './.git/*' -not -path './target/*' -not -path '*/__pycache__/*' -not -path './crates/rustls/*' -exec awk 'FNR==1{b=0} /<!-- AUTO:FACTS -->/{b=1} !b' {} + | wc -l` |
| `open_questions` | **0** | `python3 -c "import sys;sys.path.insert(0,'zreflect');from check_questions import collect,field;print(sum(1 for t in collect('questions').values() if (field(t,'Status') or '')!='resolved'))"` |
| `py_files` | **15** | `find . -name '*.py' -not -path './.git/*' -not -path './target/*' -not -path '*/__pycache__/*' -not -path './crates/rustls/*' | wc -l` |
| `py_lines` | **1933** | `find . -name '*.py' -not -path './.git/*' -not -path './target/*' -not -path '*/__pycache__/*' -not -path './crates/rustls/*' -exec cat {} + | wc -l` |
| `question_count` | **10** | `ls questions/*.md | wc -l` |
| `retraction_count` | **5** | `python3 -c "import json;print(len(json.load(open('retractions.json'))['retractions']))"` |
| `rs_files` | **45** | `find . -name '*.rs' -not -path './.git/*' -not -path './target/*' -not -path '*/__pycache__/*' -not -path './crates/rustls/*' | wc -l` |
| `rs_lines` | **19640** | `find . -name '*.rs' -not -path './.git/*' -not -path './target/*' -not -path '*/__pycache__/*' -not -path './crates/rustls/*' -exec cat {} + | wc -l` |
| `rustc_version` | **rustc 1.98.1 (48a229cea 2026-09-01)** | `rustc --version` |
| `rustls_pin` | **0.23.45** | `grep -rh '^rustls *= *{ *version' --include='Cargo.toml' . | head -1` |

321 条事实。
<!-- /AUTO:FACTS -->
