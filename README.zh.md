# uTLS-Gone（中文）

[![ci](https://github.com/ArchivalEra/uTLS-Gone/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/ArchivalEra/uTLS-Gone/actions/workflows/ci.yml)
[![release](https://img.shields.io/github/v/release/ArchivalEra/uTLS-Gone)](https://github.com/ArchivalEra/uTLS-Gone/releases)
[![license](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![rust](https://img.shields.io/badge/rust-edition%202024-orange.svg)](Cargo.toml)
[![no Go](https://img.shields.io/badge/Go-%E9%9B%B6%E4%BE%9D%E8%B5%96-success.svg)](#名字)
[![upstream](https://img.shields.io/badge/%E5%8E%9F%E7%89%88%E5%A4%B9%E5%85%B7-%E9%80%90%E5%AD%97%E8%8A%82-brightgreen.svg)](crates/utls/tests/fixtures/utls-testdata/README.md)
[![top language](https://img.shields.io/github/languages/top/ArchivalEra/uTLS-Gone)](https://github.com/ArchivalEra/uTLS-Gone)
[![last commit](https://img.shields.io/github/last-commit/ArchivalEra/uTLS-Gone)](https://github.com/ArchivalEra/uTLS-Gone/commits/main)

**ClientHello 应该是可命名、可复现、可验证的东西 —— 而不是一段每次都不一样、没人能证明它对的字节。**

`uTLS-Gone` 是 [`refraction-networking/utls`](https://github.com/refraction-networking/utls)
的纯 Rust 复刻：给定一个浏览器指纹（例如「Chrome 133」），产生一个**与那个浏览器一致**的
ClientHello，并让这个一致性**可以被一条命令复跑证明**。在这个之上，它还交付了 uTLS 生态里
最大的生产消费者 —— **XTLS/REALITY 的 Rust 等价实现**（issue #1，随
[`v0.1.0-reality.1`](https://github.com/ArchivalEra/uTLS-Gone/releases/tag/v0.1.0-reality.1) 发布）。

> English: [README.md](README.md)

## 名字

仓库叫 `uTLS-Gone`，`Gone` 是双关：

- **没有 Go**。原版 uTLS 是 Go 写的，这一份是纯 Rust —— 指纹层与引擎层里一行 Go 都没有，
  也没有用 Go 的工具链（唯一的例外在 `crates/utls/tests/fixtures/`：那是**对账材料**，
  用原版自己的 API 跑出来的夹具与探针，不是本仓的运行依赖）。
- **跑得快**。同一个活（产出一条带真密钥交换的 ClientHello）的边际 CPU 是原版的
  **约 1/8**（13.3 µs vs 102 µs）—— 实测协议、完整数据与对我们不利的那一列都在下一节。

## 速度与 CPU 消耗（实测，可复跑）

![每条 hello 的边际 CPU：uTLS-Gone 13.3 µs，uTLS（Go 1.27）102 µs，7.7×](docs/bench-zh.svg)

**对比必须在同一层做才有意义**：本仓走引擎那道缝（`FingerprintClient::plan`：起真密钥交换 +
编码 + 记账），对应的 uTLS 动作是 `tls.UClient(...) + BuildHandshakeState()`
（`gen-reference/bench/main.go`）。拿指纹层的 `marshal` 去比会得到虚高的倍数
（实测踩到过：看着 29×，其实两层的东西不可比）。

同机（AMD Ryzen 9 3900X）、同 39 档预设（两边支持集合的交集）、同协议：拼错预设名量纯循环开销；
n=48 与 10n=480 各三次取中位，解出**边际成本**；单档探针分离**一次性初始化**。
计时从循环起点起，不含进程启动。参照 = uTLS master（tarball sha256 `ae5e90b0…`，
取回命令见 `crates/utls/tests/fixtures/gen-reference/README.md`）。

| | uTLS（Go 1.27，默认构建） | 本仓（默认 release） | 本仓（+ fat LTO，CGU=1） |
|---|---|---|---|
| **每条 hello 的边际 CPU**（39 档均值） | **102 µs** | **13.3 µs**（**7.7×**） | 13.2 µs —— 与默认在噪声内 |
| 单档 `Chrome(70)` 的边际 | 75 µs | 11.8 µs | 9.3 µs |
| 批量均值（39 档 × 48 条，一次性成本摊薄在内） | 104.6 µs | 31.6 µs | 30.8 µs |
| 首条 hello（未预热的冷进程） | ~77 µs | ≈33 ms | ≈33 ms |
| 首条 hello（`warm_up()` 预热后） | ~77 µs（无一次性成本） | **~81 µs** | ~81 µs |
| **每条 hello 的分配字节**（39 档均值，循环内累计堆分配） | **20.8 KB** | **9.7 KB**（复用规划器）/ 10.8 KB（每连接新建） | 同左（LTO 不改分配行为） |
| 峰值 RSS（空跑 = 18720 条） | ~16 MB 持平 | ~16 MB 持平 | ~16 MB 持平 |

如实写全，包括对我们不利的那几行：

- **首条 hello 的 ~33 ms：根因已定位，修法已给且实测生效**。那笔钱是 aws-lc 进程内首次
  `RAND_bytes` 的 jitter-entropy 收集 —— 纯用户态（`strace -c`：全进程系统调用总共
  0.4 ms），第二次 fill 只要 **~330 ns**，先 keygen 同样要付（keygen 内部走 RAND）；上游
  [aws-lc-rs#1140](https://github.com/aws/aws-lc-rs/issues/1140) 开放中，`aws_lc_rs::init()`
  是空操作。引擎给出显式预热 **`utls_engine::warm_up(&provider)`**（一次 32 字节 RNG
  fill）：启动时调一行，首条 hello **≈33 ms → ~81 µs**，与 Go 的冷首条（~77 µs）同量级。
  表里仍保留未预热的 ≈33 ms，因为**不调 `warm_up()` 的冷进程确实还要付这笔** —— 基准
  默认测冷进程，预热后的数字用 `PLANCOST_WARM=1` 量。TLS 1.2 时代的档全程不碰
  provider RNG，单条 ~50 µs，从来不受影响。
- **内存**：峰值 RSS 两边打平 —— **~16 MB**，而且空跑与 18720 条完全一样（分配器/GC
  全程复用，谁都不随条数涨）。有差别的是**每条 hello 的分配量**：Go **20.8 KB** vs 本仓
  **9.7 KB**（复用规划器）/ 10.8 KB（`PLANCOST_FRESH=1`，每连接新建 —— 对齐 uTLS
  每连接一个 UClient 的真实形状），约 **2.1×**。口径：循环内累计堆分配，Go `TotalAlloc`
  ↔ Rust 计数分配器（realloc 按新尺寸计），`plan-cost` 打 `alloc_bytes=` 行。
- **LTO 测了，不变**（fat LTO + codegen-units=1：边际 13.3 → 13.2 µs，噪声内）：热点在
  crypto 原语（aws-lc-rs 的汇编，带运行时指令分派）与运行时初始化，**不在内联机会**。
  PGO 没测 —— 按同一形状推断空间有限，不声称。
- **模型校验**：39 档 × 480 条/档（18720 条/进程）实测 Go 1.9185 s / 本仓 283.6 ms；
  线性模型（一次性 + 边际 × 条数）预测 1919 / 283.6 ms —— 成立。
- 基准本体：[`crates/utls-engine/examples/plan-cost.rs`](crates/utls-engine/examples/plan-cost.rs)
  （打印 `checksum=`：所有产出字节的 FNV-1a，防「快是因为什么都没干」）与
  [`crates/utls/tests/fixtures/gen-reference/bench/main.go`](crates/utls/tests/fixtures/gen-reference/bench/main.go)。

## 为什么必须 fork

「用上游 rustls 加一个扩展列表就能实现」—— **已翻案**，这句话是错的（见 `retractions.json` R-001）。
两个硬约束：

1. rustls **没有**任何公开的 ClientHello 定制 API。`ClientConfig` 的字段里没有扩展表、
   没有顺序、没有 GREASE；`ClientConfig::dangerous()` 只暴露一个 `set_certificate_verifier`。
   维护者在多个 issue 里明确关闭了这个需求。
2. 自 rustls 0.23.0 起，它**每连接随机化扩展顺序**。也就是说：即使密码套件与扩展集合
   完全正确，上游也产不出稳定指纹。

所以本项目的形态与 uTLS 一致：**fork 掉 TLS 引擎，在它上面搭一层指纹**。区别只在于
引擎从 Go 的 `crypto/tls` 换成了 rustls。这不是可以绕开的选择，是前提。

## 既有方案与它们的缺口

「Rust 生态里没有任何 uTLS 的替代方案」—— **已翻案**，这句话也是错的（见 `retractions.json` R-002）。
实际已有的路线：

| 方案 | 状态 | 缺口 |
|---|---|---|
| `3andne/craftls` | rustls 0.22 的 fork，带 `FingerprintBuilder`；是 rustls 维护者在 issue 里亲自推荐的 | 停在旧版 rustls，未跟进 |
| `apify/rustls` | 唯一还在跟上游走的 fork，已跟到 0.23.4x | 为别的项目而做，接口是给别人用的 |
| `XOR-op/rustls.delta` + `ja-tools` | 最小 delta，实测对单个版本只改几个文件、十来行 | 只跟一个旧版本；靠 `[patch.crates-io]` 挂载，进不了 crates.io |

它们共同说明了一件事：**这条路在 Rust 里走得通，且补丁可以很小** —— 但没有人把它做成
一个完整的、带预设表的 uTLS。本项目补的就是这个缺口。

## 架构

两条边，方向是单向的：

```
       utls 层（我方）                      rustls（vendored fork）
  ┌────────────────────────────┐        ┌──────────────────────────────┐
  │ ClientHello 数据模型        │        │  握手状态机                  │
  │ 序列化 / GREASE / 填充      │ ─────▶ │  · 在构建 ClientHello 处插桩  │
  │ 预设表（浏览器指纹）        │        │  · 压制每连接扩展乱序         │
  │ 从原始字节反解指纹          │ ◀───── │  · 允许广播自协商不了的套件    │
  └────────────────────────────┘        └──────────────────────────────┘
```

| crate | 是什么 |
|---|---|
| `utls` | 指纹层：ClientHello 数据模型、序列化 / GREASE / 填充、预设表、从原始字节反解指纹 |
| `utls-engine` | 指纹层与引擎的缝合：外供 hello 的规划、密钥交换、会话复用、ECH 提议 |
| `rustls` | vendored 的 rustls 0.23.45，9 个文件带 `FORK(utls-rs)` 标记；补丁与判据在 `crates/rustls-fork/` |
| `reality` | REALITY 的 Rust 等价实现（issue #1，见下节） |

**指纹层不引用任何 rustls 类型。** 理由是实测的：rustls 在两年内两次重构内部扩展表示。
把易变的部分关进一个薄适配层，补丁的 delta 才只剩插桩点，跟随上游的成本才从「重写」降为「对行」。

## REALITY（issue #1，已随 v0.1.0-reality.1 发布）

本仓的第一个 issue 要求：以 [`XTLS/REALITY`](https://github.com/XTLS/REALITY) 为**权威参照**
（不引二手移植），给出 REALITY 的 Rust 等价实现。交付在 `crates/reality/`，**31 条判据全绿**
（台账键 `reality_tests`），含真栈：

- **鉴权与 KDF**：AuthKey = X25519(服务端静态私钥, 客户端临时公钥) → HKDF-SHA256；
  `sessionId` 的密封 = AES-256-GCM，AAD 是 **sessionId 置零后的整条 ClientHello**。
  KDF 与密封对 Go 参照实现产出的向量做**双向逐字节对拍**。
- **fallback 判定**：上游 `tls.go:213-275` 那段服务端决策逻辑整段移植，10 条判据。
- **镜像握手**：自己跑半段 TLS 1.3 服务端握手 —— 把真站 ServerHello 当模板、只换密钥字节；
  EE / Certificate / CertificateVerify / Finished 全部由本仓产出。镜像支持的组只有
  `X25519(29)` 与 `X25519MLKEM768(4588)` —— 上限是 uTLS 客户端自己的 key share 能力
  （`u_public.go` 只有这两类私钥位），不是我们少做了。
- **客户端半边**：能在 rustls fork 之上发起 REALITY 连接。
- **参数面 parity**：Xray 的 `config.proto` 21 个字段逐条对账，双向核对、可红验证。
- **真栈（stock Xray-core 26.3.27）**：正常客户端鉴权成功并承载流量；未鉴权的 hello 被
  转发给真站，拿到与直连**逐字节相同**的证书链。

协议形状、六个实测发现与已知边界（ML-DSA-65 未实现；HRR 不处理 —— 参照同样不做）写在
[`questions/11-reality-rust-port.md`](questions/11-reality-rust-port.md)。

## 事实系统

本仓接了一套反幻觉的事实机制（`zreflect/`，从 [`ArchivalEra/Einfacht`](https://github.com/ArchivalEra/Einfacht)
接入，只留机制、剥掉项目数据）。它的形状正好对上本项目的核心交付物：**每个预设的指纹就是一个
「测出来的值」**，所以文档里的指纹只能来自一次可复跑的测量，不能手抄。

```bash
python3 zreflect/facts.py                       # 量一遍，写台账（掉条/改口会拒绝写盘）
python3 zreflect/facts.py --render-doc STATE.md # 把机器块渲染进活状态文档
sh gates-selftest.sh                            # 每个闸门先证明自己会红（发现式名录）
sh reflect-hooks/install.sh                     # 挂 pre-commit / pre-push
```

| 部件 | 挡住什么 |
|---|---|
| `zreflect/check_facts.py` | 文档块与台账不一致、正文裸数字、引用不存在的键 |
| `zreflect/check_cmds.py` | 台账里 `cmd` 字段写的那条复跑命令**跑不出记录的值**（含 shell 方言这类只会在别的 shell 下暴露的错） |
| `zreflect/check_retractions.py` | 已被推翻的断言重新出现当现状 |
| `zreflect/check_stale.py` | 活状态里没有出处的哈希断言、退役组件名回来 |
| `zreflect/check_questions.py` | 未结案的问题只活在散文里、没有能跑的结算件 |

现在的状态、已知缺口、以及为什么本仓一个配置旋钮都没改，都写在 [`STATE.md`](STATE.md)。
在本仓工作的规矩见 [`AGENTS.md`](AGENTS.md)。

## 现在到哪了

- **指纹层**：预设表、GREASE、填充、扩展乱序、随机化族、结构化的扩展集、从原始字节反解。
  与原版的 `testdata/` 夹具逐字节一致。
- **引擎层**：vendored rustls + **八处插桩**（外供 ClientHello、压制乱序、广播自协商不了的套件、
  去掉无条件追加的 SCSV、外供密钥交换、外供第二飞、会话复用、真 ECH 提议）——
  逐处出处与上游为什么拒绝写在 `crates/rustls-fork/README.md`。
- **REALITY**：见上节 —— 31 条判据全绿，含 stock Xray 真栈。
- **真实 ECH 的接受那一半已通**：Cloudflare、defo.ie、test.defo.ie 三族服务器都接受；
  另有一条**离线**判据（我们的客户端 ↔ uTLS 自己的 ECH 服务端）。
- **41 档里 40 档都能过引擎那条路**（`cargo run --release --example plan-cost` 会打出名单）。
  剩下的一档是 `HelloCustom` = 空 spec，被拒的理由是「没有密码套件」—— 空 spec 不是一条
  合法的 ClientHello，那不是欠账。
- 两处曾经「发不出去」的形态，现在的处理与边界：
  - **TLS 1.2 时代的老预设**（Chrome 58/62、Firefox 55/56、Ios 11/12、Android 11）：spec 里
    没有 `key_share`，它们只能谈 TLS 1.2 —— 引擎现在按这个形态产出，对着同时开 1.2/1.3 的
    服务端真谈成 `TLSv1_2`。**调用方的 config 也要只开 1.2**：否则服务端放进 ServerHello
    随机数里的降级哨兵会被判成降级攻击（Go/uTLS 同样如此）。
  - **PQ 预设**（ChromePq 115/120、ChromePsk 115）：`key_share` 里的
    `X25519Kyber768Draft00` 是草案组，rustls 的提供者没有它。引擎给这个组发一个**长度正确**
    的占位公钥（形状与 Chrome 一致，总长对得上台账），真交换只交能完成的 X25519 ⇒
    服务器不认草案组时照常谈成；**认它并选了它**则响亮失败（不静默换组）。
- **引擎会发的每个密钥交换组都有正向判据**（服务端把 `kx_groups` 滤成只认那一个组，
  于是「谈成了」本身就等于「用的是它」）：P-256 三条在
  [`tests/p256_handshake.rs`](crates/utls-engine/tests/p256_handshake.rs)、混合组
  `X25519MLKEM768(4588)` 三条在
  [`tests/mixed_group_handshake.rs`](crates/utls-engine/tests/mixed_group_handshake.rs)。
  两种情形都覆盖：第一飞就被选中、`key_share` 里只给它一把、以及服务端强要它时的 HRR ——
  第二飞带上**新的**共享（混合组 1216 字节）且 client random 逐字节不变。
- ⚠️ **`Browser360(7)` 谈不成**，原因在**密码套件**而不在引擎：它报的 20 个套件全是
  CBC/RC4/3DES，而现代 TLS 栈（rustls 只实现 6 个 TLS 1.2 套件：AES-GCM 与 CHACHA20）
  与它**交集为 0** —— uTLS 底下的 Go 默认同样不实现那些套件。它的字节仍然保真，
  只是对面得是一台还认老套件的服务器。

## 等价物还差什么

`uTLS` 的每一个测试族判到了哪一步、哪些是真缺口、哪些属于 rustls 领地（不重写）、
哪些上游自己就没测 —— 一张可核对的表在 [`docs/utls-parity.md`](docs/utls-parity.md)。
**「完全等价」不是一句话，是那张表。**

## 判据与 CI

CI（[`.github/workflows/ci.yml`](.github/workflows/ci.yml)）跑七组判据，每一组都能单独变红：

| job | 判什么 |
|---|---|
| `rust` | `cargo fmt --check`、`cargo clippy --workspace --all-targets --all-features -- -D warnings`、`cargo test --workspace --all-features` |
| `gates` | 五道闸门 + `gates-selftest.sh`（每个闸门先证明自己会红）+ 文档机器块与台账一致 |
| `patch-repro` | 把 `patch.diff` 打到**原始** rustls 0.23.45 上，得到的树要与 `crates/rustls` **逐文件相同**（`crates/rustls-fork/verify-patch.sh`） |
| `ech-offline` | 内层与 uTLS 的产出逐字节相同；我们的客户端能过 uTLS 自己的 ECH 服务端 |
| `upstream` | 原版 `refraction-networking/utls` 自己的测试套件（不联网那两条 `-skip`） |
| `upstream-no-skip` | 同上，但**一条都不跳** —— 那两条的目标域名由 `go -overlay` 在构建期换成直连可达者（上游树磁盘不动） |
| `reality-stack` | stock Xray 真栈：鉴权成功并承载流量、fallback 与直连真站逐字节相同 |

**不在 CI 里跑的，以及为什么**（不是忘了）：

- **联网判据**（`end_to_end`、`ech_e2e`）：要打 browserleaks / Cloudflare / defo.ie 的 443。
  本地跑：`cargo test -p utls-engine --test end_to_end -- --ignored`（同理 `ech_e2e`）。
- **基准** `plan-cost`：只打数字给人看，不做门禁（换台机器数值就变）。

**原版那两条要真外网的测试**（`TestVerifyHostname` / `TestRealResumption`）有两条路，
`ci.yml` 里两个 job 各走一条，**都不是「跳过」**：

- `upstream` —— 上游树**一字节不改**，代价是把那两条 `-skip` 掉；
- `upstream-no-skip` —— **不跳**，代价是那两条拨号的目标域名从 `www.google.com` /
  `yahoo.com` 换成直连可达、且判据等价的 `www.baidu.com`（用 `go -overlay` 在**构建期**
  替换测试文件，上游树磁盘上仍然没动）。这两条测的机制（主机名校验 / 真实 TLS 1.3 复用）
  与对端无关，换域名不动任何断言 —— 但它是**另一条**判据，不是未改动那条的替代。
  本地跑一条命令：`sh crates/utls/tests/fixtures/gen-reference/run-upstream-suite.sh <参照树>`
  ⇒ 顶层 **222 PASS / 0 FAIL / 1 SKIP**（唯一的 skip 是上游自己 `t.Skip` 的那条）。
  有代理时跑**未改动**那条全量的配方在 `questions/09-full-suite-oracle.md`。

## 跑一遍

```bash
cargo test --workspace --all-features    # 全部离线判据（REALITY 的 31 条也在其中）
cargo clippy --workspace --all-targets --all-features

# REALITY 真栈（要 stock Xray，取法见 tests/real_stack.rs 的 xray_bin()，REALITY_XRAY 可覆盖路径）
cargo test -p reality --test real_stack -- --include-ignored

# 要真网络的判据（默认 #[ignore]）
cargo test -p utls-engine --test end_to_end -- --ignored
cargo test -p utls-engine --test ech_e2e -- --ignored

# ECH 的离线判据（要 Go 与一份 uTLS 源码树，取回命令见 crates/utls/tests/fixtures/gen-reference/README.md）
cargo test -p utls-engine --test ech_inner_utls
cargo test -p utls-engine --test ech_utls_server -- --ignored

# 原版全套**不 -skip 也不走代理**（同样要那份源码树）⇒ 222 PASS / 0 FAIL / 1 SKIP
sh crates/utls/tests/fixtures/gen-reference/run-upstream-suite.sh /tmp/utls-ref/utls-master

# 事实系统：五道闸门 + 自证
for g in zreflect/check_*.py; do python3 "$g"; done && sh gates-selftest.sh
```

## 明确的非目标

HTTP/2 的指纹 —— uTLS 本身也没有，它属于另一层（`ClientProfile` 那一类的封装）。
本项目只做 **ClientHello**（TCP 上的 TLS）。

⚠️ **HTTP/3 要分开说，别照旧稿抄**：上游 uTLS **有**一个 QUIC 指纹层
（`u_quic.go` / `u_quic_transport_parameters.go`，是它自己写的，带 golden-bytes 与
GREASE-version 测试）—— 这里从前写着「uTLS 本身也没有 HTTP/3 指纹」，那句话是错的。
现在**传输参数的编码层**已经移植（`crates/utls/src/quic.rs`，Firefox 参数集与上游
golden bytes 逐字节一致，GREASE 版本分布/哨兵替换同款判据）；还没接的是
`UQUICConn` 那层连接缝（rustls 有 `pub mod quic`）。逐条状态见
[`docs/utls-parity.md`](docs/utls-parity.md)。

## License

**我们自己的代码**：**Apache-2.0**（原文见 `LICENSE`，取自 <https://www.apache.org/licenses/LICENSE-2.0.txt>；
SPDX 在 `Cargo.toml` 的 `license` 字段）。

宽松许可，含**显式的专利授权**（§3）：任何人都可以商用、闭源、修改、再分发，
只要保留版权与许可声明、并在改动过的文件里说明改过。协议实现这一类代码选 Apache 而不是 MIT，
主要就是为这条专利授权。

需要**禁止商用**时（本仓现在是允许的），替代品是一处改动的事：
`PolyForm Noncommercial 1.0.0`（永久禁商用）或 `BSL 1.1`（先禁商用、到 change date 自动转宽松）。

本仓里有**两块不是我们写的**东西，各自的许可与出处写在 `THIRD-PARTY.md`：

- `crates/rustls/` —— vendored 的 **rustls 0.23.45**（Apache-2.0 / ISC / MIT，原文随副本一起在
  `crates/rustls/LICENSE-*`），9 个文件带 `FORK(utls-rs)` 标记，补丁在 `crates/rustls-fork/`；
- 从 **`refraction-networking/utls`**（BSD-3-Clause）派生的**夹具与表**：`tests/fixtures/utls-testdata/`、
  `utls-reference.json` / `utls-randomized.json`、以及逐条抄录的预设/权重表。
  搬这些是因为本仓的判据是「与参照实现逐字节一致」—— 判据必须带着上游的原始字节。
