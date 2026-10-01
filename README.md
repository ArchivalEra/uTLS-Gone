# uTLS-rs

[![ci](https://github.com/ArchivalEra/uTLS-Gone/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/ArchivalEra/uTLS-Gone/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![rust](https://img.shields.io/badge/rust-edition%202024-orange.svg)](Cargo.toml)
[![no Go](https://img.shields.io/badge/Go-%E9%9B%B6%E4%BE%9D%E8%B5%96-success.svg)](#%E5%90%8D%E5%AD%97)
[![upstream](https://img.shields.io/badge/%E5%8E%9F%E7%89%88%E5%A4%B9%E5%85%B7-%E9%80%90%E5%AD%97%E8%8A%82-brightgreen.svg)](crates/utls/tests/fixtures/utls-testdata/README.md)
[![top language](https://img.shields.io/github/languages/top/ArchivalEra/uTLS-Gone)](https://github.com/ArchivalEra/uTLS-Gone)
[![last commit](https://img.shields.io/github/last-commit/ArchivalEra/uTLS-Gone)](https://github.com/ArchivalEra/uTLS-Gone/commits/main)

**ClientHello 应该是可命名、可复现、可验证的东西 —— 而不是一段每次都不一样、没人能证明它对的字节。**

`uTLS-rs` 是 [`refraction-networking/utls`](https://github.com/refraction-networking/utls)
的纯 Rust 复刻：给定一个浏览器指纹（例如「Chrome 133」），产生一个**与那个浏览器一致**的
ClientHello，并让这个一致性**可以被一条命令复跑证明**。

## 名字

仓库叫 `uTLS-Gone`，`Gone` 是双关：

- **没有 Go**。原版 uTLS 是 Go 写的，这一份是纯 Rust —— 指纹层与引擎层里一行 Go 都没有，
  也没有用 Go 的工具链（唯一的例外在 `crates/utls/tests/fixtures/`：那是**对账材料**，
  用原版自己的 API 跑出来的夹具与探针，不是本仓的运行依赖）。
- **跑得快**。同一个活（产出一条带真密钥交换的 ClientHello）在这台机器上：
  本仓**每条 26 µs** CPU，原版 uTLS **每条 151 µs**；每进程固定开销 0.7 ms vs 1.9 ms。
  跑法、模型的校验、以及两个会算出假倍数的陷阱（层要对齐、固定开销要单独量）写在
  `crates/utls-engine/examples/plan-cost.rs` 与 `crates/utls/tests/fixtures/gen-reference/README.md`。

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

**我方那一层不引用任何 rustls 类型。** 理由是实测的：rustls 在两年内两次重构内部扩展表示。
把易变的部分关进一个薄适配层，补丁的 delta 才只剩插桩点，跟随上游的成本才从「重写」降为「对行」。

## 事实系统

本仓接了一套反幻觉的事实机制（`zreflect/`，从 `zcode-reflect` 接入，只留机制、剥掉项目数据）。
它的形状正好对上本项目的核心交付物：**每个预设的指纹就是一个「测出来的值」**，
所以文档里的指纹只能来自一次可复跑的测量，不能手抄。

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
- **真实 ECH 的接受那一半已通**：Cloudflare、defo.ie、test.defo.ie 三族服务器都接受；
  另有一条**离线**判据（我们的客户端 ↔ uTLS 自己的 ECH 服务端）。
- ⚠️ **一条写明的边界**：引擎那条路要求「至少一把能完成的密钥交换」，所以
  `plan-cost` 打出的 40 档里有 12 档会被拒（TLS 1.2 时代没有 `key_share` 的、
  用了提供者不提供的组的、以及空 spec 的）。**指纹层不受影响** —— 那些预设的字节照样
  与 uTLS 逐字节相同。理由与复跑方式见 `STATE.md` 的已知缺口。

## 判据与 CI

CI（[`.github/workflows/ci.yml`](.github/workflows/ci.yml)）跑五组判据，每一组都能单独变红：

| job | 判什么 |
|---|---|
| `rust` | `cargo fmt --check`、`cargo clippy --workspace --all-targets -- -D warnings`、`cargo test --workspace` |
| `gates` | 五道闸门 + `gates-selftest.sh`（每个闸门先证明自己会红）+ 文档机器块与台账一致 |
| `patch-repro` | 把 `patch.diff` 打到**原始** rustls 0.23.45 上，得到的树要与 `crates/rustls` **逐文件相同** |
| `ech-offline` | 内层与 uTLS 的产出逐字节相同；我们的客户端能过 uTLS 自己的 ECH 服务端 |
| `upstream` | 原版 `refraction-networking/utls` 自己的测试套件 |

**不在 CI 里跑的，以及为什么**（不是忘了）：

- **联网判据**（`end_to_end`、`ech_e2e`）：要打 browserleaks / Cloudflare / defo.ie 的 443。
  本地跑：`cargo test -p utls-engine --test end_to_end -- --ignored`（同理 `ech_e2e`）。
- **原版那两条要真外网的测试**：本机是经一个 SOCKS5h 代理加 `/etc/hosts` 才通的
  （配方在 `questions/09-full-suite-oracle.md`），GitHub runner 上跑不了那套转发，
  所以 `upstream` 那个 job 显式 `-skip` 它们；其余一条都不跳。
- **基准** `plan-cost`：只打数字给人看，不做门禁（换台机器数值就变）。

## 跑一遍

```bash
cargo test --workspace                 # 离线全绿（含三组与原版产出的对账）
cargo clippy --workspace --all-targets # 0 警告
for g in zreflect/check_*.py; do python3 "$g"; done && sh gates-selftest.sh

# 要真网络的判据（默认 #[ignore]）
cargo test -p utls-engine --test end_to_end -- --ignored
cargo test -p utls-engine --test ech_e2e -- --ignored

# ECH 的离线判据（要 Go 与一份 uTLS 源码树，取回命令见 crates/utls/tests/fixtures/gen-reference/README.md）
cargo test -p utls-engine --test ech_inner_utls
cargo test -p utls-engine --test ech_utls_server -- --ignored
```

## 明确的非目标

HTTP/2 与 HTTP/3 的指纹、以及 TLS record 层的行为控制 —— uTLS 本身也没有这些，
它们属于另一层（`ClientProfile` 那一类的封装）。本项目只做 ClientHello。

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
