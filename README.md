# uTLS-rs

**ClientHello 应该是可命名、可复现、可验证的东西 —— 而不是一段每次都不一样、没人能证明它对的字节。**

`uTLS-rs` 是 [`refraction-networking/utls`](https://github.com/refraction-networking/utls)
的纯 Rust 复刻：给定一个浏览器指纹（例如「Chrome 133」），产生一个**与那个浏览器一致**的
ClientHello，并让这个一致性**可以被一条命令复跑证明**。

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
| `zreflect/check_retractions.py` | 已被推翻的断言重新出现当现状 |
| `zreflect/check_stale.py` | 活状态里没有出处的哈希断言、退役组件名回来 |
| `zreflect/check_questions.py` | 未结案的问题只活在散文里、没有能跑的结算件 |

现在的状态、已知缺口、以及为什么本仓一个配置旋钮都没改，都写在 [`STATE.md`](STATE.md)。
在本仓工作的规矩见 [`AGENTS.md`](AGENTS.md)。

## 路线

1. **指纹核心**（纯计算，引擎无关）：spec 模型、序列化、GREASE、填充、预设表、从原始字节反解。
2. **引擎 fork**：vendored rustls + 五处插桩，跑通一次真实握手并用在线核对端点对账。
3. **补全 uTLS 表面**：完整预设表、结构化的扩展集、`ApplyPreset`、fingerprinter、
   session/PSK、ECH、Roller。

## 明确的非目标

HTTP/2 与 HTTP/3 的指纹、以及 TLS record 层的行为控制 —— uTLS 本身也没有这些，
它们属于另一层（`ClientProfile` 那一类的封装）。本项目只做 ClientHello。

## License

**我们自己的代码**：**Apache-2.0**（原文见 `LICENSE`，取自 <https://www.apache.org/licenses/LICENSE-2.0.txt>；
SPDX 在 `Cargo.toml` 的 `license` 字段）。

宽松许可，含**显式的专利授权**（§3）：任何人都可以商用、闭源、修改、再分发，
只要保留版权与许可声明、并在改动过的文件里说明改过。
⚠️ 一句如实提示：这跟上一轮想要的「不让企业用」**正好相反** —— Apache-2.0 是企业法务最友好的
选择之一。若哪天想改回去，`PolyForm Noncommercial 1.0.0`（禁商用）或 `BSL 1.1`（先禁商用、
到 change date 自动转宽松）都是一处改动的事。

本仓里有**两块不是我们写的**东西，各自的许可与出处写在 `THIRD-PARTY.md`：

- `crates/rustls/` —— vendored 的 **rustls 0.23.45**（Apache-2.0 / ISC / MIT，原文随副本一起在
  `crates/rustls/LICENSE-*`），9 个文件带 `FORK(utls-rs)` 标记，补丁在 `crates/rustls-fork/`；
- 从 **`refraction-networking/utls`**（BSD-3-Clause）派生的**夹具与表**：`tests/fixtures/utls-testdata/`、
  `utls-reference.json` / `utls-randomized.json`、以及逐条抄录的预设/权重表。
  搬这些是因为本仓的判据是「与参照实现逐字节一致」—— 判据必须带着上游的原始字节。
