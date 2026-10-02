# Handoff —— 给下一个会话 / 接手维护的人

本仓的目标：用纯 Rust 完整复刻 [`refraction-networking/utls`](https://github.com/refraction-networking/utls)，
并补上它生态里最大的生产消费者 —— **XTLS/REALITY** 的 Rust 等价实现。
判据不是「能编译」「像不像」，而是**跑通原版仓库自己的测试**，加上一批可复跑的
离线判据与**真栈**集成测试（stock Xray-core、真实 ECH 端点）。

**当前状态：已发 release [`v0.1.0-reality.1`](https://github.com/ArchivalEra/uTLS-Gone/releases/tag/v0.1.0-reality.1)
（2026-10-01），CI 七个 job 全绿，uTLS 等价物与 REALITY 的判据缺口均清零。**
「还剩什么」的权威口径在 [`utls-parity.md`](utls-parity.md) 与
[`questions/11-reality-rust-port.md`](questions/11-reality-rust-port.md)。

## 一句话现状

- 原版 `go test` 全量（**不带 `-skip`**）通过：222 PASS / 0 FAIL / 1 SKIP
  （那条 SKIP 是上游自己跳的）。两条路都能跑：**无代理**（换拨号域名，
  `gen-reference/run-upstream-suite.sh`，上游树磁盘不动）与**经代理跑未改动树**
  （已退役，`questions/09` 留历史）。
- 原版 `testdata/` 夹具 39 条逐字节一致；原版参照产出（预设指纹、随机化族）逐字段对账。
- **REALITY 等价物**（issue #1，`crates/reality`）：鉴权 / KDF 对拍 / 镜像握手 /
  fallback 透传 / 客户端半边 / 参数面 parity / 明文流分半 —— **35 条判据全绿**，含
  **stock Xray-core 26.3.27 真栈**（鉴权成功 + 承载流量；未鉴权拿到与直连真站
  逐字节相同的证书链）。
- `cargo test --workspace --all-features`：205 条判据全过；
  `cargo clippy --workspace --all-targets --all-features` 0 警告；
  五道闸门 + 自证全绿；`questions/` **12 条全部结案**。
- **release/tag**：`v0.1.0-reality.1`（已推送远端，release 页面已建）。

## 先读这三份，别重复推导

- [`STATE.md`](../STATE.md) —— 活状态。含已知缺口与教训，正文只引用台账键 `[[键名]]`。
- [`utls-parity.md`](utls-parity.md) —— **「离真 uTLS/REALITY 等价物还差什么」的
  唯一口径**：上游每个测试族 → 四种判定（已判 / rustls 领地 / 无 oracle / 未做）。
- [`AGENTS.md`](../AGENTS.md) —— 在本仓工作的硬规矩（事实系统怎么用、闸门怎么跑、
  **绝不在 vendored 目录跑 rustfmt** —— 那条是用一次 68 文件的污染换来的）。
- [`questions/11-reality-rust-port.md`](questions/11-reality-rust-port.md) ——
  REALITY 的结案记录：协议形状、六个实测发现、判据清单与已知边界。

## 环境里哪些东西不在仓库里

- **Go 工具链**：`~/.local/go`（1.27）。模块代理用 `GOPROXY=https://goproxy.cn,direct`。
- **uTLS 参照树**：`/tmp/utls-ref/utls-master`（codeload tarball，取回命令见
  `gen-reference/README.md`；master 是移动靶，记「取回时刻 + tarball sha256」）。
  四支 ECH 探针、REALITY 的 Go 向量发生器、上游全套测试都要在这棵树上跑。
- **stock Xray-core**：`/tmp/xray-bin/xray`（官方 release zip，REALITY 真栈判据用；
  取法在 `tests/real_stack.rs` 的 `xray_bin()`，`REALITY_XRAY` 可覆盖路径）。
  没有它时该判据**如实失败**（不 skip）。
- 上述 `/tmp` 的东西**会被清**；重取命令都写在各自的 README/文件头里。

## 判据怎么跑

```bash
cargo test --workspace --all-features          # 全部离线判据（199+ 条）
cargo test -p reality --test real_stack -- --include-ignored   # REALITY 真栈（要 xray）
sh crates/utls/tests/fixtures/gen-reference/run-upstream-suite.sh \
   /tmp/utls-ref/utls-master                   # 上游全套，无代理，不 -skip（222/0/1）
sh crates/rustls-fork/verify-patch.sh          # 补丁双重判据 + 无标记污染检查
for g in zreflect/check_*.py; do python3 "$g"; done && sh gates-selftest.sh
python3 zreflect/facts.py                      # 重测台账（改口要 --accept-changes）
```

CI（[`.github/workflows/ci.yml`](../.github/workflows/ci.yml)）跑 **7 个 job**：
`rust`（fmt/clippy/test，全 feature）、`gates`、`patch-repro`（调
`crates/rustls-fork/verify-patch.sh`，两条半判据）、`ech-offline`、`upstream`
（`-skip` 两条 egress）、`upstream-no-skip`（全量，`-overlay` 换拨号域名）、
`reality-stack`（stock Xray 真栈）。

## 踩过哪些代价高昂的坑（一句话版；细节在各文件）

- **「线上的是事实」**：外供路径绕过了引擎自建 hello 时顺手设置的那些状态
  （Debug 契约、kx_state、EchStatus、内层转录 session id、TLS 1.2 的 client
  random、early-data 调度）—— 每一样都要显式补上，只有真跑才看得出来。
- **`take_for` 的匹配顺序**：多 key share + 混合组时，先按组精确匹配、
  再退回分量匹配 —— 顺序反了就是 `cannot decrypt peer's message`（缺陷表第 8 条）。
- **rustls 严格协商签名算法**，而浏览器指纹不报 Ed25519；REALITY 证书必须是
  ed25519 ⇒ fork 开关 `(j)`（`fork_use_certificate_signature_scheme`，默认关）。
- **HMAC 的输入是裸 32 字节 ed25519 公钥**，不是 SPKI；且 `Certificate` 消息体
  要 `certificate_request_context` 与每条目后的 u16 extensions（uTLS 解析器要求）。
- **镜像的 ECDH 输入是客户端 hello 里的 key share**，不是真站 serverShare。
- **镜像的组只有 X25519/X25519MLKEM768**（uTLS 客户端能力所致）；真站选别的组
  ⇒ 明确拒绝 ⇒ 回落透传。
- **rustls 的 TCP 0-RTT 只支持有状态恢复**；**早数据在外供路径要三件事**
  （调度 / `enable` / `derive_early_traffic_secret`，见 `early_data.rs`）。
- **`cargo fmt --all` 会污染 vendored 目录**（68 文件实测）—— 判据①′现在会挡。
- 复用测试的会话存储要**共享同一个 `Arc<ClientConfig>`**（rustls 按指针比验签器）。
- **`/tmp` 会被清**；codeload 顶层目录名随 ref 变 ⇒ 一律 `--strip-components=1`。

## 还没做（按 parity 文档的口径）

- REALITY：`Mldsa65Key/Mldsa65Verify`（ML-DSA-65 扩展签名，参照的可选增强）；
  「真站飞行中其余消息的逐字节镜像」只做到形状校验；HRR 不处理（参照同样如此，
  已知边界）。
- uTLS 侧：`HelloGolang` 是「不适用」结论（不是待办）；`spider_x/y` 等调用方
  应用逻辑同层不适用。
- 若上游改了 proto/指纹/组列表：`tests/parity.rs`、`utls_json_golden`、
  `utls_testdata` 会红 —— 红了就是提醒，不是坏事。

## 收尾状态（本次会话结束时）

- 主分支 `3f83653`，远端一致，工作区干净。
- release `v0.1.0-reality.1` 已建（GitHub Releases 页面 + tag）。
- 台账 331 条事实；`questions/` 11 条全部结案；`retractions.json` 5 条。
- 事实系统的 pre-commit 会重渲染、pre-push 会拒推不新鲜的块 ——
  **改动能影响事实时手动跑一次 `python3 zreflect/facts.py`**（它只重渲染不重测，
  这是上游机制缺口，见 `docs/upstream-issues-zcode-reflect.md`）。
