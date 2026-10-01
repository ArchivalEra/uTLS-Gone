# Handoff —— 给下一个会话 / 接手维护的人

本仓的目标：用纯 Rust 完整复刻 [`refraction-networking/utls`](https://github.com/refraction-networking/utls)。
判据不是「能编译」「像不像」，而是**跑通原版仓库自己的测试**，加上一批可复跑的离线判据。
这份文档只讲三件事：**现在到哪了**、**环境里哪些东西不在仓库里**、**踩过哪些代价高昂的坑**。

## 一句话现状

判据全绿，而且没有一条靠跳过：

- 原版 `go test` 全量（**不带 `-skip`**）通过：222 PASS / 0 FAIL / 1 SKIP
  （唯一那条 SKIP 是上游自己 `t.Skip` 的）。**两条路都能跑到这个数**：一条经本机
  SOCKS5h 代理跑**未改动**的上游树，另一条**无代理**——只把那两条测试拨号的目标域名
  换成直连可达者（`run-upstream-suite.sh`，上游树磁盘不动）。配方见下面「环境」，
  两条路的区别（为什么它们是**两个**判据）见 `gen-reference/README.md`。
- 原版 `testdata/` 夹具 39 条逐字节一致；原版参照产出（预设指纹、随机化族）逐字段对账。
- **真实 ECH 的接受那一半通了**：Cloudflare、defo.ie、test.defo.ie 三族服务器都报 `Accepted`；
  另有一条离线判据（我们的客户端 ↔ uTLS 自己的 ECH 服务端）。
- `cargo test --workspace` 全绿、`cargo clippy --workspace --all-targets` 0 警告、
  五道闸门 + 自证全绿、`questions/` **10 条全部结案**。
- **P-256 已鉴定**（`crates/utls-engine/tests/p256_handshake.rs`，三条真握手判据）：
  真实预设（Firefox 的 `key_share = [X25519, P-256]`）里服务端能在**第一飞**选中它、
  只给 P-256 也谈得成、服务端强要 P-256 时第二飞带上新的 P-256 共享也谈得成。
- **混合组 `X25519MLKEM768(4588)` 已鉴定**（`crates/utls-engine/tests/mixed_group_handshake.rs`，
  三条真握手判据）：Firefox 148 的 `[4588, X25519, P-256]` 在服务端只认 4588 时于**第一飞**
  被选中并谈成、只给它一把也谈得成、服务端强要它时第二飞带上**新的** 1216 字节共享也谈得成。
  ⇒ 引擎组列表里**每一个会被真实预设发出去的组**都有一条正向结论了。

## 先读这三份，别重复推导

- [`STATE.md`](../STATE.md) —— 活状态。含已知缺口与教训，正文只引用台账键 `[[键名]]`。
- [`AGENTS.md`](../AGENTS.md) —— 在本仓工作的硬规矩（事实系统怎么用、闸门怎么跑）。
- [`questions/10-ech-acceptance-falsified.md`](../questions/10-ech-acceptance-falsified.md) ——
  ECH 那条线的**全部证据**（已 resolved）：三处真 bug、逐变量二分、三族服务器各自把什么当判据。
  **别再从头查一遍。**

代码分工：`crates/utls`（指纹层，零依赖引擎、零密码学）、`crates/utls-engine`（引擎胶水 + 密码学）、
`crates/rustls`（vendored fork，9 个文件带 `FORK(utls-rs)` 标记）、
`crates/rustls-fork/{patch.diff,README.md}`（补丁产地与**双重**判据）。

## 环境：这些不在仓库里，换台机器就没有

- **uTLS 源码树**（几条离线判据要在它上面跑）。取回是一条命令，**注意别写死顶层目录名**：

  ```bash
  export PATH="$HOME/.local/go/bin:$PATH"
  mkdir -p /tmp/utls-ref/utls-master
  curl -sSL -o /tmp/utls-master.tar.gz \
    https://codeload.github.com/refraction-networking/utls/tar.gz/refs/heads/master
  # codeload 的顶层目录名随 ref 而变（分支是 `utls-master/`、tag 是 `utls-1.8.2/`），
  # 写死 `mv utls-master-*` 会踩空 —— CI 上实测踩过。
  tar xzf /tmp/utls-master.tar.gz -C /tmp/utls-ref/utls-master --strip-components=1
  ```

  本轮那份 tarball 的 sha256、以及「**别改用 v1.8.2**」的原因（它把 ALPN 收进 `0xfd00` 标记，
  与 master 语义不同）记在 [`gen-reference/README.md`](../crates/utls/tests/fixtures/gen-reference/README.md)。
- **Go 工具链**：`~/.local/go`。模块代理用 `GOPROXY=https://goproxy.cn,direct`
  （本机 `proxy.golang.org` 不通）；GitHub runner 上不需要这个镜像。
- **探针**：`gen-reference/probes/*_test.go` 是要**复制进**那棵树才能跑的（`package tls`）。
  只复制 `ech_*_test.go`：同目录还有 `main.go`（`package main`），整个目录拷进去会让
  `go test` 直接 `setup failed`。`ech_utls_server` 那条测试会自己复制它需要的那个探针。
- **那两条要真外网的原版测试**（`TestVerifyHostname` 拨 `www.google.com`、`TestRealResumption`
  拨 `yahoo.com`）现在只有**一条**推荐路径 —— 把目标域名换成直连可达、判据等价的
  `www.baidu.com`：

  ```bash
  sh crates/utls/tests/fixtures/gen-reference/run-upstream-suite.sh /tmp/utls-ref/utls-master
  # ⇒ 上游套件（无代理 · 不 -skip）：顶层 222 PASS / 0 FAIL / 1 SKIP
  ```

  它**不改上游树**：改写稿只在临时目录里，靠 `go -overlay` 在**构建期**替换 `tls_test.go`。
  为什么换域名不算放宽判据、以及为什么 `www.jd.com` 没被选中（实测 4 次里 1 次不复用），
  见脚本与 `gen-reference/README.md` 的文件头。

  **⚠️ 另一条路（经 SOCKS5h 代理 + `/etc/hosts` 跑「完全未改动」的上游树）已于 2026-10-01 退役**：
  它每次要 sudo 改 `/etc/hosts` 再手工收尾，把「跑判据」变成一件会留系统改动的事；
  转发器脚本已删。配方与当时的观测（222/0/1）保留在
  [`questions/09`](../questions/09-full-suite-oracle.md) 作历史记录。
  **代价**：失去了「完全未改动的上游树」那条路的可复跑性 —— 那条判据现在只剩历史观测。

## 判据怎么跑

本地最快的一条路：

```bash
cargo test --workspace && cargo clippy --workspace --all-targets   # 离线全绿 / 0 警告
for g in zreflect/check_*.py; do python3 "$g"; done && sh gates-selftest.sh
```

要真网络或要参照树的那几条（默认 `#[ignore]`，README 的「跑一遍」一节列了全部）：

```bash
cargo test -p utls-engine --test ech_inner_utls                    # 内层与 uTLS 逐字节相同（离线）
cargo test -p utls-engine --test ech_utls_server -- --ignored      # 过 uTLS 自己的 ECH 服务端（离线）
cargo test -p utls-engine --test ech_e2e -- --ignored              # 真实 ECH 端点（联网）
cargo test -p utls-engine --test end_to_end -- --ignored           # 指纹层联网对账
```

CI（[`.github/workflows/ci.yml`](../.github/workflows/ci.yml)）跑六组：`rust`、`gates`、
`patch-repro`、`ech-offline`、`upstream`、`upstream-no-skip`。**联网判据、那两条 ECH/egress
测试、以及基准**不在 CI 里，理由与本地跑法写在那个文件头上。

## ECH 那条线：三处修复（现在是绿的，但别再犯）

1. **fork**：内层转录里的 session id 必须是**外层线上**那个。`emit_external_client_hello`
   曾把引擎自造的值交给 `EchState::from_supplied`，两边哈希的内层差 32 字节 ⇒
   服务端按接受走而我们判 `Rejected` ⇒ 密钥调度分叉 ⇒ `cannot decrypt peer's message`。
   修法是把消息解析提前、从字节里取。
2. **引擎**：内层按 uTLS 的模型造 —— **诚实的 hello**（引擎真实的套件/版本/ALPN）加上四个
   抄自预设的字段（keyShares / 曲线 / 签名算法 / sessionId），**不是**「外层的过滤版」
   （那是 rustls 的做法）。修完与 uTLS 的产出**逐字节**相同。
3. **引擎**：ECH 路径要去掉外层 `key_share` 里的 **GREASE 项**。DEfO/OpenSSL 系服务器否则回
   `illegal_parameter`；逐变量二分在 `ech_e2e.rs` 里（只去它 ⇒ Accepted，只去别的 ⇒ 仍拒）。
   真实 ECH 客户端本来就不发 GREASE keyshare，所以只在 ECH 路径上 scrub，非 ECH 指纹一字节不动。

## 补丁与事实系统

**补丁有两条判据，两条都要过**（细则见 [`rustls-fork/README.md`](../crates/rustls-fork/README.md)）：

1. `patch.diff` 的文件数 == 带 `FORK(utls-rs)` 标记的文件数（台账事实 `fork_patch_matches_markers`）；
2. 把它打到一份**全新的原始 rustls 0.23.45** 上，得到的树要与 `crates/rustls` **逐文件相同**。

第 2 条是被一次事故换来的：第 1 条过、补丁却是旧的（那一轮新改的文件没进补丁，测试照样全绿）。
CI 的 `patch-repro` job 现在把两条都跑。

事实系统的顺序别弄反（详见 `AGENTS.md`）：

```bash
python3 zreflect/facts.py                  # 量一遍；掉条/改口会拒绝写盘（rc=2）
python3 zreflect/facts.py --accept-changes # 逐条确认确属实测后再接受
python3 zreflect/facts.py --render-doc STATE.md
for g in zreflect/check_*.py; do python3 "$g"; done && sh gates-selftest.sh
```

- 正文只许引用**键名** `[[键名]]`，别手抄数字；`Settling:` 行必须含 `rc=` / `⇒` / `=>`
  （只写「做法」不写「两种结论」会被悬案闸门拒；写成多行、判别符号落在第二行也会被拒）。
- **第五道闸门 `zreflect/check_cmds.py` 会把台账里每条 `cmd` 真的跑一遍**（~300 条共用一个
  `cargo run` 生产者，做了合并所以是秒级）。它上线第一天就抓到：一条 bash 专属写法
  （`diff <(…) <(…)` 在 dash 下 exit 2）、它自己一个取值正则的洞、以及四条陈旧事实。
  **改 `cmd` 要记住它是被真跑的**：必须 POSIX sh，取值口径见该文件顶部。
  它在 CI 里认 `REFLECT_CMDS_SKIP`（显式跳过 `rustc_version,cargo_version` 这两条**机器相关**的，
  跳过会打印出来；默认一条不跳）。
- 加 `.md` / `.rs` 会改 `md_files` / `rs_files` 这类事实 —— 记得重测。

## 速度 / CPU（要引用这些数字时，先看它们是怎么量的）

同层、同工作量的两个基准（都在库里）：

| 侧 | 程序 | 动作 |
|---|---|---|
| 本仓 | `crates/utls-engine/examples/plan-cost.rs` | `FingerprintClient::plan()`（起真密钥交换 + 编码 + 记账） |
| uTLS | `crates/utls/tests/fixtures/gen-reference/bench/main.go` | `tls.UClient(...) + BuildHandshakeState()` |

在 Ryzen 9 3900X 上**把每进程固定开销与每条 hello 的边际成本分开量**：

| | 每进程固定开销 | 每条 ClientHello 的边际 CPU |
|---|---|---|
| uTLS（Go） | 1.9 ms | 151 µs |
| 本仓（Rust, release） | 0.7 ms | 26 µs |

模型校验：同一进程跑 4800 条，实测 Go 0.692 s / 本仓 0.118 s（预测 0.728 / 0.124）。
⇒ 同样的活，本仓 CPU 约 1/6。两个陷阱都踩过：
① **层要对齐** —— 拿指纹层的 `marshal` 去比 `UClient` 会得到虚高的倍数（第一版报的 29× 就是错的）；
② **别只跑少量条就报「µs/条」** —— 那时成本几乎全是每进程启动开销（跑 48 条时看着 700 µs/条，
其实是 33 ms 启动 ÷ 48）。

**预设覆盖**：40 档里 **39 档**能过引擎那条路（`cargo run --release --example plan-cost`
打两份名单，被拒的带原因）。唯一被拒的 `HelloCustom` = 空 spec，理由「没有密码套件」。
原先发不出去的两类现在都有判据：
- **TLS 1.2 时代 8 档**（Chrome 58/62、Firefox 55/56、Ios 11/12、Android 11、360 7）：
  `tests/tls12_presets.rs` —— 7 档真谈成 `TLSv1_2`；`360_7` 与 rustls 的 6 个 TLS 1.2 套件
  **交集为 0**（它 20 个全是 CBC/RC4/3DES）⇒ 服务端 `HandshakeFailure`，那是套件的性质。
  ⚠️ 这一档的 config 必须**只开 1.2**，否则降级哨兵会被判成降级攻击（Go/uTLS 同样）。
- **PQ 3 档**（ChromePq 115/120、ChromePsk 115）：`tests/pq_key_share.rs` —— 草案组
  `0x6399` 发**长度正确**的占位公钥（形状、总长与 uTLS 一致），真交换只交 X25519；
  服务器认草案组并选中它时**响亮失败**，不静默换组。

## 两处「只有跑起来才会知道」的补丁缺陷（本轮新增，已修）

都在 `crates/rustls-fork/README.md` 的缺陷表里（第 5–7 条），这里只记教训形状：
**外供路径绕过了「引擎自建 ClientHello」时顺手设置的那些状态**，于是每一样都要显式补上。
本轮补的三样：内层转录的 session id（ECH）、TLS 1.2 主密钥 PRF 用的 client random、
以及「调用方字节里没有 `key_share` 时就别造一把」。共同判据：**线上的是事实**。

## 代价高昂的坑（别重犯）

- **`complete_io` 把 TLS 错误包成 `io::Error`**（rustls 的错误是它的 `source`，用
  `get_ref().downcast_ref::<rustls::Error>()` 取回）—— 否则拿不到 retry configs 那种结构化信息。
- **阻塞 socket 上别用「读一个字节推动握手」**（会死等服务端，它也在等你的请求）；用 `complete_io`。
- **服务端装置要设读超时**，否则握手中途失败会挂在 `join()` 上。
- **会话复用的前提是验签器「指针相同」**（rustls 用 `Weak::ptr_eq` 比）：每条连接新建
  `ClientConfig` 会让复用**静默**失效 —— 症状看起来像 PSK 写错了。
- **内层的两种形态**：`0xfd00` 是**加密进去**的形态，**转录**用展开形态（服务器重建的那份）；
  弄混的症状是「服务端接受了而密钥分叉」。我们两个都产出，并有逐字节判据。
- **JA3 只覆盖扩展类型**（不覆盖体长、内容、顺序）——「JA3 全绿」从来不是保真证据。
- **Go 的 `||` / `&&` 里掷币在左侧**（掷币总会发生）；`Shuffle` 用 Lemire `int31n`、
  `Intn` 用拒绝采样（两个不同算法）。
- **`/tmp` 会被清**；**参照树取回时别写死顶层目录名**（见「环境」）。

## 还没做

**「完全等价」还差哪些，看 [`utls-parity.md`](utls-parity.md)** —— 那是唯一的口径，
本文件不再另抄一份（抄两份就会漂）。摘要：

- **指纹/握手判据缺口：无**。此前唯一没判过的那一格（混合组 `X25519MLKEM768(4588)`
  没有正向结论）已补齐，见 `crates/utls-engine/tests/mixed_group_handshake.rs`。
- **真缺口清零**：QUIC 指纹层（编码 + 接缝）、`ClientHelloSpec` 的 JSON 格式、
  Fingerprinter 的三条捕获判据、**early data（0-RTT，TCP）**本轮全部补上并各有判据。
- **不重写**：上游那些测 Go 引擎本身的用例（服务端、记录层、密钥计划、QUIC 连接状态机）。
- **无 oracle**：`Roller` —— 上游自己零测试。

**加固**（判据都绿，只是能更省事）：

- 把「补丁可重现」的第 2 条也在**本地**做成一条命令（CI 里已经有了，本地要手工两步）。
- 把那两条外网测试的转发器做成一条命令（现在三步；脚本已入库）。
- `security-audit`：fork 的补丁改了握手与 ECH 路径，值得一次专门审计。
