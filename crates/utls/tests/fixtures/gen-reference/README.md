# `utls-reference.json` 是怎么来的

**它是参照实现（Go 版 uTLS）的实际产出，不是我们转写的。** 这是本仓唯一一个
「数据不是我们自己产出的」的指纹来源，也正因为如此，它是最强的那条验收依据：
`crates/utls/tests/utls_conformance.rs` 拿它逐字段对账。

## 参照树（`/tmp/utls-ref/utls-master`）怎么取回 —— 及为什么它必须是这条路径

`/tmp` 会被清（本轮实测：隔了一天，整棵树没了），而四个 ECH 探针与
`ech_utls_server.rs` 都要在**那棵树上**跑。取回是**一条命令**：

```sh
export PATH="$HOME/.local/go/bin:$PATH" GOPROXY=https://goproxy.cn,direct
curl -sSL -o /tmp/utls-master.tar.gz \
  https://codeload.github.com/refraction-networking/utls/tar.gz/refs/heads/master
mkdir -p /tmp/utls-ref && tar xzf /tmp/utls-master.tar.gz -C /tmp/utls-ref \
  && mv /tmp/utls-ref/utls-master-* /tmp/utls-ref/utls-master
cp crates/utls/tests/fixtures/gen-reference/probes/ech_*_test.go /tmp/utls-ref/utls-master/
```

本轮取回的那份 tarball：sha256 `ae5e90b0ded831ced64f6fc2e029fefc7b41632a5d13c7e53d9d197a8337016b`
—— **master 是移动靶**，所以要把「取回时刻 + 这个哈希」一起记下；换了哈希就意味着
参照变了，得重跑一遍探针再改期望值。

⚠️ **别图省事改用 module proxy 的发行版**（`go mod download ...@v1.8.2` 也行得通，
但它**产出的内层与 master 不同**）：v1.8.2 把 **ALPN 收进了 `0xfd00` 标记**
（marker = `[13,5,16,51,10]`），master 则把 ALPN **内联**在标记之外
（`marshalMsgReorderOuterExts` 里那行 `if echInner && false`；marker = `[13,5,51,10]`）。
差别是**语义的**：压缩 ALPN 意味着内层用的是**外层**的 ALPN，而 master 的注释写明了
「内层的 ALPN 可能不同」，所以内联是对的。本仓跟 master（也已由三族真服务器的接受证实）。

## 四支 ECH 探针（都要在参照树里跑；它们**不改** uTLS 一行）

| 探针 | 它回答什么 |
|---|---|
| `ech_inner_probe_test.go` | uTLS 产出的**内层明文**（`tests/ech_inner_utls.rs` 逐字节比的基准） |
| `ech_decoder_probe_test.go` | uTLS 自己的**服务端解码器**吃不吃我们的字节（`parseECHExt` + `decodeInnerClientHello`） |
| `ech_confirmation_probe_test.go` | 服务器那 8 字节确认值到底是**哪串转录**算出来的（逐个候选反推） |
| `ech_server_probe_test.go` / `ech_server_live_test.go` | 让 **uTLS 自己的 ECH 服务端**跑我们的字节（离线喂字节 / 真监听一个端口） |

`ech_server_live_test.go` 由 `cargo test -p utls-engine --test ech_utls_server -- --ignored`
自动驱动（它自己复制探针、起服务端、连上去、断言两端都说「接受」）。

## 速度 / CPU 对比（两个基准，同层同工作量）

| 侧 | 程序 | 动作 | 对应参照实现 |
|---|---|---|---|
| 本仓 | `crates/utls-engine/examples/plan-cost.rs` | `FingerprintClient::plan()`（起真密钥交换 + 编码 + 记账） | `tls.UClient(...) + BuildHandshakeState()` |
| uTLS | `bench/main.go`（本目录，需自己的 go.mod，见文件头） | `build()` | 同上 |

```bash
cargo build --release --example plan-cost && ./target/release/examples/plan-cost   # 本仓（自报 units/checksum）
# Go 侧按 bench/main.go 文件头的三行 go.mod 建一个小模块再 go build
```

**测法（不照这个做会得到误导的倍数）**：

1. **单位要同层**：拿指纹层 `ClientHelloSpec::marshal`（只编码）去比 uTLS 的 `UClient` 路径
   会得到一个虚高的倍数 —— 本轮实测踩到过（看着 29×，其实两层东西不可比）。
2. **固定开销与边际成本分开量**：同一进程里跑 48 条时，「µs/条」几乎全是每进程启动开销。
   做法是「预设名拼错 ⇒ 0 条」量固定开销，同一批预设跑 n 与 10n 各一次解边际成本
   （`PLANCOST_RUNS` / `PLANBENCH_RUNS` 改每预设次数）。
3. **预设集合要对齐**：`plan-cost` 会打出它**能建**的那批（另有一批被拒，理由在它文件头）。

## 重新生成

```sh
# 1. Go 工具链（本机装在 ~/.local/go）
export PATH="$HOME/.local/go/bin:$PATH"
# 2. 模块代理：本机 proxy.golang.org 不通，用镜像
export GOPROXY=https://goproxy.cn,direct
# 3. uTLS 源码（用本地 clone，见 go.mod 的 replace）
curl -sL https://codeload.github.com/refraction-networking/utls/tar.gz/refs/heads/master \
  | tar xz -C /tmp/utls-ref --one-top-level=utls-master --strip-components=1
# 4. 跑生成器
cd crates/utls/tests/fixtures/gen-reference
go mod tidy && go build -o utlsref . && ./utlsref > ../utls-reference.json
```

## 它记了什么

每个预设：首次运行的完整 JA3 五元组（legacy_version / 密码套件 / 扩展 / 支持组 /
点格式）、JA3 文本与 MD5、ClientHello 总长，以及**跑 48 次**观测到的
`ja3_stable` / `len_stable` / 出现过的长度集合。

## 已知的边界

- uTLS 的乱序预设（Chrome 106 及以后）每次连接扩展顺序不同，所以对它们
  **只对账多重集，不对账顺序** —— 这不是放宽，那正是参照实现的行为。
- uTLS 的密钥共享是**真密钥**，这里是长度相同的哑字节。所以能对账的是
  **长度**与由长度决定的填充，而不是密钥内容。

## 随机化族（`utls-randomized.json`）

uTLS 的 `HelloRandomized{,ALPN,NoALPN}` 支持**固定种子**（`ClientHelloID.Seed`），
所以在固定种子下它的产出是确定的 —— 于是可以和静态预设一样逐字段对账。

```sh
cd crates/utls/tests/fixtures/gen-reference
go build -o utlsref . && ./utlsref randomized > ../utls-randomized.json
```

夹具是 **3 个 id × 8 个种子**，种子取 `[i; 32]`（i = 0..7），两边都好复现。
它比静态预设的对账**更强**：随机化指纹是一串加权掷币的结果，能对上说明的是
**整条取随机的流逐次对齐**，而不是「某几张表抄对了」。而且随机化 spec **完全不含 GREASE**，
所以扩展顺序与 JA3 都可以逐字比。

`crates/utls/src/hello/randomized_tables.rs` 是**生成**的，由
`extract-cipher-tables.py` 从 Go 源码提取（见该脚本的文件头）。

## `_PSK_` 预设：为什么生成器要开 `OmitEmptyPsk`

uTLS 的四个 `_PSK_` 预设（Chrome 100/112/114/115）在 spec 末尾放一条**空 PSK 扩展**。
**没有会话时 uTLS 直接报错**：

```
tls: empty psk detected; remove the psk extension for this connection or set OmitEmptyPsk
```

所以生成器里给 `Config` 开了 `OmitEmptyPsk = true` —— 那是 uTLS 自己认下的两条出路之一
（另一条是报错）。不开它，这四个预设**观测不到**，夹具里只会是一条错误。

对本层而言这条开关没有别的含义：`_PSK_` 的指纹就是「兄弟 spec + 一条不占字节的位置标记」，
所以对账时它比的是**其余部分**是否逐字一致。
