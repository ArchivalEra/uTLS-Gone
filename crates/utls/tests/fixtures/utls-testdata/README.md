# uTLS 自带 `testdata/` 抓包夹具（对账用的外部判据）

这个目录里的 55 个文件是**原样复制**自 `refraction-networking/utls` 仓库的 `testdata/`
目录。它们是 uTLS 自己的测试套件跑出来的 ClientHello 录音 —— 也就是**上游认下的标准答案**。

对账代码在 [`../../utls_testdata.rs`](../../utls_testdata.rs)；跑法：

```bash
cargo test -p utls --test utls_testdata -- --nocapture   # 加 --nocapture 才看得到跳过清单
```

## 出处（provenance）

| 项 | 值 |
|---|---|
| 仓库 | `github.com/refraction-networking/utls`（module 路径与上游 `go.mod` 一致，`go 1.26`） |
| 快照 | `/tmp/utls-ref/u.tgz`，sha256 `ae5e90b0ded831ced64f6fc2e029fefc7b41632a5d13c7e53d9d197a8337016b` |
| 取得时间 | 2026-09-30 |
| **上游 commit** | **未知** —— 这份快照来自一个 tar 包，**不含 `.git` 元数据**。所以下面用文件哈希当锚点 |

没有 commit 就用**内容哈希**钉住：我们引用/依赖的上游源文件逐个列在这里，改动其中任何一个
都意味着引用它的行号与结论需要重新核对。

| 文件 | sha256 |
|---|---|
| `handshake_client.go`（`hostnameInSNI`） | `63d541ff…3120c5` |
| `handshake_client_tls13.go` | `5872beb4…7a127` |
| `u_parrots.go`（预设表、`ShuffleChromeTLSExtensions`、`ApplyPreset`） | `122612d4…c5f108` |
| `u_conn.go`（`ApplyConfig` / `SetSNI` / `RemoveSNIExtension` / `MarshalClientHello`） | `d83957a1…4658b` |
| `u_tls_extensions.go`（`SNIExtension` 等） | `2a087a02…e7ab` |
| `u_common.go` | `e42122a4…13e545` |
| `handshake_test.go`（`testConfig`） | `3e930d78…1e9846` |
| `handshake_client_test.go` | `8283c119…deba4d4` |
| `u_conn_test.go`（夹具名的构造点、`getUTLSTestConfig`） | `ac7c3fc6…45cfcf` |
| `u_fingerprinter_test.go`（内联的真实捕获） | `6ca7c91f…78cd89` |
| 整个 `testdata/`（181 个文件的 `sha256sum` 再取哈希） | `6a22327c365fd9900795482e986de6aa55892f2f7ca183b90ad70d2159a2b6c9` |

本目录只复制了其中 **55 个** `Client-TLSv12-UTLS-*` / `Client-TLSv13-UTLS-*`
（即 uTLS 用自己预设跑出来的那些）。`Client-TLSv1*` 其余文件是 Go 标准库
`crypto/tls` 默认路径的录音，与本 crate 的指纹层无关，没有复制。

## 格式：Go 的文本十六进制转储（一处坑）

```
>>> Flow 1 (client to server)
00000000  16 03 01 02 00 01 00 01  fc 03 03 00 00 00 00 00  |................|
```

每行是 `偏移 + 8 字节 + 8 字节 + |ASCII|` —— **两组 8 字节**。
只按「第一组」解析会丢掉每行的后半段，而症状只是「对不上」，不报错。
（本仓的第一版对账脚本就是这么丢了一半字节的。）

`Flow 1` 是客户端发的第一条 ClientHello（`Flow 3` 是 HRR 之后的第二飞，本对账不看它）。
夹具整体是**记录**：前 5 字节是记录头（`16 03 01 <u16 长度>`），去掉它才是握手消息。

## 对账口径：什么必须逐字节相同

拿 `Flow 1` 与我们产出的**整条握手消息**比，这些必须完全相同：

| 字段 | 依据 |
|---|---|
| `legacy_version` | 夹具是确定的 |
| 32 字节客户端随机数 | uTLS 的测试配置是 `Rand: zeroSource{}` ⇒ 夹具里是 32 个零；我们直接给零 |
| 32 字节 session id | 同上（`u_parrots.go` 的 `ApplyPreset` 用 `config.rand()` 抽它）⇒ 夹具是 32 个零。我们这边把它从 `SessionId::Random(32)` 换成 `Fixed(32 个零)`（**唯一一处对 spec 的改写**） |
| 密码套件（数量、顺序、取值） | 全序严比 |
| 压缩方法 | 严比 |
| 扩展的**数量、顺序、类型、体** | 这些夹具的预设**全是 `Stable`**：乱序是 Chrome 106 才引入的（`ShuffleChromeTLSExtensions` 的注释），而夹具里最"新"的预设是 Chrome-70 / Firefox-63 |
| 整条消息的长度 | 填充由总长决定，而总长里没有任何随机值 |

折成哨兵的（**每连接随机**，因此不可比）只有：

- **GREASE 取值**：密码套件里那个、扩展类型本身、`supported_groups` / `supported_versions` /
  `key_share` 里的那些 —— 都折成 `0x0a0a` 再比。`Chrome-58` 的第一个密码套件是
  `0x8a8a`、夹具里是 `0x0a0a`，这不是缺陷；
- **`key_share` 的公钥字节**：我们给的是哑字节，uTLS 给的是真密钥 ⇒ 只比**长度**；
- **GREASE-ECH 的整个体**：夹具里没有带 GREASE-ECH 的预设，这一支是为将来留的。

## 夹具名就是配置（分类规则）

uTLS 的 `clientTest.name` 由 `"UTLS-" + 密码套件 + "-" + hello.helloName() + 后缀` 拼成，
而 `helloName()` 就是 `ClientHelloID.Str()`（如 `Chrome-70`）。所以预设直接从名字尾部读出，
不需要手抄一张 55 行的表 —— **手抄的表会漂，而名字不会**。

| 规则 | 依据 |
|---|---|
| 默认：预设取自名字尾部，SNI = `foobar.com` | `getUTLSTestConfig()`（`u_conn_test.go:243-256`）里 `ServerName: "foobar.com"` |
| `…-EmptyServerName` ⇒ SNI = `""` | `TestUTLSEmptyServerName`（`u_conn_test.go:218`）设 `config.ServerName = ""` |
| `…-ServerNameIP` ⇒ SNI = `1.1.1.1` | `TestUTLSServerNameIP`（`u_conn_test.go:202`）设 `config.ServerName = "1.1.1.1"` |
| `…-OmitSNI` ⇒ **删掉 SNI 槽位** | `TestUTLSRemoveSNIExtension`（`u_conn_test.go:189`）调 `RemoveSNIExtension()` |
| `…-fingerprinted` ⇒ SNI = `foobar`（无 `.com`） | `u_fingerprinter_test.go:519/554` 里 `serverName := "foobar"` |
| `Client-TLSv13-UTLS-HelloRetryRequest-Chrome-70` ⇒ SNI = `""` | `TestUTLSHelloRetryRequest`（`u_conn_test.go:174`）用 `testConfig.Clone()`，而 `testConfig`（`handshake_test.go:458`）**不设 `ServerName`** |
| `Client-TLSv12-UTLS-setclienthello-…-Chrome-58` ⇒ 随机数钉死 | `u_conn_test.go:509-517` 在 `BuildHandshakeState()` 之后 `SetClientRandom([]byte("Custom ClientRandom h^xbw8bf0sn3"))` |

**HRR 那一条曾经被误判**（本仓的对账把它标成「夹具 provenance 不明：缺 SNI」）。
结论是**我们错、夹具对**：`hostnameInSNI("")` 返回空串 ⇒ `SNIExtension.Len() == 0` ⇒
线上零字节（而槽位仍在列表里参与洗牌）。三条夹具同证此事：
`…-EmptyServerName`、`…-ServerNameIP`（IP 字面量同样被 `hostnameInSNI` 判空）、
以及这条 HRR（配置不设 ServerName）。修复见 `crates/utls/src/hello/encode.rs` 的
`hostname_in_sni`。

## 跳过（16 条，逐条给理由）

跳过**必须带理由并打印** —— 安静的跳过看起来像通过。当前 16 条分三类：

1. **9 条 `Golang-0`**：`HelloGolang` 在本架构里没有 spec（`SpecError::EngineDefined`）。
   它的意思是「用引擎自己的 ClientHello」，在 Rust 侧对应 rustls 自己那套，
   **不属于本 crate 的指纹层** —— 这是结论，不是待办。
2. **5 条是上游的 0 字节文件**：`…-AES128-GCM-SHA256-Firefox-55`、
   `…-ECDHE-ECDSA-…-Chrome-58` / `-Chrome-70` / `-AES256-GCM-SHA256-Chrome-70`、
   `…-ECDHE-ECDSA-…-Chrome-58setclienthello`。
   `ls -l` 可验：它们在上游仓库里就是**空的**。理由：uTLS 的测试先
   `O_CREATE|O_TRUNC` 打开录音文件、再跑握手，握手失败时 `t.Fatalf` 直接退出，
   录音没写，留下一个 0 字节文件并被提交进仓库。
   这条按**文件事实**（长度 == 0）判，不按名字列表判：上游哪天填上了，这里会自动开始比它。
3. **2 条无法从名字推出配置**：
   - `…-ECDHE-RSA-AES128-GCM-SHA256-Chrome-58setclienthello`：当前源码里**没有任何测试**
     构造这个名字（`helloName()` 只会返回 `ClientHelloID.Str()`，而 `Str()` 不带这个后缀），
     且它长 188 字节、与现行 Chrome-58 的 230 字节完全不同 —— 是更早版本留下的录音，
     拿它当判据等于拿一个过期的答案判我们。
   - `…-TLS_AES_128_GCM_SHA256-raw-capture-fingerprinted`：uTLS 的 `Fingerprinter` 会把
     捕获里的 SNI 丢掉、由 `config.ServerName` 重新填上，并重算填充；复现它需要
     「把反解出的 Opaque SNI 换回 `ServerName` 槽位」这一步。**它依赖的那条捕获本身**
     （`u_fingerprinter_test.go:695` 的内联十六进制，一个真浏览器发往
     `people-pa.clients6.google.com` 的握手）已经单独对账，而且覆盖更强 ——
     见 `fixtures/raw-capture.bin` 与测试 `real_world_client_hello_round_trips`。

## 怎么从更新的上游刷新

```bash
# 1. 取新快照（本机 proxy.golang.org 不通，走 goproxy.cn）
export PATH="$HOME/.local/go/bin:$PATH" GOPROXY=https://goproxy.cn,direct
# 2. 覆盖本目录里的 55 个文件，并更新上面的快照哈希表
# 3. cargo test -p utls --test utls_testdata -- --nocapture
```

上游加了新预设的夹具时，`classify()` 会**响亮失败**（「尾部不是任何一个已知预设串」）
而不是静默跳过 —— 那时去核对 `u_parrots.go` 的 `ClientHelloID.Str()` 再补表。
