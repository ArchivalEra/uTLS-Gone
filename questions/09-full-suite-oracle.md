# 09: 「跑通 uTLS 原版测试」到底卡在哪

**Status:** resolved

结案日期：2026-10-01（**当日修订**：加上了「那两条也真跑通」的办法）。

## 结论（最终版）：**原版全量套件全部通过，一条都没跳**

在一份**干净检出**（codeload master tarball，不含我们加的探针）上：

```bash
go test -count=1 -timeout 480s ./...        # 注意：**没有** -skip
# ⇒ ok  github.com/refraction-networking/utls  2.952s
# 逐条计数：222 PASS / 0 FAIL / 1 SKIP
```

那一条 SKIP 是**上游自己**跳的：`u_conn_test.go:63`
`t.Skip("Skipping golang parroting tests until adjusting for new fingerprints")`
—— 与网络无关、与我们的环境无关。

**Settling:** `cd <干净检出的 uTLS 树> && go test -count=1 -timeout 480s ./...` —— rc=0 且末行是 `ok` ⇒ 结论成立；rc≠0（或出现 `--- FAIL`）⇒ 结论要改

## 怎么让那两条「要真外网」的测试真跑

> **⚠️ 本节已退役（2026-10-01）。** 现在有一条**不碰系统、不用代理**的路：
> `sh crates/utls/tests/fixtures/gen-reference/run-upstream-suite.sh <参照树>` ——
> 它只把那两条测试**拨号的目标域名**换成直连可达且判据等价的 `www.baidu.com`
> （用 `go -overlay` 在构建期替换，上游树磁盘上一字节不动）。
> 下面这段代理配方**保留为历史记录**（它是当时唯一能让**完全未改动**的上游树跑通的办法，
> 也是 `R-005` 的取证过程），但**不再是推荐路径**；转发器脚本已随退役一并删除。

`TestVerifyHostname`（拨 `www.google.com:443`）与 `TestRealResumption`（`yahoo.com`）
在**不使用代理**时挂住（拨号被黑洞，不是拒连）。而本机**有**一个 `127.0.0.1:2080` 的
**SOCKS5h/HTTP 代理** —— 卡点只是 **Go 的 `net.Dial` 不认代理环境变量**
（`ALL_PROXY` 只对 `net/http` 生效）。所以「本机不可达」这个归因**不完整**，已登记为 `R-005`。

当时的两步（只碰本机，不改上游一行；转发器脚本**已删除**，要重现得自己再写一个）：

```bash
# ① 两个名字指到两个回环地址（443 是特权端口，所以要 sudo）
printf '127.0.0.2 www.google.com\n127.0.0.3 yahoo.com www.yahoo.com\n' | sudo tee -a /etc/hosts
# ② 两个走 SOCKS5h 的转发器，各接住一个回环地址的 443（脚本曾入库在
#    crates/utls/tests/fixtures/gen-reference/probes/socks5fwd.py，现已退役删除）
sudo python3 /tmp/socks5fwd.py 127.0.0.2 443 www.google.com 443 &
sudo python3 /tmp/socks5fwd.py 127.0.0.3 443 yahoo.com 443 &
# ③ 现在可以不带 -skip 跑全量
cd /tmp/utls-ref/utls-master && go test -count=1 -timeout 480s ./...
```

转发器当时做的事：接受本地连接 → 与 `127.0.0.1:2080` 做 SOCKS5 无认证握手 →
`CONNECT host:port`（**socks5h**：把**名字**交给代理解析，所以 google 的 DNS 污染不影响它）
→ 双向泵。实测两条隧道都拿到真证书（`www.google.com` / `yahoo.com` 的 CN 正确、TLS 1.3），
两条测试各自 `--- PASS`。

**收尾**：跑完把那两行 `/etc/hosts` 删掉、转发器杀掉（不留系统改动）。

**为什么退役**：它每次都要求 sudo 改 `/etc/hosts` 再手工收尾，把「跑一遍判据」变成一件
会留系统改动的事；而换域名那条路一条命令、无副作用、判据等价（两条测试判的机制与对端是谁无关）。
**代价如实记下**：退役后我们失去了「**完全未改动**的上游树跑那两条测试」的可复跑性 ——
那条路上的 222 PASS / 0 FAIL / 1 SKIP 仍记在上面（作为历史观测），但不再有人能一条命令重现它。


## 不带代理时的观察（仍然有效，只是不再是上界）

`go test -count=1 -timeout 480s -skip 'TestVerifyHostname|TestRealResumption' ./...`
在 1.6 秒内 PASS。三条证据各自独立：

| 类 | 测试 | 位置 | 不带代理时的表现 | 归因 |
|---|---|---|---|---|
| 需要真实外网 | `TestVerifyHostname` | `tls_test.go:524` | **挂起**（`net.Dial` 卡在 `www.google.com:443`） | 环境：拨号被黑洞（不是拒连，所以一直等） |
| 需要真实外网 | `TestRealResumption` | `tls_test.go:547` | 同上（`yahoo.com`） | 同上 |
| BoringSSL bogo shim | `bogoShim` | `handshake_test.go:413` | **默认不跑** | 在 `-bogo-mode` 标志后面；`handshake_test.go:421-422` 的那行调用是**注释掉的** |
| 其余全部 | — | — | **通过** | — |

两条外网测试都在函数第一行调 `testenv.MustHaveExternalNetwork(t)`，而那个辅助函数
在 `testing.Short()` 为真时 **skip** —— 所以 `-short` 能过不是「短版通过」，
而是**恰好只跳掉了这两条**。

定位方式（可复跑）：`go test -count=1 -timeout 60s -v .` 的最后一行 `=== RUN` 是
`TestVerifyHostname`，panic 的 goroutine 栈顶是
`net.(*netFD).connect` ← `net.(*sysDialer).dialParallel` ⇒ 是**拨号**卡住，不是握手卡住。
（另一个佐证：本机 DNS 对 `www.google.com` 返回的是 `157.240.7.20` —— 一个 **Meta** 段地址，
而到它没有路由；也就是被拦截过的答案。）

## 这意味着什么

- 原版套件是**健全的 oracle**，而且**没有任何一条需要靠跳过才能过**。
- 反过来说：**不存在**「因为 uTLS 自己在某个测试里挂了所以拿不到判据」这种情况。
  原版测试测的是 Go 实现；判**我们**的那一半由夹具对账与自建端到端补
  （`utls_testdata.rs`、`utls_conformance.rs`、`hello_retry_e2e.rs`、ECH 三层判据）。

## 复跑

```bash
export PATH="$HOME/.local/go/bin:$PATH" GOPROXY=https://goproxy.cn,direct
cd /tmp/utls-ref/utls-master
go test -count=1 -timeout 480s ./...      # 需要上面那两步（否则去掉 -skip 会挂）
```

**Type:** question

- [x] 定位到具体哪条测试挂（`TestVerifyHostname`，拨 `www.google.com`）
- [x] 枚举全部需要外网的测试（只有两条，都在 `tls_test.go`）
- [x] 查清 bogo shim 默认不跑（在 `-bogo-mode` 之后，且调用点被注释）
- [x] 用 `-skip` 证明「除那两条之外全通过」（rc=0，1.6 秒）
- [x] **修订**：用 SOCKS5h 代理（`/etc/hosts` + 转发器）让那两条**真跑**，
      全量 `./...` 无跳过 ⇒ 222 PASS / 0 FAIL / 1 SKIP（那条 SKIP 是上游自己的）
- [x] 结论回填，`Status:` 改 `resolved`
