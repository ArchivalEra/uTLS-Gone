# 12: 镜像服务端的明文流需要可分半（issue #2）

**Status:** resolved

来源：issue #2（需求：镜像服务端的明文流需要可分半 —— 鉴权路径的 handler 无法双向并发）。
issue 只留需求；本单承接「怎么做、怎么判」。

## 现象（issue 原文的复述，已核对）

鉴权成功后交给 [`Handler`](../../crates/reality/src/server.rs) 的明文流
（`MirrorStream`）只有一个 `&mut self` 入口，没有 `into_split` / `try_clone`。
handler 里做双向 splice（反代部署里几乎唯一要做的事）需要两个方向**并发**推进，
一个 `&mut` 借不出两半；套 `Arc<Mutex<…>>` 则读线程阻塞在 `read()` 时持锁、写方向饿死。

## 修法（采用了 issue 建议 1 的「分半」，并顺带把 Handler 也改成两半）

1. **[`MirrorStream::into_split`](../../crates/reality/src/mirror_tls.rs)**
   → `(MirrorReadHalf, MirrorWriteHalf)`。`sock.try_clone()` 给两半各一条 fd；
   读/写两套 `RecordKeys` **本来就各自独占**（TLS 1.3 记录层序号按方向独立，
   RFC 8446 §5.3）⇒ 分半在密码学上是安全的，纯粹是所有权问题。
   `MirrorWriteHalf` 另有 `shutdown_write()`（半关发 FIN —— 反向 splice 结束时
   通知客户端「本方向不再发数据」，否则客户端一直等）。
   读/写逻辑抽成 `read_plain` / `write_plain` 两个共享函数，`MirrorStream` 与两个半边
   走同一份实现（行为逐字节一致）。

2. **`Handler` 改成两半形态**：`Fn(Box<dyn PlaintextRead>, Box<dyn PlaintextWrite>, AuthInfo)`。
   这样处理器**天生**能做双向并发，不必自己想办法分半。
   旧的「收一个合体流」写法由
   [`handler_from_stream`](../../crates/reality/src/server.rs) 桥接（内部用
   `JoinedStream` 两把锁拼回一个 `Read+Write`）—— 串行处理器用它，**并发处理器直接
   用两个半边**（`JoinedStream` 的两方向共用锁、会串行化，正是本单要躲的形状）。

3. 服务端 `serve_connection`：镜像成功后 `stream.into_split()`；分半失败
   （`try_clone` 拿不到第二条 fd）⇒ 清点 `mirror_failed`/`fallback` 并回落透传
   （分半在写任何字节之前，回落安全）。

## 判据（4 条，全部可复跑）

**离线（`cargo test -p reality --lib`，不需要外部二进制）**，在
`crates/reality/src/mirror_tls.rs` 的 `split_tests` 模块里 —— 用一对回环
`MirrorStream`（两端镜像对称密钥）直接钉住分半语义：

1. `into_split` 给两半各一条 fd：写半边独立推进、可半关，不需要读半边配合；
2. **读阻塞不挡写**（本单的症结）：A 的读半边阻塞在 `read()` 时，A 的写半边照常把
   数据写到 B —— 旧形态借不出两半、`Arc<Mutex>` 形态在此死锁；
3. **双向并发各 64 轮**：两端各写 N 轮、两方向都在推进，每轮都到达。

**真栈（`#[ignore]`，需 stock Xray 客户端，CI 的 `reality-stack` job 跑）**，
`crates/reality/tests/real_stack.rs`：

4. `the_handler_can_splice_both_directions_over_a_real_xray_client`：
   Xray 客户端 → 本仓服务端 → **splice handler 双向接到本地 echo 后端**。后端连上后
   **主动推 banner**，客户端先读 ⇒ banner 到达即证明「后端→客户端」方向在鉴权路径上
   **独立**推进（串行 echo 做不到 —— 这正是 issue 说现有 echo 判据「掩盖了缺口」的那点）；
   随后 kick 的回显再证另一方向。

## 实测踩到的两件事（都进了代码注释）

- **Xray 的 dokodemo-door 是惰性的**：客户端不先发数据，它就不建 outbound、handler
  根本不跑 —— 真栈判据必须先发一个 kick 触发建连（第一版在这里收到 0 字节）。
- **必须先回 VLESS 响应头**（`version(1) + addon_len(1)`）：Xray 客户端在读到响应头之前
  不会把后端数据交给本地 socket，漏了它 banner 全被 Xray 挡在缓冲里（也是 0 字节）。

## 边界

**行为逐字节不变**：分半只动所有权，TLS 记录层、鉴权、镜像、fallback 的字节一律不变
（判据 1/2/4 与既有判据并行全绿即证）。

**Settling:** `cargo test -p reality` —— rc=0 且含 `split_tests` 三条 `... ok` ⇒ 分半语义成立；
`--lib` 里 `split_tests` 任一条红（rc≠0）⇒ 分半语义被破坏，本悬案重新成立。
真栈面 `cargo test -p reality --test real_stack -- --include-ignored`：rc=0（4 条 ok）⇒ 双向
splice 在鉴权路径上成立；那条 `the_handler_can_splice...` 红 ⇒ 并发 splice 缺口复现。
