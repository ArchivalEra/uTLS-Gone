# rustls-fork —— 引擎侧补丁与跟随计划

本目录**只有两个文件**，都是给「引擎 fork」这一步用的交付物：

| 文件 | 是什么 |
|---|---|
| `patch.diff` | 对钉住的 rustls 版本的 unified diff。**这是唯一要维护的东西。** |
| `README.md` | 本文件：钉住的版本、每一处改动的理由、怎么挂进 workspace、rebase 节奏与最大风险。 |

`patch.diff` **不包含** rustls 源码副本。要构建时按下面的命令取回 pristine 源码再打补丁 ——
把 30 万行上游源码签进本仓，会让「我们改了什么」这件事在下一次 rebase 时消失。

---

## 一、钉住的版本

**`rustls 0.23.45`** —— 这一条是**核过**的，不是按任务说明抄的：crates.io 的 sparse index
（`https://index.crates.io/ru/st/rustls`，本机可达，HTTP 200）里去掉 yanked 后
最新的 0.23.x 就是 `0.23.45`；同时最新的总版本是 `0.24.0-dev.1`（预发布）。复跑：

```bash
curl -s https://index.crates.io/ru/st/rustls -o /tmp/idx.json
python3 -c "
import json,re
vs=[d['vers'] for d in map(json.loads,open('/tmp/idx.json')) if not d.get('yanked')]
rel=lambda v: tuple(int(x) for x in re.split(r'[-+]',v)[0].split('.'))
s=sorted(vs,key=rel)
print('newest 0.23.x :', [v for v in s if v.startswith('0.23.')][-1])
print('newest overall:', s[-1])
"
# => newest 0.23.x : 0.23.45
# => newest overall: 0.24.0-dev.1
```

不目标 0.24：上游 0.24 目前只有 `0.24.0-dev.*` 预发布，且已经再次拆分了 `client/` 的内部结构
（见 `STATE.md` 里那条「两年内两次重构内部扩展表示」）。跟一个正在动的版等于把 rebase
成本从「对行」变回「重写」。

**取值来源与复现命令**（实测可用，HTTP 200）：

```bash
curl -sL https://static.crates.io/crates/rustls/rustls-0.23.45.crate -o /tmp/rustls.crate
mkdir -p /tmp/rs && tar xzf /tmp/rustls.crate -C /tmp/rs     # .crate 是 gzip tar
ls /tmp/rs/rustls-0.23.45/                                   # => Cargo.toml src/ ...
grep -m1 '^version' /tmp/rs/rustls-0.23.45/Cargo.toml       # => version = "0.23.45"
```

本机可用的源只有 `static.crates.io` 与 `codeload.github.com`；
`raw.githubusercontent.com` 不通（http 000），`gh` 的 GraphQL 端点 401。本次用的是前者，
没有回退。

### 补丁应当成为一条台账事实 —— **已落地**

`rustls_pin` **已在台账里**（值 `0.23.45`，复跑 `grep '^rustls' …`；
本段原文写的是「目前不在台账里 …… 应当把钉住的版本登记为事实」，那条待办**已完成**）。
按 `AGENTS.md` 第三条，升级 rustls 是一次**改口**，所以有了这条事实之后，
「换了 rustls 版本」会在闸门里显形 —— 否则下次升版会是一次静默的指纹改动。

---

## 二之前：`patch.diff` 怎么重新生成（**别沿用旧补丁的文件列表**）

```bash
# 原始树：从 crates.io 取（static.crates.io 可达；本机实测）
mkdir -p /tmp/rs-pristine && cd /tmp/rs-pristine
curl -sSLO https://static.crates.io/crates/rustls/rustls-0.23.45.crate
tar xzf rustls-0.23.45.crate && cd rustls-0.23.45
git init -q . && git add -A && git -c user.email=x@y -c user.name=x commit -qm pristine
# 把我们改过的整棵 src 覆盖过去 —— **不要**从旧 patch.diff 里读文件清单
cp -a <repo>/crates/rustls/src ./
git add -A && git diff --cached > <repo>/crates/rustls-fork/patch.diff
```

**判据（两条，都要过）—— 由脚本一次跑完，别手工两步**：

```bash
sh crates/rustls-fork/verify-patch.sh          # CI 的 patch-repro job 调的就是它
#   判据① 补丁文件数 == 带 FORK(utls-rs) 标记的文件数
#   判据② 打到原始树上，得到的树与 crates/rustls **逐文件相同**（整棵 crate，排除 .git/target）
```

两条缺一不可。第二条是本轮新增的：本轮踩到的正是**第一条过了、补丁却是旧的**——
`hs.rs` 的会话 id 修复没进补丁（`patch.diff` 比 `src` 旧），而文件数照样是 9。
「文件数相等」只是必要条件；**打出来能重现**才是判据。

⚠️ 脚本需要 `rustls-$VERSION.crate`（首次去 `static.crates.io` 取，之后复用）——
这是**要联网**的判据，取不到时它会如实失败，不会伪装成离线可跑。

手工版的等价命令（想看清每一步时用；**口径与脚本一致 = 整棵 crate**）：

```bash
rs=$(mktemp -d) && cd "$rs" && tar xzf /tmp/rs-pristine/rustls-0.23.45.crate
cd rustls-0.23.45 && git init -q . && git add -A \
  && git -c user.email=x@y -c user.name=x commit -qm p \
  && git apply <repo>/crates/rustls-fork/patch.diff \
  && diff -r -x .git -x target . <repo>/crates/rustls && echo IDENTICAL
```

<!-- 上面这段原来是「diff src」，与 README 前面的手工配方（比整棵 crate）**不是同一个判据**；
     现在统一到整棵 crate，并收进脚本一处。 -->


⚠️ **另一处踩过的**：第一版脚本从**旧补丁**的 `diff --git` 行里取文件清单，
于是「这一轮新改的**第 9 个**文件」（`src/client/tls13.rs`）根本没进补丁 ——
而补丁看上去照旧生成成功、测试也全绿（因为它压根没被编译进那条路径）。
这就是为什么覆盖的是**整棵 `src`**，不是一张清单。

## 二、八处能力：改哪个文件、为什么

补丁的规模**不在这里手抄**：`fork_patch_files` / `fork_patch_hunks` / `fork_patch_plus` /
`fork_patch_minus` 四条台账事实给出「几个文件、几个 hunk、增删多少行」，各带一条可复跑的
`grep` 命令。手抄的数字从写下那刻开始腐烂 —— 本文件下面那张表里就曾经抄着三个已经过期的
数字（文件数、行数、hunk 数），而没有任何判据会因此变红。
所有改动点都带 `FORK(utls-rs)` 标记注释，便于 rebase 时定位；带标记的文件数见 `fork_rs_modified`。

| # | 能力 | 文件 / 函数 | 上游为什么拒绝 |
|---|---|---|---|
| a | 接受外部提供的 ClientHello 并逐字节使用 | `src/client/fork.rs`（新）+ `src/client/hs.rs::emit_external_client_hello`（新函数） | 根本没有公开 API（#1421 / #1932 / #2498；PR #1564 / #1475 关闭未合并） |
| b | 压制每连接的扩展乱序 | `src/msgs/handshake.rs::ClientExtensions::order_insensitive_extensions_in_random_order` | PR #1730 起乱序无条件生效 |
| c | 广播自己协商不了的密码套件 | `src/client/hs.rs::emit_client_hello_for_retry` | #2414：「unlikely to happen」 |
| d | 去掉无条件追加的 `TLS_EMPTY_RENEGOTIATION_INFO_SCSV` | `src/client/hs.rs::emit_client_hello_for_retry` | #2485：维护者原话「没有办法避免」 |
| e | 接受外部提供的 key share / 私钥（**多把**，`key_share` 有几项就几把） | `src/client/fork.rs::ClientHelloPlan::key_exchanges` + `src/client/hs.rs::{start_handshake, OfferedKeyShares}` + `src/client/tls13.rs::handle_server_hello` | 没有 API；且引擎没有「导入裸私钥」的入口 |
| f | 外部提供的**第二飞** ClientHello（HelloRetryRequest 的回复） | `src/client/fork.rs::SuppliesClientHello::retry_plan` + `src/client/hs.rs::handle_hello_retry_request` | 同上（(a) 的第二次机会）；上游连「一条外部 hello」都不收，更不会有第二条 |
| g | **会话复用**：把可复用的会话交给调用方，并允许它自己写 `pre_shared_key` | `src/client/fork.rs::{PlanRequest, ResumptionOffer, PskBinderSlot}` + `src/client/hs.rs::{fork_resumption_offer, emit_external_client_hello}` | 没有 API：上游把 ticket、binder key 与 early key schedule 全留在自己内部 |
| h | **真 ECH 提议**：外供 hello 里的 `0xfe0d` 是提议而不是 GREASE | `src/client/fork.rs::EchOffer` + `src/client/ech.rs::EchState::from_supplied` + `src/client/hs.rs::emit_external_client_hello` | 没有 API：`EchState` 是 `pub(crate)`，而上游只会「自己构建+自己密封」那一条路 |

### (a) 外部 ClientHello —— 为什么只能在构建步骤里换掉，不能事后改字节

`emit_external_client_hello()` 把调用方给的字节当作**完整的握手消息**
（`type(1) || u24 长度 || body`）用两次：原样写到线上、原样进 transcript。
落地方式是把这些字节放进 `MessagePayload::Handshake { parsed, encoded }` ——
`encoded` 是**借用**调用方切片的一个 `Payload`，于是哈希走的是这些字节、
`encode()` 写出的也是这些字节，中间没有任何一次重新编码。

顺带就解释了为什么事后改字节不可行：ClientHello 进 transcript 且被 HRR 一致性检查引用，
一个「序列化后打补丁」的 hello 会在 transcript 哈希上与状态机分叉。**换必须在构建步骤换。**

字节只被解析一次，而且**只用于记账**：服务端回复到达时状态机要查我们「报了什么」
（选中的套件、ALPN、是否报了证书压缩、发过哪些扩展）。解析结果随后丢弃，上线的仍是原字节。

要点：

- `sent_extensions` 应当由调用方提供（`ClientHelloPlan::sent_extensions`），因为
  **rustls 的解码器会丢掉它不认识的扩展类型**（GREASE、浏览器私有扩展），而
  「服务端发了我们没报的扩展」这条检查是按我们报过的全集比对的。不提供时退化为
  从解码结果取，那只在 hello 不含未知扩展类型时才正确。
- `offered_cipher_suites` / `alpn_protocols` / `offered_cert_compression` 一律从**字节**反推，
  不从 config 反推 —— 上线的是字节，字节才是真相。
- 记录版本仍用 `TLSv1_0`（与引擎自建首条 ClientHello 一致）。

### (b) 压制乱序 —— 一个显式开关，不用哨兵值

乱序只影响 `used_extensions_in_encoding_order()` 里那段「顺序无关」的扩展；
`PreSharedKey` / `EncryptedClientHello` / `contiguous_extensions` 的位置要求不受影响，照旧排在后面。

**没有**用「`order_seed == 0` 当哨兵」的省事写法：`order_seed` 是每连接随机 `u16`，
有 1/65536 的概率本来取到 0，那会让「关掉乱序」这件事偶尔自己发生 —— 对一个核心交付物
就是「每连接都不一样、没人能证明它对」的项目来说，一个偶发的、不可复现的稳定性是缺陷，
不是小事。所以加了显式布尔量 `ClientExtensions::deterministic_order`（默认 `false`，
默认行为与上游逐字节一致），开启时按扩展类型排序。

`src/client/ech.rs` 里同步把该标记从 outer hello 带到 inner hello（一行）：否则开了
稳定顺序、又走 ECH 时，inner hello 会把每连接的熵加回来。

### (c) 广播不能协商的套件 —— 只能是「广播」

实现是在 `config.provider.cipher_suites` 之外追加调用方给的 IANA 值（去重，
重复项会污染 JA3）。**这是广播，不是协商**：服务端回复到达时
`hs.rs` 要求「选中的套件既在我们报过的列表里、又能被 provider 找到」，否则
`PeerMisbehaved::SelectedUnofferedCipherSuite`（HandshakeFailure）。
也就是说：报了做不了的套件、服务端真选了它 → **握手失败**，不会静默降级。
这是刻意的：保真度要的是线上字节，代价由调用方在选预设时承担。

### (d) 去掉 SCSV

上游只在一处追加（`hs.rs`，`supported_versions.tls12` 为真时无条件），所以只有一处要改。
注意 ECH 路径本来就会把这条 SCSV 从 outer hello 的套件表里滤掉（`ech.rs`），二者不冲突。

### (e) 外部 key share / 私钥

`src/client/fork.rs` 的 `ExternalKeyExchange` 是一个**由我方实现的 trait**：
`group() -> u16`、`pub_key() -> Vec<u8>`、`complete(&self, peer) -> Result<Vec<u8>, _>`，
另有 `hybrid_component()`。引擎侧的 `ExternalKx` 把它适配成 `ActiveKeyExchange`。
`start_handshake()` 在配置了外部 key exchange 时**不再调用** `initial_key_share()`。

两个刻意的决定：

- `complete()` 取 `&self` 而不是 `self`，因为引擎要把交换放在 `Arc` 后面持有到
  服务端的 share 到达那一刻；私钥的零化交给实现的 `Drop`。
- 这种情况下**不写 `kx_state`**（`kx_hint`）：组可能根本不在引擎的 `SupportedKxGroup` 表里，
  没有东西可记。代价是这一连接不会为将来的恢复存 kx hint。

#### 「引擎告诉我们需要哪些组的公钥」= 接口的参数，不是第六个能力

任务的设计约束里有一条是「引擎要能告诉我们需要哪些 key-exchange 组的公钥」。
它没有变成一个独立的 API，而是能力 (e) 接口的参数：`SuppliesClientHello::plan(groups: &[u16])`
的 `groups` 就是这个列表，由 `ClientConfig::fork_key_exchange_groups()` 产出
（provider 里对 TLS 1.3 可用的组，按引擎偏好排序，IANA 值）。它同时也是
**`key_share` 允许出现哪些组**的边界。一个参数同时覆盖「引擎说需要什么」和
「我方给什么」，所以不需要第二个查询 API —— 缝越窄越好，多一个查询入口就是多一处要跟随上游的东西。

### (e) 补记：外部交换是**一张表**，不是一把

能力 (e) 最初只收**一把**外部交换，而引擎也只把 `key_share` 里第一个组的交换交出去 ——
其余组的公钥照样写在字节里，私钥却被丢掉了。于是服务器只要选中另一个（我们**明明声明过**的）
组，rustls 的 `KeyExchangeChoice` 就找不到匹配的交换、报 `WrongGroupForKeyShare`。

那不是策略而是缺陷：**uTLS 把每个组的公钥都发出去，服务器选哪个都能接着谈**；
真实浏览器也正是靠这个少一轮 HRR。现在：

- `ClientHelloPlan::key_exchanges` 是一张表；
- `OfferedKeyShares::take_for` 按服务器选中的组挑对应那一把（混合组则按其**经典分量**，
  与上游 `KeyExchangeChoice` 原来对单把做的一样）；
- `handle_server_hello` 顺手把 `kx_state` 校正成**实际用到**的那个组
  （它不只是重放提示，而是状态机 —— 见缺陷 2）。

判据（`crates/utls-engine/tests/multi_key_share.rs`）：引擎交出来的表与声明组一一对应；
服务端**只认 P-384** 而客户端第一项是 X25519、第二项才是 P-384 ⇒ 握手**直接**谈成
（`HandshakeKind::Full`，不是 `FullWithHelloRetryRequest`）；对照那条只发 X25519、于是被要求 HRR ——
它证明前一条的 `Full` 确实意味着「服务端用了我们发的某个共享密钥」。

### (f) 第二飞 —— 一条外部 ClientHello 不够，服务器可能要求重来

能力 (a) 只解决「第一条 ClientHello 由谁写」。而 TLS 1.3 允许服务器回
`HelloRetryRequest` 要求换一个组或带上 cookie，于是**同一条连接里有两条 ClientHello**，
且第二条与第一条之间有一条 RFC 硬约束：

> 第二飞只许改 `key_share` / `cookie` / `pre_shared_key` / padding —— 客户端随机数、
> session id、GREASE、扩展顺序都不许变（RFC 8446 §4.1.2）。

引擎自己构建 ClientHello 时这条约束是自动满足的（它复用同一份状态）。外供路径绕过了
那套状态，所以「谁来产出第二飞」必须回到调用方 —— 只有它知道 spec 与那条指纹随机流。
这就是 `SuppliesClientHello::retry_plan(&HelloRetryRequestPlan)`：默认实现**拒绝**
（于是 fork 对只供一条 hello 的调用方仍然完全惰性），实现了它的调用方接管第二飞。

接线上的三个易错点，都写进了代码注释：

1. **在引擎自己查组之前问调用方**。服务器要的组可能是引擎的 provider 里没有的
   （uTLS 能生成的组比 rustls 宽），若先走引擎的 `find_kx_group`，那次重试会被判
   「选了没提供过的组」而死在调用方拿到机会之前；
2. **`kx_state` 要跟着换**。它不只是重放提示，而是状态机（见缺陷 2）；换了组就要
   记新组。
3. **cookie-only 的重试不改 key_share**：此时 `retry_plan` 返回 `key_exchange: None`，
   引擎继续用第一飞那把交换 —— 否则就等于把 key_share 也换了。

### (g) 会话复用 —— 密钥留在引擎里，只把「怎么写」交出去

外供 ClientHello 要能复用会话，就必须自己写 `pre_shared_key`；而它的 binder 是
`HMAC(finished_key, Hash(Truncate(ClientHello)))`（RFC 8446 §4.2.11.2），
`finished_key` 派生自**会话密钥**。于是这里有一个必须解决的归属问题：

- 会话密钥**不能**出引擎（那是整条会话的根秘密）；
- 但 binder 又必须由写字节的一方（调用方）**知道该放在哪**。

所以能力 (g) 把这件事拆成两半：

| 方向 | 给什么 | 为什么不给更多 |
|---|---|---|
| 引擎 → 调用方（`PlanRequest::resumption`） | ticket、**已经算好的**混淆年龄、binder 长度 | 这三样是「写进 hello 的数据」。密钥不给、binder key 也不给 |
| 调用方 → 引擎（`ClientHelloPlan::psk_binder`） | 截断点（RFC 8446 §4.2.11.2 的那个长度）+ binder 长度 —— 也就是**binder 该写在哪** | 调用方已经写完了字节，它当然知道位置；它只是算不出内容 |

引擎在拿到字节之后只改写那 `binder_len` 个字节。

**HRR 不作废会话**（uTLS 的 `UpdateOnHRR`）：`HelloRetryRequestPlan` 里再带一次同一份
`ResumptionOffer`，调用方在第二飞里重新填 identity、引擎在新转录
（`message_hash || HRR || Truncate(ClientHello2)`）上**重算 binder**。两处细节是
「只有跑一遍才知道」的：

- 会话**必须活到第二飞**：第一飞不能把 `fork_resumption` 取走（早先的写法取走了，
  于是第二飞只能报「声明了 binder 位置却没有会话」）。密钥那份是
  `Zeroizing<Vec<u8>>`、从不外传，`KeyScheduleEarly` **每飞重建一次** ——
  rustls 自己的路径也是每飞重跑 `prepare_resumption`。
- 重试的 cipher suite 哈希与会话的不同 ⇒ **丢掉 PSK**（RFC 8446 §4.2.11.2；
  uTLS 那边同一处写的是 `"cipher suite hash mismatch, PSK will not be used"`）。这是整个补丁里**唯一**一处对已序列化
消息做字节改写的地方，而能力 (a) 原则上禁止这件事 —— 它成立的理由只有一条：
**只改 binder、不改任何长度**，于是所有长度字段、截断消息的转录哈希、以及引擎从
外供字节里学到的状态全都不受影响。长度不符时引擎**报错**而不是照改。

调用方需要注意的一件事（不是补丁的问题，但会让复用**静默**失效）：rustls 用
`Weak::ptr_eq` 比较会话里存的验签器与当前 config 的验签器
（`msgs/persist.rs::compatible_config`）。所以「每条连接新建一个 `ClientConfig`」
的写法永远复用不了，而且**票已经被 take 走了** —— 症状是服务端按完整握手应答，
看起来像 PSK 写错了。本仓的复用测试第一版就是这么假绿的，诊断记录在
`crates/utls-engine/tests/common/mod.rs` 的 `client_config_with_roots_and_store` 上。

### (g) 补记二：早数据（0-RTT）在外供路径上的三件事

rustls 的 TCP 0-RTT 只支持**有状态恢复**（RFC 8446 §8.1 防重放：服务端把会话值存在
自己的 `session_storage` 里才能识别重放；无状态票据被 rustls 明确拒绝 ——
`server/tls13.rs` 的 `warn!("early_data with stateless resumption is not allowed")`）。
在这条路上，外供 hello 要发 0-RTT 需要**三件事**，缺一不可，且都在 fork 的
`emit_external_client_hello` 里补齐（判据 `crates/utls-engine/tests/early_data.rs`）：

1. **早数据调度**：`(psk_binder, fork_resumption)` 都存在时，`early_data_key_schedule`
   接 (g) 时就已经武装 —— 这是顺手做对的。
2. **`EarlyData::enable(max_early_data_size)`**：自建路径在 `prepare_resumption` 里调；
   外供路径原本没人调 ⇒ `early_traffic` 永远是假 ⇒ 应用写早数据被拒。
   `ForkResumption` 因此带上 `max_early_data_size`（来自同一张票据）。
3. **`derive_early_traffic_secret`**：把 `early_traffic` 置真并装上早加密器 ——
   哈希的是**刚上线的这份 hello**（含调用方的 client random，与 TLS 1.2 PRF 修复
   同一条「线上的是事实」规则）。另外调用方 hello 还必须**自带**零长度
   `early_data` 扩展（RFC 8446 §4.2.10；模型 `Extension::EarlyData`，插在 PSK 之前），
   并满足 rustls 的门控：`retryreq.is_none()` + `config.enable_early_data` +
   `max_early_data_size > 0`。

少了 2 或 3 的任何一件，握手**照样完成且恢复**，0-RTT 却悄悄没了 ——
不报错的缺失，是最需要一条判据的原因。

### (h) 真 ECH —— 「形状像」与「在提议」是两件不同的事

指纹层只需要一条**形状正确**的 `0xfe0d` 扩展（GREASE ECH 就是干这个的）。但从协议上说
「这条连接真的在藏 SNI」是另一回事：服务器可能**接受**它，而接受会把握手切换到**内层**——
内层转录与内层随机数取代外层的进密钥调度（RFC 9849 §6.1.6）。于是引擎必须拿到内层那条
hello，而它拿不到：payload 是密文。

所以能力 (h) 让调用方把内层 hello 与本连接用的 `ECHConfigList` 一起交出来
（`ClientHelloPlan::ech`），引擎据此建一个 `EchState`：

- **转录与随机数**从内层字节里取（`from_supplied` 会**解析**它并要求它真是一条 ClientHello ——
  传错字节不会响亮失败，只会安静地认证一场别人不在场的握手，所以这道解析是必需的）。
  ⚠️ 交出去的**不是整条握手消息**：内层 hello 的明文是**体**（无 4 字节握手头、
  `legacy_session_id` 为空、末尾按 32 的倍数补零），两个参照实现一致 ——
  rustls 的 `payload_encode(.., Encoding::EchInnerHello)` 明确写着
  "SessionID is required to be empty in the encoded inner client hello" 且不写握手头，
  uTLS 的 `encodeInnerClientHelloReorderOuterExts` 则是 `h = h[4:]` 直接砍掉头。
  本仓第一版按「整条消息」实现，**两个方向都错**（引擎给错的、fork 也按错的解析），
  而它自洽 —— 直到「解回载荷再逐条数扩展」的判据出来才暴露；
- **外层名字**从配置里取（拒绝时按它认证）；
- **内层扩展清单**也从内层字节里取（ECH 被接受后，「服务器发了我们没提议的扩展」这项检查是拿它比的）。

两条实测得来的语义，都写进了代码：

1. **交出 offer = 要求 ECH**。rustls 的 `EchMode::Enable` 语义就是「拒绝即终止」，
   而我们的接缝复用它：本地那台不认识 ECH 的服务端会让握手以
   `ServerRejectedEncryptedClientHello` 结束。这条比状态字段更硬 ——
   GREASE 扩展**永远**不会产生那个错误。
2. **HRR 之后外供 ECH 提议被明确拒绝**：重新密封要用调用方手里的 HPKE 上下文
   （而且重试的外层 `enc` 是空的），rustls 又需要新那次提议的内层转录。与其用外层转录
   接着跑（那会安静地认证错的握手），不如报错。

⚠️ 还有一个**格式上的坑**，只有真跑一遍才会知道：ECH 扩展体的**第一个字节是
outer/inner 的类型位**（`0` = outer，`1` = inner，而 inner 形态**只有这一个字节**）。
本仓先按「没有类型位」的格式拼外层扩展，rustls 把 `kdf_id` 的高字节当类型读，
整条 hello 直接解不开（`InvalidMessage(MessageTooShort)`）。两个参照实现都写这一位：
rustls `EncryptedClientHello::encode`、uTLS `generateOuterECHExt` 的 `b.AddUint8(0)`。

### 为什么这个缝是「每连接」的

配置是 `Arc<ClientConfig>`，会跨连接共享。能力 (e) 需要**每连接**密钥材料
（ephemeral 私钥复用是缺陷，不是特性），而 uTLS 那一侧本来也每连接变 GREASE / 填充 ——
所以计划在 `ClientHelloInput::new()` 里**每连接解析一次**，而不是把字节静态挂在 config 上。

想表达「一条固定不变的 ClientHello」时，用 `FixedClientHello`：它是一个忽略 `groups`
参数的 `ClientHelloPlan`。

---

## 三、我做了什么验证，以及**没有**做什么

**没有编译。** 按任务要求没有对 fork 跑 `cargo build`（缺 workspace 挂载，编不过本来就是预期）。
所有验证是文本层面的，下面每一条都能复跑。

### 1. 补丁能干净应用（第二份 pristine 副本）

```bash
cd /tmp && rm -rf rs-scratch && mkdir rs-scratch && tar xzf rustls.crate -C rs-scratch
cd /tmp/rs-scratch/rustls-0.23.45
git apply --check --verbose -p1 /path/to/patch.diff     # 退出码 0
patch -p1 --dry-run < /path/to/patch.diff               # 退出码 0
```

两者都通过（`git apply --check` 对 7 个文件逐个报告 OK）。更进一步：把补丁实际打进
第二份副本后，与生成补丁的工作副本 `diff -r` **完全一致**（只多出工作副本的 `.git` 目录）。

### 2. 语法

`rustfmt --edition 2021 --emit stdout <每个改动文件>` 对 7 个改动文件全部解析通过
（rustfmt 解析失败会报 error，所以这条能抓住括号/语法问题）。

### 3. 类型/借用模式的小样验证（`rustc`，无需网络）

三处容易出错的写法单独抽出来编过：

- `.map(CipherSuite::from)` / `.map(ExtensionType::from)` 这类把 `enum_builder!` 生成的
  `From<u16>` 当函数路径用 —— 因为还存在自反的 `From<T> for T`，值得先证一遍。
- **这一条抓到了一个真 bug**：`(c)` 处原本写成
  `cipher_suites.extend(... .filter(|cs| !cipher_suites.contains(cs)))`，
  在 `&mut self` 上调 `extend` 的同时在闭包里只读借用同一个 `Vec` —— E0502，**编不过**。
  已改成先 `collect()` 到临时量再 `extend`，并重新验证通过。
- 在 `&'static [&'static dyn Trait]` 上调 trait 方法（fork.rs 里的 `.name()` /
  `.usable_for_version()`）**不需要**在调用模块里 `use` 那个 trait。

这三条都是可复跑的最小复现，不是推演。

### 4. 逐项核对了引用的上游符号是否真在该版本里存在

`MessagePayload::Handshake { parsed, encoded }`、`MessagePayload::new`、
`ClientExtensions` 的 `+ { ... }` 附加字段块、`SupportedProtocolVersions` 是 `Copy`、
`Error::General(String)`、`SharedSecret: From<Vec<u8>>`、`ActiveKeyExchange` 的
`pub_key/hybrid_component/complete_hybrid_component` 签名、`ExpectServerHello` 的字段名、
`KxState::Start` 需要 `&'static dyn SupportedKxGroup` —— 都在 0.23.45 里按我用到的样子存在。
所有 `ClientExtensions { .. }` 字面量构造（含测试）都带 `..Default::default()`，
所以加字段不会破坏它们。

### 5. 当时**没能**验证的（现已全部验证，**这份是历史快照**）

补丁第一版落地时，下面这几项确实没有证据 —— 它们后来都补上了，**留在这里是为了
记住「静态审查看不出什么」**：

- **编译**：当时没有 `cargo check` 的证据。**现在**：整 crate 编得过，且
  `cargo clippy --workspace --all-targets -- -D warnings` 0 警告（CI 的 `rust` job）。
- **握手**：当时一次真实握手都没跑。**现在**：真握手覆盖到多组 / HRR / 会话复用 /
  TLS 1.2 时代指纹 / 真实 ECH —— 并且**正是「跑起来」才炸出下面那八条缺陷**
  （见「跑通之后才暴露的缺陷」一节）。这是本文件最值钱的一条教训：
  编译通过 + `git apply` 干净 + 静态核对符号，**不等于**这一版能工作。
- **行号**：README 里没有写死行号（只在第二节提到函数名），所以 rebase 后本文件不会腐烂。
  `patch.diff` 里的行号是相对 0.23.45 的 hunk 头，由 `git diff` 生成，可复跑。
- 上游 issue/PR 号（#1421/#1932/#2498/#2414/#2485/#1730、PR #1564/#1475）来自任务给定的
  既有调研，**我没有联网复核**；本机的可用网络只到 `static.crates.io` 一类的下载端点。
  （这一条**仍然**是未复核项，如实留着。）

---

## 四、怎么挂进 workspace：推荐 `[patch.crates-io]` + vendored path

两种形态：

```toml
# A. 作为 patch（推荐）
[patch.crates-io]
rustls = { path = "crates/rustls-fork/vendor/rustls-0.23.45" }

# B. 作为直接路径依赖（每个 crate 各自声明）
[dependencies]
rustls = { path = "crates/rustls-fork/vendor/rustls-0.23.45" }
```

**推荐 A。** 理由是决定性的：patch 作用于**整张依赖图**里的 `rustls ^0.23`，
包括我们没直接声明的传递依赖（`tokio-rustls`、`hyper-rustls` 之类 —— 只要它们接受
0.23.45）。B 只影响我们**自己**声明它的那几个 crate，一旦有传递依赖引入 rustls，
图上就会出现**两份 rustls**，而我们的 ClientHello 定制只对其中一份生效 ——
那种错误在指纹上看得见、在依赖表里看不见，正是 `STATE.md` 里点名的那一类。

代价，三条都要认：

1. **crates.io 可发布性**：无论 A 还是 B，fork 都进不了 crates.io。A 的 patch 只存在于本
   workspace 的解析里、不随发布物走，下游拿到的是**上游 rustls** —— 这是一个危险的静默
   失败模式（对方以为在用带指纹能力的引擎）。本仓整体形态（fork 引擎 + 预设表）本来就不是
   可发布物，所以这条代价是「明说」而不是「规避」。
2. **依赖图钉死**：patch 生效的前提是 fork 的版本号满足图中每个依赖方对 `rustls` 的
   版本要求。所以 vendored 副本的 `Cargo.toml` 必须保持**上游的 name/version 原样**
   （`rustls` / `0.23.45`），不要改成 `rustls-fork` 之类的名字，否则 patch 不生效。
   同一张图里若出现另一个 rustls 大版本（例如某个老依赖要 0.22），一个版本补不了两份，
   要单独处理。
3. **rebase 节奏**：见下。

---

## 五、rebase 节奏与最大风险

**节奏：钉住，不跟随。** 只在「我们需要上游的某个修复」时主动升版，升版是一次显式改口
（台账的 `rustls_pin` 会显形），而不是跟着上游发版的例行公事。当前 delta 的规模
（7 文件 / 21 hunk / 38 处标记）决定了每次 rebase 是一个下午的活，不是一次 `git rebase`。

rebase 的动作：取回新版 pristine → `git apply --check` 看补丁 → 按 21 个 hunk 逐个手工对位 →
把 `(a)` 那个新函数整段搬过去（它不依赖周边代码，只依赖 7 个上游符号，最不容易冲突）→
重跑第三节那两条核对（补丁能应用、打完补丁与工作副本逐字节一致）。

**最大的一处翻车风险：`src/client/hs.rs::emit_client_hello_for_retry`（本补丁 192 行里的绝大部分）。**

它是唯一一个「所有定制都必须嵌进去」的函数，也恰恰是上游每次小版本都在动的地方：
扩展集构造在 0.23.4 被重塑过一次（引入 `ClientExtensions { order_seed, .. }`），
`client/` 在 0.24-dev 又被拆过。具体会咬人的是三个插入点 ——
`(a)` 的早退分支、`(b)` 跟 `order_seed` 同一行的赋值、`(c)(d)` 对 `cipher_suites` 的构造 ——
它们都贴在会被上游重排的代码旁边。

**第二大风险（同量级）：`src/msgs/handshake.rs` 的扩展表示。**
`(b)` 依赖 `ClientExtensions` 的「附加字段块」和那两个排序函数；扩展表示两年内被重构两次，
而 `(b)` 又必须知道「乱序发生在哪一段」，不能只在外面改 config。

**降低这两个风险的既有机制**：`AGENTS.md` 第三条已经把「delta 越小越好、每处必带标记注释、
我方那层不引用 rustls 类型」定成纪律，本补丁是照它写的 —— 38 处 `FORK(utls-rs)` 标记
就是 rebase 时的锚点。

---

## 六、这一版补丁已知的边界

> ⚠️ **这一节的三条（1)(2)(3) 都已经被后续补丁取代** —— 保留原文是为了记住「能力是分批长出来的」，
> 但**别照它判断现在能做什么**。取代关系：1 → 见 (e) 补记（外部交换是**一张表**，
> 不是一把）；2 → 见 (g)（会话复用/PSK 已接）与 (h)（真实 ECH 已接）；3 → 见 (f)（第二飞已跑通）。
> 现在仍成立的是下面 (4)(5) 与 (i)。

1. ~~只支持一个 key exchange~~（已被 (e) 补记取代 —— 多组与 hybrid component 都在支持之列，
   另有 `tests/multi_key_share.rs`、`tests/key_share_reuse.rs` 的真握手判据）。
2. ~~外部 hello 不支持恢复（PSK）、早数据、ECH~~（PSK 见 (g)、ECH 见 (h)；
   **早数据也已接上** —— 见 (g) 补记第二条；判据 `crates/utls-engine/tests/early_data.rs`）。
3. ~~外部 hello / 外部 key exchange 遇上 HelloRetryRequest 会明确报错~~
   （第二飞已跑通，见 (f)：`tests/hello_retry.rs`、`tests/hello_retry_e2e.rs`）。
4. **`(c)` 是广播而非协商**（见第二节 `(c)`）。
5. **不写 kx_hint**（见第二节 (e)）。

---

## 跑通之后才暴露的缺陷

补丁的能力设计是对的（编译期就通过了对它的静态检查，`git apply` 也干净）。
但把它接进 workspace、真的连一台服务器之后，连炸三处；后来把**第二飞**也跑起来，
又炸第四处；再往后接**真实 ECH** 与 **TLS 1.2 时代的指纹**，又炸第五、六、七处；
最后做 **Firefox 148 的混合/经典 key_share 复用**（uTLS 的
`ReuseHybridAndClassicalKeyShares`）时炸第八处。
八次都不是「设计想错了」，而是「**没运行过**」。八条现在都修了，并且各自在代码里留了说明。

| # | 症状 | 根因 | 修法 |
|---|---|---|---|
| 1 | `cargo check` 就编不过：`(dyn SuppliesClientHello + 'static)` doesn't implement `Debug` | `ClientConfig` derive 了 `Debug` 并持有那个 `Arc<dyn …>`，而 trait 没有 `Debug` 约束 | 给 `SuppliesClientHello` / `ExternalKeyExchange` 加 `Debug` 超 trait，给 `FixedClientHello` 补 derive |
| 2 | 第一次真实握手 panic：`assertion failed: matches!(self, Self::Start(_))` | 补丁为「外供交换」写了**不记 `kx_state`** 的注释，理由是「组可能不是引擎认识的，没有东西可记」—— 那条理由对**重放提示**成立，但漏了 `kx_state` 同时**是个状态机**：`KxState::complete()` 会对它断言 | 引擎认识那个组就记 `KxState::Start(g)`；不认识就记新加的无载荷变体 `KxState::External`（`complete()` 接受它） |
| 3 | `PeerMisbehaved(UnsolicitedEchExtension)`，来自 `tls.browserleaks.com` | 浏览器的 ClientHello 带 **GREASE ECH**（`0xfe0d`），而那台服务器**回了 ECH 重试配置** —— 这对 GREASE ECH 是完全正常的应答。但 rustls 的 `EchStatus` 仍是 `NotOffered`（它只在**自己**插入 GREASE ECH 时才置 `Grease`），而 ServerHello 收到 ECH ack 而状态不是「已发出」时判违规 | 外供路径里检查 `sent_extensions` 是否含 `0xfe0d`，含则置 `EchStatus::Grease` |

| 4 | `PeerMisbehaved(IllegalHelloRetryRequestWithWrongSessionId)`，来自把一条真实的 HRR 喂进第二飞路径时 | 引擎自己为每条连接生成一个 `legacy_session_id`（RFC 8446 §4.1.2 的兼容措施），并在收到 HRR 时**要求服务器回显它**。但外供 hello 的 session id 是**调用方写进字节里的**（uTLS 的预设也是自己生成的），引擎那个值从来没上过线 —— 于是每一次重试都判「回显不对」 | 外供路径里从**将要发出的字节**里读 `legacy_session_id`，覆盖引擎自己那个值（与它已经在做的「从字节里学 offered cipher suites / ALPN」同一件事） |

| 5 | 真实 ECH 里判成 `Rejected` + `cannot decrypt peer's message`（服务器明明接受了） | `EchState::from_supplied` 重建内层转录时，session id 用的是**引擎自己**生成的那个，而服务器重建内层时插的是**外层线上**那个 —— 两边哈希的内层差 32 字节 | 外供路径里先把要发出的消息解析出来，把 `outer_session_id` 从字节里取出来交给 `from_supplied`（细节见 `questions/10`） |
| 6 | **TLS 1.2** 握手：服务端回 `BadRecordMac`（TLS 1.3 全绿，所以一直没暴露） | `ConnectionRandoms::new(self.input.random, …)` 是 TLS 1.2 主密钥 PRF 的输入，而 `input.random` 是**引擎自己**生成的值，不是调用方写进字节里的那个 ⇒ 客户端与服务端算出两个主密钥 | 外供路径里把 `input.random` 也从字节里读入（与第 4 条同一件事：**线上的是事实**） |
| 7 | TLS 1.2 时代的指纹（没有 `key_share`）里，引擎**背着调用方造了一把**共享密钥 | `supplied.is_empty()` 原来一律回落到 `OfferedKeyShares::single(tls13::initial_key_share(...))` —— 那条回落是给「引擎自建 hello」写的 | 只有调用方的字节里**确实有** `key_share` 扩展时才回落（判据取自 `ClientHelloPlan::sent_extensions`，也就是调用方自己那份扩展清单） |
| 8 | 一条同时报 `X25519MLKEM768(4588)` 与 `X25519(29)` 且**两者材料独立**的 hello（Chrome 131/133 就是），服务端选中 `29` 时握手死在 `cannot decrypt peer's message` | `OfferedKeyShares::take_for` 在**一次** `position()` 里同时接受「组相等**或**它是我某个混合组的经典分量」。这份 hello 的列表是 `[混合, X25519]`，于是选中 `29` 先命中了**排在前面的混合条目**（按分量），随后按分量完成 —— 算出的是混合组内部那把 X25519 的秘密，而不是**线上那条 29 公钥**对应的秘密（上游不会遇到：它自建 hello 时这种情形只可能是「同一条交换写两个条目」） | `take_for` 改成**两趟**：先找**组相等**的条目，找不到再退回「按经典分量匹配」。（顺带把 `any_group_matches` 也按分量匹配，两处口径一致 —— 它管 HRR 里「服务器要的组我们是不是已经发过」，口径不一致会漏判 RFC 8446 §4.1.4 的违规） |

**这八条的共同形状值得记住**：补丁把「ClientHello 的字节由谁写」这件事处理对了，
但**引擎在字节之外还维护着一堆状态**（`Debug` 契约、`kx_state` 状态机、`EchStatus`、
内层转录的 session id、TLS 1.2 的主密钥随机数），那些状态原本是由「引擎自己构建
ClientHello」这条路径顺手设置的。外供路径绕过了设置它们的地方，于是每一样都要显式补上 ——
而**只有真的跑起来才会知道漏了哪几样**。静态审查看不出第三条（触发条件是「服务器回不回
ECH ack」），也看不出第五条（要一台真接受 ECH 的服务器）与第六条
（要跑 TLS 1.2 的指纹 —— 前六条修完之前，那几档连字节都发不出去）。
第八条也一样：它要一条**同时报混合组与经典组、而两者材料独立**的 hello
（`Chrome(133)`）配一台**选中那个经典组**的服务器 —— 两边都凑齐才看得见，
而它此前没有判据（`mixed_group_handshake.rs` 只让服务端选混合组）。

## 现在的规模

- 补丁的规模：见台账 `fork_patch_files` / `fork_patch_hunks` / `fork_patch_plus` /
  `fork_patch_minus`（本文件不再抄数字）
- vendored 的 rustls：见台账 `fork_rs_files` / `fork_rs_lines`；其中**带 `FORK(utls-rs)`
  标记的只有 `fork_rs_modified` 个文件**（其余是上游原文，升级时按那几个文件对行）
- 补丁的**可复现性已验证**：把它应用到 `rustls-0.23.45.crate` 的原始 tarball 上，
  产物与仓库里 vendored 的树**逐文件相同**（`diff -r` 无输出）

复跑：

```sh
# 补丁能否应用、以及能否复现 vendored 树
cd /tmp && mkdir -p chk && cd chk
curl -sL https://static.crates.io/crates/rustls/rustls-0.23.45.crate | tar xz
cd rustls-0.23.45 && git init -q . && git add -A && git -c user.email=a@b -c user.name=t commit -qm base
git apply -p1 <repo>/crates/rustls-fork/patch.diff
diff -r -x .git -x target -x Cargo.lock . <repo>/crates/rustls   # 应当无输出

# 端到端（要联网）
cargo test -p utls-engine --test end_to_end -- --ignored --nocapture
```
