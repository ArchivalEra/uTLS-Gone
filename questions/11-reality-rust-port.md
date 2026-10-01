# 11: REALITY 的 Rust 等价实现 —— 从哪一步开始、对什么判据

**Status:** resolved

来源：issue #1（需求单：REALITY 的 Rust 等价实现，权威参照 = XTLS/REALITY）。
本工单承接「怎么做、怎么判」；issue 只留需求。

## 读参照读到的结构（2026-10-01，对照源码逐行确认）

`XTLS/REALITY` 是 **Go crypto/tls 的 fork**（`tls.go:5` 自述），REALITY 的实质性
修改集中在四处，其余是上游原文：

1. **鉴权**（`tls.go:200-300`，`Server()` 监听器里）：
   - SNI 白名单（`config.ServerNames`）不命中 ⇒ 直接 fallback；
   - key share 的**形状与顺序**：`X25519MLKEM768`（data = 1184+32，**末 32 字节**
     是其 X25519 分量 = `peerPub2`）必须在前，可选 `X25519`（32 字节 = `peerPub`）
     在后，各最多一次，否则 fallback；
   - `AuthKey = X25519(config.PrivateKey, peerPub)`（peerPub 优先取独立 X25519，
     次选 MLKEM768 的分量），再
     `HKDF-SHA256(ikm=AuthKey, salt=hello.random[:20], info="REALITY")` 读 32 字节；
   - `sessionId`（32 字节）= `AES-256-GCM(AuthKey)` 密文，nonce = `random[20:32]`，
     **AAD = 原始 ClientHello 全字节**（含密文 sessionId 本身）；明文
     `[0:4]`=ClientVer、`[4:8]`=unix time（BE）、`[8:16]`=shortId、`[16:32]`=客户端随机填充；
   - 门控：`MinClientVer`/`MaxClientVer`/`|time|≤MaxTimeDiff`/`ShortIds[shortId]`
     全过 ⇒ 鉴权（`hs.c.conn = conn`）；任何一步失败 ⇒ fallback。
2. **镜像握手**（`tls.go:330-410`）：把客户端的原始 hello 原样发给真站（dest），
   逐记录读真站的回 flight 并按类型表校验（`[0]`=ServerHello、`[1]`=CCS、
   `[2..]`=ApplicationData 载荷），**Unmarshal 真站的 ServerHello** 存进 `hs.hello`
   —— 客户端看到的 ServerHello 是真站的，**唯一被替换的是 serverShare 的密钥字节**
   （`handshake_server_tls13.go:104-120`：服务端生成**全新** X25519，与客户端的
   对应分量做 ECDHE，把新公钥覆写进 serverShare；MLKEM768 时另做一次
   Encapsulate 并覆写密文段）。密钥派生是**普通的 TLS 1.3 调度**（这次 ECDHE），
   **AuthKey 不进记录层密钥** —— 它只用于鉴权与证书尾签（下条）。
3. **证书尾签**（`handshake_server_tls13.go:143-160`）：服务端证书是 init() 时
   生成的一次性 ed25519 自签证书，**最后 64 字节**被覆写为
   `HMAC-SHA512(AuthKey, ed25519_pub)`；客户端校验语义（Xray `reality.go:101-128`）：
   `cert.Signature == HMAC-SHA512(AuthKey, cert.PublicKey)` 成立 ⇒ REALITY 服务端
   得到认证；不成立 ⇒ 退回普通 x509 链验证（fallback/镜像路径）。
4. **fallback 透传**（`tls.go:300-310, 410-425`）：未鉴权（或真站 flow 校验失败）⇒
   双向 `io.Copy`，客户端拿到与直连真站逐字节相同的握手。

客户端半边（Xray `reality.go` 的 `UClient`）：uTLS 指纹 hello + `SessionId[0:4]`
=Xray 版本、`[4:8]`=unix time、`[8:16]`=ShortId、`[16:32]`=随机；AuthKey =
`ECDHE(客户端临时私钥, 服务端静态公钥)`（同一把 HKDF）；`VerifyPeerCertificate`
如上。客户端的临时私钥在 rustls 侧由能力 (e) 的注入式密钥交换解决（调用方自己
持有 X25519 私钥）。

## 结案判据（与 issue 对齐，可复跑）

1. **离线三测**：CH 解析（random/sessionId/SNI/key shares 含顺序与 MLKEM 分量）/
   密钥派生 / fallback 判定（shortId 错、时间超窗、SNI 不在列、AEAD 失败各有
   独立断言）。
2. **KDF 对拍**：同一 (privateKey, 时刻, ClientHello) 输入 ⇒ 与复刻
   `tls.go:241-260` + `reality.go:186-198` 的 Go 向量发生器产出**逐字节一致**
   （AuthKey 与 sessionId 密文双向：Go 封 ⇒ Rust 开；Rust 封 ⇒ Go 开）。
3. **真栈**：Rust 镜像服务端 + 客户端 ⇒ 鉴权路径握手成功并承载流量；
   未鉴权客户端拿到与直连真站逐字节相同的握手字节。
4. **P-256-only dest**：**靠透传完成握手**（不是镜像）—— 见下方「判据 4 的修正」。
   `tests/real_stack.rs` 的 `a_p256_only_dest_still_completes_by_falling_back_to_passthrough`
   判三件事：透传路径下客户端与真站**完成握手**、镜像路径对 P-256 **明确拒绝**、
   拒绝后**回落透传**（`mirror_failed`/`fallback` 各记一次）。
5. **客户端半边**（`tests/client_side.rs` 5 条）：`seal_hello` 与镜像证书校验、
   与「本仓服务端」闭环、只改 sessionId 32 字节。
6. **参数面 parity**（`tests/parity.rs` 2 条）：`config.proto` 的 **21 个字段逐条**给出
   归宿（本仓对应物 / 同层不适用 / 未实现），并与上游 proto 文件**双向**核对
   （数量相等 + 每个字段名与类型都在文件里）。「未实现」被断言**恰好**是 ML-DSA 那一对。

## 已知边界

- **HRR 不处理**：真站对 CH 回 HelloRetryRequest 时镜像失败 —— Go 参照同样如此
  （`tls.go` 的 flow 校验会 `break f` 进 fallback）。记为已知边界，不修。
- ML-DSA-65 证书扩展签名（`Mldsa65Key`）暂不实现（Go 参照的可选增强）。

## 落法与顺序（已执行）

spike **密钥派生**（issue 建议且本轮采纳）→ CH 解析 → fallback 判定 →
客户端半边 → 镜像/透传服务端 → 真栈（stock Xray-core，官方 release 可取，已跑通）。

**Settling:** `cargo test -p reality` —— rc=0 且输出 24 条 `... ok`（**0 failed**）⇒ 结论成立；
rc≠0 或出现 `FAILED` ⇒ 结论要改。真栈那三条另外需要 `/tmp/xray-bin/xray`
（官方 release；取法在 `tests/real_stack.rs` 的 `xray_bin()`，可用 `REALITY_XRAY` 覆盖路径）：
没有二进制时会以「找不到 stock Xray」失败（**不是** skip）—— 那同样是 rc≠0，但它证伪的是
「真栈判据在本机可跑」，与另外 21 条离线判据无关。

## 结论（2026-10-01 当日完成）

四类判据全部落地，逐条对照 issue 的结案条件：

1. **离线三测**（`tests/ch_parse.rs` 4 条 / `tests/kdf_vectors.rs` 2 条 /
   `tests/fallback_decision.rs` 10 条）：CH 解析（含 MLKEM768 优先 X25519 的形状与
   线序）、密钥派生、fallback 判定（每条失败路径一个独立断言）。
2. **KDF 对拍**（`tests/kdf_vectors.rs`）：向量由 `fixtures/gen-reality/main.go`
   生成 —— 逐行复刻 `tls.go:241-260` 与 `reality.go` 的 UClient，hello 用上游 uTLS
   的真指纹（HelloChrome_100）+ 确定性 rand。**双向逐字节**：Go 封 ⇒ Rust 开、
   Rust 封 ⇒ 与 Go 密文相同；AuthKey 两侧各自派生并相等。
3. **真栈**（`tests/real_stack.rs`，**stock Xray-core 26.3.27**）：
   鉴权路径完成握手并承载流量（VLESS 请求到达 handler、`short_id` 解出、
   回显往返）；未鉴权客户端拿到与**直连真站逐字节相同**的证书链（实测断言相等）。
4. **P-256-only dest 的修正**（判据 4 原文要求「完成握手并承载数据」）：
   查权威参照后这条**按字面做不到，也不该做** —— 是 uTLS 客户端的硬边界：
   `KeySharePrivateKeys`（`u_public.go:926-931`）只有 `Ecdhe`(X25519)/`Mlkem`/
   `MlkemEcdhe` 三个字段，**没有 P-256 私钥位**，所以 uTLS/Xray 客户端在任何情况下
   都完不成「服务端选 P-256」的握手；XTLS `tls.go:222-239` 只挑那两个组正是为此。
   本仓的处理：镜像**明确拒绝** P-256 ⇒ **回落透传**，客户端与真站直接谈成
   （判据见 `tests/real_stack.rs`，三件事都断言）。

## 过程中的六个实测发现（都进了代码注释）

1. **rustls 严格协商签名算法**，而浏览器指纹（Chrome 131/133）**不报 Ed25519** ——
   REALITY 的证书恰恰必须是 ed25519（客户端按 `ed25519.PublicKey` 做 HMAC 校验）。
   Go 参照把 `hs.sigAlg = Ed25519` 写死（`handshake_server_tls13.go:165`）。
   本仓加了 fork 开关 `ServerConfig::fork_use_certificate_signature_scheme`
   （默认关，FORK(utls-rs) (j)），打开后把签名键自己支持的方案并进候选。
   不打开时的症状：`PeerIncompatible::NoSignatureSchemesInCommon`。
2. **HMAC 的输入是裸 ed25519 公钥（32 字节），不是 SPKI**。第一版传 rustls 的
   `SubjectPublicKeyInfoDer`（44 字节），AuthKey 两侧明明相同（打印核对过），
   客户端仍 `BadCertificate`。
3. **`Certificate` 消息的形状有两处坑**（都是对着 uTLS 解析器逐行核出来的）：
   体首的 `certificate_request_context`（u8 长度）**与每个证书条目后的 u16
   extensions 字段**（`handshake_messages.go:1602-1608`）。少任何一个，客户端
   `readHandshake` 解不开、回 `unexpected message`（看不出原因的错）。
4. **ed25519 公钥的偏移不能猜**：第一版取「签名值前 32 字节」，那是 DER 结构字节；
   真公钥在 SPKI 里（找 OID `2b6570` 后跳 12 字节）。症状 `bad_certificate`。
5. **镜像的 ECDH 输入是客户端 hello 里的 key share**，不是真站 serverShare
   （后者是它自己的密文/公钥）。喂错在 MLKEM768 上炸 `InvalidKeyShare`
   （1120 vs 1216）。参照：`handshake_server_tls13.go:104-120`。
6. **`split_dest_flight` 的 Malformed 要逐条查**，只查第一条会漏掉「缺 CCS」这类
   出现在第二条的坏形状（对照 `tls.go:368-372` 的逐条 `break f`）。

## 已知边界（与 issue 一致）

- **HRR 不处理**：真站对 CH 回 HelloRetryRequest 时镜像失败 —— Go 参照同样如此。
- **Mldsa65Key / Mldsa65Verify（ML-DSA-65 证书扩展签名）未实现** —— 参照的可选增强，
  也是 `tests/parity.rs` 里唯一被断言允许的「未实现」字段对。
- **镜像的组只有 X25519 与 X25519MLKEM768** —— 依据是 uTLS 客户端的能力（见判据 4）。
- **传输层的旁路能力**（`type`/`xver`/`limit_fallback_*`/`spider_x`/`master_key_log`）
  **同层不适用**：本 crate 是协议层（鉴权/镜像/密钥），监听器与传输交给调用方。
  逐条归宿在 `tests/parity.rs` 的表里。
