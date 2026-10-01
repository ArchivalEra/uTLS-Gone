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
4. **P-256-only dest**：完成握手并承载数据（客户端用带 P-256 share 的预设，
   如 Firefox 148 的 `[4588, X25519, P-256]`）。

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
4. **P-256-only dest**：鉴权与镜像计划成立（`tests/mirror_server.rs` 与
   `tests/real_stack.rs` 各一条，真站与客户端都用真 P-256 公钥 —— 哑字节会被
   rustls 以 `PeerMisbehaved(InvalidKeyShare)` 拒绝，这条弯路已记录）。

## 过程中的四个实测发现（都进了代码注释）

1. **rustls 严格协商签名算法**，而浏览器指纹（Chrome 131/133）**不报 Ed25519** ——
   REALITY 的证书恰恰必须是 ed25519（客户端按 `ed25519.PublicKey` 做 HMAC 校验）。
   Go 参照把 `hs.sigAlg = Ed25519` 写死（`handshake_server_tls13.go:165`）。
   本仓加了 fork 开关 `ServerConfig::fork_use_certificate_signature_scheme`
   （默认关，FORK(utls-rs) (j)），打开后把签名键自己支持的方案并进候选。
   不打开时的症状：`PeerIncompatible::NoSignatureSchemesInCommon`。
2. **HMAC 的输入是裸 ed25519 公钥（32 字节），不是 SPKI**。第一版传 rustls 的
   `SubjectPublicKeyInfoDer`（44 字节），AuthKey 两侧明明相同（打印核对过），
   客户端仍 `BadCertificate`。SPKI 里 ed25519 公钥固定在最后 32 字节。
3. **rustls 的 TCP 0-RTT 只支持有状态恢复**（本仓既有结论，本轮再次用到）。
4. **`split_dest_flight` 的 Malformed 要逐条查**，只查第一条会漏掉「缺 CCS」这类
   出现在第二条的坏形状（对照 `tls.go:368-372` 的逐条 `break f`）。

## 已知边界（与 issue 一致）

- **HRR 不处理**：真站对 CH 回 HelloRetryRequest 时镜像失败 —— Go 参照同样如此。
- **Mldsa65Key / Mldsa65Verify（ML-DSA-65 证书扩展签名）暂不实现** —— 参照的可选增强。
- **架构性差异（写进 `src/server.rs` 模块头）**：参照拿真站的 ServerHello 当模板、
  只换 serverShare 密钥字节；本实现跑在 rustls 上、不 fork 服务端，所以 ServerHello
  由 rustls 生成（密码学合法、客户端只验转录与尾签），但「ServerHello 与真站同形」
  这层保真**没做**。要做需给 fork 加服务端侧的 ClientHello/ServerHello 缝。
