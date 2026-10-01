# 11: REALITY 的 Rust 等价实现 —— 从哪一步开始、对什么判据

**Status:** ready-for-agent  <!-- 无人值守推进中：spike 已完成，镜像/客户端半边待做 -->

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

## 落法与顺序

先 spike **密钥派生**（issue 建议且本轮采纳）：完全离线、有 Go 向量可对拍、
且是唯一「生态里没有对应物」的一步。随后 CH 解析（复用 `crates/utls` 的解析器）、
fallback 判定、镜像/透传代理、客户端半边。真栈的 stock Xray-core 客户端判据
视二进制可得性，不可得时如实记录于本工单。

**Settling:** `cargo test -p reality` —— 离线三测 + KDF 对拍全绿 ⇒ spike 成立；
Go 向量重生成后 Rust 侧仍绿 ⇒ 对拍持续成立。真栈判据的 settles 另列于测试文件头。
