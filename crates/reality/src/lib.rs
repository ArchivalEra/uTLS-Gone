//! XTLS/REALITY 的 Rust 等价实现 —— **鉴权与密钥派生**这一半。
//!
//! 权威参照：`XTLS/REALITY`（Go crypto/tls fork）`tls.go:241-260` 的服务端鉴权，
//! 与 Xray-core `transport/internet/reality/reality.go` `UClient` 的客户端封装。
//! 本 crate 的每一步都与那两段逐行对应，并以**从 Go 实现生成的测试向量**
//! 逐字节对拍（`tests/fixtures/gen-reality/`，重生成命令见其文件头）。
//!
//! # 协议形状（读参照读出的，一处不猜）
//!
//! * `AuthKey = X25519(server_static_priv, client_ephemeral_pub)`（服务端视角；
//!   客户端用 `X25519(client_ephemeral_priv, server_static_pub)` 得同一把），
//!   再 `HKDF-SHA256(ikm=AuthKey, salt=hello.random[:20], info="REALITY")` 读 32 字节。
//! * `sessionId`（32 字节，在 ClientHello 的固定偏移 39）=
//!   `AES-256-GCM(AuthKey).Seal(nonce=random[20:32], plaintext=[ver(4)|time(4)|shortId(8)],
//!   AAD=**sessionId 置零后的原始 ClientHello**)`。
//!   AAD 的置零约定两侧一致：客户端封包前置零 `Raw[39:71]`，服务端用全零
//!   `plainText` 覆写后再 Open（`tls.go:255-258` 的 `copy(hs.clientHello.sessionId, plainText)`）。
//! * 明文 `[0:4]`=客户端版本、`[4:8]`=unix time（BE）、`[8:16]`=shortId、
//!   `[16:32]` 不发送（AEAD tag 占位）。
//!
//! # 已知边界
//!
//! HRR 不处理（真站对 CH 回 HelloRetryRequest 时镜像失败 —— Go 参照同样如此，
//! 记为已知边界）；ML-DSA-65 证书扩展签名暂不实现。

pub mod auth;
pub mod ch;

/// 鉴权失败/回退的原因。每一条都对应参照实现里一个**显式的**分支，
/// 不存在「未知原因的 fallback」—— 那种 fallback 会把可诊断性丢掉。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FallbackReason {
    /// SNI 不在 `ServerNames` 白名单里（`tls.go:216` 的
    /// `!config.ServerNames[hs.clientHello.serverName]`）。
    ServerNameNotAllowed(String),
    /// key share 形状/顺序不满足：`X25519MLKEM768` 必须在前（其末 32 字节为
    /// X25519 分量），可选 `X25519` 在后，各最多一次（`tls.go:219-239`）。
    KeyShareShape(String),
    /// X25519 本身失败（低阶点等 —— Go 的 `curve25519.X25519` 同样会报错）。
    X25519(String),
    /// sessionId 的 AEAD Open 失败（`tls.go:254-256` 的 `break`）。
    SessionIdAuth,
    /// shortId 不在白名单（`tls.go:272`）。
    ShortIdNotAllowed([u8; 8]),
    /// 客户端版本超出 `MinClientVer`/`MaxClientVer`（`tls.go:269-271`）。
    ClientVersion { got: [u8; 4] },
    /// 时刻超出 `MaxTimeDiff`（`tls.go:270` 的
    /// `time.Since(hs.c.ClientTime).Abs() <= config.MaxTimeDiff`）。
    TimeOutsideWindow { got: u32 },
}

/// 鉴权决定：[`Decision::Authenticated`] 走镜像握手；[`Decision::Fallback`]
/// 把连接**原样透传**给真站（客户端拿到一次完全正常的 TLS 握手）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Authenticated {
        /// AEAD 打开的明文 16 字节（ver/time/shortId；tag 占位不发送）。
        plaintext: [u8; 16],
        client_ver: [u8; 4],
        /// unix 秒（BE，来自明文 `[4:8]`）。
        client_time: u32,
        short_id: [u8; 8],
        /// X25519 共享（HKDF 之前）—— 诊断用；密钥派生的输入。
        shared: [u8; 32],
        auth_key: [u8; 32],
    },
    Fallback {
        reason: FallbackReason,
    },
}
