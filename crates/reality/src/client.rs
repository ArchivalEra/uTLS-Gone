//! **客户端半边**：Xray `transport/internet/reality/reality.go` 的 `UClient` 与
//! `UConn.VerifyPeerCertificate` 的 Rust 等价物。
//!
//! # 参照的三件事（逐条对应）
//!
//! 1. `UClient` 在**指纹 hello 已经建好**之后动手（`uConn.BuildHandshakeState()`）：
//!    把 `SessionId` 填成 `[ver(4) | unix_time(4) | shortId(8) | 0*8]`，
//!    用**客户端的临时 X25519 私钥**与服务端静态公钥算出 AuthKey，
//!    再 `Seal` 出 32 字节密文**回填** `raw[39:71]`。
//!    ⇒ [`seal_hello`] 是本仓的对应物：**就地改已序列化的 hello**，只改 sessionId
//!    那 32 字节（与 fork 的 PSK binder 补写同一类操作：只改定长区域，不动长度）。
//! 2. `VerifyPeerCertificate`：`cert.Signature == HMAC-SHA512(AuthKey, cert.PublicKey)`
//!    成立 ⇒ 这是 REALITY 服务端（`c.Verified = true`）；
//!    否则退回普通 x509 链验证（镜像/fallback 路径下客户端看到的真站证书）。
//! 3. `SessionTicketsDisabled: true`（`utlsConfig`）—— 0-RTT/票据在 REALITY 里关掉。
//!
//! # 与 utls 的接缝
//!
//! uTLS 的 `KeyShareKeys.Ecdhe` 是本仓**没有**的：我们的指纹层把「公钥发给引擎、
//! 私钥留给自己」这条线做成了注入式（见 `utls-engine` 的 `ExternalKeyExchange`）。
//! 所以客户端这里由调用方**自己持有 X25519 私钥**并把公钥喂进 spec —— 与
//! `crates/utls-engine/tests/early_data.rs` 里 `CLIENT_PRIV` 的用法同形。

use crate::auth;

/// 客户端配置（对应 Xray `Config` 的客户端面；字段名与 `config.proto` 逐条
/// 对齐，判据在 `tests/parity.rs`）。
#[derive(Debug, Clone)]
pub struct ClientConfig {
    /// 服务端静态 X25519 公钥（Xray `Config.PublicKey`）。
    pub public_key: [u8; 32],
    /// shortId（Xray `Config.ShortId`，≤8 字节，不足右侧补零）。
    pub short_id: [u8; 8],
    /// 客户端版本四字节（Xray `core.Version_x/y/z/reserved`）。
    pub client_ver: [u8; 4],
    /// 镜像证书校验失败时是否**直接失败**（`false` ⇒ 退回系统根验证，
    /// 即 fallback 路径；与 Xray 的 `certs[0].Verify(opts)` 分支一致）。
    pub fallback_to_webpki: bool,
}

/// `sessionId` 的明文形态（16 字节；`[16:32]` 由 AEAD tag 占位）。
pub fn session_id_plaintext(ver: [u8; 4], unix_time: u32, short_id: [u8; 8]) -> [u8; 16] {
    let mut out = [0u8; 16];
    out[0..4].copy_from_slice(&ver);
    out[4..8].copy_from_slice(&unix_time.to_be_bytes());
    out[8..16].copy_from_slice(&short_id);
    out
}

/// 客户端立刻要用的 AuthKey 与它对应的密文 —— [`seal_hello`] 的返回值。
#[derive(Debug, Clone)]
pub struct SealedHello {
    /// 线上 hello（sessionId 已被密文替换）。
    pub hello: Vec<u8>,
    /// 客户端 AuthKey（校验镜像证书时要用它做 HMAC-SHA512）。
    pub auth_key: [u8; 32],
}

/// `UClient` 的核心动作：给定**已序列化的指纹 hello**、客户端临时私钥、
/// 时间与配置，产出线上 hello 与 AuthKey。
///
/// 与 Xray 的差别只有一处、且是**架构性**的：那里 `AuthKey` 来自
/// `utls` 内部的 `KeyShareKeys.Ecdhe`，这里由调用方把私钥交进来
/// （原因见模块头）。密码学原语与顺序逐句对应。
pub fn seal_hello(
    handshake_msg: &[u8],
    client_ephemeral_private: &[u8; 32],
    config: &ClientConfig,
    unix_time: u64,
) -> Result<SealedHello, String> {
    let mut hello = crate::ch::ClientHello::parse(handshake_msg)
        .map_err(|e| format!("指纹 hello 解析失败：{e:?}"))?;
    // AuthKey = X25519(客户端临时私钥, 服务端静态公钥) → HKDF。
    let shared = auth::x25519(client_ephemeral_private, &config.public_key)
        .map_err(|e| format!("X25519 失败：{e:?}"))?;
    let auth_key = auth::auth_key(&shared, &hello.random);
    // 明文字段（Xray：ver / time / shortId）。
    let pt = session_id_plaintext(
        config.client_ver,
        u32::try_from(unix_time).map_err(|_| String::from("unix 时间超出 u32"))?,
        config.short_id,
    );
    // AAD：sessionId 置零后的 hello（客户端封包前的形态）。
    let zeroed = hello.aad_with_zeroed_session_id();
    let cipher = auth::seal_session_id(&auth_key, &hello.random, &zeroed, &pt)?;
    // 回填 raw[39:71]。
    hello.raw[crate::auth::SESSION_ID_OFFSET
        ..crate::auth::SESSION_ID_OFFSET + crate::auth::SESSION_ID_LEN]
        .copy_from_slice(&cipher);
    Ok(SealedHello {
        hello: hello.raw,
        auth_key,
    })
}

/// 镜像证书的校验结果 —— `VerifyPeerCertificate` 的两个分支。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerVerdict {
    /// 尾签对上了：这是 **REALITY 服务端**（`c.Verified = true`）。
    RealityServer,
    /// 尾签没对上：**退回普通 x509 链验证**（镜像/fallback 路径；
    /// 客户端看到的是真站的真证书，由调用方的根存储决定信任）。
    NotRealityServer,
}

/// `UConn.VerifyPeerCertificate` 的等价物：`HMAC-SHA512(AuthKey, cert.PublicKey)`
/// 与 `cert.Signature` 比较（Xray `reality.go:109-128`）。
///
/// 入参是**证书的两个字段**（不是整张证书）：ed25519 公钥字节与签名位。
/// RELATITY 服务端的证书由 `handshake_server_tls13.go:143-150` 一次性生成，
/// 签名位被覆写为那个 HMAC —— 判据只需要这两个字段，不需要解析 DER。
pub fn verify_mirror_signature(
    auth_key: &[u8; 32],
    cert_public_key: &[u8],
    cert_signature: &[u8],
) -> PeerVerdict {
    use hmac::{Hmac, Mac};
    use sha2::Sha512;
    let mut mac = <Hmac<Sha512> as Mac>::new_from_slice(auth_key).expect("HMAC 接受任意键长");
    mac.update(cert_public_key);
    let want = mac.finalize().into_bytes();
    if want.as_slice() == cert_signature {
        PeerVerdict::RealityServer
    } else {
        PeerVerdict::NotRealityServer
    }
}

/// 服务端为**自签证书**生成尾签的等价物（`handshake_server_tls13.go:149-151`）：
/// `HMAC-SHA512(AuthKey, ed25519_pub)` 写进证书签名的最后 64 字节。
///
/// 与 [`verify_mirror_signature`] 是同一算法的两侧 —— 判据里成对使用，
/// 也用于「不是 REALITY 服务端」的负例构造。
pub fn mirror_signature(auth_key: &[u8; 32], cert_public_key: &[u8]) -> [u8; 64] {
    use hmac::{Hmac, Mac};
    use sha2::Sha512;
    let mut mac = <Hmac<Sha512> as Mac>::new_from_slice(auth_key).expect("HMAC 接受任意键长");
    mac.update(cert_public_key);
    let out = mac.finalize().into_bytes();
    let mut sig = [0u8; 64];
    sig.copy_from_slice(&out);
    sig
}
