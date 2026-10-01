//! AuthKey 派生与 sessionId 的 AEAD 封装/开启 —— 与 `XTLS/REALITY`
//! `tls.go:241-260`（服务端）和 Xray `reality.go` `UClient`（客户端）逐行对应。
//!
//! 对拍：`tests/kdf_vectors.rs` 拿 `tests/fixtures/gen-reality/main.go`
//! 生成的向量逐字节核（向量由 Go 侧按同一伪代码产出）。

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use sha2::Sha256;
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret as XStaticSecret};

use crate::FallbackReason;

/// HKDF-SHA256 的 info 标签（`tls.go:244` 的 `[]byte("REALITY")`）。
const REALITY_INFO: &[u8] = b"REALITY";
/// sessionId 在 ClientHello 原始字节里的偏移与长度（`raw[39:]`，固定 32 字节）。
pub const SESSION_ID_OFFSET: usize = 39;
pub const SESSION_ID_LEN: usize = 32;

/// X25519（RFC 7748）。`Err` 对应 Go `curve25519.X25519` 对低阶点的报错分支。
pub fn x25519(private: &[u8; 32], peer_public: &[u8; 32]) -> Result<[u8; 32], FallbackReason> {
    let secret = XStaticSecret::from(*private);
    let public = XPublicKey::from(*peer_public);
    let shared = secret.diffie_hellman(&public);
    if !shared.was_contributory() {
        // Go 的 curve25519.X25519 对全零输出返回 error（`tls.go:242` 的 break）。
        return Err(FallbackReason::X25519(String::from(
            "low-order / all-zero shared secret",
        )));
    }
    Ok(*shared.as_bytes())
}

/// `AuthKey = HKDF-SHA256(ikm=shared, salt=random[:20], info="REALITY")`，读 32 字节。
///
/// `tls.go:244`：`hkdf.New(sha256.New, hs.c.AuthKey, hs.clientHello.random[:20],
/// []byte("REALITY")).Read(hs.c.AuthKey)`。
pub fn auth_key(shared: &[u8; 32], hello_random: &[u8; 32]) -> [u8; 32] {
    let hk = hkdf::Hkdf::<Sha256>::new(Some(&hello_random[..20]), shared);
    let mut out = [0u8; 32];
    hk.expand(REALITY_INFO, &mut out)
        .expect("32 字节输出对 HKDF-SHA256 恒在范围内");
    out
}

/// AEAD 实例（AES-256-GCM，密钥 = AuthKey；`tls.go:247-249`）。
fn aead(auth_key: &[u8; 32]) -> Aes256Gcm {
    Aes256Gcm::new_from_slice(auth_key).expect("AES-256-GCM 密钥恰为 32 字节")
}

/// 客户端封装（Xray `reality.go` `UClient`）：
/// `Seal(nonce=random[20:32], plaintext=16 字节, AAD=sessionId 置零后的原始 hello)`
/// ⇒ 32 字节（16 密文 + 16 tag）。
///
/// `aad` 必须已经是「sessionId 置零」形态 —— 见 [`crate`] 模块头与
/// [`ch::zero_session_id`]。
pub fn seal_session_id(
    auth_key: &[u8; 32],
    hello_random: &[u8; 32],
    aad_sid_zeroed: &[u8],
    plaintext16: &[u8; 16],
) -> Result<[u8; 32], String> {
    let nonce = Nonce::from_slice(&hello_random[20..32]);
    let sealed = aead(auth_key)
        .encrypt(
            nonce,
            Payload {
                msg: plaintext16,
                aad: aad_sid_zeroed,
            },
        )
        .map_err(|e| format!("AEAD Seal 失败：{e}"))?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&sealed);
    Ok(out)
}

/// 服务端开启（`tls.go:254-258`）：AEAD Open 失败 ⇒
/// [`FallbackReason::SessionIdAuth`]（参照实现的 `break` ⇒ fallback）。
pub fn open_session_id(
    auth_key: &[u8; 32],
    hello_random: &[u8; 32],
    aad_sid_zeroed: &[u8],
    session_id_cipher: &[u8; 32],
) -> Result<[u8; 16], FallbackReason> {
    let nonce = Nonce::from_slice(&hello_random[20..32]);
    let plain = aead(auth_key)
        .decrypt(
            nonce,
            Payload {
                msg: session_id_cipher,
                aad: aad_sid_zeroed,
            },
        )
        .map_err(|_| FallbackReason::SessionIdAuth)?;
    // Go 参照（tls.go:256-260）：Open 的明文缓冲是 32 字节，但读的只有
    // `[0:4]`=ver、`[4:8]`=time、`[8:16]`=shortId —— 明文本身只有 16 字节。
    let mut out = [0u8; 16];
    out.copy_from_slice(&plain);
    Ok(out)
}
