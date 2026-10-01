//! **KDF/AEAD 对拍**：Go 向量发生器（`fixtures/gen-reality/main.go`）产出的
//! 向量在这里逐字节核 —— 对应 issue #1 结案判据第 2 条。
//!
//! # 向量的来源与可信度
//!
//! Go 发生器**逐行复刻**两段权威实现（不改语义，只把随机源换成确定性的）：
//! `XTLS/REALITY` `tls.go:241-260`（服务端开启）与 Xray `reality.go`
//! `UClient`（客户端封装）；hello 本身用**上游 uTLS** 的真实指纹
//! （HelloChrome_100）+ 确定性 rand 产出 —— 与 `utls-reference.json`
//! 同一取样原则：向量来自参照实现的实际产出，不手抄。
//!
//! # 双向
//!
//! * Go 封 ⇒ Rust 开（服务端开启路径：AAD 置零、nonce=random[20:]）；
//! * Rust 封 ⇒ 与 Go 的密文**逐字节相同**（客户端封装路径；
//!   AES-256-GCM 对同 (key, nonce, aad, pt) 是确定性的，所以逐字节可比）。
//!
//! # 对拍范围（以及为什么这样切）
//!
//! 对拍的输入是 (privateKey, clientEphemeral, hello) 三元组 —— 正是 issue
//! 判据写的「同一 (privateKey, 时刻, ClientHello) 输入」；hello 同时由本仓的
//! `ch::ClientHello::parse` 解析，nonce/AAD/sessionId 全部**从解析结果取**，
//! 不从向量字段直接读 —— 这样解析器也被同一条向量钉住。

use reality::auth;
use reality::ch::ClientHello;

const VECTORS: &str = include_str!("fixtures/reality-vectors.json");

fn field(name: &str) -> Vec<u8> {
    let v: serde_json::Value = serde_json::from_str(VECTORS).expect("向量是合法 JSON");
    let s = v
        .get(name)
        .and_then(|x| x.as_str())
        .unwrap_or_else(|| panic!("向量缺字段 {name}"));
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("向量字段是合法 hex"))
        .collect()
}

fn str_field(name: &str) -> String {
    let v: serde_json::Value = serde_json::from_str(VECTORS).expect("向量是合法 JSON");
    v.get(name)
        .and_then(|x| x.as_str())
        .unwrap_or_else(|| panic!("向量缺字段 {name}"))
        .to_string()
}

fn hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}

/// **判据 2（KDF 对拍）**：客户端视角 —— `AuthKey = ECDHE(客户端临时私钥,
/// 服务端静态公钥) → HKDF-SHA256(salt=random[:20], info="REALITY")`。
#[test]
fn auth_key_matches_the_go_derivation() {
    let client_ephemeral: [u8; 32] = field("client_ephemeral").try_into().unwrap();
    let server_public: [u8; 32] = field("server_public").try_into().unwrap();
    let random: [u8; 32] = field("hello_random").try_into().unwrap();
    let want: Vec<u8> = field("auth_key");

    // 客户端侧的 shared：临时私钥 × 服务端静态公钥。
    let client_secret = x25519_dalek::StaticSecret::from(client_ephemeral);
    let shared = client_secret.diffie_hellman(&x25519_dalek::PublicKey::from(server_public));
    assert!(shared.was_contributory(), "向量里的密钥对不该是低阶点");

    let got = auth::auth_key(shared.as_bytes(), &random);
    assert_eq!(hex(&got), hex(&want), "AuthKey 与 Go 派生不一致");
}

/// **判据 2（KDF 对拍）+ 离线三测之「密钥派生」**：服务端视角 ——
/// 从 hello 的原始字节解析出 random/sessionId，先解析（钉住解析器），
/// 再开启 AEAD，最后用 Rust 封装与 Go 的密文对拍。
#[test]
fn server_side_open_and_seal_match_the_go_vectors() {
    let hello_raw: Vec<u8> = field("hello_raw_sid_cipher");
    let server_private: [u8; 32] = field("server_private").try_into().unwrap();
    let want_auth_key: [u8; 32] = field("auth_key").try_into().unwrap();
    let want_cipher: [u8; 32] = field("session_id_cipher").try_into().unwrap();
    let want_plain16: Vec<u8> = field("plaintext16");

    // ① 解析器先核一遍：random/sessionId/SNI/key_share 都从向量 hello 取。
    let hello = ClientHello::parse(&hello_raw).expect("向量 hello 该能解析");
    assert_eq!(
        hello.random,
        &field("hello_random")[..],
        "random 解析不一致"
    );
    assert_eq!(
        hello.session_id, want_cipher,
        "线上的 sessionId 就是 AEAD 密文（回填后的形态）"
    );
    assert_eq!(
        hello.server_name.as_deref(),
        Some(str_field("sni").as_str())
    );

    // ② 服务端派生：shared = X25519(静态私钥, 客户端临时公钥)。
    //    客户端临时公钥 = X25519(客户端临时私钥, basepoint) —— 从向量里的
    //    私钥推出来，保证与 Go 发生器用的是同一把。
    let client_ephemeral: [u8; 32] = field("client_ephemeral").try_into().unwrap();
    let client_pub =
        x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(client_ephemeral));
    let shared = auth::x25519(&server_private, client_pub.as_bytes()).expect("X25519");

    // ③ AuthKey 逐字节。
    let auth_key = auth::auth_key(&shared, &hello.random);
    assert_eq!(
        hex(&auth_key),
        hex(&want_auth_key),
        "服务端派生的 AuthKey 与 Go 不一致"
    );

    // ④ 开启：AAD 用「sessionId 置零」的同一份 hello —— 解析器给的 AAD 形态。
    let plain = auth::open_session_id(
        &auth_key,
        &hello.random,
        &hello.aad_with_zeroed_session_id(),
        &hello.session_id,
    )
    .expect("Go 封的 sessionId 必须能被 Rust 开（AAD/nonce/密钥全一致）");
    assert_eq!(&plain[..16], &want_plain16, "明文 16 字节逐字节一致");
    // 明文[16:32] 是 AEAD tag 占位（客户端封包时为零），开出来必然是 tag 覆盖区，不判。

    // ⑤ 封装回拍：Rust 封的密文必须与 Go 的**逐字节相同**
    //    （AES-256-GCM 对同 (key, nonce, aad, pt) 是确定性的）。
    let mut pt16 = [0u8; 16];
    pt16.copy_from_slice(&want_plain16);
    let sealed = auth::seal_session_id(
        &auth_key,
        &hello.random,
        &hello.aad_with_zeroed_session_id(),
        &pt16,
    )
    .expect("封装不该失败");
    assert_eq!(sealed, want_cipher, "Rust 封装与 Go 的密文不一致");
}
