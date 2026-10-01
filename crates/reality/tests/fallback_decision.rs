//! **离线三测之三：fallback 判定**（issue #1 结案判据 1 的第三格）。
//!
//! 判什么：`ch::decide` 在**每一条**失败路径上都给出对应的 [`FallbackReason`]，
//! 且只有全部通过时才 [`Decision::Authenticated`]。参照 `tls.go:213-275`：
//! 任何一个条件不满足都会落进 fallback 分支，**没有**「部分通过」的中间态。
//!
//! 构造方式：先用本仓的客户端封装（`auth::seal_session_id`）造一条**合法**的
//! hello 字节，再逐个变量把它弄坏 —— 每个 `#[test]` 只动一个变量，
//! 这样断言失败的归因是唯一的。

use reality::ch::{ClientHello, RealityConfig, decide};
use reality::{Decision, FallbackReason, auth};

/// 服务端静态密钥对（确定性字节 —— 这不是密码学测试，是接线测试）。
const SERVER_PRIV: [u8; 32] = [0x11; 32];
const CLIENT_PRIV: [u8; 32] = [0x22; 32];
const SHORT_ID: [u8; 8] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
const XRAY_VER: [u8; 4] = [1, 8, 13, 0];
const NOW: u64 = 1_767_139_200; // 与 KDF 向量的「时刻」同源（2026-01-01T00:00:00Z）

/// Firefox 148 的 hello（`[MLKEM768, X25519, P-256]`，线序符合 REALITY 要求）。
fn raw_hello() -> Vec<u8> {
    use utls::hello::{ClientHelloId, ClientHelloSpec, HandshakeInputs, SessionId};
    use utls::values as v;
    let mut spec = ClientHelloSpec::from_preset(ClientHelloId::Firefox(148)).unwrap();
    spec.session_id = SessionId::Fixed(vec![0u8; 32]);
    let mut inputs = HandshakeInputs::deterministic([0x33; 32]);
    inputs.sni = Some("example.com".into());
    let client_pub = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(CLIENT_PRIV));
    inputs.key_exchange = vec![
        (v::X25519, client_pub.as_bytes().to_vec()),
        (v::X25519_MLKEM768, vec![0xBB; 1184 + 32]),
        (v::CURVE_P256, vec![0xCC; 65]),
    ];
    spec.marshal(&inputs).expect("指纹层该能产出").into_bytes()
}

/// 两侧 AuthKey（相等是构造前置）。
fn both_auth_keys(hello: &ClientHello) -> ([u8; 32], [u8; 32]) {
    let peer = hello.reality_peer_pub().expect("合法 hello 有 peerPub");
    let server_shared = auth::x25519(&SERVER_PRIV, &peer).expect("X25519");
    let server_key = auth::auth_key(&server_shared, &hello.random);
    let client_secret = x25519_dalek::StaticSecret::from(CLIENT_PRIV);
    let server_pub = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(SERVER_PRIV));
    let client_shared = client_secret.diffie_hellman(&server_pub);
    let client_key = auth::auth_key(client_shared.as_bytes(), &hello.random);
    (server_key, client_key)
}

fn pt16() -> [u8; 16] {
    let mut p = [0u8; 16];
    p[0..4].copy_from_slice(&XRAY_VER);
    p[4..8].copy_from_slice(&(NOW as u32).to_be_bytes());
    p[8..16].copy_from_slice(&SHORT_ID);
    p
}

/// 把一条 hello 的 sessionId 按 REALITY 客户端的方式封装好（返回线上字节）。
fn wire(hello: &ClientHello, pt: &[u8; 16]) -> Vec<u8> {
    let (_, client_key) = both_auth_keys(hello);
    let aad = hello.aad_with_zeroed_session_id();
    let cipher = auth::seal_session_id(&client_key, &hello.random, &aad, pt).expect("封");
    let mut out = hello.raw.clone();
    out[39..71].copy_from_slice(&cipher);
    out
}

fn authentic_wire() -> Vec<u8> {
    let parsed = ClientHello::parse(&raw_hello()).expect("解析");
    let (server_key, client_key) = both_auth_keys(&parsed);
    assert_eq!(server_key, client_key, "两侧 AuthKey 必须相等（构造前置）");
    wire(&parsed, &pt16())
}

fn config() -> RealityConfig {
    RealityConfig {
        server_names: vec![String::from("example.com")],
        private_key: SERVER_PRIV,
        short_ids: vec![SHORT_ID],
        min_client_ver: Some([1, 0, 0, 0]),
        max_client_ver: Some([9, 9, 9, 9]),
        max_time_diff: Some(3600),
    }
}

/// 控制组：合法输入 ⇒ 鉴别通过，且解出的三个字段正确。
#[test]
fn a_valid_hello_authenticates_and_yields_the_plaintext_fields() {
    let hello = ClientHello::parse(&authentic_wire()).expect("解析");
    match decide(&hello, &config(), NOW) {
        Decision::Authenticated {
            client_ver,
            client_time,
            short_id,
            ..
        } => {
            assert_eq!(client_ver, XRAY_VER);
            assert_eq!(client_time, NOW as u32);
            assert_eq!(short_id, SHORT_ID);
        }
        Decision::Fallback { reason } => panic!("合法输入不该 fallback：{reason:?}"),
    }
}

#[test]
fn sni_outside_the_allowlist_falls_back() {
    let hello = ClientHello::parse(&authentic_wire()).expect("解析");
    let mut cfg = config();
    cfg.server_names = vec![String::from("other.example")];
    assert!(matches!(
        decide(&hello, &cfg, NOW),
        Decision::Fallback {
            reason: FallbackReason::ServerNameNotAllowed(_)
        }
    ));
}

#[test]
fn a_short_id_outside_the_allowlist_falls_back() {
    let hello = ClientHello::parse(&authentic_wire()).expect("解析");
    let mut cfg = config();
    cfg.short_ids = vec![[0xFF; 8]];
    assert!(matches!(
        decide(&hello, &cfg, NOW),
        Decision::Fallback {
            reason: FallbackReason::ShortIdNotAllowed(sid)
        } if sid == SHORT_ID
    ));
}

#[test]
fn a_stale_timestamp_falls_back() {
    let hello = ClientHello::parse(&authentic_wire()).expect("解析");
    let later = NOW + 7200;
    assert!(matches!(
        decide(&hello, &config(), later),
        Decision::Fallback {
            reason: FallbackReason::TimeOutsideWindow { got }
        } if got == NOW as u32
    ));
    let earlier = NOW - 7200;
    assert!(matches!(
        decide(&hello, &config(), earlier),
        Decision::Fallback {
            reason: FallbackReason::TimeOutsideWindow { .. }
        }
    ));
    // 边界内（正好 1 小时）不倒 —— Go 是 `<=`。
    assert!(matches!(
        decide(&hello, &config(), NOW + 3600),
        Decision::Authenticated { .. }
    ));
}

#[test]
fn a_client_version_outside_the_window_falls_back() {
    let hello = ClientHello::parse(&authentic_wire()).expect("解析");
    let mut cfg = config();
    cfg.min_client_ver = Some([1, 9, 0, 0]);
    assert!(matches!(
        decide(&hello, &cfg, NOW),
        Decision::Fallback {
            reason: FallbackReason::ClientVersion { got }
        } if got == XRAY_VER
    ));
    let mut cfg = config();
    cfg.max_client_ver = Some([1, 7, 0, 0]);
    assert!(matches!(
        decide(&hello, &cfg, NOW),
        Decision::Fallback {
            reason: FallbackReason::ClientVersion { .. }
        }
    ));
}

#[test]
fn a_tampered_session_id_fails_the_aead_and_falls_back() {
    let mut wired = authentic_wire();
    wired[39] ^= 0x01;
    let hello = ClientHello::parse(&wired).expect("仍然可解析（只是密文坏了）");
    assert!(matches!(
        decide(&hello, &config(), NOW),
        Decision::Fallback {
            reason: FallbackReason::SessionIdAuth
        }
    ));
}

#[test]
fn tampering_with_a_cipher_suite_byte_breaks_the_aead_because_the_whole_hello_is_the_aad() {
    // AAD 是**整条原始 hello**（sessionId 置零后）—— 防篡改面：
    // 改动任何一个不参与鉴权前置判定的字节，AEAD 就该失败。
    let mut wired = authentic_wire();
    let at = wired
        .windows(2)
        .position(|w| w == [0x13, 0x01])
        .expect("hello 里有 TLS_AES_128_GCM_SHA256");
    wired[at] = 0x13;
    wired[at + 1] = 0x02; // 换成 TLS_AES_256_GCM_SHA384（长度不变）
    let hello = ClientHello::parse(&wired).expect("仍可解析");
    assert!(matches!(
        decide(&hello, &config(), NOW),
        Decision::Fallback {
            reason: FallbackReason::SessionIdAuth
        }
    ));
}

/// 在 hello 字节里找某个 key_share 组 id 的偏移。
fn find_group_offset(hello: &[u8], group: u16) -> Option<usize> {
    let target = group.to_be_bytes();
    for i in 0..hello.len().saturating_sub(4) {
        if hello[i..i + 2] != target {
            continue;
        }
        let len = u16::from_be_bytes([hello[i + 2], hello[i + 3]]) as usize;
        if len == 32 || len == 1184 + 32 || len == 65 {
            return Some(i);
        }
    }
    None
}

#[test]
fn a_hello_without_mlkem_share_falls_back() {
    // tls.go:239-241：没有 X25519MLKEM768 ⇒ reject（哪怕 X25519 在场）。
    //
    // 构造：**先在解析结果上**删掉 MLKEM768 share（此时不需要 peerPub 也能封），
    // 再从解析结果重新编码整条 hello —— 编码器逐字段写，删掉的 share 不出现在线上，
    // AAD 与密文都基于同一份字节。
    let parsed = ClientHello::parse(&raw_hello()).expect("解析");
    // 用「把组名换掉」的方式表达删除：直接改 key_shares 列表 + 重新编码。
    // 本仓没有「重新编码任意 hello」的接口（指纹层从 spec 编码），所以这里
    // 走**最小字节手术**：把 MLKEM768 的组 id 改成 GREASE 的合法值 0x0a0a，
    // 它既不是 MLKEM768 也不是 X25519 ⇒ reality_peer_pub 应当报缺 MLKEM768。
    // 但 0x0a0a 是 GREASE —— 判定层对 GREASE 的处理与参照一致（跳过），
    // 于是「形状里没有 MLKEM768」这条检查被触发。
    let mut wired = raw_hello();
    let at = find_group_offset(&wired, 4588).expect("有 MLKEM768 share");
    wired[at] = 0x0a;
    wired[at + 1] = 0x0a;
    let stripped = ClientHello::parse(&wired).expect("解析");
    // 重封（AAD 变了）。此时 both_auth_keys 会因 peerPub 报错 —— 用**未剥离**的
    // hello 算 AuthKey（密钥派生只看真实 X25519 share，与 MLKEM768 无关）。
    let client_secret = x25519_dalek::StaticSecret::from(CLIENT_PRIV);
    let server_pub = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(SERVER_PRIV));
    let shared = client_secret.diffie_hellman(&server_pub);
    let client_key = auth::auth_key(shared.as_bytes(), &parsed.random);
    let aad = stripped.aad_with_zeroed_session_id();
    let cipher = auth::seal_session_id(&client_key, &stripped.random, &aad, &pt16()).expect("封");
    let mut out = stripped.raw.clone();
    out[39..71].copy_from_slice(&cipher);
    let hello = ClientHello::parse(&out).expect("解析");
    assert!(matches!(
        decide(&hello, &config(), NOW),
        Decision::Fallback {
            reason: FallbackReason::KeyShareShape(_)
        }
    ));
}

#[test]
fn mlkem_after_x25519_falls_back() {
    // tls.go:228-239：MLKEM768 必须在 X25519 之前。
    let mut wired = raw_hello();
    let mlkem_at = find_group_offset(&wired, 4588).expect("MLKEM768");
    let x25519_at = find_group_offset(&wired, 29).expect("X25519");
    assert!(mlkem_at < x25519_at, "前置条件：原始线序里 MLKEM768 在前");
    wired[mlkem_at] = 0x00;
    wired[mlkem_at + 1] = 0x1d;
    wired[x25519_at] = 0x11;
    wired[x25519_at + 1] = 0xec;
    let parsed = ClientHello::parse(&wired).expect("解析");
    assert!(matches!(
        parsed.reality_peer_pub(),
        Err(FallbackReason::KeyShareShape(_))
    ));
}

#[test]
fn a_wrong_private_key_falls_back_at_the_aead_not_earlier() {
    // 密钥不匹配 ⇒ AEAD Open 失败（而不是 X25519 失败）—— 这是 fallback 的
    // 「陌生人」路径：任何人连上来都会拿到一次正常的握手。
    let hello = ClientHello::parse(&authentic_wire()).expect("解析");
    let mut cfg = config();
    cfg.private_key = [0x99; 32];
    assert!(matches!(
        decide(&hello, &cfg, NOW),
        Decision::Fallback {
            reason: FallbackReason::SessionIdAuth
        }
    ));
}
