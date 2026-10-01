//! **客户端半边判据**（issue #1 结案判据 1 的延伸 + 判据 3 的客户端面）。
//!
//! 判什么：
//!
//! 1. `seal_hello` 产出的 hello：sessionId 是**本仓服务端**（`ch::decide`）能鉴别
//!    的密文 —— 客户端与服务端两条路在同一份字节上闭环；
//! 2. 其余字节**一个都没动**（除 sessionId 的 32 字节）—— 指纹保真；
//! 3. 镜像证书校验的两个分支（REALITY 服务端 / 镜像真站）。

use reality::ch::{ClientHello, RealityConfig, decide};
use reality::client::{ClientConfig, mirror_signature, seal_hello, verify_mirror_signature};
use reality::{Decision, PeerVerdict};

const SERVER_PRIV: [u8; 32] = [0x51; 32];
const CLIENT_PRIV: [u8; 32] = [0x52; 32];
const SHORT_ID: [u8; 8] = [0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8];
const VER: [u8; 4] = [1, 8, 13, 0];
const NOW: u64 = 1_767_139_200;

fn server_public() -> [u8; 32] {
    *x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(SERVER_PRIV)).as_bytes()
}

/// 一条真实指纹 hello（Firefox 148：`[MLKEM768, X25519, P-256]`），
/// X25519 share 用 `CLIENT_PRIV` 的公钥。
fn fingerprint_hello() -> Vec<u8> {
    use utls::hello::{ClientHelloId, ClientHelloSpec, HandshakeInputs, SessionId};
    use utls::values as v;
    let mut spec = ClientHelloSpec::from_preset(ClientHelloId::Firefox(148)).unwrap();
    spec.session_id = SessionId::Fixed(vec![0u8; 32]);
    let mut inputs = HandshakeInputs::deterministic([0x66; 32]);
    inputs.sni = Some("example.com".into());
    let client_pub = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(CLIENT_PRIV));
    inputs.key_exchange = vec![
        (v::X25519, client_pub.as_bytes().to_vec()),
        (v::X25519_MLKEM768, vec![0xBB; 1184 + 32]),
        (v::CURVE_P256, vec![0xCC; 65]),
    ];
    spec.marshal(&inputs).expect("指纹层该能产出").into_bytes()
}

fn client_config() -> ClientConfig {
    ClientConfig {
        public_key: server_public(),
        short_id: SHORT_ID,
        client_ver: VER,
        fallback_to_webpki: true,
    }
}

/// **判据 1：闭环** —— 客户端封的 hello，本仓服务端用 `decide` 鉴别通过。
#[test]
fn the_client_seals_a_hello_that_our_own_server_authenticates() {
    let original = fingerprint_hello();
    let sealed = seal_hello(&original, &CLIENT_PRIV, &client_config(), NOW).expect("封包");

    // 服务端视角：同一把静态私钥。
    let cfg = RealityConfig {
        server_names: vec![String::from("example.com")],
        private_key: SERVER_PRIV,
        short_ids: vec![SHORT_ID],
        min_client_ver: Some([1, 0, 0, 0]),
        max_client_ver: Some([9, 9, 9, 9]),
        max_time_diff: Some(3600),
    };
    let hello = ClientHello::parse(&sealed.hello).expect("解析");
    match decide(&hello, &cfg, NOW) {
        Decision::Authenticated {
            client_ver,
            client_time,
            short_id,
            auth_key,
            ..
        } => {
            assert_eq!(client_ver, VER, "版本从 sessionId 明文里解出");
            assert_eq!(client_time, NOW as u32);
            assert_eq!(short_id, SHORT_ID, "shortId 从 sessionId 明文里解出");
            assert_eq!(
                auth_key, sealed.auth_key,
                "服务端派生的 AuthKey 必须与客户端手上的那把相同"
            );
        }
        Decision::Fallback { reason } => panic!("自己封的 hello 该被鉴别：{reason:?}"),
    }
}

/// **判据 2：指纹保真** —— 除 sessionId 的 32 字节外，hello 一个字节都没动。
#[test]
fn sealing_touches_only_the_session_id_bytes() {
    let original = fingerprint_hello();
    let sealed = seal_hello(&original, &CLIENT_PRIV, &client_config(), NOW).expect("封包");
    assert_eq!(sealed.hello.len(), original.len(), "长度不许变");
    for (i, (got, want)) in sealed.hello.iter().zip(original.iter()).enumerate() {
        if (39..71).contains(&i) {
            continue; // sessionId 那 32 字节被密文替换（预期）
        }
        assert_eq!(got, want, "第 {i} 字节不该被改（只有 sessionId 区域能变）");
    }
    assert_ne!(
        &sealed.hello[39..71],
        &original[39..71],
        "sessionId 必须真的被换成密文"
    );
}

/// 时间不同 ⇒ 密文不同（时间在明文里）；其余输入相同 ⇒ 幂等。
#[test]
fn the_sealed_session_id_depends_on_the_time_and_is_deterministic() {
    let original = fingerprint_hello();
    let a = seal_hello(&original, &CLIENT_PRIV, &client_config(), NOW).expect("封");
    let b = seal_hello(&original, &CLIENT_PRIV, &client_config(), NOW).expect("封");
    let c = seal_hello(&original, &CLIENT_PRIV, &client_config(), NOW + 1).expect("封");
    assert_eq!(
        a.hello, b.hello,
        "同输入 ⇒ 逐字节相同（GCM 对同参数是确定性的）"
    );
    assert_ne!(a.hello, c.hello, "时间不同 ⇒ 密文不同");
    assert_eq!(
        a.auth_key, b.auth_key,
        "AuthKey 与时间无关（只看 X25519 + random）"
    );
}

/// **判据 3：镜像证书的两个分支**。
#[test]
fn the_mirror_signature_distinguishes_a_reality_server_from_a_mirrored_site() {
    let sealed = seal_hello(&fingerprint_hello(), &CLIENT_PRIV, &client_config(), NOW).expect("封");
    // 服务端生成尾签（handshake_server_tls13.go:149-151 的等价物）。
    let fake_ed25519_pub = [0xE5u8; 32];
    let sig = mirror_signature(&sealed.auth_key, &fake_ed25519_pub);
    assert_eq!(
        verify_mirror_signature(&sealed.auth_key, &fake_ed25519_pub, &sig),
        PeerVerdict::RealityServer,
        "尾签对上 ⇒ REALITY 服务端"
    );
    // 镜像真站的证书：签名是真 CA 签的，不可能等于我们的 HMAC。
    let ca_sig = [0x00u8; 64];
    assert_eq!(
        verify_mirror_signature(&sealed.auth_key, &fake_ed25519_pub, &ca_sig),
        PeerVerdict::NotRealityServer,
        "尾签对不上 ⇒ 退回 x509 链验证（镜像/fallback 路径）"
    );
    // 用**别的** AuthKey 签的也不算（换了连接就换了密钥）。
    let other_key = [0x77u8; 32];
    let other_sig = mirror_signature(&other_key, &fake_ed25519_pub);
    assert_eq!(
        verify_mirror_signature(&sealed.auth_key, &fake_ed25519_pub, &other_sig),
        PeerVerdict::NotRealityServer
    );
}

/// 攻击面：**没有** AuthKey 的人无法伪造尾签（HMAC 需要密钥），
/// 所以「客户端看到真站的证书」不会被冒充成「REALITY 服务端」。
#[test]
fn a_third_party_cannot_forge_the_mirror_signature() {
    let sealed = seal_hello(&fingerprint_hello(), &CLIENT_PRIV, &client_config(), NOW).expect("封");
    let fake_pub = [0x11u8; 32];
    // 攻击者猜一把密钥。
    let mut forged = [0u8; 64];
    for (i, b) in forged.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(7);
    }
    assert_eq!(
        verify_mirror_signature(&sealed.auth_key, &fake_pub, &forged),
        PeerVerdict::NotRealityServer
    );
}
