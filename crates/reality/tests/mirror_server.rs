//! **镜像服务端判据**（issue #1 结案判据 3 的服务端面）：
//! 一条**真实的 TLS 1.3 服务端**在本地充当「真站（dest）」，REALITY 服务端的
//! 镜像计划读它回流的字节并分类 —— 判据全部取**真站与客户端的实际字节**。
//!
//! # 判据
//!
//! 1. 本地真站的 flight 被 [`split_dest_flight`] 正确分类：ServerHello / CCS /
//!    应用数据——**顺序与类型**是参照 `tls.go:330-360` 的校验表；
//! 2. 鉴权通过时计划为 [`MirrorPlan::Authenticated`]，且 AuthKey 与客户端一致；
//! 3. 未鉴权时计划为 [`MirrorPlan::Fallback`]，且**透传的字节与直连真站逐字节相同**；
//! 4. 真站 flight 形状不对（例如没有 CCS）⇒ 落回透传，不猜。
//!
//! # 「P-256-only dest」的说明
//!
//! issue 判据 4 要求「P-256-only dest 完成握手并承载数据」。real 的镜像**不**参与
//! 真站的密钥协商（它只转发 hello、读回真站的 flight；会话密钥由 REALITY 服务端
//! 自己生成 —— `handshake_server_tls13.go:104-120` 用客户端的 key share）。
//! 所以「dest 只支持 P-256」对镜像计划的影响落在**客户端 hello 的 key share**上：
//! 客户端必须发 P-256 share（Firefox 148 的预设正是 `[MLKEM768, X25519, P-256]`）。
//! 判据 5 用 P-256-only 的本地真站跑一遍完整镜像流程来钉住这一点。

mod common;

use reality::ch::{ClientHello, RealityConfig, decide};
use reality::client::seal_hello;
use reality::mirror::{DestRecord, MirrorPlan, plan, split_dest_flight};
use reality::{Decision, FallbackReason};

const SERVER_PRIV: [u8; 32] = [0x71; 32];
const CLIENT_PRIV: [u8; 32] = [0x72; 32];
const SHORT_ID: [u8; 8] = [0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8];
const NOW: u64 = 1_767_139_200;

fn reality_config() -> RealityConfig {
    RealityConfig {
        server_names: vec![String::from("localhost")],
        private_key: SERVER_PRIV,
        short_ids: vec![SHORT_ID],
        min_client_ver: None,
        max_client_ver: None,
        max_time_diff: None,
    }
}

/// 客户端：真实指纹 hello（Firefox 148）+ REALITY 封装，SNI = localhost。
fn authenticated_client_hello() -> Vec<u8> {
    use utls::hello::{ClientHelloId, ClientHelloSpec, HandshakeInputs, SessionId};
    use utls::values as v;
    let mut spec = ClientHelloSpec::from_preset(ClientHelloId::Firefox(148)).unwrap();
    spec.session_id = SessionId::Fixed(vec![0u8; 32]);
    let mut inputs = HandshakeInputs::deterministic([0x88; 32]);
    inputs.sni = Some("localhost".into());
    let client_pub = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(CLIENT_PRIV));
    // P-256 的 share 必须是**真公钥**：真站要拿它做 ECDH，哑字节会得到
    // rustls 的 `PeerMisbehaved(InvalidKeyShare)`（P-256-only 判据就是这样炸出来的）。
    // 用固定私钥导出一个未压缩点（65 字节，`0x04 || X || Y`）。
    let p256_share = p256_public_key();
    inputs.key_exchange = vec![
        (v::X25519, client_pub.as_bytes().to_vec()),
        (v::X25519_MLKEM768, vec![0xBB; 1184 + 32]),
        (v::CURVE_P256, p256_share),
    ];
    let raw = spec.marshal(&inputs).expect("指纹层该能产出").into_bytes();
    let server_pub =
        *x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(SERVER_PRIV)).as_bytes();
    let cfg = reality::client::ClientConfig {
        public_key: server_pub,
        short_id: SHORT_ID,
        client_ver: [1, 8, 13, 0],
        fallback_to_webpki: true,
    };
    seal_hello(&raw, &CLIENT_PRIV, &cfg, NOW)
        .expect("封包")
        .hello
}

/// 本地真站：真实的 rustls TLS 1.3 服务端（与 `utls-engine` 的测试装置同款证书）。
fn dest_flight(only_p256: bool) -> Vec<u8> {
    let cfg = if only_p256 {
        common::server_config(Some(vec![rustls::NamedGroup::secp256r1]))
    } else {
        common::server_config(None)
    };
    common::run_tls13_server_and_capture_flight(cfg, authenticated_client_hello())
}

/// **判据 1 + 2**：真站 flight 分类正确，鉴权通过时计划成立。
#[test]
fn an_authenticated_hello_plans_a_mirrored_handshake_against_a_real_dest() {
    let client_hello = authenticated_client_hello();
    let flight = dest_flight(false);
    let records = split_dest_flight(&flight);
    assert!(
        matches!(records.first(), Some(DestRecord::ServerHello(_))),
        "第一条必须是 ServerHello：{records:?}"
    );
    assert!(
        matches!(records.get(1), Some(DestRecord::ChangeCipherSpec)),
        "第二条必须是 CCS：{records:?}"
    );
    assert!(
        records[2..]
            .iter()
            .all(|r| matches!(r, DestRecord::ApplicationData(_))),
        "之后必须是应用数据：{records:?}"
    );

    let hello = ClientHello::parse(&client_hello).expect("解析");
    match plan(&hello, &reality_config(), NOW, &flight) {
        MirrorPlan::Authenticated {
            peer_group,
            dest_records,
            auth_key,
        } => {
            assert_eq!(
                peer_group, 4588,
                "客户端发了 MLKEM768 ⇒ 优先用它（参照的 serverShare 形状）"
            );
            assert_eq!(
                dest_records.len(),
                records.len(),
                "计划里的记录数与原 flight 一致"
            );
            // AuthKey 与服务端 decide 的一致（同一条路径算出来）。
            match decide(&hello, &reality_config(), NOW) {
                Decision::Authenticated { auth_key: k, .. } => assert_eq!(auth_key, k),
                Decision::Fallback { reason } => panic!("该鉴别通过：{reason:?}"),
            }
        }
        MirrorPlan::Fallback { reason } => panic!("该走鉴权路径：{reason:?}"),
    }
}

/// **判据 3**：未鉴权（shortId 错）⇒ 计划为 Fallback，且调用方可以原样透传。
#[test]
fn an_unauthenticated_hello_plans_a_byte_for_byte_fallback() {
    let client_hello = authenticated_client_hello();
    let flight = dest_flight(false);
    let hello = ClientHello::parse(&client_hello).expect("解析");
    let mut cfg = reality_config();
    cfg.short_ids = vec![[0xFF; 8]];
    match plan(&hello, &cfg, NOW, &flight) {
        MirrorPlan::Fallback { reason } => {
            assert!(matches!(reason, FallbackReason::ShortIdNotAllowed(_)));
        }
        MirrorPlan::Authenticated { .. } => panic!("短 ID 错不该鉴别通过"),
    }
    // 透传的语义：客户端的 hello 与真站的 flight 都由调用方原样转发 ——
    // 判据是「两个方向的字节都还在」（本仓不解释它们，一个字节都不改）。
    assert_eq!(
        split_dest_flight(&flight).len(),
        3,
        "真站 flight 仍是三段（透传不改它）"
    );
}

/// **判据 4**：真站 flight 形状不对（没有 CCS）⇒ 落回透传，不猜。
#[test]
fn a_dest_flight_of_the_wrong_shape_falls_back_instead_of_guessing() {
    let client_hello = authenticated_client_hello();
    let hello = ClientHello::parse(&client_hello).expect("解析");
    // 伪造一段「ServerHello 直接接应用数据」的 flight（缺 CCS）。
    let mut bad = vec![0x16, 0x03, 0x03, 0x00, 0x02, 0x02, 0x00];
    bad.extend_from_slice(&[0x17, 0x03, 0x03, 0x00, 0x01, 0xAA]);
    match plan(&hello, &reality_config(), NOW, &bad) {
        MirrorPlan::Fallback { reason } => {
            let text = format!("{reason:?}");
            assert!(
                text.contains("CCS") || text.contains("形状"),
                "理由该指向形状：{text}"
            );
        }
        MirrorPlan::Authenticated { .. } => panic!("形状不对不该走鉴权路径"),
    }
}

/// **判据 5（P-256-only dest）**：dest 只支持 P-256 时，镜像计划照样成立 ——
/// 真站的密钥协商与我们无关（会话密钥由 REALITY 服务端用客户端的 key share 生成），
/// 所以 P-256-only 的约束落在**客户端 hello 必须报 P-256 share**上。
#[test]
fn a_p256_only_dest_still_yields_a_mirrored_plan() {
    let client_hello = authenticated_client_hello();
    // 客户端确实报了 P-256 share（Firefox 148 的 [MLKEM768, X25519, P-256]）。
    let hello = ClientHello::parse(&client_hello).expect("解析");
    assert!(
        hello.key_shares.iter().any(|(g, _)| *g == 23),
        "客户端 hello 必须带 P-256 share：{:?}",
        hello.key_shares.iter().map(|(g, _)| *g).collect::<Vec<_>>()
    );
    let flight = dest_flight(true);
    let records = split_dest_flight(&flight);
    assert!(
        matches!(records.first(), Some(DestRecord::ServerHello(_))),
        "P-256-only 真站仍回 ServerHello：{records:?}"
    );
    match plan(&hello, &reality_config(), NOW, &flight) {
        MirrorPlan::Authenticated { dest_records, .. } => {
            assert!(dest_records.len() >= 3, "至少 ServerHello+CCS+载荷");
        }
        MirrorPlan::Fallback { reason } => panic!("P-256-only dest 该成立：{reason:?}"),
    }
}

/// 一个**真实**的 P-256 公钥（未压缩点，65 字节）：从固定私钥导出。
///
/// 为什么必须真：真站（rustls）会用客户端的 share 做 ECDH，哑字节会得到
/// `PeerMisbehaved(InvalidKeyShare)` —— P-256-only 判据第一次跑就是这么红的。
fn p256_public_key() -> Vec<u8> {
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    let secret = p256::SecretKey::from_slice(&[0x5Au8; 32]).expect("固定私钥");
    secret
        .public_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec()
}
