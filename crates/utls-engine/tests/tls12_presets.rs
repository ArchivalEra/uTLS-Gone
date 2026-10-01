//! **TLS 1.2 时代的指纹也能真握手**（`key_share` 不存在的那 8 档）。
//!
//! # 被修掉的是什么
//!
//! 引擎原来要求 `plan()` 至少交出**一把**外部密钥交换，否则报
//! 「spec 的 key_share 组 [] 与引擎能完成的组 […] 没有交集」。而那 8 档
//! （Chrome 58/62、Firefox 55/56、iOS 11/12、Android 11、360 7）的 spec 里
//! **根本没有 `key_share` 扩展** —— 它们出生在 TLS 1.3 之前。于是这 8 档连字节都发不出去。
//!
//! 两处一起改：
//!
//! 1. **引擎**：`key_share` 列表为空的 spec 不再当成错误（那是这一档的正常形态）；
//! 2. **fork**：外供 hello **没有** `key_share` 扩展时，不再**背着调用方造一个**。
//!    原来那条路（`OfferedKeyShares::single(tls13::initial_key_share(...))`）会让
//!    状态机以为「我发过一个共享密钥」，而线上那条字节里没有 —— 后面 TLS 1.2 的
//!    第二飞（`ClientKeyExchange`）本来就自己做 ECDHE，第一飞不该有交换。
//!
//! # 判据
//!
//! 不是「不报错了」，而是**服务端说的**：谈成 `TLSv1_2`，且服务端收到的字节里有
//! 真实的 SNI（`localhost`）—— 与其它测试同一套证据形状（对端看到的才是事实）。
//!
//! ⚠️ 一条写明的边界：`HelloCustom`（`ClientHelloSpec::empty()`）**仍然被拒**，
//! 理由是「没有密码套件」—— 空 spec 不是一条合法的 ClientHello，那不是欠账。

mod common;

use std::sync::Arc;

use rustls::ClientConnection;
use rustls::pki_types::ServerName;
use utls::hello::{ClientHelloId, ClientHelloSpec};
use utls_engine::FingerprintClient;

/// TLS 1.2 时代、spec 里没有 `key_share` 的那些预设。
const TLS12_ERA: [ClientHelloId; 8] = [
    ClientHelloId::Chrome(58),
    ClientHelloId::Chrome(62),
    ClientHelloId::Firefox(55),
    ClientHelloId::Firefox(56),
    ClientHelloId::Ios(11),
    ClientHelloId::Ios(12),
    ClientHelloId::Android(11),
    ClientHelloId::Browser360(7),
];

/// 这 8 档：**能谈的上就谈成 TLS 1.2，谈不上的要知道为什么**。
///
/// # 为什么不是「8 档都必须谈成」
///
/// 判据按**算出来的交集**分流，而不是写死一份名单：
///
/// | | 与这台服务端的 TLS 1.2 套件有没有交集 | 期望 |
/// |---|---|---|
/// | 7 档（Chrome 58/62、Firefox 55/56、Ios 11/12、Android 11） | 有 | 谈成 `TLSv1_2` |
/// | `Browser360(7)`（2015 年的 360 浏览器） | **没有** | 服务端回 `HandshakeFailure`（没有共同套件）|
///
/// 实测数字：rustls 的提供者只实现 **6 个** TLS 1.2 套件（ECDHE-*-AES-GCM 与 ECDHE-*-CHACHA20），
/// 而 `360_7` 报的 20 个套件全是 CBC / RC4 / 3DES —— 交集**为 0**。这不是本仓的缺陷：
/// uTLS 底下的 Go 默认同样不实现那些套件，所以**任何现代 TLS 栈**都握不上这一档的手。
/// 它的指纹仍然是保真的（字节照样与 uTLS 逐字节一致），只是对面得是一台还认老套件的服务器。
#[test]
fn tls12_era_fingerprints_negotiate_tls12_where_the_cipher_suites_allow_it() {
    for id in TLS12_ERA {
        let name = id.name();
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let spec = ClientHelloSpec::from_preset(id).unwrap();

        // 这一档与服务端有没有共同套件 —— 期望由它算出来，不是写死的。
        let server_t12: Vec<u16> = provider
            .cipher_suites
            .iter()
            .filter(|s| s.version().version == rustls::ProtocolVersion::TLSv1_2)
            .map(|s| u16::from(s.suite()))
            .collect();
        let common = spec
            .cipher_suites
            .iter()
            .filter_map(|c| match c {
                utls::hello::CodePoint::Fixed(v) => Some(*v),
                _ => None,
            })
            .filter(|s| server_t12.contains(s))
            .count();

        let (addr, server) = common::spawn_server(common::server_config_tls12_13(), 1);
        // ⚠️ 这一档的 config **只开 TLS 1.2**：只开 1.2 才与指纹一致 —— 否则服务端放进
        // ServerHello 随机数里的降级哨兵会被判成降级攻击（见 `common::client_config_tls12`）。
        let config = Arc::new(common::client_config_tls12(
            FingerprintClient::new(spec, provider).with_sni("localhost"),
            Vec::new(),
            common::shared_verifier(),
        ));
        let mut conn = ClientConnection::new(config, ServerName::try_from("localhost").unwrap())
            .expect("建连接");
        let mut sock = std::net::TcpStream::connect(addr).expect("连回环");
        let result = common::drive_client(&mut conn, &mut sock);

        let served = server.join().expect("服务端线程");
        assert_eq!(served.len(), 1, "{name}: hello 该发出去了");
        let hello = &served[0].client_hello[5..];
        assert!(
            !has_extension(hello, 0x0033),
            "{name}: 这一档的 hello 里不该有 key_share —— 引擎不该背着调用方造一个"
        );
        assert!(
            served[0].client_hello.windows(9).any(|w| w == b"localhost"),
            "{name}: 服务端该在 ClientHello 里看到真实 SNI"
        );

        if common == 0 {
            let e = result.expect_err("没有共同套件时握手必须失败");
            let text = e.to_string();
            assert!(
                text.contains("HandshakeFailure") || text.contains("alert"),
                "{name}: 期望「服务端说没有共同套件」，实际 {text}"
            );
        } else {
            result.unwrap_or_else(|e| panic!("{name}: 有 {common} 个共同套件，握手该谈成：{e}"));
            assert_eq!(
                served[0].version,
                Some(rustls::ProtocolVersion::TLSv1_2),
                "{name}: 服务端该谈成 TLS 1.2"
            );
        }
    }
}

/// 对照：**同一台**服务端上，TLS 1.3 的预设仍然谈成 1.3 ——
/// 免得上面那条判据变成「服务端只会谈 1.2」的自我实现。
#[test]
fn a_tls13_fingerprint_still_negotiates_tls13_on_the_same_server() {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let spec = ClientHelloSpec::from_preset(ClientHelloId::Chrome(133)).unwrap();
    let (addr, server) = common::spawn_server(common::server_config_tls12_13(), 1);
    let config = Arc::new(common::client_config_tls12_13(
        FingerprintClient::new(spec, provider).with_sni("localhost"),
        Vec::new(),
        common::shared_verifier(),
    ));
    let mut conn =
        ClientConnection::new(config, ServerName::try_from("localhost").unwrap()).expect("建连接");
    let mut sock = std::net::TcpStream::connect(addr).expect("连回环");
    common::drive_client(&mut conn, &mut sock).expect("握手该谈成");
    let served = server.join().expect("服务端线程");
    assert_eq!(
        served[0].version,
        Some(rustls::ProtocolVersion::TLSv1_3),
        "Chrome 133 有 key_share，该谈 TLS 1.3（1.2 只是这台服务端的能力上限之一）"
    );
}

/// `HelloCustom` = `ClientHelloSpec::empty()`：**仍然被拒**，且理由是能看懂的。
#[test]
fn the_empty_custom_spec_is_refused_for_a_reason_that_names_the_problem() {
    use rustls::client::{PlanRequest, SuppliesClientHello};

    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let groups: Vec<u16> = provider
        .kx_groups
        .iter()
        .filter(|g| g.usable_for_version(rustls::ProtocolVersion::TLSv1_3))
        .map(|g| u16::from(g.name()))
        .collect();
    let spec = ClientHelloSpec::from_preset(ClientHelloId::Custom).unwrap();
    let client = FingerprintClient::new(spec, provider).with_sni("localhost");
    let err = client
        .plan(&PlanRequest {
            groups,
            resumption: None,
        })
        .expect_err("空 spec 不该产出 hello");
    let text = err.to_string();
    assert!(
        text.contains("密码套件") || text.contains("cipher"),
        "拒绝的理由该指出「没有密码套件」，而不是一句笼统的错：{text}"
    );
}

/// 一条握手消息里有没有某个扩展类型。
fn has_extension(message: &[u8], want: u16) -> bool {
    let mut p = 4 + 2 + 32;
    p += 1 + message[p] as usize;
    let cs = u16::from_be_bytes([message[p], message[p + 1]]) as usize;
    p += 2 + cs;
    p += 1 + message[p] as usize;
    let n = u16::from_be_bytes([message[p], message[p + 1]]) as usize;
    p += 2;
    let region = &message[p..p + n];
    let mut q = 0usize;
    while q + 4 <= region.len() {
        let ty = u16::from_be_bytes([region[q], region[q + 1]]);
        if ty == want {
            return true;
        }
        let bl = u16::from_be_bytes([region[q + 2], region[q + 3]]) as usize;
        q += 4 + bl;
    }
    false
}
