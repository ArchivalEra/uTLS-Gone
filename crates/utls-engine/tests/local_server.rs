//! 本地服务端的判据：**真握手、真 HRR，都要跑完**。
//!
//! 这台装置（`tests/common/mod.rs`）的意义在于：它是唯一一个「完全可控 + 握手能跑完」
//! 的服务端。打 `tls.browserleaks.com` 不可控（没法让它要求特定组），手写的假服务端
//! 又跑不完（只能证「第二飞发出去了」）。这里两条缺口一起补上。

mod common;

use std::sync::Arc;

use rustls::pki_types::ServerName;
use rustls::{ClientConnection, HandshakeKind, NamedGroup};
use utls::hello::{ClientHelloId, ClientHelloSpec};
use utls_engine::FingerprintClient;

fn client(addr: std::net::SocketAddr, id: ClientHelloId, alpn: Vec<Vec<u8>>) -> ClientConnection {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let spec = ClientHelloSpec::from_preset(id).unwrap();
    let fingerprint = FingerprintClient::new(spec, provider).with_sni("localhost");
    let config = Arc::new(common::client_config_with_roots(fingerprint, alpn));
    let mut conn = ClientConnection::new(config, ServerName::try_from("localhost").unwrap())
        .expect("建客户端连接");
    let mut sock = std::net::TcpStream::connect(addr).expect("连回环");
    // 把这条连接**跑到底**（含握手后读到 NewSessionTicket）；上限 8 轮防呆。
    for _ in 0..8 {
        if conn.complete_io(&mut sock).is_err() || !conn.is_handshaking() {
            break;
        }
    }
    conn
}

#[test]
fn a_local_rustls_server_completes_a_handshake_with_our_client() {
    let (addr, server) = common::spawn_server(common::server_config(false, None), 1);
    let conn = client(addr, ClientHelloId::Firefox(148), vec![b"h2".to_vec()]);

    let served = server.join().expect("服务端线程").pop().expect("一条结果");
    assert_eq!(
        conn.protocol_version(),
        Some(rustls::ProtocolVersion::TLSv1_3),
        "客户端侧该谈成 TLS 1.3"
    );
    assert_eq!(served.version, Some(rustls::ProtocolVersion::TLSv1_3), "服务端侧同上");
    assert_eq!(served.alpn.as_deref(), Some(&b"h2"[..]), "ALPN 该谈成 h2");
    assert_eq!(served.handshake_kind, Some(HandshakeKind::Full), "第一次连接是完整握手");
    assert!(!served.resumed, "第一次连接不该是复用的");
    // 服务端收到的第一条记录必须是 ClientHello，且长度自洽。
    let rec = &served.client_hello;
    assert_eq!(rec[0], 0x16, "第一条记录不是握手记录");
    let len = u16::from_be_bytes([rec[3], rec[4]]) as usize;
    assert_eq!(len + 5, rec.len(), "记录长度与实际不符");
    assert_eq!(rec[5], 1, "握手类型不是 ClientHello");
}

/// **真·HelloRetryRequest 握手跑完**：服务端只认 P-384，而 Chrome-70 的 `key_share`
/// 只给 X25519 ⇒ 服务端必须回 HRR；我们回第二飞；会话谈成。
///
/// 这条同时是「第二飞真的能被服务器接受」的判据 —— 它比 `hello_retry_e2e.rs` 强：
/// 那边只证明第二飞发出去了，这边证明它**被接受并完成了握手**。
/// 而且 `handshake_kind` 是服务端给的，不是我们自己数的。
#[test]
fn a_full_hello_retry_request_handshake_completes() {
    let config = common::server_config(false, Some(vec![NamedGroup::secp384r1]));
    let (addr, server) = common::spawn_server(config, 1);
    let conn = client(addr, ClientHelloId::Chrome(70), Vec::new());

    let served = server.join().expect("服务端线程").pop().expect("一条结果");
    assert_eq!(
        served.handshake_kind,
        Some(HandshakeKind::FullWithHelloRetryRequest),
        "服务端说这次不是「带 HRR 的完整握手」—— 说明 HRR 没发生（那就没测到东西）"
    );
    assert_eq!(served.version, Some(rustls::ProtocolVersion::TLSv1_3), "HRR 之后该谈成 TLS 1.3");
    assert_eq!(
        conn.protocol_version(),
        Some(rustls::ProtocolVersion::TLSv1_3),
        "客户端侧也该是 TLS 1.3"
    );
}
