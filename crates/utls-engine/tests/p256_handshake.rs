//! **P-256（secp256r1）能不能正常握手** —— 三条路都要有服务端给的结论。
//!
//! 为什么单独立一份判据：`multi_key_share.rs` 用的是 **P-384**，`local_server.rs` 的
//! 强制 HRR 那条也是 **P-384**，而 **P-256** 此前只出现在单元层的 `retry_plan`
//! （`hello_retry.rs` 里 `selected_group: Some(v::CURVE_P256)`）—— 没有一条真握手判据。
//! 而 P-256 恰恰是**真实预设里真的会发**的那个第二组：Firefox 家族的 `key_share` 是
//! `[X25519, P-256]`（`u_parrots.go` 如此，本仓预设逐条抄自它）。
//!
//! 三条路各判一件事：
//!
//! | 测试 | 情形 | 要证什么 |
//! |---|---|---|
//! | 1 | Firefox 的 `[X25519, P-256]` + 服务端只认 P-256 | 服务端**在第一飞里**选中 P-256，握手直接谈成（`Full`，没有 HRR）⇒ 引擎交出的那把 P-256 交换真的能用 |
//! | 2 | `key_share` 只有 P-256 + 服务端只认 P-256 | 没有任何 X25519 可退时，P-256 也能独立谈成 |
//! | 3 | Chrome-70（只发 X25519）+ 服务端只认 P-256 | 服务端**回 HRR 要 P-256** ⇒ 我们的第二飞带上**新的** P-256 共享，服务端接受并谈成 |
//!
//! 判据一律取**服务端**的说法（`handshake_kind` / `negotiated_version`），不取我们自报的。

mod common;

use std::sync::Arc;

use rustls::pki_types::ServerName;
use rustls::{ClientConnection, HandshakeKind, NamedGroup};
use utls::hello::{ClientHelloId, ClientHelloSpec, CodePoint, Extension};
use utls::values as v;
use utls_engine::FingerprintClient;

/// P-256 的未压缩点：`1 + 2×32` 字节。
const P256_SHARE_LEN: usize = 65;

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::aws_lc_rs::default_provider())
}

/// 一把钥匙：本地服务端**只认 P-256**（`kx_groups` 被滤掉其余组），
/// 所以「谈成了」这件事本身就是「用的是 P-256」。
fn server_only_p256() -> Arc<rustls::ServerConfig> {
    common::server_config(false, Some(vec![NamedGroup::secp256r1]))
}

fn connect(addr: std::net::SocketAddr, spec: ClientHelloSpec, sni: &str) -> ClientConnection {
    let config = Arc::new(common::client_config_with_verifier(
        FingerprintClient::new(spec, provider()).with_sni(sni),
        Vec::new(),
        common::shared_verifier(),
        None,
    ));
    let mut conn = ClientConnection::new(config, ServerName::try_from(sni.to_string()).unwrap())
        .expect("建连接");
    let mut sock = std::net::TcpStream::connect(addr).expect("连回环");
    common::drive_client(&mut conn, &mut sock).expect("握手该谈成");
    conn
}

/// 把 spec 的 `key_share` 换成给定的组（顺序即线序）。
fn spec_with_key_shares(spec: &ClientHelloSpec, groups: &[u16]) -> ClientHelloSpec {
    let mut spec = spec.clone();
    let at = spec
        .extensions
        .iter()
        .position(|e| matches!(e, Extension::KeyShare(_)))
        .expect("这个预设有 key_share");
    spec.extensions[at] =
        Extension::KeyShare(groups.iter().copied().map(CodePoint::Fixed).collect());
    spec
}

/// 从一条握手消息里取 `key_share` 的 `(组, 公钥长)` 列表（第一条测试与第三条都用它当证据）。
fn key_share_entries(message: &[u8]) -> Vec<(u16, usize)> {
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
        let bl = u16::from_be_bytes([region[q + 2], region[q + 3]]) as usize;
        let body = &region[q + 4..q + 4 + bl];
        if ty == 0x0033 {
            let mut out = Vec::new();
            let mut r = 2usize;
            while r + 4 <= body.len() {
                let g = u16::from_be_bytes([body[r], body[r + 1]]);
                let kl = u16::from_be_bytes([body[r + 2], body[r + 3]]) as usize;
                out.push((g, kl));
                r += 4 + kl;
            }
            return out;
        }
        q += 4 + bl;
    }
    Vec::new()
}

/// 一：真实预设（Firefox 的 `[X25519, P-256]`）里，服务端**在第一飞**就选中 P-256。
#[test]
fn firefox_preset_completes_when_the_server_picks_the_p256_share_in_the_first_flight() {
    let spec = ClientHelloSpec::from_preset(ClientHelloId::Firefox(120)).unwrap();
    // 先钉住「这个预设确实发了 P-256，且长度是未压缩点」—— 否则下面谈成了也说明不了什么。
    let (addr, server) = common::spawn_server(server_only_p256(), 1);
    let conn = connect(addr, spec, "localhost");
    let served = server.join().expect("服务端线程").pop().expect("一条结果");

    let hello = &served.client_hello[5..];
    let entries = key_share_entries(hello);
    assert!(
        entries.contains(&(v::CURVE_P256, P256_SHARE_LEN)),
        "Firefox 的第一飞该带 P-256 共享（65 字节未压缩点），实际 {entries:?}"
    );
    assert_eq!(
        served.handshake_kind,
        Some(HandshakeKind::Full),
        "服务端该**在第一飞里**选中 P-256 —— `FullWithHelloRetryRequest` 说明它没能用上我们的共享"
    );
    assert_eq!(
        served.version,
        Some(rustls::ProtocolVersion::TLSv1_3),
        "该谈成 TLS 1.3"
    );
    assert_eq!(
        conn.protocol_version(),
        Some(rustls::ProtocolVersion::TLSv1_3),
        "客户端侧也该是 TLS 1.3"
    );
}

/// 二：`key_share` **只有** P-256（没有任何 X25519 可退）也能谈成。
#[test]
fn p256_alone_is_enough_to_complete_a_handshake() {
    let spec = spec_with_key_shares(
        &ClientHelloSpec::from_preset(ClientHelloId::Chrome(70)).unwrap(),
        &[v::CURVE_P256],
    );
    let (addr, server) = common::spawn_server(server_only_p256(), 1);
    let conn = connect(addr, spec, "localhost");
    let served = server.join().expect("服务端线程").pop().expect("一条结果");

    let entries = key_share_entries(&served.client_hello[5..]);
    assert_eq!(
        entries,
        vec![(v::CURVE_P256, P256_SHARE_LEN)],
        "这一飞该只有一把 P-256 共享"
    );
    assert_eq!(
        served.handshake_kind,
        Some(HandshakeKind::Full),
        "只给 P-256 时也该直接谈成"
    );
    assert_eq!(served.version, Some(rustls::ProtocolVersion::TLSv1_3));
    assert_eq!(
        conn.protocol_version(),
        Some(rustls::ProtocolVersion::TLSv1_3)
    );
}

/// 三：客户端只发 X25519，服务端只认 P-256 ⇒ **强制 HRR**，第二飞必须带上**新的** P-256 共享。
#[test]
fn a_server_that_insists_on_p256_forces_a_retry_that_succeeds() {
    // Chrome-70 的 `key_share` 只有 `[GREASE, X25519]`，但 `supported_groups` 里有 P-256
    // ⇒ 服务端要它要得合法（RFC 8446 §4.1.4 只许要客户端报过的组）。
    let spec = ClientHelloSpec::from_preset(ClientHelloId::Chrome(70)).unwrap();
    let (addr, server) = common::spawn_server(server_only_p256(), 1);
    let conn = connect(addr, spec, "localhost");
    let served = server.join().expect("服务端线程").pop().expect("一条结果");

    assert_eq!(
        served.handshake_kind,
        Some(HandshakeKind::FullWithHelloRetryRequest),
        "服务端只认 P-256 而第一飞没有它的共享 ⇒ 必须回一次 HRR（不然这条没测到东西）"
    );
    assert_eq!(
        served.client_hellos.len(),
        2,
        "这条连接该有两条 ClientHello（第一飞 + HRR 之后那飞）"
    );
    let second = &served.client_hellos[1][5..];
    assert_eq!(
        key_share_entries(second),
        vec![(v::CURVE_P256, P256_SHARE_LEN)],
        "第二飞该只带一把**新的** P-256 共享（65 字节未压缩点）"
    );
    // 两条 hello 的 client random 必须**逐字节相同**（RFC 8446 §4.1.2 不许改）。
    assert_eq!(
        &served.client_hellos[0][11..43],
        &served.client_hellos[1][11..43],
        "第二飞的客户端随机数该与第一飞完全相同"
    );
    assert_eq!(
        served.version,
        Some(rustls::ProtocolVersion::TLSv1_3),
        "HRR 之后该谈成 TLS 1.3"
    );
    assert_eq!(
        conn.protocol_version(),
        Some(rustls::ProtocolVersion::TLSv1_3),
        "客户端侧也该是 TLS 1.3"
    );
}
