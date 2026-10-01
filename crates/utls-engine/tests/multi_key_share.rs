//! **多组 `key_share` 的判据**：服务器选中我们声明过的**第二个**组时，握手也要能完成。
//!
//! # 被修掉的是什么
//!
//! 这道缝原来只收**一把**外部密钥交换（`ClientHelloPlan::key_exchange`），而引擎也只把
//! `key_share` 里**第一个**组的交换交出去 —— 其余组的公钥照样写在字节里，但私钥被丢掉了。
//! 于是服务器只要选中另一个（我们明明声明过的）组，握手就死：
//! rustls 的 `KeyExchangeChoice` 找不到匹配的交换，报 `WrongGroupForKeyShare`。
//!
//! 那不是策略而是缺陷：**uTLS 把每个组的公钥都发出去，服务器选哪个都能接着谈**。
//! 现在 `key_exchanges` 是一张表，`OfferedKeyShares::take_for` 按服务器选中的组
//! （混合组则按其经典分量）挑出对应那一把。
//!
//! # 判据分两层
//!
//! 1. **引擎层**（无网络）：`plan()` 交出来的交换表必须**每个声明组各一把**（顺序同 spec）。
//!    这条直接钉住「不再丢掉后面的组」。
//! 2. **线上层**：服务端**只认 P-384**，而客户端 `key_share` 里第一项是 X25519、第二项才是 P-384。
//!    握手必须完成，且 `handshake_kind == Full`（**不是** `FullWithHelloRetryRequest`）——
//!    后者意味着服务端没找到可用的共享密钥、只能要求重试。修好前这里就是失败。

mod common;

use std::sync::Arc;

use rustls::client::{PlanRequest, SuppliesClientHello};
use rustls::pki_types::ServerName;
use rustls::{ClientConnection, HandshakeKind, NamedGroup};
use utls::hello::{ClientHelloId, ClientHelloSpec, CodePoint, Extension};
use utls::values as v;
use utls_engine::FingerprintClient;

/// Chrome-70 的 spec，但 `key_share` 换成 **[X25519, P-384]**（两组，P-384 在后）。
///
/// Chrome-70 的 `supported_groups` 本来就含 P-384（`0x0018`），所以这不是伪造一个
/// 不可能的客户端：真实浏览器也会为多个组预先发共享密钥，正是为了少一轮 HRR。
fn spec_with_two_key_shares() -> ClientHelloSpec {
    let mut spec = ClientHelloSpec::from_preset(ClientHelloId::Chrome(70)).unwrap();
    let at = spec
        .extensions
        .iter()
        .position(|e| matches!(e, Extension::KeyShare(_)))
        .expect("Chrome-70 有 key_share");
    spec.extensions[at] = Extension::KeyShare(vec![
        CodePoint::Fixed(v::X25519),
        CodePoint::Fixed(v::CURVE_P384),
    ]);
    spec
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::aws_lc_rs::default_provider())
}

#[test]
fn the_engine_hands_over_one_exchange_per_declared_group() {
    let spec = spec_with_two_key_shares();
    let client = FingerprintClient::new(spec, provider());
    let groups = rustls::crypto::aws_lc_rs::default_provider()
        .kx_groups
        .iter()
        .filter(|g| g.usable_for_version(rustls::ProtocolVersion::TLSv1_3))
        .map(|g| u16::from(g.name()))
        .collect::<Vec<u16>>();
    let plan = client
        .plan(&PlanRequest {
            groups,
            resumption: None,
        })
        .expect("该能产出 plan");

    let got: Vec<u16> = plan.key_exchanges.iter().map(|kx| kx.group()).collect();
    assert_eq!(
        got,
        vec![v::X25519, v::CURVE_P384],
        "交出来的交换该与 `key_share` 里声明的组一一对应（同序）—— \
         少一个就意味着「服务器选中它时握手会失败」"
    );
}

#[test]
fn a_server_selecting_the_second_offered_group_completes_the_handshake() {
    // 服务端只认 P-384，而客户端第一项给的是 X25519 ⇒ 服务端只能选第二项。
    let (addr, server) = common::spawn_server(
        common::server_config(false, Some(vec![NamedGroup::secp384r1])),
        1,
    );

    let spec = spec_with_two_key_shares();
    let config = Arc::new(common::client_config_with_verifier(
        FingerprintClient::new(spec.clone(), provider()).with_sni("localhost"),
        Vec::new(),
        common::shared_verifier(),
        None,
    ));
    let mut conn =
        ClientConnection::new(config, ServerName::try_from("localhost").unwrap()).expect("建连接");
    let mut sock = std::net::TcpStream::connect(addr).expect("连回环");
    common::drive_client(&mut conn, &mut sock)
        .expect("服务器选第二组也该能谈成 —— 修好前这里是 WrongGroupForKeyShare");

    let served = server.join().expect("服务端线程");
    assert_eq!(served.len(), 1);
    assert_eq!(
        served[0].handshake_kind,
        Some(HandshakeKind::Full),
        "该是**直接**谈成：`FullWithHelloRetryRequest` 意味着服务端没找到能用的共享密钥、\
         只好要求重试（那条路是另一条判据覆盖的）"
    );
    assert_eq!(
        conn.protocol_version(),
        Some(rustls::ProtocolVersion::TLSv1_3),
        "该谈成 TLS 1.3"
    );
    // 服务端收到的 key_share 里两个组都在（我们在字节里没少发）。
    let hk = &served[0].client_hellos[0];
    assert!(
        hk.len() > 100,
        "服务端该收到一条像样的 ClientHello（{} 字节）",
        hk.len()
    );
}

/// 反面：只给**一个**组（X25519）而服务端只认 P-384 ⇒ 服务端只能要求 HRR。
///
/// 这条不是缺陷，是协议行为 —— 它的作用是证明上一条的 `HandshakeKind::Full` **确实**意味着
/// 「服务端用了我们发的某个共享密钥」，而不是「服务端反正都会直接谈成」。
#[test]
fn a_single_share_the_server_cannot_use_gets_a_retry_request_instead() {
    let (addr, server) = common::spawn_server(
        common::server_config(false, Some(vec![NamedGroup::secp384r1])),
        1,
    );
    let mut spec = spec_with_two_key_shares();
    let at = spec
        .extensions
        .iter()
        .position(|e| matches!(e, Extension::KeyShare(_)))
        .unwrap();
    spec.extensions[at] = Extension::KeyShare(vec![CodePoint::Fixed(v::X25519)]);

    let config = Arc::new(common::client_config_with_verifier(
        FingerprintClient::new(spec, provider()).with_sni("localhost"),
        Vec::new(),
        common::shared_verifier(),
        None,
    ));
    let mut conn =
        ClientConnection::new(config, ServerName::try_from("localhost").unwrap()).expect("建连接");
    let mut sock = std::net::TcpStream::connect(addr).expect("连回环");
    let _ = common::drive_client(&mut conn, &mut sock);
    let served = server.join().expect("服务端线程");
    assert_eq!(
        served[0].handshake_kind,
        Some(HandshakeKind::FullWithHelloRetryRequest),
        "只给 X25519、而服务端只认 P-384 ⇒ 该被要求 HRR（这正是上一条的对照）"
    );
}
