//! **指纹化 QUIC 客户端**：真实 QUIC-TLS 握手里，我们的 ClientHello 是不是上线了。
//!
//! # 为什么需要这条判据
//!
//! TLS over QUIC 时，客户端的**传输参数**就是 ClientHello 里的一个扩展
//! （码点 39；上游 `u_quic.go` 注释说得很直白：preset 路径下 `SetTransportParameters`
//! 不走 `quic.transportParams`，而是进 hello）。rustls 的 QUIC 服务端**要求**
//! ClientHello 必须带它（否则 `MissingQuicTransportParameters`）—— 所以
//! 「指纹预设 + QUIC」能不能用，取决于我们的外供 hello 能不能走到 QUIC 那条
//! 状态机路径上。此前这条路上没有任何判据。
//!
//! # 判别器（这是本测试最要紧的设计）
//!
//! `quic::ClientConnection::new(config, …, params)` 的 `params` 会被 rustls 塞进
//! **它自建**的 hello；我们的外供 hello 则带 spec 里那份字节。两份**故意不同**：
//! 服务端报告 `quic_transport_parameters()` 时，
//!
//! * 看到我们的字节 ⇒ 线上的是**外供的** ClientHello（fork 在 QUIC 路径上仍然生效）；
//! * 看到 rustls 的占位字节 ⇒ fork 没接上（测试就该红）。
//!
//! 只断言「握手完成」是不够的 —— 那样两种情况都会绿。
//!
//! # rustls 的 QUIC 模块只有 QUIC-TLS 那一半
//!
//! 打包 / ACK / 拥塞控制不在 rustls 里（那是 quinn 的活）。本判据需要的恰好是
//! rustls 有的那一半：握手状态机、CRYPTO 帧进出（`write_hs` / `read_hs`）、
//! 以及服务端从 ClientHello 里读出的传输参数。

mod common;

use std::sync::Arc;

use rustls::pki_types::ServerName;
use rustls::quic::{self, Version};
use utls::hello::{ClientHelloId, ClientHelloSpec, Extension};
use utls_engine::FingerprintClient;

/// 我们嵌进 hello 的传输参数（用 [`crate::quic`] 的编码器造一份真形状的：
/// Firefox 那套参数 + 一个 GREASE 参数，与 `quic.rs` 的 golden 同源但内容不同）。
fn our_transport_parameters() -> Vec<u8> {
    use utls::quic::{TransportParameter, TransportParameters};
    let mut tps = TransportParameters(vec![
        TransportParameter::InitialMaxStreamDataBidiRemote(0x10_0000),
        TransportParameter::InitialMaxStreamsBidi(16),
        TransportParameter::InitialMaxData(0x180_0000),
        TransportParameter::MaxIdleTimeout(30_000),
        TransportParameter::ActiveConnectionIdLimit(8),
        TransportParameter::GreaseQuicBit,
        // GREASE 参数不带 override ⇒ 每连接新抽（与 hello 的 seed 分域）。
        TransportParameter::Grease {
            id_override: None,
            length: 24,
            value_override: Vec::new(),
        },
        TransportParameter::DisableActiveMigration,
    ]);
    tps.marshal(&[7; 32]).expect("传输参数编码不该失败")
}

/// rustls 自建 hello 会带的那份（**故意不同**，当判别器用）。
fn placeholder_params() -> Vec<u8> {
    vec![0xde, 0xad, 0xbe, 0xef]
}

#[test]
fn a_fingerprinted_quic_client_puts_our_hello_on_the_wire() {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());

    // ① 指纹预设 + QUIC 传输参数扩展。
    let mut spec = ClientHelloSpec::from_preset(ClientHelloId::Chrome(133)).unwrap();
    let our_params = our_transport_parameters();
    spec.extensions
        .push(Extension::QuicTransportParameters(our_params.clone()));

    // ② 两端配置：客户端走外供路径（fork），ALPN 两边都开（RFC 9001 要求 QUIC 必须谈 ALPN）。
    let client_config = Arc::new(common::client_config_with_verifier(
        FingerprintClient::new(spec, provider.clone()).with_sni("localhost"),
        vec![b"h3".to_vec()],
        common::shared_verifier(),
        None,
    ));
    let server_config = common::server_config(false, None);

    // ③ QUIC 连接。客户端的 `params` 是**占位字节**（判别器）；
    //    我们那份真字节只在 spec 里。
    let mut client = quic::ClientConnection::new(
        client_config,
        Version::V1,
        ServerName::try_from("localhost").unwrap(),
        placeholder_params(),
    )
    .expect("建 QUIC 客户端");
    let mut server = quic::ServerConnection::new(server_config, Version::V1, vec![0xaa; 8])
        .expect("建 QUIC 服务端");

    // ④ 互相泵 CRYPTO 帧，直到两边都不在握手。
    let mut rounds = 0;
    while client.is_handshaking() || server.is_handshaking() {
        rounds += 1;
        assert!(rounds < 16, "握手在 {rounds} 轮后还没收敛 —— 别死循环");

        let mut up = Vec::new();
        client.write_hs(&mut up);
        if !up.is_empty() {
            server.read_hs(&up).expect("服务端吃客户端的 CRYPTO 数据");
        }

        let mut down = Vec::new();
        server.write_hs(&mut down);
        if !down.is_empty() {
            client.read_hs(&down).expect("客户端吃服务端的 CRYPTO 数据");
        }

        if up.is_empty() && down.is_empty() && (client.is_handshaking() || server.is_handshaking())
        {
            panic!("两边都无数据可换但握手没完 —— 卡住了");
        }
    }

    // ⑤ 服务端给的结论：它读到的传输参数是**我们那份**，不是 rustls 的占位字节。
    assert_eq!(
        server.quic_transport_parameters(),
        Some(our_params.as_slice()),
        "服务端读到的传输参数必须来自我们外供的 ClientHello —— \
         若是占位字节，说明 fork 在 QUIC 路径上没接上，线上跑的是 rustls 自建的 hello"
    );
    // GREASE 参数是惰性抽取的：编码时抽过一次并缓存 ⇒ 字节确定，但必须仍是合法 GREASE 形。
    assert_eq!(
        our_params.len() % 2,
        0,
        "参数体该是 (ID, len, value) 的整数倍拼接"
    );

    assert!(
        !client.is_handshaking() && !server.is_handshaking(),
        "两端都该完成握手"
    );
    assert_eq!(
        server.protocol_version(),
        Some(rustls::ProtocolVersion::TLSv1_3),
        "QUIC 只跑 TLS 1.3"
    );
}
