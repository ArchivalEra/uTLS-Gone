//! **early data（0-RTT）在指纹化客户端上跑通** —— 本项目移植动机本身的那条判据。
//!
//! # 为什么这条此前不存在、又为什么它值得单独一份
//!
//! 早数据只发生在**恢复**握手上：连接 1 拿到带 `max_early_data_size` 的票据，
//! 连接 2 用那张票据恢复、在握手完成前把应用数据当 0-RTT 发出去。对指纹层意味着
//! 连接 2 的 hello 必须**同时**是「指纹逐字节保真」与「PSK binder 正确」的 ——
//! 任何一样错，服务端要么拒绝恢复、要么拒绝早数据。
//!
//! fork 侧此前缺一块：`emit_external_client_hello` 算出了早数据**调度**
//! （`early_data_key_schedule`，接 (g) 时顺手做的），却没像自建路径那样在 hello
//! 出去之后调 `derive_early_traffic_secret` —— 于是 `early_traffic` 永远是假，
//! 应用写早数据会被拒绝。握手**照样完成且恢复**，0-RTT 却悄悄没了：
//! 不报错的缺失，正是最需要一条判据的原因。
//!
//! # 判据全部取服务端
//!
//! * `ServerConnection::early_data()` 返回 `Some` 并读出**原字节**（服务端接受了
//!   0-RTT 并交出内容）；
//! * `handshake_kind() == Resumed`（服务端判定这是恢复握手 —— binder 是对的）。
//!
//! 客户端自报的一切（协议版本、写了多少）在这里只是背景。

mod common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;

use rustls::pki_types::ServerName;
use rustls::{ClientConnection, HandshakeKind, ServerConnection};
use utls::hello::{ClientHelloId, ClientHelloSpec, Extension};
use utls_engine::FingerprintClient;

const EARLY_PAYLOAD: &[u8] = b"0-RTT from uTLS-rs";

fn client_config(enable_early: bool) -> Arc<rustls::ClientConfig> {
    // 用 `_PSK_` 系预设（ChromePsk(100)）：spec 里**自带** PSK 槽位，恢复时引擎直接填。
    // 普通 Chrome 预设没有那个槽位，引擎会按设计拒绝（补扩展必须调用方显式要求）。
    let mut spec = ClientHelloSpec::from_preset(ClientHelloId::ChromePsk(100)).unwrap();
    if enable_early {
        // RFC 8446 §4.2.10：提供 0-RTT 的 ClientHello 带零长度 `early_data` 扩展。
        // 必须插在 PSK **之前**（§4.2.11 要求 PSK 排最后）。
        let at = spec.psk_position().expect("ChromePsk 自带 PSK 槽位");
        spec.extensions.insert(at, Extension::EarlyData);
    }
    let mut cc = common::client_config_with_verifier(
        FingerprintClient::new(
            spec,
            Arc::new(rustls::crypto::aws_lc_rs::default_provider()),
        )
        .with_sni("localhost"),
        vec![b"h2".to_vec()],
        common::shared_verifier(),
        None, // 默认的内存会话存储即可 —— 前提是两条连接共用**同一个** Arc<ClientConfig>
    );
    cc.enable_early_data = true;
    Arc::new(cc)
}

/// rustls 的 TCP 0-RTT **只支持有状态恢复**（RFC 8446 §8.1 的防重放：服务端把会话值
/// 存在自己的 `session_storage` 里才能识别重放；无状态加密票据被 rustls 明确拒绝 ——
/// `server/tls13.rs` 的 `warn!("early_data with stateless resumption is not allowed")`）。
/// 所以服务端的 ticketer 必须禁用：NST 变成「随机 ID」，会话值存在服务端内存里。
#[derive(Debug)]
struct NoTickets;
impl rustls::server::ProducesTickets for NoTickets {
    fn enabled(&self) -> bool {
        false
    }
    fn lifetime(&self) -> u32 {
        0
    }
    fn encrypt(&self, _: &[u8]) -> Option<Vec<u8>> {
        None
    }
    fn decrypt(&self, _: &[u8]) -> Option<Vec<u8>> {
        None
    }
}

fn server_config() -> Arc<rustls::ServerConfig> {
    let mut sc = common::server_config(true, None);
    let cfg = Arc::get_mut(&mut sc).expect("服务端配置此刻应无别的引用");
    // 唯一引用 ⇒ get_mut 可用：0 是「禁用早数据」的默认值。
    cfg.max_early_data_size = 4096;
    cfg.ticketer = Arc::new(NoTickets);
    cfg.send_tls13_tickets = 2;
    sc
}

#[test]
fn early_data_survives_a_fingerprinted_resumption() {
    let client_cfg = client_config(true);
    let server_cfg = server_config();

    // ── 连接 1：完整握手，把带早数据额度的票据收进共享 store ──
    {
        let (addr, server) = common::spawn_server(server_cfg.clone(), 1);
        let mut conn = ClientConnection::new(
            Arc::clone(&client_cfg),
            ServerName::try_from("localhost").unwrap(),
        )
        .expect("建连接");
        let mut sock = TcpStream::connect(addr).expect("连回环");
        common::drive_client(&mut conn, &mut sock).expect("连接 1 该完成");
        let served = server.join().expect("服务端线程");
        assert_eq!(
            served[0].handshake_kind,
            Some(HandshakeKind::Full),
            "连接 1 该是完整握手"
        );
    }

    // ── 连接 2：指纹化恢复 + 早数据 ──
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("占端口");
    let addr = listener.local_addr().expect("端口");
    let server_thread = std::thread::spawn(move || {
        let (sock, _) = listener.accept().expect("accept");
        let mut sock = sock;
        sock.set_read_timeout(Some(std::time::Duration::from_secs(10)))
            .expect("读超时");
        let mut conn = ServerConnection::new(server_cfg).expect("建服务端连接");
        while conn.is_handshaking() {
            conn.complete_io(&mut sock).expect("服务端握手 IO");
        }
        // 早数据只在握手中可读：完成之后缓冲仍在，读出全部。
        let mut early = conn
            .early_data()
            .expect("服务端该**接受**早数据 —— None 意味着被拒或根本没来");
        let mut payload = Vec::new();
        early.read_to_end(&mut payload).expect("读早数据");
        (payload, conn.handshake_kind(), conn.protocol_version())
    });

    let mut conn = ClientConnection::new(
        Arc::clone(&client_cfg),
        ServerName::try_from("localhost").unwrap(),
    )
    .expect("建连接");
    // 握手尚未开始驱动：现在写的应用数据就是 0-RTT。
    // 若 fork 没武装早流量密钥，这一步会被 rustls 拒绝（测试当场红）。
    let mut early = conn
        .early_data()
        .expect("早数据写手为 None ⇒ 状态机没被武装（fork 的 enable 没跑）");
    early
        .write_all(EARLY_PAYLOAD)
        .expect("写早数据 —— 被拒绝即说明外供路径没武装早流量密钥");
    let mut sock = TcpStream::connect(addr).expect("连回环");
    common::drive_client(&mut conn, &mut sock).expect("连接 2 该完成");

    let (payload, kind, version) = server_thread.join().expect("服务端线程");
    assert_eq!(
        kind,
        Some(HandshakeKind::Resumed),
        "服务端判定：这必须是恢复握手 —— binder 由引擎按会话密钥补写"
    );
    assert_eq!(
        payload, EARLY_PAYLOAD,
        "服务端读到的 0-RTT 必须与客户端写的逐字节相同"
    );
    assert_eq!(
        version,
        Some(rustls::ProtocolVersion::TLSv1_3),
        "0-RTT 只存在于 TLS 1.3"
    );
}

/// **对照**：不带指纹 fork 的原生 rustls 客户端，同一套服务端配置。
/// 这条过了而指纹那条不过 ⇒ 问题在 fork 的外供路径；这条也不过 ⇒ 测试装置有错。
#[test]
fn plain_rustls_early_data_works_as_the_control() {
    let mut cc = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .expect("TLS 1.3")
    .dangerous()
    .with_custom_certificate_verifier(common::shared_verifier())
    .with_no_client_auth();
    cc.alpn_protocols = vec![b"h2".to_vec()];
    cc.enable_early_data = true;
    let client_cfg = Arc::new(cc);
    let server_cfg = server_config();

    // 连接 1
    {
        let (addr, server) = common::spawn_server(server_cfg.clone(), 1);
        let mut conn = ClientConnection::new(
            Arc::clone(&client_cfg),
            ServerName::try_from("localhost").unwrap(),
        )
        .expect("建连接");
        let mut sock = TcpStream::connect(addr).expect("连回环");
        common::drive_client(&mut conn, &mut sock).expect("连接 1");
        let served = server.join().expect("服务端线程");
        assert_eq!(served[0].handshake_kind, Some(HandshakeKind::Full));
    }

    // 连接 2
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("占端口");
    let addr = listener.local_addr().expect("端口");
    let server_thread = std::thread::spawn(move || {
        let (sock, _) = listener.accept().expect("accept");
        let mut sock = sock;
        sock.set_read_timeout(Some(std::time::Duration::from_secs(10)))
            .expect("读超时");
        let mut conn = ServerConnection::new(server_cfg).expect("建服务端连接");
        while conn.is_handshaking() {
            conn.complete_io(&mut sock).expect("服务端握手 IO");
        }
        let mut early = conn.early_data().expect("早数据该被接受");
        let mut payload = Vec::new();
        early.read_to_end(&mut payload).expect("读早数据");
        (payload, conn.handshake_kind())
    });

    let mut conn = ClientConnection::new(
        Arc::clone(&client_cfg),
        ServerName::try_from("localhost").unwrap(),
    )
    .expect("建连接");
    let mut early = conn.early_data().expect("早数据写手");
    early.write_all(EARLY_PAYLOAD).expect("写早数据");
    let mut sock = TcpStream::connect(addr).expect("连回环");
    common::drive_client(&mut conn, &mut sock).expect("连接 2");

    let (payload, kind) = server_thread.join().expect("服务端线程");
    assert_eq!(kind, Some(HandshakeKind::Resumed));
    assert_eq!(payload, EARLY_PAYLOAD);
}

/// **二分**：指纹化恢复、hello 里带 `early_data` 扩展，但**不写**早数据。
/// 过 ⇒ 问题在早数据记录的加密/发送；不过 ⇒ 问题在带扩展的 hello 本身。
#[test]
fn fingerprinted_resumption_with_early_data_ext_but_no_early_data() {
    let client_cfg = client_config(true);
    let server_cfg = server_config();
    {
        let (addr, server) = common::spawn_server(server_cfg.clone(), 1);
        let mut conn = ClientConnection::new(
            Arc::clone(&client_cfg),
            ServerName::try_from("localhost").unwrap(),
        )
        .expect("建连接");
        let mut sock = TcpStream::connect(addr).expect("连回环");
        common::drive_client(&mut conn, &mut sock).expect("连接 1");
        let served = server.join().expect("服务端线程");
        assert_eq!(served[0].handshake_kind, Some(HandshakeKind::Full));
    }
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("占端口");
    let addr = listener.local_addr().expect("端口");
    let server_thread = std::thread::spawn(move || {
        let (sock, _) = listener.accept().expect("accept");
        let mut sock = sock;
        sock.set_read_timeout(Some(std::time::Duration::from_secs(10)))
            .expect("读超时");
        let mut conn = ServerConnection::new(server_cfg).expect("建服务端连接");
        while conn.is_handshaking() {
            conn.complete_io(&mut sock).expect("服务端握手 IO");
        }
        conn.handshake_kind()
    });
    let mut conn = ClientConnection::new(
        Arc::clone(&client_cfg),
        ServerName::try_from("localhost").unwrap(),
    )
    .expect("建连接");
    let mut sock = TcpStream::connect(addr).expect("连回环");
    common::drive_client(&mut conn, &mut sock).expect("连接 2");
    let kind = server_thread.join().expect("服务端线程");
    assert_eq!(
        kind,
        Some(HandshakeKind::Resumed),
        "带 early_data 扩展的指纹恢复该成立"
    );
}
