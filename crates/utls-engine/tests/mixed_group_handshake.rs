//! **混合组 `X25519MLKEM768(4588)` 能不能正常握手** —— 三条路都要有服务端给的结论。
//!
//! 为什么单独立一份判据：这是引擎组列表里**被真实预设真的发出去**的最大那个组
//! （Chrome 131/133 的 `key_share` 是 `[GREASE, 4588, X25519]`，Firefox 148 是
//! `[4588, X25519, P-256]`），也是唯一一个「经典那一半嵌在里面」的组：线上的
//! 公钥是 `ML-KEM-768 封装密钥(1184) || X25519(32)` 一份 1216 字节的拼接，而
//! `complete` 与 `complete_hybrid_component` 是**两条不同的路**（见 fork 的
//! `ExternalKx`）。此前对它的判据只有**反向**的一条（`pq_key_share.rs` 第三条：
//! `ChromePq(120)` 与只认 4588 的服务端没有共同组 ⇒ 服务端失败），
//! 没有任何一条把服务端限制成只认 4588 再断言**谈成**。
//!
//! 三条路各判一件事：
//!
//! | 测试 | 情形 | 要证什么 |
//! |---|---|---|
//! | 1 | Firefox 148 的 `[4588, X25519, P-256]` + 服务端只认 4588 | 服务端**在第一飞里**选中混合组，握手直接谈成（`Full`）⇒ 引擎交出的那把混合交换（含它的经典分量）真的能用 |
//! | 2 | `key_share` 只有 4588 + 服务端只认 4588 | 没有 X25519 / P-256 可退时，混合组也能独立谈成 |
//! | 3 | `key_share` 被改成只有 X25519（`supported_groups` 里仍有 4588）+ 服务端只认 4588 | 服务端**回 HRR 要混合组** ⇒ 我们的第二飞带上**新的** 1216 字节共享并谈成 |
//!
//! 判据一律取**服务端**的说法（`handshake_kind` / `version`），不取我们自报的。

mod common;

use std::sync::Arc;

use rustls::pki_types::ServerName;
use rustls::{ClientConnection, HandshakeKind, NamedGroup};
use utls::hello::{ClientHelloId, ClientHelloSpec, CodePoint, Extension, KeyShare};
use utls::values as v;
use utls_engine::FingerprintClient;

/// 混合组的共享公钥：`ML-KEM-768 封装密钥` + `X25519`。
/// 与指纹层的长度表同源（`values::group_public_key_len(v::X25519_MLKEM768)`）。
const HYBRID_SHARE_LEN: usize = 1184 + 32;

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::aws_lc_rs::default_provider())
}

/// 一把钥匙：本地服务端**只认混合组**（`kx_groups` 被滤掉其余组），
/// 所以「谈成了」这件事本身就是「用的是 4588」。
fn server_only_hybrid() -> Arc<rustls::ServerConfig> {
    common::server_config(false, Some(vec![NamedGroup::X25519MLKEM768]))
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
    spec.extensions[at] = Extension::KeyShare(KeyShare::groups(
        groups
            .iter()
            .copied()
            .map(CodePoint::Fixed)
            .collect::<Vec<_>>(),
    ));
    spec
}

/// 从一条握手消息里取 `key_share` 的 `(组, 公钥长)` 列表。
fn key_share_entries(message: &[u8]) -> Vec<(u16, usize)> {
    let mut p = 4 + 2 + 32;
    p += 1 + message[p] as usize; // legacy_session_id
    let cs = u16::from_be_bytes([message[p], message[p + 1]]) as usize;
    p += 2 + cs;
    p += 1 + message[p] as usize; // compression_methods
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

/// 一：真实预设（Firefox 148 的 `[4588, X25519, P-256]`）里，服务端**在第一飞**就选中混合组。
#[test]
fn firefox_preset_completes_when_the_server_picks_the_hybrid_share_in_the_first_flight() {
    let spec = ClientHelloSpec::from_preset(ClientHelloId::Firefox(148)).unwrap();
    let (addr, server) = common::spawn_server(server_only_hybrid(), 1);
    let conn = connect(addr, spec, "localhost");
    let served = server.join().expect("服务端线程").pop().expect("一条结果");

    // 先钉住「这个预设确实发了混合组，且长度是那份拼接」—— 否则谈成了也说明不了什么。
    let entries = key_share_entries(&served.client_hello[5..]);
    assert!(
        entries.contains(&(v::X25519_MLKEM768, HYBRID_SHARE_LEN)),
        "Firefox 148 的第一飞该带混合组共享（{HYBRID_SHARE_LEN} 字节），实际 {entries:?}"
    );
    assert_eq!(
        served.handshake_kind,
        Some(HandshakeKind::Full),
        "服务端该**在第一飞里**选中混合组 —— `FullWithHelloRetryRequest` 说明它没能用上我们的共享"
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

/// 二：`key_share` **只有**混合组（没有 X25519 / P-256 可退）也能谈成。
#[test]
fn the_hybrid_share_alone_is_enough_to_complete_a_handshake() {
    let spec = spec_with_key_shares(
        &ClientHelloSpec::from_preset(ClientHelloId::Firefox(148)).unwrap(),
        &[v::X25519_MLKEM768],
    );
    let (addr, server) = common::spawn_server(server_only_hybrid(), 1);
    let conn = connect(addr, spec, "localhost");
    let served = server.join().expect("服务端线程").pop().expect("一条结果");

    assert_eq!(
        key_share_entries(&served.client_hello[5..]),
        vec![(v::X25519_MLKEM768, HYBRID_SHARE_LEN)],
        "这一飞该只有一把混合组共享"
    );
    assert_eq!(
        served.handshake_kind,
        Some(HandshakeKind::Full),
        "只给混合组时也该直接谈成"
    );
    assert_eq!(served.version, Some(rustls::ProtocolVersion::TLSv1_3));
    assert_eq!(
        conn.protocol_version(),
        Some(rustls::ProtocolVersion::TLSv1_3)
    );
}

/// 三：客户端只发 X25519，服务端只认混合组 ⇒ **强制 HRR**，第二飞必须带上**新的**混合组共享。
#[test]
fn a_server_that_insists_on_the_hybrid_forces_a_retry_that_succeeds() {
    // `supported_groups` 里仍有 4588（Firefox 的列表），只是第一飞的 `key_share` 里没有
    // ⇒ 服务端要它要得合法（RFC 8446 §4.1.4 只许要客户端报过的组）。
    let spec = spec_with_key_shares(
        &ClientHelloSpec::from_preset(ClientHelloId::Firefox(148)).unwrap(),
        &[v::X25519],
    );
    let (addr, server) = common::spawn_server(server_only_hybrid(), 1);
    let conn = connect(addr, spec, "localhost");
    let served = server.join().expect("服务端线程").pop().expect("一条结果");

    assert_eq!(
        served.handshake_kind,
        Some(HandshakeKind::FullWithHelloRetryRequest),
        "服务端只认混合组而第一飞没有它的共享 ⇒ 必须回一次 HRR（不然这条没测到东西）"
    );
    assert_eq!(
        served.client_hellos.len(),
        2,
        "这条连接该有两条 ClientHello（第一飞 + HRR 之后那飞）"
    );
    let second = &served.client_hellos[1][5..];
    assert_eq!(
        key_share_entries(second),
        vec![(v::X25519_MLKEM768, HYBRID_SHARE_LEN)],
        "第二飞该只带一把**新的**混合组共享（{HYBRID_SHARE_LEN} 字节）"
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
