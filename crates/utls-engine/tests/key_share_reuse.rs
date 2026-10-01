//! **混合组与经典组共用密钥材料**（uTLS 的 `ReuseHybridAndClassicalKeyShares`）。
//!
//! # 被修掉的是什么
//!
//! 真实 Firefox 只生成**一把** X25519 密钥，于是它发出去的 `key_share` 里，
//! 混合组 `X25519MLKEM768(4588)` 条目的**末 32 字节**与那个独立的
//! `X25519(29)` 条目**逐字节相同**。uTLS 复刻了这个关系：预设里用
//! `ReuseHybridAndClassicalKeyShares(hybrid, classical)`（`u_public.go:656`）打一对标记，
//! `ApplyPreset` 消费它，并且有一条专门的判据
//! `TestParrotFingerprintsReuseHybridClassicalKeyShare`（`u_parrots_test.go:63`），
//! 外加一条互补判据断言「默认是独立的」（`:96`）。
//!
//! 本仓原先**没有**实现这个关系：引擎为 `key_share` 里每个组各起一把独立交换
//! （「每连接一次」），所以 `Firefox(148)` 发出去的字节**形状**与 Firefox 一致
//! （长度、JA3、扩展顺序全对），但**关系**不同 —— 两个条目各用各的材料。
//! 这不是「像不像」的问题：那是一条可判的字节级事实，上游有判据，我们没有。
//!
//! 修法：`Firefox(148)` 的 spec 声明 `KeyShare::reuse = Some((4588, 29))`
//! （**只有它**，`u_parrots.go:1535` 是上游唯一的使用点），引擎据此**只交一把**混合交换，
//! 经典条目的公钥取它的 `hybrid_component()` —— 也就是 rustls 自己那条「第二条
//! key_share 白送」的路径（`rustls/src/client/hs.rs:505-533`）用的机制。
//!
//! 判据一律取**服务端看到的字节**与**服务端给的结论**（`handshake_kind`），不取我们自报的。

mod common;

use std::sync::Arc;

use rustls::pki_types::ServerName;
use rustls::{ClientConnection, HandshakeKind, NamedGroup};
use utls::hello::{ClientHelloId, ClientHelloSpec};
use utls::values as v;
use utls_engine::FingerprintClient;

/// 混合组的共享公钥长度：`ML-KEM-768 封装密钥(1184)` + `X25519(32)`。
const HYBRID_SHARE_LEN: usize = 1184 + 32;
const X25519_SHARE_LEN: usize = 32;

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::aws_lc_rs::default_provider())
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

/// 从一条握手消息里取「组 → 公钥字节」的映射（保留完整公钥，才能比那 32 字节）。
fn key_share_bytes(message: &[u8]) -> Vec<(u16, Vec<u8>)> {
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
                out.push((g, body[r + 4..r + 4 + kl].to_vec()));
                r += 4 + kl;
            }
            return out;
        }
        q += 4 + bl;
    }
    Vec::new()
}

fn share_of(entries: &[(u16, Vec<u8>)], group: u16) -> Vec<u8> {
    entries
        .iter()
        .find(|(g, _)| *g == group)
        .unwrap_or_else(|| {
            panic!(
                "hello 里没有组 0x{group:04x}，实际 {:?}",
                entries.iter().map(|(g, _)| *g).collect::<Vec<_>>()
            )
        })
        .1
        .clone()
}

/// 一：**Firefox 148 的 `key_share` 里，混合组的末 32 字节 == 独立的 X25519 项**。
///
/// 判在**服务端看到的字节**上 —— 那才是线上事实。同时钉住两项的形状
/// （混合组 1216 字节、经典组 32 字节），免得「两个都空」也能过。
#[test]
fn firefox_148_sends_the_hybrid_and_classical_shares_with_one_x25519_material() {
    let spec = ClientHelloSpec::from_preset(ClientHelloId::Firefox(148)).unwrap();
    assert_eq!(
        spec.key_share_reuse(),
        Some((v::X25519_MLKEM768, v::X25519)),
        "Firefox 148 的 spec 该声明这对复用（uTLS u_parrots.go:1535）"
    );

    // 服务端只认经典组：这样既拿到字节，又顺带证明「复用的那一半」真的能用。
    let (addr, server) = common::spawn_server(
        common::server_config(false, Some(vec![NamedGroup::X25519])),
        1,
    );
    let conn = connect(addr, spec, "localhost");
    let served = server.join().expect("服务端线程").pop().expect("一条结果");

    let entries = key_share_bytes(&served.client_hello[5..]);
    let hybrid = share_of(&entries, v::X25519_MLKEM768);
    let classical = share_of(&entries, v::X25519);
    assert_eq!(hybrid.len(), HYBRID_SHARE_LEN, "混合组公钥该是 1216 字节");
    assert_eq!(classical.len(), X25519_SHARE_LEN, "经典组公钥该是 32 字节");
    assert_eq!(
        &hybrid[HYBRID_SHARE_LEN - X25519_SHARE_LEN..],
        &classical[..],
        "混合组的末 32 字节必须与独立的 X25519 项逐字节相同（Firefox 共用同一份材料）"
    );

    assert_eq!(
        served.handshake_kind,
        Some(HandshakeKind::Full),
        "服务端只认 X25519 时该直接谈成 —— `FullWithHelloRetryRequest` 说明它没用上我们那份共享"
    );
    assert_eq!(served.version, Some(rustls::ProtocolVersion::TLSv1_3));
    assert_eq!(
        conn.protocol_version(),
        Some(rustls::ProtocolVersion::TLSv1_3),
        "客户端侧也该是 TLS 1.3"
    );
}

/// 二：**互补判据** —— 不声明复用的预设（Chrome 133 的 `[GREASE, 4588, X25519]`）
/// 两个条目**必须不同**。
///
/// 这条挡的是「把复用当成通用规则」：如果哪天有人按「报了混合组也报了它的经典分量」
/// 去推断复用，Chrome 的字节就会变成 Firefox 的样子 —— 而上游明说了默认是独立的
/// （`u_parrots_test.go:96` 的 `TestHybridClassicalKeySharesAreIndependentByDefault`）。
#[test]
fn chrome_133_keeps_the_two_shares_independent() {
    let spec = ClientHelloSpec::from_preset(ClientHelloId::Chrome(133)).unwrap();
    assert_eq!(
        spec.key_share_reuse(),
        None,
        "Chrome 133 不该声明复用 —— 上游只给 Firefox 148 用了那个标记"
    );

    let (addr, server) = common::spawn_server(
        common::server_config(false, Some(vec![NamedGroup::X25519])),
        1,
    );
    let _ = connect(addr, spec, "localhost");
    let served = server.join().expect("服务端线程").pop().expect("一条结果");

    let entries = key_share_bytes(&served.client_hello[5..]);
    let hybrid = share_of(&entries, v::X25519_MLKEM768);
    let classical = share_of(&entries, v::X25519);
    assert_ne!(
        &hybrid[HYBRID_SHARE_LEN - X25519_SHARE_LEN..],
        &classical[..],
        "Chrome 133 的两项该是各自独立的密钥材料（相同即说明复用被误当成了通用规则）"
    );
}

/// 三：服务端只认**混合组**时，声明了复用也照常谈成 `Full` ——
/// 「只交一把」不该把混合组那条路弄坏。
#[test]
fn declaring_reuse_still_completes_when_the_server_takes_the_hybrid() {
    let spec = ClientHelloSpec::from_preset(ClientHelloId::Firefox(148)).unwrap();
    let (addr, server) = common::spawn_server(
        common::server_config(false, Some(vec![NamedGroup::X25519MLKEM768])),
        1,
    );
    let conn = connect(addr, spec, "localhost");
    let served = server.join().expect("服务端线程").pop().expect("一条结果");

    assert_eq!(
        served.handshake_kind,
        Some(HandshakeKind::Full),
        "服务端只认混合组时该直接谈成"
    );
    assert_eq!(served.version, Some(rustls::ProtocolVersion::TLSv1_3));
    assert_eq!(
        conn.protocol_version(),
        Some(rustls::ProtocolVersion::TLSv1_3)
    );
}

/// 四：`from_bytes` **推不出**这对声明 —— 线上那两个条目只是「两串随机字节」，
/// 分不清「共用」与「恰好相同」。所以反解出来的 spec 一律不带它。
///
/// 这条挡的是「反解时凭空补一个声明」：uTLS 的 `Fingerprinter` 也不还原它。
///
/// # 顺带钉住一条**已知边界**（不是本条要证的，但在这里看得最清楚）
///
/// 反解把 `key_share` 归成 [`Extension::Opaque`]（体原样保留）—— 这正是
/// `real_world_client_hello_round_trips` 能做到逐字节回放的原因。代价是
/// **反解出来的 spec 没有「组」这个概念**，所以它目前走不了引擎那条路
/// （引擎不知道要为哪些组准备密钥交换）。
///
/// uTLS 那边是可以的：它在写出时**总是**用引擎新生成的密钥覆盖 spec 里的
/// keyshare 数据（`handshake_client_tls13.go:391` 的 `// new ks seems to be
/// generated either way`），所以一份 `Fingerprinter` 出的 spec 照样能握手。
/// 这条差距记在 `docs/utls-parity.md`（Fingerprinter 一族），不在这里假装已经对齐。
#[test]
fn parsing_a_client_hello_does_not_invent_the_reuse_declaration() {
    let spec = ClientHelloSpec::from_preset(ClientHelloId::Firefox(148)).unwrap();
    let (addr, server) = common::spawn_server(
        common::server_config(false, Some(vec![NamedGroup::X25519])),
        1,
    );
    let _ = connect(addr, spec, "localhost");
    let served = server.join().expect("服务端线程").pop().expect("一条结果");

    let hello = &served.client_hello[5..];
    let parsed = ClientHelloSpec::from_bytes(hello).expect("反解");
    assert_eq!(
        parsed.key_share_reuse(),
        None,
        "线上字节里看不出「共用」，反解就不该声称它"
    );
    assert!(
        parsed.key_share_groups().is_empty(),
        "反解把 key_share 归成 Opaque ⇒ 组列表为空（这正是回放能逐字节相同的原因）"
    );
    // 但字节要能原样回放 —— 那半边由 `real_world_client_hello_round_trips` 严判。
    let replay = utls::hello::HandshakeInputs::for_replay(hello).expect("回放输入");
    let again = parsed.marshal(&replay).expect("回放").into_bytes();
    assert_eq!(again, hello, "反解再回放该逐字节相同");
}
