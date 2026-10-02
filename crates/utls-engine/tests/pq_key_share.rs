//! **PQ 预设的 `key_share` 判据**：草案组发得出去，握手只在能完成的组上谈。
//!
//! # 被修掉的是什么
//!
//! Chrome 的 PQ 预设（`ChromePq(115)`/`ChromePq(120)`/`ChromePsk(115)`）的 `key_share` 是
//! `[GREASE, X25519Kyber768Draft00(0x6399), X25519]`。`0x6399` 是**草案**组，
//! rustls 的 aws-lc-rs 提供者只有 `X25519MLKEM768(4588)` —— 于是引擎原来只把
//! 「能完成的组」的公钥交出去，而指纹层的编码器要求 `key_share` 里**每个**非 GREASE 组
//! 都有公钥 ⇒ 这 3 档在 `marshal` 就报错（`key_share 需要组 25497 的公钥`）。
//!
//! 修法：给完不成的组一个**长度正确的占位公钥**（长度表在指纹层，它认得这个草案组），
//! 真交换仍旧只交可完成的那把。**后果如实写在这里**：
//!
//! - 服务器**不认** `0x6399` ⇒ 它选 X25519 ⇒ 握手照常完成（真实世界也正是这样回退的）；
//! - 服务器**认** `0x6399` 并选了它 ⇒ 我们完成不了 —— 但**不会静默降级**，
//!   第二飞那一层会响亮报错（见第三条测试：服务端只认 `4588` 时，我们连 HRR 都回不了）。
//!
//! 与 uTLS 的**语义差异**：uTLS 自己实现了这个草案组，所以它那 3 档能真完成 Kyber。
//! 我们选择「形状与 Chrome 逐字节一致（长度、JA3 都不变）+ 只能在 X25519 上完成」，
//! 而不是「拒绝整档预设」——前者可观测的那一面（字节）是对的，后者会让这 3 档根本没法用。

mod common;

use std::sync::Arc;

use rustls::client::{PlanRequest, SuppliesClientHello};
use rustls::pki_types::ServerName;
use rustls::{ClientConnection, HandshakeKind, NamedGroup};
use utls::hello::{ClientHelloId, ClientHelloSpec};
use utls::values as v;
use utls_engine::FingerprintClient;

/// 三档用了草案 PQ 组的预设。它们的 `key_share` 都是 `[GREASE, 0x6399, X25519]`。
const PQ_PRESETS: [ClientHelloId; 3] = [
    ClientHelloId::ChromePq(115),
    ClientHelloId::ChromePq(120),
    ClientHelloId::ChromePsk(115),
];

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::aws_lc_rs::default_provider())
}

/// 引擎能完成的 TLS 1.3 组（与 `ClientConfig::fork_key_exchange_groups` 同一口径）。
fn engine_groups(p: &Arc<rustls::crypto::CryptoProvider>) -> Vec<u16> {
    p.kx_groups
        .iter()
        .filter(|g| g.usable_for_version(rustls::ProtocolVersion::TLSv1_3))
        .map(|g| u16::from(g.name()))
        .collect()
}

/// 黄金值（原先从 FACTS.json 台账读取；台账退役后内联 —— 判据自己当权威）。
/// 来源：`u_parrots.go` 的逐字节 marshal 实测，与上游 testdata 对账。
fn golden(name: &str) -> (u64, bool) {
    match name {
        "chrome_115_pq" => (1526, true),
        "chrome_120_pq" => (1780, false),
        "chrome_115_psk" => (1526, true),
        _ => panic!("未知的 PQ 预设：{name}"),
    }
}

/// 从一条**握手消息**（`type || u24 || 体`）里取 `key_share` 的 `(组, 公钥长)` 列表。
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
            // `key_share` 的体：`u16 列表长 || (u16 组 || u16 公钥长 || 公钥)*`
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

/// 第一条：**形状对**（草案组的公钥长度正确、总长与台账一致），而**不声称能完成它**。
#[test]
fn the_draft_hybrid_share_goes_out_shaped_but_is_not_claimed() {
    let p = provider();
    for id in PQ_PRESETS {
        let name = id.name().to_string();
        let spec = ClientHelloSpec::from_preset(id).unwrap();
        let client = FingerprintClient::new(spec, p.clone()).with_sni("example.com");
        let plan = client
            .plan(&PlanRequest {
                groups: engine_groups(&p),
                resumption: None,
            })
            .unwrap_or_else(|e| panic!("{name} 该能产出 hello：{e}"));
        let bytes = plan.client_hello.expect("外供路径一定给字节");

        // 形状：草案组在，公钥长度是 32 + 1184（X25519 分量 + Kyber768 分量）。
        let entries = key_share_entries(&bytes);
        let draft = entries
            .iter()
            .find(|(g, _)| *g == v::X25519_KYBER768_DRAFT00)
            .unwrap_or_else(|| panic!("{name} 的 hello 里该有草案组 0x6399，实际 {entries:?}"));
        assert_eq!(
            draft.1,
            32 + 1184,
            "{name}: 草案组的公钥长度该与 Chrome 一致（32 + 1184）"
        );
        assert!(
            entries.iter().any(|(g, l)| *g == v::X25519 && *l == 32),
            "{name} 该同时带一个 X25519 共享（那才是我们能完成的那把）：{entries:?}"
        );
        // 总长与黄金值对。`name()` 的形状与 golden 表里的键同源（`chrome_115_pq`）。
        //
        // ⚠️ 分两种：stable = true 的档**精确**相等（那就是硬判据 ——
        // `chrome_115_pq` 的 1526 一个字节都不能差）；不稳定的档（GREASE-ECH 的载荷长度
        // 每连接四选一，**uTLS 自己也这样**）只存了一个采样，
        // 所以只能判「模 32 一致 + 在 ±96 内」—— 而占位公钥长度错了会偏 1184 字节，照样抓得到。
        let (want, stable) = golden(&id.name());
        let got = bytes.len() as u64;
        if stable {
            assert_eq!(got, want, "{name}: 长度稳定档，总长该与台账**精确**一致");
        } else {
            assert_eq!(got % 32, want % 32, "{name}: 总长该与台账模 32 同余");
            assert!(
                got.abs_diff(want) <= 96,
                "{name}: 总长 {got} 偏离台账 {want} 超过 GREASE-ECH 的候选跨度（±96）"
            );
        }

        // 不声称：交换表里只有 X25519，没有草案组。
        let groups: Vec<u16> = plan.key_exchanges.iter().map(|k| k.group()).collect();
        assert_eq!(groups, vec![v::X25519], "{name}: 只该声称 X25519 能完成");
    }
}

/// 第二条：服务端**只认 X25519** ⇒ 握手完成，且 `Full`（**没有** HRR）——
/// 那正是「服务端用了我们第一飞发出去的 X25519 共享」的证据。
#[test]
fn a_pq_fingerprint_completes_a_real_handshake_when_the_server_picks_x25519() {
    let p = provider();
    let spec = ClientHelloSpec::from_preset(ClientHelloId::ChromePq(115)).unwrap();
    let (addr, server) = common::spawn_server(
        common::server_config(false, Some(vec![NamedGroup::X25519])),
        1,
    );
    let config = Arc::new(common::client_config_with_verifier(
        FingerprintClient::new(spec, p).with_sni("localhost"),
        Vec::new(),
        common::shared_verifier(),
        None,
    ));
    let mut conn =
        ClientConnection::new(config, ServerName::try_from("localhost").unwrap()).expect("建连接");
    let mut sock = std::net::TcpStream::connect(addr).expect("连回环");
    common::drive_client(&mut conn, &mut sock).expect("握手该完成");

    let served = server.join().expect("服务端线程");
    assert_eq!(
        served[0].handshake_kind,
        Some(HandshakeKind::Full),
        "该直接谈成：`FullWithHelloRetryRequest` 意味着服务端没用上我们第一飞的共享密钥"
    );
    assert_eq!(
        served[0].version,
        Some(rustls::ProtocolVersion::TLSv1_3),
        "该谈成 TLS 1.3"
    );
    // 服务端看到的字节里确实有那个草案组 —— 形状真的发出去了。
    let hello = &served[0].client_hello[5..];
    assert!(
        key_share_entries(hello)
            .iter()
            .any(|(g, _)| *g == v::X25519_KYBER768_DRAFT00),
        "服务端该看到草案组（那是指纹的一部分）"
    );
}

/// 第三条：**失败要响亮、且原因是能看懂的**。
///
/// 服务端只认 `X25519MLKEM768(4588)`；而 `ChromePq(120)` 的 `supported_groups` 里
/// **根本没有** 4588（那是 Chrome 131+ 才加的），所以服务端与客户端**没有共同组** ⇒
/// 服务端自己发 `handshake_failure`。这一条钉住的是：我们不会在这种情况下静默换一个组继续谈。
///
/// ⚠️ 「服务器**认** `0x6399` 并选了它」那一种情况**本机造不出来**（本地 rustls 不认识那个
/// 草案组），所以它由第一条测试的「只声称 X25519 能完成」钉住 —— 那正是「不会静默降级」的
/// 可观测形式（我们连声称都不声称）。
#[test]
fn a_server_without_a_common_group_refuses_instead_of_silently_downgrading() {
    let p = provider();
    let spec = ClientHelloSpec::from_preset(ClientHelloId::ChromePq(120)).unwrap();
    let (addr, server) = common::spawn_server(
        common::server_config(false, Some(vec![NamedGroup::X25519MLKEM768])),
        1,
    );
    let config = Arc::new(common::client_config_with_verifier(
        FingerprintClient::new(spec, p).with_sni("localhost"),
        Vec::new(),
        common::shared_verifier(),
        None,
    ));
    let mut conn =
        ClientConnection::new(config, ServerName::try_from("localhost").unwrap()).expect("建连接");
    let mut sock = std::net::TcpStream::connect(addr).expect("连回环");
    let err = common::drive_client(&mut conn, &mut sock).expect_err("没有共同组，握手必须失败");
    let text = err.to_string();
    assert!(
        text.contains("HandshakeFailure") || text.contains("alert") || text.contains("no common"),
        "失败该是「服务端判没有共同组」这一类，而不是一个看不出原因的错：{text}"
    );
    let _ = server.join();
}
