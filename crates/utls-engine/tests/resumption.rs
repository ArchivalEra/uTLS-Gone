//! **session/resumption 跑通**：fork 的第七处能力（`PlanRequest::resumption` /
//! `ClientHelloPlan::psk_binder`）在本地服务端装置上的判据。
//!
//! # 判据为什么必须由**服务端**给
//!
//! 客户端自报「我复用了会话」不算证据 —— 它可能只是把 PSK 扩展发出去了，而服务端
//! 拒掉它、退化成完整握手。所以这里的结论来自 [`Served::resumed`]，即服务端自己的
//! `handshake_kind() == Resumed`。
//!
//! # 两遍序列化与 binder 的归属
//!
//! RFC 8446 §4.2.11.2 的 binder 是 `HMAC(finished_key, Hash(Truncate(ClientHello)))`，
//! 而 `finished_key` 来自**会话密钥**。会话密钥只在 rustls 手里，所以：
//!
//! 1. 引擎把会话当**数据**交给调用方（ticket + 混淆年龄 + binder 长度）；
//! 2. 调用方把它写进 spec 的 PSK 槽位，binder 位置留**全零占位**；
//! 3. 引擎拿到字节后，只改写那 `binder_len` 个字节（`PskBinderSlot`）。
//!
//! 第 3 步是「对已序列化的消息做字节改写」，而能力 (a) 原则上禁止这件事 ——
//! 它在这里成立的唯一理由是**只改 binder、不改任何长度**，于是转录哈希与引擎从
//! 外供字节里学到的状态都不受影响。这条测试就是在验它真的成立。

mod common;

use std::sync::Arc;

use rustls::client::ClientSessionStore;
use rustls::pki_types::ServerName;
use rustls::{ClientConnection, HandshakeKind};
use utls::hello::{ClientHelloId, ClientHelloSpec};
use utls::values as v;
use utls_engine::FingerprintClient;

/// 一条 ClientHello 里出现过的扩展类型（按线序）。
fn ext_types(record: &[u8]) -> Vec<u16> {
    assert_eq!(record[0], 0x16, "不是握手记录");
    let msg = &record[5..];
    assert_eq!(msg[0], 1, "不是 ClientHello");
    let len = ((msg[1] as usize) << 16) | ((msg[2] as usize) << 8) | msg[3] as usize;
    let body = &msg[4..4 + len];
    let mut p = 2 + 32;
    p += 1 + body[p] as usize;
    let cs = u16::from_be_bytes([body[p], body[p + 1]]) as usize;
    p += 2 + cs;
    p += 1 + body[p] as usize;
    let n = u16::from_be_bytes([body[p], body[p + 1]]) as usize;
    p += 2;
    let region = &body[p..p + n];
    let mut out = Vec::new();
    let mut q = 0usize;
    while q + 4 <= region.len() {
        out.push(u16::from_be_bytes([region[q], region[q + 1]]));
        let bl = u16::from_be_bytes([region[q + 2], region[q + 3]]) as usize;
        q += 4 + bl;
    }
    out
}

/// key_share 里报的组（按顺序）—— 用来验 HRR 之后只剩服务器要的那一个。
fn key_share_groups(record: &[u8]) -> Vec<u16> {
    let msg = &record[5..];
    let len = ((msg[1] as usize) << 16) | ((msg[2] as usize) << 8) | msg[3] as usize;
    let body = &msg[4..4 + len];
    let mut p = 2 + 32;
    p += 1 + body[p] as usize;
    let cs = u16::from_be_bytes([body[p], body[p + 1]]) as usize;
    p += 2 + cs;
    p += 1 + body[p] as usize;
    let n = u16::from_be_bytes([body[p], body[p + 1]]) as usize;
    p += 2;
    let region = &body[p..p + n];
    let mut q = 0usize;
    while q + 4 <= region.len() {
        let ty = u16::from_be_bytes([region[q], region[q + 1]]);
        let bl = u16::from_be_bytes([region[q + 2], region[q + 3]]) as usize;
        if ty == v::EXT_KEY_SHARE {
            let ks = &region[q + 4..q + 4 + bl];
            let list_len = u16::from_be_bytes([ks[0], ks[1]]) as usize;
            let mut out = Vec::new();
            let mut r = 2usize;
            while r + 4 <= 2 + list_len {
                out.push(u16::from_be_bytes([ks[r], ks[r + 1]]));
                let kl = u16::from_be_bytes([ks[r + 2], ks[r + 3]]) as usize;
                r += 4 + kl;
            }
            return out;
        }
        q += 4 + bl;
    }
    Vec::new()
}

/// 取 PSK 扩展的体（`u16 identities_len || identities || u16 binders_len || binders`）。
fn psk_body(record: &[u8]) -> Option<Vec<u8>> {
    let msg = &record[5..];
    let len = ((msg[1] as usize) << 16) | ((msg[2] as usize) << 8) | msg[3] as usize;
    let body = &msg[4..4 + len];
    let mut p = 2 + 32;
    p += 1 + body[p] as usize;
    let cs = u16::from_be_bytes([body[p], body[p + 1]]) as usize;
    p += 2 + cs;
    p += 1 + body[p] as usize;
    let n = u16::from_be_bytes([body[p], body[p + 1]]) as usize;
    p += 2;
    let region = &body[p..p + n];
    let mut q = 0usize;
    while q + 4 <= region.len() {
        let ty = u16::from_be_bytes([region[q], region[q + 1]]);
        let bl = u16::from_be_bytes([region[q + 2], region[q + 3]]) as usize;
        if ty == v::EXT_PRE_SHARED_KEY {
            return Some(region[q + 4..q + 4 + bl].to_vec());
        }
        q += 4 + bl;
    }
    None
}

/// 用**同一个** `Arc<ClientConfig>` 跑一条连接。
///
/// 「同一个 config」不是省事，是**复用的前提**：rustls 按 `Weak::ptr_eq` 比较
/// 会话里存的验签器与当前 config 的验签器，指针不同就静默拒绝复用 ——
/// 而票已经被 `take_tls13_ticket` 拿走了（票没了、也没复用）。见 `common` 里的说明。
fn connect(addr: std::net::SocketAddr, config: Arc<rustls::ClientConfig>) -> ClientConnection {
    let mut conn = ClientConnection::new(config, ServerName::try_from("localhost").unwrap())
        .expect("建连接");
    let mut sock = std::net::TcpStream::connect(addr).expect("连回环");
    common::drive_client(&mut conn, &mut sock).expect("握手该跑完");
    conn
}

/// 按预设造一个带共享会话存储与共享验签器的 config。
fn config_for(
    preset: ClientHelloId,
    store: Arc<dyn ClientSessionStore>,
    verifier: Arc<common::AcceptAnySignature>,
) -> Arc<rustls::ClientConfig> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let spec = ClientHelloSpec::from_preset(preset).unwrap();
    let fingerprint = FingerprintClient::new(spec, provider).with_sni("localhost");
    Arc::new(common::client_config_with_verifier(
        fingerprint,
        vec![b"h2".to_vec()],
        verifier,
        Some(store),
    ))
}

/// **核心判据**：第二次连接被服务端认定为 `Resumed`，且第二条 ClientHello 里
/// 真的带了 PSK 扩展（identity 是服务端发的 ticket）。
///
/// 用 `ChromePsk(100)` 这个预设：`_PSK_` 系列的 spec 里**有** PSK 槽位（uTLS 就是
/// 为这件事加的它们）；普通 Chrome 预设没有那个槽位，本层**不会**替调用方补一条
/// （补扩展会改指纹，那必须显式要求 —— 见引擎里那条报错的文案）。
#[test]
fn a_second_connection_resumes_and_the_server_says_so() {
    let (addr, server) = common::spawn_server(common::server_config(true, None), 2);
    let store = Arc::new(common::RecordingStore::new());
    let as_store: Arc<dyn ClientSessionStore> = store.clone();
    let config = config_for(ClientHelloId::ChromePsk(100), as_store, common::shared_verifier());

    let first = connect(addr, config.clone());
    // 票真的进了库 —— 这一步单列，因为「收到了 ticket」与「库里真的有票」是两件事，
    // 而后者才是复用的前提（本仓实测踩到过一次静默的差：`ClientSessionMemoryCache`
    // 里就是查不到，而客户端明明收到了 2 张）。
    assert_eq!(first.tls13_tickets_received(), 2, "第一次该收到 2 张 ticket");
    assert!(!store.is_empty(), "票没进存储 —— 复用无从谈起");
    // 第一次是完整握手：`_PSK_` 预设的 PSK 槽位在没有会话时**零字节**（uTLS 的
    // `pskExtLen() == 0`），所以那条 hello 里不该有 0x0029。
    let second = connect(addr, config.clone());

    let served = server.join().expect("服务端线程");
    assert_eq!(served.len(), 2, "该收到两条连接");
    assert_eq!(
        served[0].handshake_kind,
        Some(HandshakeKind::Full),
        "第一次该是完整握手"
    );
    assert!(
        !ext_types(&served[0].client_hello).contains(&v::EXT_PRE_SHARED_KEY),
        "第一次连接没有会话可复用，PSK 扩展该是零字节（不出现在线上）"
    );
    assert_eq!(
        served[1].handshake_kind,
        Some(HandshakeKind::Resumed),
        "**服务端**说第二次不是复用 —— PSK 没被接受（binder、identity 或年龄哪一个错了）"
    );
    assert_eq!(
        first.protocol_version(),
        Some(rustls::ProtocolVersion::TLSv1_3),
        "第一次该谈成 TLS 1.3"
    );
    assert_eq!(
        second.protocol_version(),
        Some(rustls::ProtocolVersion::TLSv1_3),
        "复用也是 TLS 1.3"
    );

    // 第二条 ClientHello：有 PSK 扩展，identity 就是服务端给的 ticket。
    let body = psk_body(&served[1].client_hello).expect("第二条该带 PSK 扩展");
    let ids_len = u16::from_be_bytes([body[0], body[1]]) as usize;
    assert!(ids_len > 0, "PSK identities 不能为空");
    let identity_len = u16::from_be_bytes([body[2], body[3]]) as usize;
    assert!(identity_len > 0, "identity（ticket）不能为空");
    // binders 向量：长度字段 + 每条 (u8 长度 + binder)。
    let binders_off = 2 + ids_len;
    let binders_len = u16::from_be_bytes([body[binders_off], body[binders_off + 1]]) as usize;
    let binder_len = body[binders_off + 2] as usize;
    assert_eq!(binders_len, 1 + binder_len, "一个 identity 一个 binder");
    assert_eq!(binder_len, 32, "SHA-256 会话的 binder 该是 32 字节");
    let binder = &body[binders_off + 3..binders_off + 3 + binder_len];
    assert!(
        binder.iter().any(|b| *b != 0),
        "binder 还是全零占位 —— 引擎没把真 binder 写进去"
    );
}

/// 会话槽位在**第一条**连接上就存在时，第二条的指纹变化只有「PSK 扩展从零字节变成
/// 一条真扩展」—— 别的扩展（尤其顺序与长度）都不该动。
///
/// 这条钉住的是「填 PSK 用的是一次 spec 克隆，没污染预设本身」。
#[test]
fn filling_the_psk_slot_does_not_disturb_the_rest_of_the_hello() {
    let (addr, server) = common::spawn_server(common::server_config(true, None), 2);
    let store: Arc<dyn ClientSessionStore> = Arc::new(common::RecordingStore::new());
    let config = config_for(ClientHelloId::ChromePsk(100), store, common::shared_verifier());
    let _ = connect(addr, config.clone());
    let _ = connect(addr, config);
    let served = server.join().expect("服务端线程");

    // GREASE 扩展的**类型取值**每连接都不同（那是它的用途），折成哨兵再比；
    // PSK 本身当然不同（第一条零字节、第二条是真扩展），单独排除。
    let norm = |t: u16| if v::is_grease(t) { 0x0a0a } else { t };
    let a: Vec<u16> = ext_types(&served[0].client_hello)
        .into_iter()
        .filter(|t| *t != v::EXT_PRE_SHARED_KEY)
        .map(norm)
        .collect();
    let b: Vec<u16> = ext_types(&served[1].client_hello)
        .into_iter()
        .filter(|t| *t != v::EXT_PRE_SHARED_KEY)
        .map(norm)
        .collect();
    assert_eq!(a, b, "除 PSK 之外的扩展序列变了 —— 填槽位污染了别的扩展");
}


/// **HRR + 复用**：服务器强制 HRR（只认 P-384，而客户端的 key_share 只给 X25519），
/// 同时又能复用会话 —— 于是第二飞里必须有 PSK，而且它的 binder 是在
/// `message_hash || HRR || Truncate(ClientHello2)` 上**重算**的。
///
/// 这是 uTLS 的 `UpdateOnHRR` 那条路。判据仍然是**服务端**给的：
/// `FullWithHelloRetryRequest`（真的 HRR 了）+ `Resumed`（PSK 真的被接受了）。
/// 少了任何一半都说明只测到了半条路。
#[test]
fn a_hello_retry_request_still_resumes() {
    use rustls::NamedGroup;
    // 服务器只认 P-384 ⇒ 第一飞必被 HRR；tickets 打开 ⇒ 第二连接可复用。
    let (addr, server) = common::spawn_server(
        common::server_config(true, Some(vec![NamedGroup::secp384r1])),
        2,
    );
    let store = Arc::new(common::RecordingStore::new());
    let as_store: Arc<dyn ClientSessionStore> = store.clone();
    let config = config_for(ClientHelloId::ChromePsk(100), as_store, common::shared_verifier());

    let first = connect(addr, config.clone());
    assert_eq!(first.tls13_tickets_received(), 2, "HRR 之后服务端仍该发 ticket");
    assert!(!store.is_empty(), "票没进存储");
    let _second = connect(addr, config.clone());

    let served = server.join().expect("服务端线程");

    // 两条连接**各自**都该有两条 ClientHello —— 这是「HRR 真的发生了」的直接证据，
    // 比看 `HandshakeKind` 强：那个枚举里 `Resumed` 与 `FullWithHelloRetryRequest`
    // 是互斥的取值，而「带 HRR 的复用」在它里面只报 `Resumed`（枚举没有第三个组合值）。
    for (i, sv) in served.iter().enumerate() {
        assert_eq!(
            sv.client_hellos.len(),
            2,
            "第 {i} 条连接该发了两条 ClientHello（HRR 的第二飞）"
        );
        assert!(
            sv.client_hello.len() > psk_body(&sv.client_hellos[0]).map(|b| b.len()).unwrap_or(0),
            "第 {i} 条：第一条 hello 的形状不对劲"
        );
    }

    // 第一条连接：没有会话可复用，两条 ClientHello 里都不该有 PSK 扩展。
    assert_eq!(
        served[0].handshake_kind,
        Some(HandshakeKind::FullWithHelloRetryRequest),
        "第一条连接该是「带 HRR 的完整握手」"
    );
    for (k, hello) in served[0].client_hellos.iter().enumerate() {
        assert!(
            psk_body(hello).is_none(),
            "第一条连接的第 {k} 条 hello 不该带 PSK（没有会话）"
        );
    }

    // 第二条连接：**第二飞**里必须有 PSK，且 binder 是在新转录上重算的（非零）。
    assert!(
        served[1].resumed,
        "**服务端**说第二条没复用 —— HRR 之后的 binder 没算对"
    );
    let second_flight = &served[1].client_hellos[1];
    let body = psk_body(second_flight).expect("第二飞该带 PSK 扩展");
    let ids_len = u16::from_be_bytes([body[0], body[1]]) as usize;
    let off = 2 + ids_len;
    assert_eq!(body[off + 2] as usize, 32, "SHA-256 的 binder 该是 32 字节");
    assert!(
        body[off + 3..off + 35].iter().any(|b| *b != 0),
        "第二飞的 binder 还是全零占位 —— 没有重算"
    );
    // 第二飞的 key_share 该只剩服务器要的 P-384（HRR 的必然结果）：
    // 第一飞给的是 X25519，第二飞必须换成被要求的那一个。
    assert_eq!(
        key_share_groups(second_flight),
        vec![v::CURVE_P384],
        "第二飞的 key_share 该只剩 P-384"
    );
    assert!(
        key_share_groups(&served[1].client_hellos[0]).contains(&v::X25519),
        "第一飞该给 X25519（否则这次 HRR 不是被 key_share 逼出来的）"
    );
    // 第二连接的第一飞**也**该带 PSK（uTLS/rustls 都是这样：先报 identity，
    // HRR 之后只是把 binder 重算一遍）——这条把「只有第二飞才发 PSK」这种
    // 想当然的实现挡掉。
    assert!(
        psk_body(&served[1].client_hellos[0]).is_some(),
        "第二连接的第一飞也该带 PSK identity"
    );
}

/// 只做 HRR、**不复用**时，第二飞里不该冒出 PSK 扩展（没有会话就没有 PSK）。
///
/// 这条挡的是「为了复用顺手把 PSK 也塞进所有第二飞」这类过度实现。
#[test]
fn a_hello_retry_request_without_a_session_carries_no_psk() {
    use rustls::NamedGroup;
    let (addr, server) = common::spawn_server(
        common::server_config(false, Some(vec![NamedGroup::secp384r1])),
        1,
    );
    let store = Arc::new(common::RecordingStore::new());
    let as_store: Arc<dyn ClientSessionStore> = store;
    let config = config_for(ClientHelloId::ChromePsk(100), as_store, common::shared_verifier());
    let _ = connect(addr, config);

    let served = server.join().expect("服务端线程");
    assert_eq!(
        served[0].client_hellos.len(),
        2,
        "该发了第二飞（HRR）"
    );
    for (k, hello) in served[0].client_hellos.iter().enumerate() {
        assert!(
            psk_body(hello).is_none(),
            "没有会话可复用时，第 {k} 条 hello 都不该带 PSK 扩展"
        );
    }
}
