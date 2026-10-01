//! fork 第八处能力（真 ECH 提议）的**可观测判据**。
//!
//! 判据的形状是**差分**：同一条 spec、同一个本地服务端，只有「有没有交出一份真的
//! `EchOffer`」这一个变量。于是：
//!
//! | 情形 | `ech_status()` |
//! |---|---|
//! | 只有 `0xfe0d` 扩展，没交 offer | `Grease` —— 「形状像 ECH，但它不是提议」 |
//! | 交了 offer | `Offered` → 服务端不确认时 `Rejected` |
//!
//! 这一格之差就是能力 (h) 的全部意义：`Grease` 不会被服务器「接受」，
//! 而 `Offered` 会走**接受/拒绝判定** —— 判定的实现是 rustls 的
//! （`EchState::confirm_acceptance`），它要的输入（内层转录、内层随机数）只有
//! 交出来的那份内层 hello 才有。
//!
//! # 这台本地服务端不是 ECH 服务器
//!
//! 它不认识 ECH，所以永远不确认 ⇒ 期望 `Rejected`，且握手按外层名字继续（RFC 9849
//! §6.1.6 的「服务端拒绝 ECH 时，客户端按 public_name 认证」）。这恰好是我们能在
//! 离线环境里验到的那一半，而**接受**那一半需要一台真的 ECH 服务器（见 STATE.md 的已知缺口：
//! rustls 没有服务端 ECH，公网 ECH 端点又要求真实 egress）。
//! 所以这条测试**不说**「ECH 全通了」，它说「提议被当成提议了，判定跑起来了」。

mod common;

use std::sync::Arc;

use rustls::ClientConnection;
use rustls::client::EchStatus;
use rustls::pki_types::ServerName;
use utls::hello::{ClientHelloId, ClientHelloSpec, Extension, HandshakeInputs};
use utls::values as v;
use utls_engine::FingerprintClient;

/// 外层 ECH 扩展体：**用引擎里那一处定义**（类型位 + 四个字段）。
fn outer_ech_body(config_id: u8, enc: &[u8], payload_len: usize) -> Vec<u8> {
    utls_engine::ech::outer_ech_extension_body(
        utls::hello::HpkeSymmetricCipherSuite {
            kdf_id: 0x0001,
            aead_id: 0x0001,
        },
        config_id,
        enc,
        &vec![0x5Au8; payload_len],
    )
}

/// 跑一条连接，返回连接。
fn connect(
    addr: std::net::SocketAddr,
    fingerprint: FingerprintClient,
    alpn: Vec<Vec<u8>>,
) -> ClientConnection {
    let config = Arc::new(common::client_config_with_verifier(
        fingerprint,
        alpn,
        common::shared_verifier(),
        None,
    ));
    let mut conn =
        ClientConnection::new(config, ServerName::try_from("localhost").unwrap()).expect("建连接");
    let mut sock = std::net::TcpStream::connect(addr).expect("连回环");
    common::drive_client(&mut conn, &mut sock).expect("握手该跑完");
    conn
}

#[test]
fn an_offer_is_treated_as_a_real_ech_offer_and_a_bare_extension_as_grease() {
    let suite = common::ech_hpke_suite();
    let (public_key, _private) = suite.generate_key_pair().expect("生成 ECH 密钥");
    let config_list = common::ech_config_list(&public_key.0, 0x11, &[]);

    // spec：Chrome-70 + 一条 `0xfe0d` 扩展（内容按外层格式拼，虽然这台服务器不会去解它）。
    let mut spec = ClientHelloSpec::from_preset(ClientHelloId::Chrome(70)).unwrap();
    let body = outer_ech_body(0x11, &[0u8; 32], 64);
    spec.extensions.push(Extension::Opaque {
        id: v::EXT_ENCRYPTED_CLIENT_HELLO,
        body,
    });

    // 内层 hello：指纹层按**真实** SNI 产出的那条（真实用法里它就是被封进 payload 的东西）。
    let mut inner_spec = ClientHelloSpec::from_preset(ClientHelloId::Chrome(70)).unwrap();
    inner_spec.session_id = utls::hello::SessionId::Empty; // 内层格式要求
    let mut inputs = HandshakeInputs::deterministic([7u8; 32]);
    inputs.sni = Some("localhost".into());
    inputs.key_exchange = vec![(v::X25519, vec![0x5Au8; 32])];
    // ⚠️ 交出去的是内层 hello 的**体**（无 4 字节握手头）—— 两个参照实现都这样编码
    //（uTLS `h = h[4:]`；rustls 的 `payload_encode` 也不写头），见 fork 里的说明。
    let inner = inner_spec
        .marshal(&inputs)
        .expect("内层 hello")
        .into_bytes()[4..]
        .to_vec();

    // ── 情形一：只带扩展，不交 offer ⇒ GREASE ──
    let (addr, server) = common::spawn_server(common::server_config(false, None), 1);
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let grease = connect(
        addr,
        FingerprintClient::new(spec.clone(), provider.clone()).with_sni("localhost"),
        Vec::new(),
    );
    let served = server.join().expect("服务端线程");
    assert_eq!(served.len(), 1);
    assert!(
        !served[0].client_hellos.is_empty(),
        "服务端该收到 ClientHello"
    );
    assert_eq!(
        grease.ech_status(),
        EchStatus::Grease,
        "只有扩展、没交 offer 时该是 GREASE —— 「形状像」不等于「在提议」"
    );

    // ── 情形二：同一份 spec + 交出 offer ⇒ 真提议 ──
    let (addr, server) = common::spawn_server(common::server_config(false, None), 1);
    let config = Arc::new(common::client_config_with_verifier(
        FingerprintClient::new(spec.clone(), provider)
            .with_sni("localhost")
            .with_ech_offer(config_list.clone(), inner.clone()),
        Vec::new(),
        common::shared_verifier(),
        None,
    ));
    let mut conn =
        ClientConnection::new(config, ServerName::try_from("localhost").unwrap()).expect("建连接");
    let mut sock = std::net::TcpStream::connect(addr).expect("连回环");
    let err = common::drive_client(&mut conn, &mut sock)
        .expect_err("这台服务器不接受 ECH，而 rustls 的 ECH 是「要求」语义：拒绝即终止");

    // 判据一：**状态**是「已提议 → 被拒绝」。`Grease` 或 `NotOffered` 都说明 offer 没被用上。
    assert_eq!(
        conn.ech_status(),
        EchStatus::Rejected,
        "该走完接受/拒绝判定并判为拒绝"
    );
    // 判据二：**错误正是 ECH 被拒**（RFC 9849 §6.1.6：拒绝且没给 retry configs ⇒ 中止）。
    // 这条比状态更硬：GREASE 扩展**永远**不会产生这个错误 —— 只有真提议才会。
    let text = err.to_string();
    assert!(
        text.contains("ServerRejectedEncryptedClientHello"),
        "错误该是「服务器拒绝了 ECH」，实际是：{text}"
    );

    // 服务端确实收到了那条 ClientHello（说明失败发生在**协商**这一步，不是发都没发出去）。
    let served = server.join().expect("服务端线程");
    assert_eq!(served.len(), 1);
    assert!(
        !served[0].client_hellos.is_empty(),
        "服务端该收到我们的外层 hello"
    );
}

/// **语义说明**：交出 offer 等于「要求 ECH」（rustls 的 `EchMode::Enable` 语义）——
/// 服务器拒绝就终止，不会静默退回普通握手。这与 GREASE 完全不同（后者永远不要求什么）。
/// 想让「拒绝时退回」，得给这道缝加一个容忍位；那是下一步，这里先把语义钉住。
#[test]
fn an_offer_means_ech_is_required_not_merely_suggested() {
    // 上面那条已经把「拒绝即终止」钉住了；这里只把两种情形的**差别**再写一遍，
    // 免得读代码的人以为交不交 offer 只是状态字段的差别。
    assert_ne!(EchStatus::Grease, EchStatus::Offered);
    assert_ne!(EchStatus::Offered, EchStatus::Rejected);
}

/// 交了 offer，但那条 hello 里**没有** `0xfe0d` 扩展 ⇒ 明确报错。
///
/// 静默地把 `Offered` 记上、却没有可接受的扩展，会让「服务器确认了 ECH」这种
/// 本该不可能的状态变得可能 —— 而那正是最危险的一类错（认证了错误的转录）。
#[test]
fn an_offer_without_the_extension_is_refused() {
    let suite = common::ech_hpke_suite();
    let (public_key, _private) = suite.generate_key_pair().expect("生成 ECH 密钥");
    let config_list = common::ech_config_list(&public_key.0, 0x22, &[]);
    let inner = {
        let mut inputs = HandshakeInputs::deterministic([9u8; 32]);
        inputs.sni = Some("localhost".into());
        inputs.key_exchange = vec![(v::X25519, vec![0x5Au8; 32])];
        // 同上：交**体**，不是整条消息。
        ClientHelloSpec::from_preset(ClientHelloId::Chrome(70))
            .unwrap()
            .marshal(&inputs)
            .unwrap()
            .into_bytes()[4..]
            .to_vec()
    };

    // 注意：这台服务端**不会**收到连接（错误在建连接时就出），所以**不能** `join()`
    // —— 它会一直等在 `accept()` 上，把整条测试挂住（踩过）。
    let (_, _server) = common::spawn_server(common::server_config(false, None), 1);
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let config = Arc::new(common::client_config_with_verifier(
        FingerprintClient::new(
            ClientHelloSpec::from_preset(ClientHelloId::Chrome(70)).unwrap(),
            provider,
        )
        .with_sni("localhost")
        .with_ech_offer(config_list, inner),
        Vec::new(),
        common::shared_verifier(),
        None,
    ));
    // 这条错误在**建连接**时就出（`plan()` 里就发现「说要提议、却连扩展都没写」），
    // 而不是等到握手 —— 早失败比晚失败好：那时还没有任何字节离开进程。
    let err = ClientConnection::new(config, ServerName::try_from("localhost").unwrap())
        .expect_err("该报错：交了 offer 却没有 ECH 扩展");
    let text = err.to_string();
    assert!(
        text.contains("EchOffer"),
        "报错该说清是「交了 EchOffer 却没有 0xfe0d 扩展」：{text}"
    );
}

/// 从内层明文（体）里取 `supported_versions` 的体（`u8 长度 + u16 版本*`）。
fn inner_rec_body(opened: &[u8]) -> Vec<u8> {
    let mut p = 2 + 32;
    p += 1 + opened[p] as usize;
    let cs = u16::from_be_bytes([opened[p], opened[p + 1]]) as usize;
    p += 2 + cs;
    p += 1 + opened[p] as usize;
    let n = u16::from_be_bytes([opened[p], opened[p + 1]]) as usize;
    p += 2;
    let region = &opened[p..p + n];
    let mut q = 0usize;
    while q + 4 <= region.len() {
        let ty = u16::from_be_bytes([region[q], region[q + 1]]);
        let bl = u16::from_be_bytes([region[q + 2], region[q + 3]]) as usize;
        if ty == 43 {
            return region[q + 4..q + 4 + bl].to_vec();
        }
        q += 4 + bl;
    }
    Vec::new()
}

/// 在一条记录的 ClientHello 里取 ECH 扩展的体。
fn ech_ext_body(record: &[u8]) -> Option<Vec<u8>> {
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
        if ty == v::EXT_ENCRYPTED_CLIENT_HELLO {
            return Some(region[q + 4..q + 4 + bl].to_vec());
        }
        q += 4 + bl;
    }
    None
}

/// 记录的 ClientHello 里，扩展类型序列（按线序）。
fn ext_types_of(record: &[u8]) -> Vec<u16> {
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
    let mut out = Vec::new();
    let mut q = 0usize;
    while q + 4 <= region.len() {
        out.push(u16::from_be_bytes([region[q], region[q + 1]]));
        let bl = u16::from_be_bytes([region[q + 2], region[q + 3]]) as usize;
        q += 4 + bl;
    }
    out
}

/// **引擎自己造的 offer**：把发出去的那条 hello 的载荷**解回来**，逐条验五条内层规则。
///
/// 判据不是「服务器接受了」（本机没有 ECH 服务器），而是「我们封进去的东西长什么样」——
/// 而那正好是五条规则的全部内容。解封用的是**我们自己的测试私钥**（扮演服务器），
/// 所以这条判据与「服务器会不会接受」无关，却能把每条规则钉死。
#[test]
fn the_engine_builds_the_inner_hello_by_the_five_rules() {
    use rustls::crypto::hpke::EncapsulatedSecret;

    let suite = common::ech_hpke_suite();
    let (public_key, private_key) = suite.generate_key_pair().expect("生成 ECH 密钥");
    let config_list = common::ech_config_list(&public_key.0, 0x33, &[]);

    let (addr, server) = common::spawn_server(common::server_config(false, None), 1);
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let config = Arc::new(common::client_config_with_verifier(
        FingerprintClient::new(
            ClientHelloSpec::from_preset(ClientHelloId::Chrome(70)).unwrap(),
            provider,
        )
        .with_sni("localhost")
        .with_ech(config_list.clone()),
        Vec::new(),
        common::shared_verifier(),
        None,
    ));
    // 注意：spec 里**没有**手写 `0xfe0d` —— 外层那条是 `with_ech` 写上去的。
    let mut conn =
        ClientConnection::new(config, ServerName::try_from("localhost").unwrap()).expect("建连接");
    let mut sock = std::net::TcpStream::connect(addr).expect("连回环");
    let _ = common::drive_client(&mut conn, &mut sock); // 本机服务端不接受 ECH ⇒ 必然报错
    let served = server.join().expect("服务端线程");
    let outer = &served[0].client_hellos[0];

    // 外层：有 `0xfe0d`，且类型序列与不带 ECH 时相同（只多那一条）。
    let outer_ext = ech_ext_body(outer).expect("外层该带 ECH 扩展");
    assert_eq!(outer_ext[0], 0, "外层扩展体的首字节该是 0（outer）");

    // 解回载荷。AAD = 外层编码且载荷段全零 ⇒ 把载荷段清零后再解。
    let body_len = outer_ext.len();
    assert!(
        body_len > 1 + 4 + 1 + 2 + 32 + 2,
        "外层扩展体太短：{body_len}"
    );
    let enc_len = u16::from_be_bytes([outer_ext[6], outer_ext[7]]) as usize;
    let payload_len_off = 1 + 4 + 1 + 2 + enc_len;
    let payload_len =
        u16::from_be_bytes([outer_ext[payload_len_off], outer_ext[payload_len_off + 1]]) as usize;
    assert_eq!(
        payload_len,
        outer_ext.len() - payload_len_off - 2,
        "载荷长度该自洽"
    );
    // 体布局：`type(1) || kdf(2) || aead(2) || config_id(1) || enc_len(2) || enc || payload_len(2) || payload`
    let enc = outer_ext[8..8 + enc_len].to_vec();

    // AAD 是**握手消息**（没有 5 字节记录头）且载荷段全零 —— 与引擎密封时用的是同一份。
    let message = &outer[5..];
    let payload_in_msg = message.len() - payload_len; // 载荷是这条扩展体的尾巴
    // AAD 是**体**（不含 4 字节握手头）—— 与引擎一致；弄错的话本测试会以「解不开」失败，
    // 而真服务器会以「回 retry configs」失败（两条判据在这一处是同一件事）。
    let mut aad = message[4..].to_vec();
    aad[payload_in_msg - 4..].fill(0);

    // `info` = `"tls ech\0" || <整条 ECHConfig 的原始字节>`。配置列表的布局是
    // `u16 list_len || (u16 version || u16 cfg_len || body)`，所以第一条配置从下标 2 开始、
    // 总长 `4 + cfg_len`（版本与长度字段自己也算在内）。
    let cfg_len = u16::from_be_bytes([config_list[4], config_list[5]]) as usize;
    let mut info = b"tls ech\0".to_vec();
    info.extend_from_slice(&config_list[2..2 + 4 + cfg_len]);

    // 载荷在**消息**里的偏移仍是 `payload_in_msg`（只有 AAD 换成了体的坐标系）。
    let ciphertext = &message[payload_in_msg..];
    let opened = suite
        .open(
            &EncapsulatedSecret(enc),
            &info,
            &aad,
            ciphertext,
            &private_key,
        )
        .expect("用私钥该能解开我们封的载荷");
    eprintln!("解出的内层明文 {} 字节", opened.len());

    // ── 五条规则 ──
    // 规则 4：没有 4 字节握手头（体直接以 legacy_version 开头）。
    assert_eq!(
        &opened[..2],
        &[0x03, 0x03],
        "内侧明文该以 legacy_version 开头（无握手头）"
    );
    // 规则 3：session id 为空。
    assert_eq!(opened[34], 0, "内层 hello 的 session id 该为空");
    // 规则 5：补零到 32 的倍数。
    assert_eq!(opened.len() % 32, 0, "内层明文该补零到 32 的倍数");
    // 规则 1 + 2：内层带 `[1]` 形态的 ECH 扩展，且不带那三条 TLS 1.2 扩展。
    // 把内层明文包成一条「记录」以便复用 `ech_ext_body`/`ext_types_of`（它俩吃记录）。
    // 明文是**体**（无握手头），补一个头 + 记录头即可。
    let as_record = |body: &[u8]| -> Vec<u8> {
        let mut msg = vec![1u8];
        let n = body.len();
        msg.extend_from_slice(&[(n >> 16) as u8, (n >> 8) as u8, n as u8]);
        msg.extend_from_slice(body);
        let mut rec = vec![0x16, 0x03, 0x03];
        rec.extend_from_slice(&(msg.len() as u16).to_be_bytes());
        rec.extend_from_slice(&msg);
        rec
    };
    let inner_rec = as_record(&opened);
    let types = ext_types_of(&inner_rec);
    assert!(
        types.contains(&v::EXT_ENCRYPTED_CLIENT_HELLO),
        "内层该带 ECH 扩展"
    );
    for skipped in [23u16, 35, 11] {
        assert!(
            !types.contains(&skipped),
            "内层不该带扩展 {skipped}（rustls/uTLS 都把它从内层里去掉）"
        );
    }
    let inner_ech = ech_ext_body(&inner_rec).expect("内层该有 ECH 扩展");
    assert_eq!(inner_ech, vec![1], "内层的 ECH 扩展体该只有类型位 1");

    // ── 规则 6/7（uTLS 的模型：内层是**诚实的 hello**，见 `ech::InnerHelloInputs`）──
    // 规则 6：内层的 `supported_versions` 只有 **TLS 1.3**（连 GREASE 都没有）——
    //   出处是 uTLS 的 `makeClientHello`：`supportedVersions = config.supportedVersions()`
    //   （ECH 强制 MinVersion ≥ TLS 1.3 ⇒ 只有 1.3 一项）。低于 1.3 的版本会让服务器
    //   `illegal_parameter`（`decodeInnerClientHello` 的版本校验）。
    let sv = inner_rec_body(&opened);
    assert_eq!(sv[0], 2, "内层的 supported_versions 该只有一项（2 字节）");
    let v0 = u16::from_be_bytes([sv[1], sv[2]]);
    assert_eq!(
        v0, 0x0304,
        "那一项该是 TLS 1.3 —— 低于它的版本会让服务器 illegal_parameter"
    );
    // 规则 7：可压缩扩展要收进 `0xfd00`，并且**内层没有 GREASE 扩展**。
    let marker = ech_ext_body(&inner_rec);
    let _ = marker;
    let has_fd00 = types.contains(&0xfd00);
    assert!(
        has_fd00,
        "内层该有 `0xfd00`（ECHOuterExtensions）标记：实测 rustls/uTLS 都这么做"
    );
    // GREASE 扩展类型的形态是 0x?A?A，内层里不该出现（uTLS 的内层由 Go 的 marshaller 产出，不含它）。
    assert!(
        !types
            .iter()
            .any(|t| *t & 0x0f0f == 0x0a0a && (*t >> 8) as u8 == *t as u8),
        "内层不该有 GREASE 扩展，实际类型序列 = {types:?}"
    );

    // 真实 SNI 在内层里（外层放的是公开名）。
    assert!(
        opened.windows(9).any(|w| w == b"localhost"),
        "内层该带真实 SNI（localhost）"
    );
    // 外层放的是公开名。
    assert!(
        outer
            .windows(b"public.example".len())
            .any(|w| w == b"public.example"),
        "外层该带公开名（public.example）"
    );
    assert!(
        !outer.windows(9).any(|w| w == b"localhost"),
        "外层不该出现真实名字"
    );
}
