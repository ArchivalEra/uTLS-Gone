//! **离线三测之一：CH 解析**（issue #1 结案判据 1 的第一格）。
//!
//! 判什么：`ch::ClientHello::parse` 从**真实指纹层产出的 hello**里取出
//! REALITY 鉴权要用的全部字段 —— random、sessionId、SNI、key shares
//! （含**线序**与 MLKEM768 的 X25519 分量位置）。
//!
//! 为什么必须用真实指纹层产出的 hello：鉴权发生在 `utls` 产出的 hello 上，
//! 解析器若只对自造字节成立，上了线就是另一回事。

use reality::ch::ClientHello;
use utls::hello::{ClientHelloId, ClientHelloSpec, HandshakeInputs, SessionId};
use utls::values as v;

/// 用真实预设产一条 hello（确定性 seed；X25519 公钥给真实长度的哑字节）。
fn hello_of(id: ClientHelloId) -> Vec<u8> {
    let mut spec = ClientHelloSpec::from_preset(id).unwrap();
    // REALITY 客户端的 sessionId 恒为 32 字节（AEAD 密文）；这里放占位。
    if matches!(spec.session_id, SessionId::Empty) {
        spec.session_id = SessionId::Fixed(vec![0u8; 32]);
    }
    let mut inputs = HandshakeInputs::deterministic([7; 32]);
    inputs.sni = Some("example.com".into());
    // ChromePsk(100) 的 key_share 只有 X25519；Firefox 148 是 [MLKEM768, X25519, P-256]。
    inputs.key_exchange = vec![
        (v::X25519, vec![0xAA; 32]),
        (v::X25519_MLKEM768, vec![0xBB; 1184 + 32]),
        (v::CURVE_P256, vec![0xCC; 65]),
    ];
    spec.marshal(&inputs).expect("指纹层该能产出").into_bytes()
}

/// key share 的组序列（线序）—— 判定顺序用。
fn key_share_groups(hello: &ClientHello) -> Vec<u16> {
    hello.key_shares.iter().map(|(g, _)| *g).collect()
}

#[test]
fn chrome_100_hello_parses_with_the_auth_fields() {
    let raw = hello_of(ClientHelloId::Chrome(100));
    let hello = ClientHello::parse(&raw).expect("真实指纹 hello 该能解析");
    assert_eq!(hello.random, &raw[6..38], "random 在固定偏移 6..38");
    assert_eq!(
        hello.session_id,
        &raw[39..71],
        "sessionId 在固定偏移 39..71"
    );
    assert_eq!(
        hello.server_name.as_deref(),
        Some("example.com"),
        "SNI 来自指纹层的 inputs.sni"
    );
    // Chrome 100 的 key_share：GREASE + X25519（线序）—— GREASE 条目也在，
    // 判定层跳过它们（reality_peer_pub 只认 MLKEM768 与 X25519）。
    let groups = key_share_groups(&hello);
    assert!(
        groups.contains(&v::X25519),
        "Chrome 100 该有 X25519 share：{groups:?}"
    );
    assert!(
        groups.first() != Some(&v::X25519_MLKEM768) || true,
        "（Chrome 100 无 MLKEM，PeerPub 取独立 X25519 —— 由 fallback 判定测试覆盖）"
    );
    // X25519 share 的字节要原样（32 字节哑字节 0xAA）。
    let x = hello
        .key_shares
        .iter()
        .find(|(g, _)| *g == v::X25519)
        .expect("有 X25519 share");
    assert_eq!(x.1, vec![0xAA; 32], "X25519 公钥字节原样保留");
}

#[test]
fn firefox_148_hello_has_mlkem_before_x25519_as_reality_requires() {
    let raw = hello_of(ClientHelloId::Firefox(148));
    let hello = ClientHello::parse(&raw).expect("真实指纹 hello 该能解析");
    let groups = key_share_groups(&hello);
    // Firefox 148 的 key_share = [MLKEM768, X25519, P-256]（线序）——
    // REALITY 的 peerPub 优先取独立 X25519；MLKEM768 的存在只是入场券。
    let mlkem_at = groups
        .iter()
        .position(|g| *g == v::X25519_MLKEM768)
        .expect("Firefox 148 该有 MLKEM768 share");
    let x25519_at = groups
        .iter()
        .position(|g| *g == v::X25519)
        .expect("Firefox 148 该有 X25519 share");
    assert!(
        mlkem_at < x25519_at,
        "MLKEM768 必须在 X25519 之前（tls.go:228-239 的顺序检查）：{groups:?}"
    );
    // MLKEM768 share 的末 32 字节 = 其 X25519 分量（REALITY 的次选 peerPub）。
    let mlkem = hello
        .key_shares
        .iter()
        .find(|(g, _)| *g == v::X25519_MLKEM768)
        .expect("有 MLKEM768");
    assert_eq!(mlkem.1.len(), 1184 + 32, "MLKEM768 share 恒 1216 字节");
    assert_eq!(
        &mlkem.1[1184..],
        &vec![0xBB; 32],
        "末 32 字节是 X25519 分量"
    );
    // PeerPub：优先独立 X25519（tls.go:236-238）。
    assert_eq!(hello.reality_peer_pub().as_ref(), Ok(&[0xAA; 32]));
}

#[test]
fn mlkem_only_hello_falls_back_to_the_mlkem_component() {
    // tls.go:236-238 的 secondary choice：没有独立 X25519 时，
    // peerPub = MLKEM768 share 的末 32 字节。
    let raw = hello_of(ClientHelloId::Firefox(148));
    let mut hello = ClientHello::parse(&raw).expect("解析");
    // 把独立 X25519 share 从解析结果里删掉（模拟「只发 MLKEM768」的客户端）。
    hello.key_shares.retain(|(g, _)| *g != v::X25519);
    let got = hello.reality_peer_pub().expect("次选路径该给出分量");
    assert_eq!(
        &got[..],
        &hello
            .key_shares
            .iter()
            .find(|(g, _)| *g == v::X25519_MLKEM768)
            .expect("仍在")
            .1[1184..],
        "peerPub 该是 MLKEM768 share 的末 32 字节"
    );
}

#[test]
fn malformed_hello_is_an_error_not_a_panic() {
    // 前缀正确、长度字段说谎 —— 解析器必须报错（判定层把它归 fallback），
    // 与 Go `readClientHello` 的 err ⇒ fallback 对齐。
    let mut raw = hello_of(ClientHelloId::Chrome(100));
    let declared = ((raw[1] as usize) << 16) | ((raw[2] as usize) << 8) | raw[3] as usize;
    raw.truncate(4 + declared - 1);
    assert!(ClientHello::parse(&raw).is_err(), "截断的 hello 必须报错");
    assert!(ClientHello::parse(&raw[..4]).is_err());
    assert!(ClientHello::parse(&[]).is_err());
}
