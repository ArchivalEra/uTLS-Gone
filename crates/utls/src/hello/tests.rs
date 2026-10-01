//! `hello` 模块的接口级测试。
//!
//! 全部测试只走公开接口（`from_preset` / `from_bytes` / `marshal` / `ja3`），
//! 不碰任何私有项 —— 因为**接口就是测试面**（`codebase-design` 的纪律）。
//! 模块是纯计算（依赖分类 1：in-process），所以这些测试不需要任何替身、
//! 不需要 mock、也不需要网络：需要确定性的地方，确定性是接口里的一个**值**
//! （`HandshakeInputs::deterministic`），不是一个 seam。

use super::*;
use crate::values as v;

/// Chrome 133 需要两个密钥交换公钥：X25519MLKEM768 与 X25519。
///
/// 长度是**真实的**（X25519 32 字节；ML-KEM-768 封装密钥 1184 字节 ⇒ 混合组 1216），
/// 内容是哑的 —— 这里是序列化测试，不是密码学测试。长度必须真实，
/// 因为长度进指纹（它决定 ClientHello 的总长）。
const X25519_PUB_LEN: usize = 32;
const X25519_MLKEM768_PUB_LEN: usize = 32 + 1184;

fn inputs_with_keys(seed: u8) -> HandshakeInputs {
    let mut i = HandshakeInputs::deterministic([seed; 32]);
    i.sni = Some("example.com".into());
    i.key_exchange = vec![
        (v::X25519, vec![0xAA; X25519_PUB_LEN]),
        (v::X25519_MLKEM768, vec![0xBB; X25519_MLKEM768_PUB_LEN]),
    ];
    i
}

fn chrome() -> ClientHelloSpec {
    ClientHelloSpec::from_preset(ClientHelloId::Chrome(133)).unwrap()
}

fn firefox() -> ClientHelloSpec {
    ClientHelloSpec::from_preset(ClientHelloId::Firefox(148)).unwrap()
}

/// Firefox 148 的 key_share 需要这三个组。P-256 也真的带一个密钥共享
/// （Chrome 只报 P-256 但不给它发共享）—— 这是两个预设的又一个结构差别。
fn inputs_for_firefox(seed: u8) -> HandshakeInputs {
    let mut i = HandshakeInputs::deterministic([seed; 32]);
    i.sni = Some("example.com".into());
    i.key_exchange = vec![
        (v::X25519, vec![0xAA; X25519_PUB_LEN]),
        (v::X25519_MLKEM768, vec![0xBB; X25519_MLKEM768_PUB_LEN]),
        (v::CURVE_P256, vec![0xCC; 65]),
    ];
    i
}

/// 第一处不同的偏移。比 `assert_eq!(a, b)` 有用得多 —— 后者会打出两千个数字。
fn first_diff(a: &[u8], b: &[u8]) -> Option<usize> {
    a.iter().zip(b).position(|(x, y)| x != y).or({
        if a.len() == b.len() {
            None
        } else {
            Some(a.len().min(b.len()))
        }
    })
}

/// 从线字节里读出 GREASE-ECH 扩展的**体长**（0xfe0d）。
///
/// 单列这个辅助是因为它是「长度为什么会变」的唯一来源：其他部分的长度都是固定的
/// （session id 32、公钥长度固定），只有 GREASE-ECH 的载荷从候选表里取。
fn grease_ech_body_len(bytes: &[u8]) -> Option<usize> {
    let len = ((bytes[1] as usize) << 16) | ((bytes[2] as usize) << 8) | bytes[3] as usize;
    let body = &bytes[4..4 + len];
    let mut p = 2 + 32;
    p += 1 + body[p] as usize;
    let cs = u16::from_be_bytes([body[p], body[p + 1]]) as usize;
    p += 2 + cs;
    p += 1 + body[p] as usize;
    let exts = u16::from_be_bytes([body[p], body[p + 1]]) as usize;
    p += 2;
    let ext_bytes = &body[p..p + exts];
    let mut q = 0usize;
    while q < ext_bytes.len() {
        let id = u16::from_be_bytes([ext_bytes[q], ext_bytes[q + 1]]);
        let bl = u16::from_be_bytes([ext_bytes[q + 2], ext_bytes[q + 3]]) as usize;
        if id == v::EXT_ENCRYPTED_CLIENT_HELLO {
            return Some(bl);
        }
        q += 4 + bl;
    }
    None
}

/// 从线字节里取出 GREASE-ECH 扩展（0xfe0d）的**体**。
///
/// 与 `grease_ech_body_len` 同一套定位逻辑，只是把体本身也交出来 ——
/// 判「与上游那条向量逐字段相同」需要体，而判「长度分布」只需要长度。
fn grease_ech_body_bytes(bytes: &[u8]) -> Option<&[u8]> {
    let len = ((bytes[1] as usize) << 16) | ((bytes[2] as usize) << 8) | bytes[3] as usize;
    let body = &bytes[4..4 + len];
    let mut p = 2 + 32;
    p += 1 + body[p] as usize;
    let cs = u16::from_be_bytes([body[p], body[p + 1]]) as usize;
    p += 2 + cs;
    p += 1 + body[p] as usize;
    let exts = u16::from_be_bytes([body[p], body[p + 1]]) as usize;
    p += 2;
    let ext_bytes = &body[p..p + exts];
    let mut q = 0usize;
    while q < ext_bytes.len() {
        let id = u16::from_be_bytes([ext_bytes[q], ext_bytes[q + 1]]);
        let bl = u16::from_be_bytes([ext_bytes[q + 2], ext_bytes[q + 3]]) as usize;
        if id == v::EXT_ENCRYPTED_CLIENT_HELLO {
            return Some(&ext_bytes[q + 4..q + 4 + bl]);
        }
        q += 4 + bl;
    }
    None
}

// ── 往返：接口最强的单条断言 ────────────────────────────────────────────────

#[test]
fn round_trip_is_byte_exact() {
    // 「反解出的 spec + 捕获里的随机数 重新编码 == 原字节」。它同时压住了解析器、模型、
    // 编码器、GREASE-as-Fixed、顺序保持与填充重建 —— 一条断言覆盖五个部件。
    let hello = chrome().marshal(&inputs_with_keys(1)).unwrap();
    let spec = ClientHelloSpec::from_bytes(hello.as_bytes()).expect("反解失败");
    let replay = HandshakeInputs::for_replay(hello.as_bytes()).expect("回放输入构造失败");
    let again = spec.marshal(&replay).unwrap();
    assert_eq!(
        first_diff(again.as_bytes(), hello.as_bytes()),
        None,
        "往返不是逐字节相同（原长 {}，重编码长 {}）",
        hello.len(),
        again.len()
    );
}

#[test]
fn replay_needs_nothing_but_the_random() {
    // 契约的另一半：反解出的 spec **自带** SNI / ALPN / key_share / GREASE-ECH 的字节，
    // 所以回放不需要任何外部输入 —— 只有那 32 字节随机数必须从捕获里带回来。
    // 这条断言就是「SNI/ALPN/公钥 都落成了 Opaque」的可执行形式。
    let hello = chrome().marshal(&inputs_with_keys(2)).unwrap();
    let spec = ClientHelloSpec::from_bytes(hello.as_bytes()).unwrap();
    let replay = HandshakeInputs::for_replay(hello.as_bytes()).unwrap();
    assert!(replay.sni.is_none(), "回放输入不该带 SNI");
    assert!(replay.alpn.is_empty(), "回放输入不该带 ALPN");
    assert!(replay.key_exchange.is_empty(), "回放输入不该带公钥");
    let out = spec.marshal(&replay).unwrap();
    assert_eq!(first_diff(out.as_bytes(), hello.as_bytes()), None);
}

#[test]
fn for_replay_rejects_malformed_input() {
    assert!(HandshakeInputs::for_replay(&[]).is_none());
    assert!(
        HandshakeInputs::for_replay(&[2, 0, 0, 34]).is_none(),
        "不是 ClientHello"
    );
    // 声明长度与实长不符 ⇒ 不猜。
    let good = chrome().marshal(&inputs_with_keys(0)).unwrap();
    let mut bad = good.as_bytes().to_vec();
    bad[1] = bad[1].wrapping_add(1);
    assert!(HandshakeInputs::for_replay(&bad).is_none());
}

// ── 确定性 ─────────────────────────────────────────────────────────────────

#[test]
fn same_inputs_give_identical_bytes() {
    let a = chrome().marshal(&inputs_with_keys(9)).unwrap();
    let b = chrome().marshal(&inputs_with_keys(9)).unwrap();
    assert_eq!(a.as_bytes(), b.as_bytes());
}

#[test]
fn different_seeds_differ_only_through_grease_ech_payload() {
    // 乱序 + GREASE 让字节每连接不同。**但长度变化的来源只有一个**：GREASE-ECH 的载荷
    // 从候选表 {128,160,192,224}(+16) 里取（uTLS `u_ech.go` 的 `CandidatePayloadLens`）。
    // 把「长度减去 GREASE-ECH 体长」钉成常量，就证明了**没有任何别的部分随 seed 变化** ——
    // 这比「长度相等」强：后者会掩盖「A 变长 32、B 变短 32」这种抵消。
    let mut baseline: Option<usize> = None;
    let mut payload_lens = std::collections::BTreeSet::new();
    let mut seen_bytes = std::collections::HashSet::new();
    for seed in 0u8..64 {
        let hello = chrome().marshal(&inputs_with_keys(seed)).unwrap();
        let ech = grease_ech_body_len(hello.as_bytes()).expect("没有 GREASE-ECH 扩展");
        payload_lens.insert(ech);
        let fixed_part = hello.len() - ech;
        match baseline {
            None => baseline = Some(fixed_part),
            Some(b) => assert_eq!(
                fixed_part, b,
                "seed={seed}：除 GREASE-ECH 载荷之外还有别的东西随 seed 变了"
            ),
        }
        seen_bytes.insert(hello.as_bytes().to_vec());
    }
    assert_eq!(seen_bytes.len(), 64, "64 个 seed 竟然没有 64 串不同字节");
    assert_eq!(
        payload_lens.len(),
        4,
        "GREASE-ECH 载荷没有覆盖全部 4 个候选长度：{payload_lens:?}"
    );
}

#[test]
fn shuffle_preserves_the_extension_multiset_and_pinned_positions() {
    // 「乱序只改顺序」的可执行形式：**非 GREASE** 类型多重集不变。
    // （GREASE 扩展的类型本身每连接就变，所以必须滤掉 —— 这正是不滤会误判的地方。）
    let reference = chrome().marshal(&inputs_with_keys(0)).unwrap();
    let non_grease_types = |b: &[u8]| {
        let mut t: Vec<u16> = extension_types_in_wire_order(b)
            .into_iter()
            .filter(|id| !v::is_grease(*id))
            .collect();
        t.sort_unstable();
        t
    };
    let want = non_grease_types(reference.as_bytes());
    assert!(!want.is_empty());
    for seed in 0u8..64 {
        let got = chrome().marshal(&inputs_with_keys(seed)).unwrap();
        assert_eq!(
            non_grease_types(got.as_bytes()),
            want,
            "seed={seed} 的类型多重集变了"
        );
    }
}

#[test]
fn shuffle_keeps_grease_extensions_at_both_ends() {
    // uTLS 的 ShuffleChromeTLSExtensions 让 GREASE / 填充 / PSK **位置不动**。
    // Chrome 133 的规范顺序是「GREASE 打头、GREASE 收尾」，乱序之后必须仍然如此。
    for seed in 0u8..128 {
        let hello = chrome().marshal(&inputs_with_keys(seed)).unwrap();
        let types = extension_types_in_wire_order(hello.as_bytes());
        let first = types[0];
        let last = *types.last().unwrap();
        assert!(
            v::is_grease(first),
            "seed={seed}：首部不是 GREASE（是 {first}）"
        );
        assert!(
            v::is_grease(last),
            "seed={seed}：尾部不是 GREASE（是 {last}）"
        );
    }
}

// ── JA3 ────────────────────────────────────────────────────────────────────

#[test]
fn ja3_does_not_depend_on_grease_or_order() {
    // JA3 忽略 GREASE。对 Chrome 133（乱序）它会随顺序变化 —— 这正是要钉住的事实：
    // **乱序预设的 JA3 不稳定是设计，不是缺陷**（真实 Chrome 与 rustls 0.23 都这样）。
    let seen: std::collections::HashSet<String> = (0u8..48)
        .map(|s| {
            chrome()
                .marshal(&inputs_with_keys(s))
                .unwrap()
                .ja3()
                .hash_hex()
        })
        .collect();
    assert!(
        seen.len() > 1,
        "乱序预设的 JA3 竟然只有一个取值 —— 乱序没生效？"
    );

    // 但每个取值都必须落在同一个「形状」上：GREASE 一律不出现在任何字段里。
    for seed in 0u8..48 {
        let text = chrome()
            .marshal(&inputs_with_keys(seed))
            .unwrap()
            .ja3()
            .text();
        for field in text.split(',') {
            for item in field.split('-') {
                if let Ok(n) = item.parse::<u16>() {
                    assert!(
                        !v::is_grease(n),
                        "seed={seed}：JA3 里出现了 GREASE 值 {n:#06x}"
                    );
                }
            }
        }
    }
}

#[test]
fn ja3_of_stable_spec_is_stable() {
    // 把 Chrome 133 反解成 Stable 的 spec 之后，JA3 必须完全稳定 ——
    // 这是「反解 = 固定顺序」这一契约的可见后果。
    let hello = chrome().marshal(&inputs_with_keys(5)).unwrap();
    let spec = ClientHelloSpec::from_bytes(hello.as_bytes()).unwrap();
    let hashes: std::collections::HashSet<String> = (0u8..32)
        .map(|s| {
            spec.marshal(&HandshakeInputs::deterministic([s; 32]))
                .unwrap()
                .ja3()
                .hash_hex()
        })
        .collect();
    assert_eq!(hashes.len(), 1, "Stable 的 spec 的 JA3 不稳定：{hashes:?}");
}

#[test]
fn chrome_133_ja3_carries_the_expected_pieces() {
    let hello = chrome().marshal(&inputs_with_keys(0)).unwrap();
    let j = hello.ja3();
    assert_eq!(j.ssl_version, v::LEGACY_VERSION);
    // 密码套件：GREASE 被滤掉，TLS 1.3 三件套在最前。
    assert_eq!(
        &j.cipher_suites[..3],
        &[
            v::TLS_AES_128_GCM_SHA256,
            v::TLS_AES_256_GCM_SHA384,
            v::TLS_CHACHA20_POLY1305_SHA256
        ]
    );
    assert_eq!(j.cipher_suites.len(), 15, "16 个里滤掉 1 个 GREASE");
    // 支持组：GREASE 滤掉，剩 ML-KEM 混合组 + X25519 + P256 + P384。
    assert_eq!(
        j.elliptic_curves,
        vec![v::X25519_MLKEM768, v::X25519, v::CURVE_P256, v::CURVE_P384]
    );
    assert_eq!(j.ec_point_formats, vec![v::POINT_FORMAT_UNCOMPRESSED]);
    // 扩展：GREASE 与 GREASE-ECH 之外的 16 个类型都在（顺序另测）。
    let mut exts = j.extensions.clone();
    exts.sort_unstable();
    assert!(exts.contains(&v::EXT_SERVER_NAME));
    assert!(exts.contains(&v::EXT_ALPN));
    assert!(exts.contains(&v::EXT_ENCRYPTED_CLIENT_HELLO));
}

// ── Firefox 148：与 Chrome 133 恰好互补的那条路径 ─────────────────────────

#[test]
fn firefox_is_stable_no_grease_and_fixed_length() {
    // Firefox 148 是「Stable + 完全不用 GREASE + GREASE-ECH 只有单一载荷长度」的样板。
    // 三条后果一起验：
    //   · JA3 跨 64 个 seed **完全相同**（无 GREASE、顺序固定）；
    //   · 总长**完全相同**（唯一会变长的 GREASE-ECH 被钉成单一候选）；
    //   · 字节仍然各不相同（GREASE-ECH 的 config_id / 封装密钥 / 载荷是随机的）——
    //     这一条很重要：如果字节也不变，那说明「每连接变化」整条路径都死了。
    let mut ja3s = std::collections::BTreeSet::new();
    let mut lens = std::collections::BTreeSet::new();
    let mut bodies = std::collections::HashSet::new();
    for seed in 0u8..64 {
        let hello = firefox().marshal(&inputs_for_firefox(seed)).unwrap();
        ja3s.insert(hello.ja3().hash_hex());
        lens.insert(hello.len());
        bodies.insert(hello.as_bytes().to_vec());
    }
    assert_eq!(
        ja3s.len(),
        1,
        "Firefox 的 JA3 竟然不稳定（它没有 GREASE、也不乱序）：{ja3s:?}"
    );
    assert_eq!(
        lens.len(),
        1,
        "Firefox 的总长竟然会变（它的 GREASE-ECH 只有单一载荷长度）"
    );
    assert_eq!(
        bodies.len(),
        64,
        "Firefox 的字节竟然完全相同 —— 每连接变化没生效"
    );
}

#[test]
fn firefox_ja3_has_no_grease_at_all() {
    let j = firefox().marshal(&inputs_for_firefox(0)).unwrap().ja3();
    // Firefox 的密码套件里一个 GREASE 都没有 ⇒ 17 个全部计入。
    assert_eq!(j.cipher_suites.len(), 17);
    for x in &j.cipher_suites {
        assert!(
            !v::is_grease(*x),
            "Firefox 的密码套件里出现了 GREASE {x:#06x}"
        );
    }
    // 支持组：7 个，含两个 FFDHE 群 —— Chrome 不报它们。
    assert_eq!(j.elliptic_curves.len(), 7);
    assert!(j.elliptic_curves.contains(&v::FFDHE2048));
    assert!(j.elliptic_curves.contains(&v::FFDHE3072));
    assert!(
        j.elliptic_curves.contains(&v::CURVE_P521),
        "Firefox 报 P-521"
    );
    // 扩展里也没有 GREASE 类型的占位扩展（Chrome 有 2 个）。
    for x in &j.extensions {
        assert!(
            !v::is_grease(*x),
            "Firefox 的扩展里出现了 GREASE 类型 {x:#06x}"
        );
    }
}

#[test]
fn firefox_round_trips_byte_exact_too() {
    // 往返契约不是 Chrome 专属的：任何预设都必须满足它。
    let hello = firefox().marshal(&inputs_for_firefox(3)).unwrap();
    let spec = ClientHelloSpec::from_bytes(hello.as_bytes()).expect("反解失败");
    let out = spec
        .marshal(&HandshakeInputs::for_replay(hello.as_bytes()).unwrap())
        .unwrap();
    assert_eq!(first_diff(out.as_bytes(), hello.as_bytes()), None);
}

#[test]
fn empty_psk_marker_is_positional_only() {
    // 本层对「没有会话的 PSK 扩展」取的是 uTLS 自己给出的替代形态：**不发空 PSK**
    // （等价于 `OmitEmptyPsk = true`；uTLS 的默认行为是**报错**，见
    // `Extension::PreSharedKey(super::spec::PreSharedKey::empty())` 的说明）。
    //
    // 所以：**声明里有它（位置约束），字节里没有它**。这两件事必须同时成立 ——
    // 它在列表里参与乱序抽取，但一个字节都不写。
    let spec = ClientHelloSpec::from_preset(ClientHelloId::ChromePsk(100)).unwrap();
    assert!(
        spec.extensions
            .iter()
            .any(|e| matches!(e, Extension::PreSharedKey(_))),
        "声明里该有 PSK 标记"
    );
    let hello = spec.marshal(&inputs_with_keys(0)).unwrap();
    let types = extension_types_in_wire_order(hello.as_bytes());
    assert!(
        !types.contains(&v::EXT_PRE_SHARED_KEY),
        "空 PSK 不该写出任何字节，而字节里出现了 41：{types:?}"
    );
    assert!(types.contains(&v::EXT_SERVER_NAME));
    assert!(types.contains(&v::EXT_SUPPORTED_VERSIONS));

    // 反解出来的 spec 里也不该有它（字节里没有，反解自然没有）—— 所以往返仍然逐字节成立。
    let parsed = ClientHelloSpec::from_bytes(hello.as_bytes()).unwrap();
    assert!(
        !parsed
            .extensions
            .iter()
            .any(|e| matches!(e, Extension::PreSharedKey(_)))
    );
    let again = parsed
        .marshal(&HandshakeInputs::for_replay(hello.as_bytes()).unwrap())
        .unwrap();
    assert_eq!(again.as_bytes(), hello.as_bytes());
}

#[test]
fn always_add_padding_inserts_before_the_psk() {
    // uTLS 的 `AlwaysAddPadding`（`u_common.go:274-287`）专门为这条写了分支：
    // 有 PSK 时填充要插在它**前面**，否则 PSK 就不是最后一条了。
    let mut s = ClientHelloSpec::from_preset(ClientHelloId::ChromePsk(100)).unwrap();
    assert!(s.psk_position().is_some());
    assert!(
        !s.extensions
            .iter()
            .any(|e| matches!(e, Extension::Padding(_)))
    );
    s.always_add_padding();
    let pad = s
        .extensions
        .iter()
        .position(|e| matches!(e, Extension::Padding(_)))
        .unwrap();
    let psk = s.psk_position().unwrap();
    assert_eq!(pad + 1, psk, "填充该紧贴在 PSK 之前");
    assert_eq!(psk, s.extensions.len() - 1, "PSK 仍须在最后");

    // 幂等：再调一次不该变成两条。
    s.always_add_padding();
    assert_eq!(
        s.extensions
            .iter()
            .filter(|e| matches!(e, Extension::Padding(_)))
            .count(),
        1
    );

    // 没有 PSK 的 spec：追加到末尾。
    let mut s2 = ClientHelloSpec::from_preset(ClientHelloId::Chrome(133)).unwrap();
    s2.extensions
        .retain(|e| !matches!(e, Extension::Padding(_)));
    assert!(s2.psk_position().is_none());
    s2.always_add_padding();
    assert!(matches!(s2.extensions.last(), Some(Extension::Padding(_))));
}

#[test]
fn always_add_psk_is_idempotent_and_goes_last() {
    // uTLS 的 `Config.AlwaysIncludePSK` 在 `ApplyPreset` 里做的事：没有 PSK 就补一条。
    let mut s = ClientHelloSpec::from_preset(ClientHelloId::Chrome(133)).unwrap();
    assert!(s.psk_position().is_none());
    assert!(s.always_add_psk(), "没有 PSK 时该补上");
    assert_eq!(
        s.psk_position().unwrap(),
        s.extensions.len() - 1,
        "补在末尾"
    );
    assert!(!s.always_add_psk(), "已经有了就不该再补");
    assert_eq!(
        s.extensions
            .iter()
            .filter(|e| matches!(e, Extension::PreSharedKey(_)))
            .count(),
        1
    );
}

// ── 结构化扩展集：`classify` 必须是 `body()` 的逆 ──────────────────────────

/// 一个「只有这一条扩展」的 spec，用来单独观测某个变体的编码。
fn one_ext(e: Extension) -> ClientHelloSpec {
    let mut s = ClientHelloSpec::empty();
    s.cipher_suites = vec![CodePoint::Fixed(v::TLS_AES_128_GCM_SHA256)];
    s.extensions = vec![Extension::ServerName, e];
    s
}

fn marshal_one(e: Extension) -> Vec<u8> {
    let spec = one_ext(e);
    let mut i = HandshakeInputs::deterministic([0; 32]);
    i.sni = Some("e.com".into());
    spec.marshal(&i).unwrap().into_bytes()
}

/// 取出这条 hello 里唯一的那个扩展（跳过 SNI）的 `(类型, 体)`。
fn second_ext(hello: &[u8]) -> (u16, Vec<u8>) {
    let all = wire_ext_bodies(hello);
    all[1].clone()
}

#[test]
fn every_typed_extension_is_the_inverse_of_its_body_writer() {
    // 这是结构化扩展集的**核心契约**：反解产出的变体，重新编码必须逐字节相同。
    // 每条都从「声明 → 字节 → 反解 → 字节」走一圈，并顺带断言类型对得上。
    use crate::hello::{
        ApplicationSettingsAlps, CompressCertificate, DelegatedCredentials, EcPointFormats,
        RenegotiationInfo, SessionTicket, SignatureAlgorithmsCert,
    };
    let cases: Vec<(Extension, u16, &[u8])> = vec![
        (
            Extension::StatusRequest,
            v::EXT_STATUS_REQUEST,
            &[1, 0, 0, 0, 0],
        ),
        (
            Extension::ExtendedMasterSecret,
            v::EXT_EXTENDED_MASTER_SECRET,
            &[],
        ),
        (
            Extension::RenegotiationInfo(RenegotiationInfo {
                renegotiated_connection: vec![],
            }),
            v::EXT_RENEGOTIATION_INFO,
            &[0],
        ),
        (
            Extension::RenegotiationInfo(RenegotiationInfo {
                renegotiated_connection: vec![0xAA, 0xBB],
            }),
            v::EXT_RENEGOTIATION_INFO,
            &[2, 0xAA, 0xBB],
        ),
        (
            Extension::SessionTicket(SessionTicket { ticket: vec![] }),
            v::EXT_SESSION_TICKET,
            &[],
        ),
        (
            Extension::SessionTicket(SessionTicket {
                ticket: vec![1, 2, 3],
            }),
            v::EXT_SESSION_TICKET,
            &[1, 2, 3],
        ),
        (
            Extension::EcPointFormats(EcPointFormats {
                formats: vec![v::POINT_FORMAT_UNCOMPRESSED],
            }),
            v::EXT_EC_POINT_FORMATS,
            &[1, 0],
        ),
        (
            Extension::CompressCertificate(CompressCertificate {
                algorithms: vec![v::CERT_COMPRESSION_BROTLI],
            }),
            v::EXT_COMPRESS_CERTIFICATE,
            &[2, 0x00, 0x02],
        ),
        (
            Extension::ApplicationSettings(ApplicationSettingsAlps {
                protocols: vec![b"h2".to_vec()],
            }),
            v::EXT_APPLICATION_SETTINGS,
            &[0x00, 0x03, 0x02, b'h', b'2'],
        ),
        (
            Extension::ApplicationSettingsNew(ApplicationSettingsAlps {
                protocols: vec![b"h2".to_vec()],
            }),
            v::EXT_APPLICATION_SETTINGS_NEW,
            &[0x00, 0x03, 0x02, b'h', b'2'],
        ),
        (Extension::SignedCertificateTimestamp, v::EXT_SCT, &[]),
        (
            Extension::PskKeyExchangeModes {
                modes: vec![v::PSK_MODE_DHE],
            },
            v::EXT_PSK_KEY_EXCHANGE_MODES,
            &[1, 1],
        ),
        (
            Extension::RecordSizeLimit { limit: 0x4001 },
            v::EXT_RECORD_SIZE_LIMIT,
            &[0x40, 0x01],
        ),
        (
            Extension::SignatureAlgorithmsCert(SignatureAlgorithmsCert {
                schemes: vec![v::ECDSA_WITH_P256_AND_SHA256],
            }),
            v::EXT_SIGNATURE_ALGORITHMS_CERT,
            &[0x00, 0x02, 0x04, 0x03],
        ),
        (
            Extension::DelegatedCredentials(DelegatedCredentials {
                schemes: vec![v::ECDSA_WITH_P256_AND_SHA256, v::ECDSA_WITH_SHA1],
            }),
            v::EXT_DELEGATED_CREDENTIALS,
            &[0x00, 0x04, 0x04, 0x03, 0x02, 0x03],
        ),
        (Extension::Npn, v::EXT_NPN, &[]),
        (
            Extension::ChannelId {
                old_codepoint: false,
            },
            v::EXT_CHANNEL_ID,
            &[],
        ),
        (
            Extension::ChannelId {
                old_codepoint: true,
            },
            v::EXT_CHANNEL_ID_OLD,
            &[],
        ),
    ];

    for (ext, want_ty, want_body) in cases {
        let hello = marshal_one(ext.clone());
        let (ty, body) = second_ext(&hello);
        assert_eq!(ty, want_ty, "类型不符（{ext:?}）");
        assert_eq!(body, want_body, "体不符（{ext:?}）");

        // 反解：应当拿回**同一个变体**，并且重新编码逐字节相同。
        let parsed = ClientHelloSpec::from_bytes(&hello).unwrap();
        assert_eq!(parsed.extensions[1], ext, "反解没拿回同一个变体（{ext:?}）");
        let again = parsed
            .marshal(&HandshakeInputs::for_replay(&hello).unwrap())
            .unwrap();
        assert_eq!(
            again.as_bytes(),
            &hello[..],
            "往返不是逐字节相同（{ext:?}）"
        );
    }
}

#[test]
fn non_canonical_bodies_fall_back_to_opaque() {
    // 「宁可不可编辑，也不能不可靠」：本模型表达不了的形状必须回落到 `Opaque`，
    // 而不是被硬塞进一个有类型的变体里（那会破坏逐字节往返）。
    use crate::hello::Extension as E;
    let cases: Vec<(&str, u16, Vec<u8>)> = vec![
        // status_request 带上了 responder id —— uTLS 的 `StatusRequestExtension` 表达不了。
        (
            "status_request 带 responder",
            v::EXT_STATUS_REQUEST,
            vec![1, 0, 2, 0xAA, 0xBB, 0, 0],
        ),
        // renegotiation_info 的长度前缀与实长不符。
        (
            "reneg 长度前缀不符",
            v::EXT_RENEGOTIATION_INFO,
            vec![5, 0xAA],
        ),
        // extended_master_secret 本该是空体。
        ("ems 非空体", v::EXT_EXTENDED_MASTER_SECRET, vec![0]),
        // ec_point_formats 的长度前缀不符。
        ("points 长度不符", v::EXT_EC_POINT_FORMATS, vec![3, 0]),
        // NPN 的体本该为空。
        ("npn 非空体", v::EXT_NPN, vec![1, 2]),
        // record_size_limit 本该恰好两字节。
        ("rsl 三字节", v::EXT_RECORD_SIZE_LIMIT, vec![1, 2, 3]),
    ];
    for (what, id, body) in cases {
        let ext = E::Opaque {
            id,
            body: body.clone(),
        };
        let hello = marshal_one(ext);
        let (_, got) = second_ext(&hello);
        assert_eq!(got, body, "{what}: 编码该原样透传");
        let parsed = ClientHelloSpec::from_bytes(&hello).unwrap();
        assert!(
            matches!(parsed.extensions[1], E::Opaque { .. }),
            "{what}: 该回落成 Opaque，实际是 {:?}",
            parsed.extensions[1]
        );
    }
}

// ── 误差面 ─────────────────────────────────────────────────────────────────

#[test]
fn missing_key_exchange_is_an_error_not_a_shorter_hello() {
    let mut i = inputs_with_keys(0);
    i.key_exchange.retain(|(g, _)| *g != v::X25519);
    let e = chrome().marshal(&i).unwrap_err();
    assert_eq!(e, SpecError::MissingKeyExchange(v::X25519));
}

// ── SNI：空名字 / IP 字面量是「零字节的扩展」，不是错误 ─────────────────────

#[test]
fn hostname_in_sni_is_utls_byte_for_byte() {
    // 每个样例都是 uTLS `handshake_client.go:1365` 那个函数的直接后果，
    // 其中两条是**照抄而不是改好**的怪癖（见 `encode::hostname_in_sni` 的注释）。
    use super::encode::hostname_in_sni;
    let cases: &[(&str, &str)] = &[
        ("", ""),
        ("example.com", "example.com"),
        // 尾点循环剥掉：`"a.."` 一路剥到 `"a"`。
        ("example.com.", "example.com"),
        ("a..", "a"),
        (".", ""),
        // IP 字面量不是合法 SNI ⇒ 空串。夹具 `…-Chrome-70-ServerNameIP` 用的就是这个。
        ("1.1.1.1", ""),
        ("::1", ""),
        ("[::1]", ""),
        ("::ffff:1.2.3.4", ""),
        // IPv6 zone：先剥 `%` 再判 IP ⇒ 判定为空串。
        ("fe80::1%eth0", ""),
        // 怪癖 1：方括号只对 `ParseIP` 那一步生效，**不进输出** ——
        // 非 IP 的方括号名原样发出。
        ("[example.com]", "[example.com]"),
        // 怪癖 2：`%` 的判据是「位置 > 0」，且剥出来的 `host` 只用于判 IP、不用于输出。
        ("%eth0", "%eth0"),
        ("a%eth0", "a%eth0"),
        // 不是 IP 的近似物一律原样保留。
        ("1.2.3.4.5", "1.2.3.4.5"),
        ("0x1.1.1.1", "0x1.1.1.1"),
        ("1.2.3.256", "1.2.3.256"),
        ("example.com:443", "example.com:443"),
    ];
    for (input, want) in cases {
        assert_eq!(&hostname_in_sni(input), want, "hostname_in_sni({input:?})");
    }
}

#[test]
fn empty_sni_writes_no_bytes_but_keeps_its_slot() {
    // 判据是 uTLS 自带的三条夹具（`-EmptyServerName` / `-ServerNameIP` /
    // `-HelloRetryRequest-Chrome-70`）：**扩展列表里没有类型 0**，而同预设的正常夹具里有。
    //
    // 这条同时钉住「槽位仍在列表里」：空 SNI 与长 SNI 占**同样的槽位数**，
    // 而洗牌只取决于列表长度与固定位 —— 所以两者的**相对顺序必须完全相同**。
    // 旧行为两条都不满足（`sni = None` 直接报错；`Some("")` 发出 4 字节空体）。
    let spec = ClientHelloSpec::from_preset(ClientHelloId::Chrome(106)).unwrap();
    assert_eq!(spec.variability, Variability::Shuffled);

    let order_of = |sni: &str| -> Vec<u16> {
        let mut i = inputs_with_keys(1);
        i.sni = Some(sni.to_string());
        let hello = spec.marshal(&i).unwrap();
        extension_types_in_wire_order(hello.as_bytes())
            .into_iter()
            // 填充发不发**会**被 SNI 长度推动（它按总长决定），与本条无关。
            .filter(|t| *t != v::EXT_PADDING)
            .collect()
    };

    let named = order_of("example.com");
    let empty = order_of("");
    assert!(named.contains(&v::EXT_SERVER_NAME), "正常 SNI 没发出去");
    assert!(!empty.contains(&v::EXT_SERVER_NAME), "空 SNI 竟然写了字节");
    // 同一个置换，**只是少写出那一条** —— 这正是「槽位照占、洗牌照抽」的可观测形式。
    let named_others: Vec<u16> = named
        .iter()
        .copied()
        .filter(|t| *t != v::EXT_SERVER_NAME)
        .collect();
    assert_eq!(
        empty, named_others,
        "空 SNI 与长 SNI 的相对顺序不同 —— 说明空 SNI 把槽位从列表里删掉了，\
         而 uTLS 只是让它 `Len() == 0`（槽位照占、洗牌照抽）"
    );

    // `None` 与 `Some("")` 在 uTLS 里同义（都是空串）—— 都走「零字节」那一支。
    let mut none = inputs_with_keys(1);
    none.sni = None;
    let hello = spec.marshal(&none).unwrap();
    assert!(!extension_types_in_wire_order(hello.as_bytes()).contains(&v::EXT_SERVER_NAME));
}

#[test]
fn sni_is_normalised_at_the_moment_it_is_written() {
    // 归一化必须发生在**写字节那一刻**（uTLS 的 `SNIExtension.Read` 里再过一次
    // `hostnameInSNI`），所以「尾点」这种一个字节的差异能被线上字节看见。
    let bare = one_ext(Extension::ExtendedMasterSecret);
    let mut i = HandshakeInputs::deterministic([0; 32]);
    i.sni = Some("e.com".into());
    let without = bare.marshal(&i).unwrap();

    let mut j = HandshakeInputs::deterministic([0; 32]);
    j.sni = Some("e.com.".into());
    let with_dot = bare.marshal(&j).unwrap();
    assert_eq!(
        with_dot.as_bytes(),
        without.as_bytes(),
        "尾点没有被剥掉：归一化漏了「写字节之前」这一处"
    );
}

#[test]
fn empty_spec_cannot_be_marshalled() {
    let spec = ClientHelloSpec::from_preset(ClientHelloId::Custom).unwrap();
    assert_eq!(
        spec.marshal(&HandshakeInputs::deterministic([0; 32]))
            .unwrap_err(),
        SpecError::EmptyCipherSuites
    );
}

#[test]
fn empty_alpn_omits_the_extension_instead_of_sending_an_empty_list() {
    let mut spec = chrome();
    // 去掉预设施加的 ALPN，换成不带默认值的形式：模拟「调用方与预设都没给协议」。
    for e in spec.extensions.iter_mut() {
        if matches!(e, Extension::Alpn(_)) {
            *e = Extension::Alpn(Vec::new());
        }
    }
    let mut i = inputs_with_keys(0);
    i.alpn.clear();
    let hello = spec.marshal(&i).unwrap();
    assert!(
        !extension_types_in_wire_order(hello.as_bytes()).contains(&v::EXT_ALPN),
        "两处都没有 ALPN，扩展却还在"
    );
}

#[test]
fn inputs_alpn_overrides_the_preset_default() {
    let mut i = inputs_with_keys(0);
    i.alpn = vec![b"http/1.1".to_vec()];
    let hello = chrome().marshal(&i).unwrap();
    let text = String::from_utf8_lossy(hello.as_bytes()).to_string();
    assert!(text.contains("http/1.1"));
    assert!(!text.contains("h2\x02"), "预设的 h2 没有被覆盖掉");
}

#[test]
fn padding_decision_does_not_disturb_the_shuffle() {
    // 这条是**修复的可证伪判据**。
    //
    // uTLS 洗牌时把「长度 0 的扩展」（窗口外的填充、空 PSK）**留在列表里**，只是不写字节；
    // 洗牌按列表长度抽，所以它的存在会消耗抽取。反过来：**填充发不发，不该改变其余扩展的
    // 相对顺序** —— 因为那个决定既不消耗随机数、也不改变列表长度。
    //
    // 修复前本仓是「窗口外就从列表里删掉」，于是列表长度变了 ⇒ 洗牌结果变了 ⇒
    // 同一个预设在不同 SNI 长度下，其余扩展的相对顺序**不一样**。这条断言在那种实现下会红。
    //
    // 用 chrome_106：Shuffled、带填充、**没有 GREASE-ECH**（所以未填充长不随种子变），
    // 而它的未填充长落在 BoringPaddingStyle 的窗口里 —— 于是**只有 SNI 长度**能把它推过
    // 512，而 SNI 长度**不消耗随机数抽取**。这正是能测出这条性质的最小装置。
    //
    // （chrome_120 不行：它的填充决定由 GREASE-ECH 的载荷长度决定，而那个随种子变 ——
    //   于是洗牌本身也跟着变，两边就不可比了。第一版就是拿它写的，测试自己报了
    //   「没有跨过窗口」。）
    let spec = ClientHelloSpec::from_preset(ClientHelloId::Chrome(106)).unwrap();
    assert_eq!(spec.variability, Variability::Shuffled);

    let mut reference: Option<Vec<u16>> = None;
    let mut saw_emitted = false;
    let mut saw_omitted = false;
    for sni_len in [1usize, 40, 80, 120, 160, 200, 255] {
        let mut i = inputs_with_keys(1);
        i.sni = Some("a".repeat(sni_len));
        let hello = spec.marshal(&i).unwrap();
        let types = extension_types_in_wire_order(hello.as_bytes());
        let has_padding = types.contains(&v::EXT_PADDING);
        saw_emitted |= has_padding;
        saw_omitted |= !has_padding;
        let others: Vec<u16> = types
            .iter()
            .copied()
            .filter(|t| *t != v::EXT_PADDING)
            .collect();
        match &reference {
            None => reference = Some(others),
            Some(r) => assert_eq!(
                &others, r,
                "SNI 长 {sni_len} 时其余扩展的相对顺序变了 —— \
                 说明填充的决定影响到了洗牌（它不该影响）"
            ),
        }
    }
    assert!(
        saw_emitted && saw_omitted,
        "这组 SNI 长度没有跨过填充窗口（emitted={saw_emitted}, omitted={saw_omitted}）—— \
         那这条测试就没测到东西，得换一组"
    );
}

// ── PSK：真 identities + binders ───────────────────────────────────────────

/// 一条只有一个 PSK 扩展的 spec（+ 必填的 SNI 由 `one_ext` 提供）。
fn psk_spec(psk: PreSharedKey) -> ClientHelloSpec {
    let mut s = ClientHelloSpec::empty();
    s.cipher_suites = vec![CodePoint::Fixed(v::TLS_AES_128_GCM_SHA256)];
    s.extensions = vec![Extension::PreSharedKey(psk)];
    s
}

fn marshal_psk(psk: PreSharedKey) -> Vec<u8> {
    marshalled_psk(psk).into_bytes()
}

/// 同上，但要拿到 [`ClientHello`] 本身（`psk_transcript_len` 在它上面）。
fn marshalled_psk(psk: PreSharedKey) -> ClientHello {
    let mut i = HandshakeInputs::deterministic([0; 32]);
    i.sni = None;
    psk_spec(psk).marshal(&i).unwrap()
}

#[test]
fn psk_wire_format_is_exactly_rfc8446() {
    // 手算的期望字节：这一条是「编码器有没有把 RFC 的格式抄对」的判据，
    // 不依赖任何参照实现 —— 三个字段（两个长度前缀 + 一个 u8 的 binder 长度）里错一个都会红。
    let psk = PreSharedKey {
        identities: vec![
            PskIdentity {
                label: vec![0xAA, 0xBB],
                obfuscated_ticket_age: 0x01020304,
            },
            PskIdentity {
                label: vec![0xCC],
                obfuscated_ticket_age: 0,
            },
        ],
        binders: vec![vec![0x11; 2], vec![0x22; 3]],
    };
    let hello = marshal_psk(psk);
    let (ty, body) = {
        let l = wire_ext_bodies(&hello);
        let (t, b) = l
            .iter()
            .find(|(t, _)| *t == v::EXT_PRE_SHARED_KEY)
            .expect("有 PSK")
            .clone();
        (t, b)
    };
    assert_eq!(ty, v::EXT_PRE_SHARED_KEY);
    assert_eq!(
        body,
        vec![
            // identities 长度 = (2+2+4) + (2+1+4) = 15
            0x00, 0x0F, 0x00, 0x02, 0xAA, 0xBB, 0x01, 0x02, 0x03, 0x04, 0x00, 0x01, 0xCC, 0x00,
            0x00, 0x00, 0x00, // binders 长度 = (1+2) + (1+3) = 7
            0x00, 0x07, 0x02, 0x11, 0x11, 0x03, 0x22, 0x22, 0x22,
        ],
        "PSK 体与 RFC 8446 §4.2.11 的形状不一致"
    );
}

#[test]
fn psk_without_a_session_writes_nothing_but_keeps_its_slot() {
    // uTLS 的 `pskExtLen() == 0` ⇒ 不写字节。零字节槽位仍参与洗牌（见 `Resolved::emit`）。
    // 这一条同时钉住「空 PSK 不再是单独一个变体」：它就是 identities/binders 都空的 `PreSharedKey`。
    let hello = marshal_psk(PreSharedKey::empty());
    assert!(
        !wire_ext_bodies(&hello)
            .iter()
            .any(|(t, _)| *t == v::EXT_PRE_SHARED_KEY),
        "没有会话时 PSK 不该写字节"
    );
    // 只有 identity 没有 binder（或反过来）也是零字节 —— uTLS 的判据是「任一为空」。
    let only_ids = PreSharedKey {
        identities: vec![PskIdentity {
            label: vec![1],
            obfuscated_ticket_age: 0,
        }],
        binders: Vec::new(),
    };
    let hello = marshal_psk(only_ids);
    assert!(
        !wire_ext_bodies(&hello)
            .iter()
            .any(|(t, _)| *t == v::EXT_PRE_SHARED_KEY)
    );
}

#[test]
fn psk_placeholder_and_real_binder_produce_the_same_length_and_same_truncation() {
    // **两遍序列化的不变量**：先按「全零占位 binder」序列化、算出真 binder、再换进去 ——
    // 两次的总长必须相同，且**截断点**必须相同（否则要哈希的那段就变了，binder 永远验不过）。
    // 这是 uTLS `InitializeByUtls` + `PatchBuiltHello` 的等价物，也是本仓 PSP/PSK 接线的基础。
    let ids = vec![
        PskIdentity {
            label: vec![0x41; 32],
            obfuscated_ticket_age: 7,
        },
        PskIdentity {
            label: vec![0x42; 48],
            obfuscated_ticket_age: 9,
        },
    ];
    let placeholder = PreSharedKey::placeholder(ids.clone(), 32);
    let c1 = marshalled_psk(placeholder.clone());
    let h1 = c1.as_bytes().to_vec();

    let mut real = placeholder.clone();
    real.set_binders(vec![vec![0x99; 32], vec![0x98; 32]])
        .unwrap();
    let c2 = marshalled_psk(real);
    let h2 = c2.as_bytes().to_vec();

    assert_eq!(
        h1.len(),
        h2.len(),
        "两遍序列化的总长不同 ⇒ 整个 hello 的哈希都会变"
    );
    assert_eq!(
        c1.psk_transcript_len(),
        c2.psk_transcript_len(),
        "截断点变了"
    );
    let t = c1.psk_transcript_len().unwrap();
    assert!(t < h1.len() && t > 0);
    // 截断点之后的字节**只包含** binders 向量（u16 长度 + 各 binder），
    // 而截断点之前的部分（含 identities）逐字节相同。
    assert_eq!(&h1[..t], &h2[..t], "截断点之前的字节变了");
    assert_ne!(&h1[t..], &h2[t..], "binder 没被换掉");
    // binders 向量长度 = 2 + (1+32)*2 = 68 ⇒ 截断点 = 总长 - 68。
    assert_eq!(h1.len() - t, 2 + 2 * (1 + 32));
}

#[test]
fn psk_binder_count_must_match_identity_count() {
    let mut psk = PreSharedKey::placeholder(
        vec![PskIdentity {
            label: vec![1],
            obfuscated_ticket_age: 0,
        }],
        32,
    );
    assert_eq!(
        psk.set_binders(vec![vec![0; 32], vec![0; 32]]).unwrap_err(),
        SpecError::BinderCountMismatch {
            identities: 1,
            binders: 2
        }
    );
    // 直接构造一个不匹配的 spec 也要在编码时报错（不是静默产出畸形字节）。
    let bad = PreSharedKey {
        identities: psk.identities.clone(),
        binders: vec![vec![0; 32], vec![0; 32]],
    };
    let mut i = HandshakeInputs::deterministic([0; 32]);
    i.sni = None;
    assert_eq!(
        psk_spec(bad).marshal(&i).unwrap_err(),
        SpecError::BinderCountMismatch {
            identities: 1,
            binders: 2
        }
    );
}

#[test]
fn psk_round_trips_byte_exact_including_the_binders() {
    // 反解必须能把 identities 与 binders 都还原（于是「回放一条捕获」不需要任何外部输入）。
    let psk = PreSharedKey {
        identities: vec![PskIdentity {
            label: vec![0x5A; 20],
            obfuscated_ticket_age: 1234,
        }],
        binders: vec![vec![0xC3; 32]],
    };
    let hello = marshal_psk(psk.clone());
    let spec = ClientHelloSpec::from_bytes(&hello).expect("反解");
    assert_eq!(
        spec.extensions.iter().find_map(|e| match e {
            Extension::PreSharedKey(p) => Some(p.clone()),
            _ => None,
        }),
        Some(psk.clone()),
        "反解出的 PSK 与写进去的不同（identities 或 binders 丢了）"
    );
    let replay = HandshakeInputs::for_replay(&hello).unwrap();
    assert_eq!(spec.marshal(&replay).unwrap().as_bytes(), &hello[..]);
}

// ── HelloRetryRequest 的第二飞 ──────────────────────────────────────────────

#[test]
fn for_hello_retry_keeps_only_the_selected_group_and_nothing_else() {
    // uTLS `processHelloRetryRequest` 对 spec 的改动只有一处：`key_share` 变成
    // `[selected_group]`。判据是 uTLS 自带夹具的 HRR 那条 `Flow 3`（见 `utls_testdata`）。
    let spec = ClientHelloSpec::from_preset(ClientHelloId::Chrome(70)).unwrap();
    let retry = spec.for_hello_retry(v::CURVE_P256).unwrap();

    let groups = |s: &ClientHelloSpec| -> Vec<u16> {
        s.extensions
            .iter()
            .find_map(|e| match e {
                Extension::KeyShare(ks) => {
                    Some(ks.groups.iter().map(|c| c.resolve(0x0a0a)).collect())
                }
                _ => None,
            })
            .expect("有 key_share")
    };
    assert_eq!(
        groups(&retry),
        vec![v::CURVE_P256],
        "key_share 该只剩选中的那个组"
    );
    assert_eq!(
        retry.extensions.len(),
        spec.extensions.len(),
        "扩展数量不该变"
    );
    // 位置也不该变：改的是那一条扩展的**内容**。
    let at = |s: &ClientHelloSpec| {
        s.extensions
            .iter()
            .position(|e| matches!(e, Extension::KeyShare(_)))
    };
    assert_eq!(at(&retry), at(&spec));

    // 三条前置检查各有各的报错（对应 uTLS 的三条文案）。
    let mut no_ks = spec.clone();
    no_ks
        .extensions
        .retain(|e| !matches!(e, Extension::KeyShare(_)));
    assert_eq!(
        no_ks.for_hello_retry(v::CURVE_P256).unwrap_err(),
        SpecError::HelloRetryWithoutKeyShare
    );
    // P-384 在 Chrome-70 的 supported_groups 里但在 key_share 里没有 ⇒ 合法。
    assert!(spec.for_hello_retry(v::CURVE_P384).is_ok());
    // X25519 第一飞已经给过共享密钥 ⇒ HRR 多余。
    assert_eq!(
        spec.for_hello_retry(v::X25519).unwrap_err(),
        SpecError::HelloRetryRedundantKeyShare(v::X25519)
    );
    // 没声明过的组。
    assert_eq!(
        spec.for_hello_retry(0x1234).unwrap_err(),
        SpecError::HelloRetryUnsupportedGroup(0x1234)
    );
}

#[test]
fn cookie_is_echoed_and_never_lands_on_the_last_slots() {
    // uTLS 在 HRR 里收到 cookie 时：已有 cookie 扩展就写进去，没有就**插一条新的**，
    // 位置抽自 `Intn(len - 2)`（好让 PSK 仍在最后）。我们让调用方给位置，理由见方法注释。
    let spec = ClientHelloSpec::from_preset(ClientHelloId::Chrome(70)).unwrap();
    let n = spec.extensions.len();

    let with = spec.with_cookie(b"abc", 3).unwrap();
    assert_eq!(with.extensions.len(), n + 1, "没有 cookie 扩展时该插一条");
    assert!(
        matches!(with.extensions[3], Extension::Cookie(_)),
        "插在给定位置"
    );
    let at = with
        .extensions
        .iter()
        .position(|e| matches!(e, Extension::Cookie(_)))
        .unwrap();
    // 插进去之后重新编码，字节里能读出 cookie。
    let mut i = inputs_with_keys(0);
    i.sni = Some("example.com".into());
    let bytes = with.marshal(&i).unwrap();
    assert!(
        wire_ext_bodies(bytes.as_bytes())
            .iter()
            .any(|(t, b)| *t == v::EXT_COOKIE && b == &[0, 3, b'a', b'b', b'c']),
        "cookie 的体该是 u16 长度 + 原字节（第 {at} 位那条）"
    );

    // 已有 cookie 扩展 ⇒ 只改内容，不插新的。
    let again = with.with_cookie(b"xy", 99).unwrap();
    assert_eq!(again.extensions.len(), n + 1, "已有 cookie 时不该再插一条");
    assert!(matches!(&again.extensions[at], Extension::Cookie(c) if c.cookie == b"xy"));

    // 越界：uTLS 用 `len - 2` 当上界，为的是不把 PSK 挤下去。
    assert_eq!(
        spec.with_cookie(b"z", n - 1).unwrap_err(),
        SpecError::CookieIndexOutOfRange {
            index: n - 1,
            len: n
        }
    );
    assert!(spec.with_cookie(b"z", n - 2).is_ok(), "倒数第三位是允许的");
    assert!(matches!(
        spec.with_cookie(b"z", 0).unwrap().extensions[0],
        Extension::Cookie(_)
    ));
}

#[test]
fn fill_to_produces_an_exact_total_length() {
    let mut spec = chrome();
    spec.variability = Variability::Stable;
    // 目标必须**高于最长的那种未填充长度**：Chrome 133 的 ClientHello 本身就一千多字节
    // （ML-KEM 混合组的公钥 1216 字节），再加 255 字节 SNI。
    // 「目标取小了」不是缺陷而是正确的报错 —— 见下一条测试。
    let target = 4096u16;
    spec.extensions
        .push(Extension::Padding(Padding::FillTo(target)));
    let mut lens = std::collections::BTreeSet::new();
    for sni_len in [0usize, 1, 7, 40, 200, 255] {
        let mut i = inputs_with_keys(1);
        i.sni = Some("a".repeat(sni_len));
        let hello = spec.marshal(&i).unwrap();
        lens.insert(hello.len());
        assert_eq!(
            hello.len(),
            target as usize,
            "SNI 长 {sni_len} 时总长不是目标长度（填充算术与 SNI 长度脱钩了）"
        );
    }
    // 6 种 SNI 长度都填到同一个总长 ⇒ 长度指纹稳定，这正是 Chrome 要填充的原因。
    assert_eq!(lens.len(), 1);
}

#[test]
fn unreachable_padding_target_is_an_error() {
    let mut spec = chrome();
    spec.variability = Variability::Stable;
    spec.extensions
        .push(Extension::Padding(Padding::FillTo(16)));
    let e = spec.marshal(&inputs_with_keys(0)).unwrap_err();
    assert!(
        matches!(e, SpecError::PaddingTargetUnreachable { .. }),
        "拿到的是 {e:?}"
    );
}

// ── 反解的健壮性 ───────────────────────────────────────────────────────────

#[test]
fn parser_never_panics_on_arbitrary_bytes() {
    // 确定性伪随机 + 边界变体。目标不是「找出所有畸形」，而是「任何输入都不 panic」——
    // 一个会在解析攻击者可控字节时 panic 的库，是一个 DoS。
    let mut s: u32 = 0x1234_5678;
    for len in 0..600usize {
        let mut buf = vec![0u8; len];
        for b in buf.iter_mut() {
            s ^= s << 13;
            s ^= s >> 17;
            s ^= s << 5;
            *b = s as u8;
        }
        let _ = ClientHelloSpec::from_bytes(&buf);
        let _ = crate::ja3::ja3_of_client_hello(&buf);
    }
    // 再拿一个合法的开头 + 随机尾巴，专门打结构解析。
    let good = chrome().marshal(&inputs_with_keys(0)).unwrap().into_bytes();
    for cut in 0..good.len() {
        let _ = ClientHelloSpec::from_bytes(&good[..cut]);
    }
}

#[test]
fn wrong_handshake_type_is_rejected() {
    assert_eq!(
        ClientHelloSpec::from_bytes(&[2, 0, 0, 4, 3, 3, 0, 0]).unwrap_err(),
        ParseError::NotAClientHello(2)
    );
}

#[test]
fn declared_length_must_match() {
    let good = chrome().marshal(&inputs_with_keys(0)).unwrap().into_bytes();
    let mut bad = good.clone();
    bad[1] = bad[1].wrapping_add(1);
    assert!(matches!(
        ClientHelloSpec::from_bytes(&bad).unwrap_err(),
        ParseError::LengthMismatch { .. }
    ));
}

// ── 测试辅助：从字节读扩展类型（故意自己解一遍，不复用模型）──────────────────

/// 从线字节里读出每个扩展的 `(类型, 体)` —— 与集成测试里那份同形，
/// 但单元测试看不到那个文件，所以各留一份（都是十来行，不值得为它建共享模块）。
fn wire_ext_bodies(bytes: &[u8]) -> Vec<(u16, Vec<u8>)> {
    let len = ((bytes[1] as usize) << 16) | ((bytes[2] as usize) << 8) | bytes[3] as usize;
    let body = &bytes[4..4 + len];
    let mut p = 2 + 32;
    p += 1 + body[p] as usize;
    let cs = u16::from_be_bytes([body[p], body[p + 1]]) as usize;
    p += 2 + cs;
    p += 1 + body[p] as usize;
    let exts = u16::from_be_bytes([body[p], body[p + 1]]) as usize;
    p += 2;
    let region = &body[p..p + exts];
    let mut out = Vec::new();
    let mut q = 0usize;
    while q + 4 <= region.len() {
        let ty = u16::from_be_bytes([region[q], region[q + 1]]);
        let bl = u16::from_be_bytes([region[q + 2], region[q + 3]]) as usize;
        out.push((ty, region[q + 4..q + 4 + bl].to_vec()));
        q += 4 + bl;
    }
    out
}

fn extension_types_in_wire_order(bytes: &[u8]) -> Vec<u16> {
    let len = ((bytes[1] as usize) << 16) | ((bytes[2] as usize) << 8) | bytes[3] as usize;
    let body = &bytes[4..4 + len];
    let mut p = 0usize;
    p += 2 + 32; // legacy_version + random
    let sid = body[p] as usize;
    p += 1 + sid;
    let cs = u16::from_be_bytes([body[p], body[p + 1]]) as usize;
    p += 2 + cs;
    let comp = body[p] as usize;
    p += 1 + comp;
    let exts = u16::from_be_bytes([body[p], body[p + 1]]) as usize;
    p += 2;
    let ext_bytes = &body[p..p + exts];
    let mut out = Vec::new();
    let mut q = 0usize;
    while q < ext_bytes.len() {
        let id = u16::from_be_bytes([ext_bytes[q], ext_bytes[q + 1]]);
        let bl = u16::from_be_bytes([ext_bytes[q + 2], ext_bytes[q + 3]]) as usize;
        out.push(id);
        q += 4 + bl;
    }
    out
}

/// 上游 `u_ech_test.go:12`（`TestGREASEECHWrite`）里那条**内联真向量**，在这里逐字段移植。
///
/// # 上游判的是什么
///
/// 把这条 `0xfe0d` 读进它的结构、再写出来，要求**长度与结构字段一致**：
/// 候选套件 1 个 = `(HKDF_SHA256, AES_128_GCM)`、封装密钥 32 字节、
/// 载荷长度字段 `0x00d0`（= 192 + 16 字节 AEAD tag）。它**不比载荷字节** ——
/// 载荷在真实实现里是 HPKE 封装结果，本来就是每连接的随机量。
///
/// # 我们为什么能移植、以及判到哪里
///
/// 我们的编码器产的是同一个线格式（`[ECH_OUTER_CLIENT_HELLO] || kdf || aead ||
/// config_id || enc_len || enc || payload_len || payload`），且**不**做真 HPKE 封装
/// （用等长随机字节代替，取舍登记在 `STATE.md` 的已知缺口里）。所以能判的是
/// **结构 + 长度**，而这恰好就是上游那条判据的全部内容：
///
/// 1. 向量自身自洽（类型、长度字段、各结构字段）—— 免得一个抄错的常量当权威；
/// 2. 用**能表达这条向量的选项**（1 个候选套件 + 载荷候选 192）编出来的体，
///    长度与每个结构字段都与它相同。
///
/// config_id / 封装密钥 / 载荷的**内容**是每连接的随机量，两边都不比 —— 只判长度。
#[test]
fn grease_ech_matches_the_upstream_inline_vector_fields() {
    /// `u_ech_test.go:12` 的 `rawECH_HKDFSHA256_AES128GCM.raw`（254 字节 = 4 字节扩展头 + 250 体）。
    const VECTOR: &[u8] = &[
        0xfe, 0x0d, 0x00, 0xfa, 0x00, 0x00, 0x01, 0x00, 0x01, 0x77, 0x00, 0x20, 0x3d, 0x3e, 0xe0,
        0xa6, 0x1f, 0x46, 0x4f, 0x89, 0x5f, 0x39, 0x4a, 0xfd, 0x6e, 0xbc, 0x7f, 0x4e, 0xe2, 0x5a,
        0xdc, 0x4e, 0xda, 0x9a, 0x9f, 0x5f, 0x2b, 0xf5, 0x21, 0x0e, 0xc6, 0x33, 0x64, 0x32, 0x00,
        0xd0, 0xae, 0xff, 0x25, 0xd6, 0x4a, 0x23, 0x3a, 0x13, 0x5b, 0xdc, 0xe4, 0xaf, 0x6c, 0xb8,
        0xaf, 0x66, 0x57, 0xbd, 0x44, 0x2d, 0xca, 0xb6, 0xbb, 0xaf, 0xda, 0x8a, 0x6b, 0x12, 0xb2,
        0x42, 0xf1, 0x3d, 0xf6, 0x26, 0xd4, 0x82, 0x30, 0x40, 0xd4, 0x53, 0x06, 0x7c, 0xf1, 0x10,
        0xf3, 0x80, 0x16, 0x95, 0xa7, 0xfb, 0x08, 0x76, 0x82, 0x85, 0x86, 0xb4, 0x3a, 0x7b, 0xea,
        0xfb, 0xaa, 0xc3, 0xe0, 0x51, 0xcf, 0x42, 0xf6, 0xa0, 0x15, 0x0e, 0x26, 0x4d, 0x37, 0x35,
        0x95, 0x4d, 0xce, 0xf6, 0xd6, 0x58, 0x78, 0x67, 0x42, 0xd3, 0xc6, 0xac, 0xb5, 0xe9, 0x3e,
        0xb6, 0x02, 0x87, 0x66, 0xb3, 0xb2, 0x56, 0x99, 0xb2, 0xdb, 0x8c, 0x3b, 0x04, 0xf1, 0x7c,
        0x85, 0x5b, 0xc3, 0x93, 0x8e, 0xdb, 0x5d, 0x87, 0x66, 0xfb, 0x66, 0x54, 0xf3, 0xec, 0x25,
        0xe5, 0x70, 0x3c, 0xd5, 0x0e, 0x8e, 0xd5, 0xd2, 0xbb, 0x24, 0x2b, 0xb5, 0x01, 0xa0, 0x5e,
        0xba, 0x45, 0xaf, 0x68, 0x96, 0x8a, 0x83, 0x90, 0x20, 0x5b, 0x8c, 0x7d, 0x24, 0x00, 0x2f,
        0x08, 0x7f, 0x29, 0x8c, 0x32, 0x5e, 0x57, 0xb5, 0x64, 0xaa, 0x0b, 0xf4, 0x42, 0x54, 0xdc,
        0xe5, 0xd4, 0x08, 0xf4, 0x4d, 0x27, 0x5d, 0x90, 0x52, 0x32, 0x22, 0xc8, 0xb6, 0xd8, 0x80,
        0xa6, 0x30, 0xa0, 0x20, 0x98, 0x2c, 0x0b, 0x3e, 0x55, 0x4a, 0x09, 0xa9, 0x09, 0xa4, 0x99,
        0x89, 0x02, 0x6e, 0xab, 0xe3, 0xa1, 0xe9, 0xb8, 0x58, 0x20, 0xcc, 0xc8, 0xb0, 0x73,
    ];

    // ① 向量自身自洽 —— 结构字段写在断言里，好让「我们编出来的」有可比的对象。
    assert_eq!(&VECTOR[0..2], &[0xfe, 0x0d], "扩展类型该是 GREASE-ECH");
    assert_eq!(
        u16::from_be_bytes([VECTOR[2], VECTOR[3]]) as usize,
        VECTOR.len() - 4,
        "长度字段该吃掉余下的全部字节"
    );
    let up = &VECTOR[4..];
    assert_eq!(up[0], v::ECH_OUTER_CLIENT_HELLO, "体首字节");
    assert_eq!(
        u16::from_be_bytes([up[1], up[2]]),
        v::HPKE_KDF_HKDF_SHA256,
        "候选套件的 KDF"
    );
    assert_eq!(
        u16::from_be_bytes([up[3], up[4]]),
        v::HPKE_AEAD_AES_128_GCM,
        "候选套件的 AEAD"
    );
    let up_enc_len = u16::from_be_bytes([up[6], up[7]]) as usize;
    let up_payload_len = u16::from_be_bytes([up[40], up[41]]) as usize;
    assert_eq!(
        up_enc_len,
        v::X25519_ENCAPSULATED_KEY_LEN,
        "封装密钥长度字段"
    );
    assert_eq!(
        up_payload_len,
        192 + 16,
        "载荷长度字段 = 上游的 CandidatePayloadLens(192) + AEAD tag(16)"
    );
    assert_eq!(
        6 + 2 + up_enc_len + 2 + up_payload_len,
        up.len(),
        "向量自洽（无余量）"
    );

    // ② 我们的编码器用「能表达这条向量的选项」编一遍，逐字段对。
    let mut spec = chrome();
    let at = spec
        .extensions
        .iter()
        .position(|e| matches!(e, Extension::GreaseEch(_)))
        .expect("Chrome 133 自带 GREASE-ECH");
    spec.extensions[at] = Extension::GreaseEch(GreaseEchOptions {
        cipher_suites: vec![(v::HPKE_KDF_HKDF_SHA256, v::HPKE_AEAD_AES_128_GCM)],
        payload_lens: vec![192],
    });
    let hello = spec.marshal(&inputs_with_keys(7)).unwrap();
    let ours = grease_ech_body_bytes(hello.as_bytes()).expect("我们编出来的体里有 GREASE-ECH");

    assert_eq!(ours.len(), up.len(), "体长该与上游向量相同（250）");
    assert_eq!(ours[0], up[0], "体首字节（ECH_OUTER_CLIENT_HELLO）");
    assert_eq!(&ours[1..3], &up[1..3], "KDF id");
    assert_eq!(&ours[3..5], &up[3..5], "AEAD id");
    assert_eq!(&ours[6..8], &up[6..8], "封装密钥长度字段（0x0020）");
    assert_eq!(&ours[40..42], &up[40..42], "载荷长度字段（0x00d0）");
}
