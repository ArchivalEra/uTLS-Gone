//! **随机化指纹的对账**：同一个种子，我们与参照实现必须产出**同一份 spec**。
//!
//! 夹具 `tests/fixtures/utls-randomized.json` 是 Go 版 uTLS 在**固定种子**下实际产出的
//! `HelloRandomized{,ALPN,NoALPN}`（生成方式见 `gen-reference/README.md` 与 `main.go`
//! 的 `randomizedDump`）。
//!
//! # 为什么这条对账特别有说服力
//!
//! 随机化指纹不是一份固定数据，而是**一串加权掷币的结果**。所以它能对上，说明的不是
//! 「某几张表抄对了」，而是「**整条取随机的流逐次对齐**」—— 包括：
//!
//! - Go 的 `||` / `&&` 短路所**跳过**的那些掷币（见 `randomized.rs` 模块头）；
//! - `Shuffle` 用的 Lemire `int31n` 与 `Intn` 用的拒绝采样 `Int31n` 是**两个**算法；
//! - ALPS 那次掷币走的是 HKDF 派生出来的**另一条流**，不消耗主流。
//!
//! 这三处任何一处错位，后面每一次掷币都会跟着错，几十个布尔值里必然对不上。
//! 而且随机化 spec **完全不含 GREASE**，所以扩展顺序与 JA3 都可以**逐字**比。

use std::collections::BTreeMap;

use utls::hello::{ClientHelloId, ClientHelloSpec, CodePoint, Extension, HandshakeInputs};
use utls::values as v;

const FIXTURE: &str = include_str!("fixtures/utls-randomized.json");

fn id_of(name: &str) -> ClientHelloId {
    match name {
        "randomized" => ClientHelloId::Randomized,
        "randomized_alpn" => ClientHelloId::RandomizedAlpn,
        "randomized_no_alpn" => ClientHelloId::RandomizedNoAlpn,
        other => panic!("夹具里有未知的随机化 id：{other}"),
    }
}

/// 按 spec 的 `key_share` 组给**长度正确**的哑公钥 —— 长度进指纹（它决定总长与填充）。
fn canonical_inputs(spec: &ClientHelloSpec) -> HandshakeInputs {
    let mut inputs = HandshakeInputs::deterministic([0u8; 32]);
    inputs.sni = Some("example.com".into());
    let mut groups: Vec<u16> = Vec::new();
    for e in &spec.extensions {
        if let Extension::KeyShare(cps) = e {
            for cp in cps {
                if let CodePoint::Fixed(g) = cp
                    && !v::is_grease(*g)
                    && !groups.contains(g)
                {
                    groups.push(*g);
                }
            }
        }
    }
    inputs.key_exchange = groups
        .into_iter()
        .map(|g| {
            let len = v::group_public_key_len(g)
                .unwrap_or_else(|| panic!("group_public_key_len 不认组 {g}"));
            (g, vec![0x5A; len])
        })
        .collect();
    inputs
}

fn to_u16_list(s: &str) -> Vec<u16> {
    if s.is_empty() {
        Vec::new()
    } else {
        s.split('-').map(|x| x.parse().expect("不是数字")).collect()
    }
}

fn wire_ext_lengths(hello: &[u8]) -> Vec<(u16, usize)> {
    let len = ((hello[1] as usize) << 16) | ((hello[2] as usize) << 8) | hello[3] as usize;
    let body = &hello[4..4 + len];
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
        out.push((ty, bl));
        q += 4 + bl;
    }
    out
}

#[test]
fn every_seed_reproduces_the_utls_reference() {
    let doc: serde_json::Value = serde_json::from_str(FIXTURE).expect("夹具不是合法 JSON");
    let items = doc.as_object().expect("顶层该是对象");
    assert!(!items.is_empty(), "夹具是空的 —— 空不是通过");
    assert_eq!(items.len(), 24, "夹具该有 3 个 id × 8 个种子");

    let mut checked: BTreeMap<String, usize> = BTreeMap::new();
    for (key, e) in items {
        assert!(e.get("error").is_none(), "{key}: 夹具带着生成期错误 {e:?}");
        let name = e["name"].as_str().unwrap();
        let seed_byte = e["seed"].as_u64().unwrap() as u8;
        let p = &e["parsed"];

        // 与参照生成器用同一个种子。
        let spec = ClientHelloSpec::randomized(id_of(name), [seed_byte; 32], &[])
            .unwrap_or_else(|err| panic!("{key}: 生成失败：{err}"));
        let hello = spec
            .marshal(&canonical_inputs(&spec))
            .unwrap_or_else(|err| panic!("{key}: marshal 失败：{err}"));
        let ours = hello.ja3().text();
        let parts: Vec<&str> = ours.split(',').collect();

        // JA3 文本逐字 —— 随机化 spec 无 GREASE，所以这四条必须**完全**相同。
        assert_eq!(parts[0].parse::<u16>().unwrap(), p["legacy_version"].as_u64().unwrap() as u16,
            "{key}: legacy_version");
        assert_eq!(
            to_u16_list(parts[1]),
            p["ciphers"].as_array().unwrap().iter().map(|x| x.as_u64().unwrap() as u16).collect::<Vec<_>>(),
            "{key}: 密码套件（顺序）—— 说明取随机的流在洗牌那一步就对上了"
        );
        assert_eq!(
            to_u16_list(parts[2]),
            p["extensions"].as_array().unwrap().iter().map(|x| x.as_u64().unwrap() as u16).collect::<Vec<_>>(),
            "{key}: 扩展类型（顺序）—— 说明每一次加权掷币的次序与结果都对上了"
        );
        assert_eq!(
            to_u16_list(parts[3]),
            p["groups"].as_array().unwrap().iter().map(|x| x.as_u64().unwrap() as u16).collect::<Vec<_>>(),
            "{key}: 支持组"
        );
        assert_eq!(
            to_u16_list(parts[4]),
            p["point_formats"].as_array().unwrap().iter().map(|x| x.as_u64().unwrap() as u16).collect::<Vec<_>>(),
            "{key}: 点格式"
        );

        // 整条 JA3 的 MD5 也逐字比 —— 它是上面五段的一个函数，所以这条在语义上有冗余，
        // 但它让「这条对账到底比了什么」在**失败信息**里一眼可见。
        assert_eq!(
            hello.ja3().hash_hex(),
            p["ja3_md5"].as_str().unwrap(),
            "{key}: JA3 的 MD5"
        );

        // 逐扩展体长：JA3 覆盖不到的那一半（padding 与 key_share 的长度都算进去了）。
        let mut our_lens = wire_ext_lengths(hello.as_bytes());
        our_lens.sort_unstable();
        let mut ref_lens: Vec<(u16, usize)> = p["ext_lengths"]
            .as_array()
            .expect("夹具该有 ext_lengths")
            .iter()
            .map(|pair| {
                let a = pair.as_array().unwrap();
                (a[0].as_u64().unwrap() as u16, a[1].as_u64().unwrap() as usize)
            })
            .collect();
        ref_lens.sort_unstable();
        assert_eq!(our_lens, ref_lens, "{key}: 逐扩展体长（含 padding 与 key_share 长度）");

        // 总长。
        assert_eq!(
            hello.len(),
            p["length"].as_u64().unwrap() as usize,
            "{key}: ClientHello 总长"
        );

        *checked.entry(name.to_string()).or_default() += 1;
    }

    assert_eq!(checked.len(), 3, "三个 id 都要覆盖到：{checked:?}");
    for (k, n) in &checked {
        assert_eq!(*n, 8, "{k} 只对了 {n} 个种子");
    }
}

/// 随机化 ID **不能**走 `from_preset` —— 它需要种子。这条断言把这个契约钉住，
/// 免得有人日后把它加进 `implemented()` 然后在没种子的地方拿到一份「默认指纹」。
#[test]
fn randomized_ids_refuse_from_preset() {
    for id in ClientHelloId::randomized_family() {
        let err = ClientHelloSpec::from_preset(*id).unwrap_err();
        assert!(
            matches!(err, utls::hello::SpecError::RandomizedNeedsSeed(_)),
            "{id} 该报 RandomizedNeedsSeed，实际是 {err:?}"
        );
    }
    // 同一份种子必须给出同一份指纹（可复现），不同种子给不同的。
    let a = ClientHelloSpec::randomized(ClientHelloId::Randomized, [1u8; 32], &[]).unwrap();
    let b = ClientHelloSpec::randomized(ClientHelloId::Randomized, [1u8; 32], &[]).unwrap();
    let c = ClientHelloSpec::randomized(ClientHelloId::Randomized, [2u8; 32], &[]).unwrap();
    assert_eq!(a, b, "同种子必须同 spec");
    assert_ne!(a, c, "不同种子该给出不同的 spec");
}
