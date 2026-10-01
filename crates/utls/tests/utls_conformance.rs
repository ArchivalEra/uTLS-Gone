//! **uTLS 一致性对账** —— 本项目最强的那条外部验证。
//!
//! 夹具 `tests/fixtures/utls-reference.json` 是**参照实现（Go 版 uTLS）实际产出**的
//! ClientHello 指纹（生成方式见 `tests/fixtures/gen-reference/README.md`）。这里把它
//! 与我们的产出逐字段比。
//!
//! # 为什么这条比仓内任何测试都强
//!
//! 仓内所有其它测试都是**自证**：预设数据抄错了，编码器和解码器会一起错，往返测试照样绿。
//! 只有拿参照实现的产出来比，才能发现「我们抄错了 Go 的哪一行」。
//!
//! # 对账的口径（哪些字段必须完全相同）
//!
//! | 字段 | 要求 |
//! |---|---|
//! | `legacy_version` / 密码套件序 / 支持组序 / 点格式 | **始终**逐序相同 |
//! | 扩展**多重集** | **始终**相同 |
//! | 扩展**顺序** | 仅对 `Stable` 预设要求相同 |
//! | JA3 文本与 MD5 | 仅对 `Stable` 预设要求相同 |
//! | 总长 | 必须落在参照跑 48 次观测到的长度集合里 |
//! | `len_stable` / `ja3_stable` | 必须与参照的判断一致 |
//!
//! **乱序预设不比对顺序，不是放宽** —— uTLS 的 Chrome 106 及以后每次连接都置换扩展，
//! 所以「顺序每次不同」正是参照实现的行为本身。可对账的是多重集。

use std::collections::BTreeMap;

use utls::hello::{ClientHelloId, ClientHelloId as Id, ClientHelloSpec, HandshakeInputs};
use utls::values as v;

mod common;
use common::*;

const REFERENCE: &str = include_str!("fixtures/utls-reference.json");

/// 本文件用的规范 SNI。**单独一个常量**：`utls_testdata` 那边每个夹具的 SNI 不同，
/// 而这里是「同一份输入跑所有预设」——两者是不同的口径，别混。
const CANONICAL_SNI: Option<&str> = Some("example.com");

fn ref_inputs(spec: &ClientHelloSpec) -> HandshakeInputs {
    canonical_inputs(spec, CANONICAL_SNI)
}

fn ref_inputs_with_seed(spec: &ClientHelloSpec, seed: u8) -> HandshakeInputs {
    canonical_inputs_with_seed(spec, CANONICAL_SNI, seed)
}

fn parse_u16_list(s: &str) -> Vec<u16> {
    if s.is_empty() {
        return Vec::new();
    }
    s.split('-').map(|x| x.parse().expect("不是数字")).collect()
}

fn preset_id(name: &str) -> ClientHelloId {
    for id in ClientHelloId::implemented() {
        if id.name() == name {
            return *id;
        }
    }
    panic!("夹具里有 {name}，但 ClientHelloId::implemented() 里没有 —— 两者必须一一对应");
}

/// 夹具里的一条记录。
struct Ref {
    legacy_version: u16,
    ciphers: Vec<u16>,
    extensions: Vec<u16>,
    groups: Vec<u16>,
    point_formats: Vec<u16>,
    ja3_text: String,
    ext_lengths: Vec<(u16, usize)>,
    /// 逐扩展的**体内容** —— 只比长度会漏掉「长度一样、内容错了」。
    ext_bodies: Vec<(u16, Vec<u8>)>,
    ja3_md5: String,
    lens: Vec<usize>,
    len_stable: bool,
    ja3_stable: bool,
}

fn load_reference() -> BTreeMap<String, Ref> {
    let doc: serde_json::Value =
        serde_json::from_str(REFERENCE).expect("夹具不是合法 JSON —— 它该由生成器产出");
    let obj = doc.as_object().expect("夹具顶层该是对象");
    let mut out = BTreeMap::new();
    for (name, e) in obj {
        if e.get("error").is_some() {
            panic!("夹具里 {name} 带着生成期的错误：{}", e["error"]);
        }
        let p = &e["parsed"];
        let pf = p["point_formats"]
            .as_array()
            .expect("point_formats 该是数组（生成器里踩过 []uint8 会被编成 base64 的坑）");
        out.insert(
            name.clone(),
            Ref {
                legacy_version: p["legacy_version"].as_u64().unwrap() as u16,
                ciphers: p["ciphers"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|x| x.as_u64().unwrap() as u16)
                    .collect(),
                extensions: p["extensions"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|x| x.as_u64().unwrap() as u16)
                    .collect(),
                groups: p["groups"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|x| x.as_u64().unwrap() as u16)
                    .collect(),
                point_formats: pf.iter().map(|x| x.as_u64().unwrap() as u16).collect(),
                ja3_text: p["ja3_text"].as_str().unwrap().to_string(),
                ext_bodies: p["ext_bodies"]
                    .as_array()
                    .expect("夹具里该有 ext_bodies（加它就是为了比体内容）")
                    .iter()
                    .map(|e| {
                        let ty = e["type"].as_u64().unwrap() as u16;
                        let hexs = e["body"].as_str().unwrap();
                        (ty, decode_hex(hexs))
                    })
                    .collect(),
                ext_lengths: p["ext_lengths"]
                    .as_array()
                    .expect("夹具里该有 ext_lengths")
                    .iter()
                    .map(|pair| {
                        let a = pair.as_array().unwrap();
                        (
                            a[0].as_u64().unwrap() as u16,
                            a[1].as_u64().unwrap() as usize,
                        )
                    })
                    .collect(),
                ja3_md5: p["ja3_md5"].as_str().unwrap().to_string(),
                lens: e["lens"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|x| x.as_u64().unwrap() as usize)
                    .collect(),
                len_stable: e["len_stable"].as_bool().unwrap(),
                ja3_stable: e["ja3_stable"].as_bool().unwrap(),
            },
        );
    }
    assert!(!out.is_empty(), "夹具是空的 —— 空不是通过");
    out
}

#[test]
fn every_preset_matches_the_utls_reference() {
    let reference = load_reference();
    let mut checked = 0usize;
    let mut order_matched = 0usize;
    let mut ja3_matched = 0usize;
    let mut stable_count = 0usize;

    for (name, r) in &reference {
        let id: ClientHelloId = preset_id(name);
        let spec = ClientHelloSpec::from_preset(id).unwrap_or_else(|e| panic!("{name}: {e}"));
        let hello = spec
            .marshal(&ref_inputs(&spec))
            .unwrap_or_else(|e| panic!("{name}: marshal 失败：{e}"));
        let ours = hello.ja3().text();
        let parts: Vec<&str> = ours.split(',').collect();
        assert_eq!(parts.len(), 5, "{name}: JA3 文本该有五段");

        // ── 始终要求逐序相同的四段 ──
        assert_eq!(
            parts[0].parse::<u16>().unwrap(),
            r.legacy_version,
            "{name}: legacy_version"
        );
        assert_eq!(
            parse_u16_list(parts[1]),
            r.ciphers,
            "{name}: 密码套件（顺序）"
        );
        assert_eq!(parse_u16_list(parts[3]), r.groups, "{name}: 支持组（顺序）");
        assert_eq!(parse_u16_list(parts[4]), r.point_formats, "{name}: 点格式");

        // ── 逐扩展体长：JA3 覆盖不到的那一半 ──
        // 乱序预设的**顺序**不同，但「类型 → 体长」这个映射必须一致。
        // GREASE 扩展的**类型每连接都不同**，所以必须先把类型规范化再比，
        // 否则会得到「类型配错了对」的假失败。规范化之后，这条断言顺便验证了
        // uTLS 那条「第 1 个 GREASE 扩展体为空、第 2 个是 [0]」的规则。
        let varies = !r.len_stable;
        let keep =
            |t: u16| !(varies && (t == v::EXT_ENCRYPTED_CLIENT_HELLO || t == v::EXT_PADDING));
        let mut our_lens: Vec<(u16, usize)> = wire_ext_lengths(hello.as_bytes())
            .into_iter()
            .map(|(t, l)| (normalize_ext_type(t), l))
            .filter(|(t, _)| keep(*t))
            .collect();
        our_lens.sort_unstable();
        let mut ref_lens: Vec<(u16, usize)> = r
            .ext_lengths
            .iter()
            .map(|(t, l)| (normalize_ext_type(*t), *l))
            .filter(|(t, _)| keep(*t))
            .collect();
        ref_lens.sort_unstable();
        assert_eq!(
            our_lens, ref_lens,
            "{name}: 逐扩展体长对不上 —— 上面第一个不同的那对就是出错的那条扩展"
        );

        // ── 逐扩展**体内容** ──
        //
        // 比体长更严的一层：长度一样、内容错的错，只有它能抓到 —— 而「把 Opaque 升级成
        // 有类型的变体」正是最容易犯这种错的地方（体换了生成方式，长度却不变）。
        let mut our_bodies: Vec<(u16, Vec<u8>)> = wire_ext_bodies(hello.as_bytes())
            .into_iter()
            .map(|(t, b)| (normalize_ext_type(t), normalize_body(t, &b)))
            .filter(|(t, _)| keep(*t))
            .collect();
        let mut ref_bodies: Vec<(u16, Vec<u8>)> = r
            .ext_bodies
            .iter()
            .map(|(t, b)| (normalize_ext_type(*t), normalize_body(*t, b)))
            .filter(|(t, _)| keep(*t))
            .collect();
        // `Stable` 预设连顺序一起比；乱序预设比「类型 → 体」的多重集。
        if spec.variability == utls::hello::Variability::Stable {
            assert_eq!(our_bodies, ref_bodies, "{name}: 逐扩展体内容（含顺序）");
        } else {
            our_bodies.sort();
            ref_bodies.sort();
            assert_eq!(our_bodies, ref_bodies, "{name}: 逐扩展体内容（多重集）");
        }

        // ── 扩展多重集：除去「随连接变化」的那一条之外始终相同 ──
        //
        // `len_stable == false` 的预设里，padding 的**存在与否**也随连接变（未填充长
        // 一旦涨过 0x200 它就不发），所以它不在多重集的可比范围内 —— 它由上面的
        // 「总长落在观测集合里」覆盖。
        let mut our_exts = parse_u16_list(parts[2]);
        let mut ref_exts = r.extensions.clone();
        if varies {
            our_exts.retain(|t| *t != v::EXT_PADDING);
            ref_exts.retain(|t| *t != v::EXT_PADDING);
        }
        our_exts.sort_unstable();
        ref_exts.sort_unstable();
        assert_eq!(our_exts, ref_exts, "{name}: 扩展多重集");

        // ── JA3 的稳定性：由 `Variability` 决定 ──
        //
        // `Stable` ⇒ JA3 跨连接恒定；`Shuffled` ⇒ 不恒定（真实 Chrome 与 rustls 0.23 都如此）。
        // 参照那边的 `ja3_stable` 是跑 48 次量出来的，所以这条断言是在拿**观测**验**设计**。
        let our_ja3_stable = spec.variability == utls::hello::Variability::Stable;
        assert_eq!(
            our_ja3_stable, r.ja3_stable,
            "{name}: ja3_stable 与参照不一致"
        );

        // ── 顺序与 JA3 文本：仅对 Stable 预设 ──
        if spec.variability == utls::hello::Variability::Stable {
            assert_eq!(
                parse_u16_list(parts[2]),
                r.extensions,
                "{name}: 扩展顺序（Stable 预设）"
            );
            assert_eq!(ours, r.ja3_text, "{name}: JA3 文本");
            assert_eq!(hello.ja3().hash_hex(), r.ja3_md5, "{name}: JA3 的 MD5");
            order_matched += 1;
            ja3_matched += 1;
        }
        if spec.variability == utls::hello::Variability::Stable {
            stable_count += 1;
        }

        // ── 总长必须落在参照观测到的集合里 ──
        // 用**长度集合**而不是单点：它同时约束 GREASE-ECH 的候选长度表、各公钥的长度、
        // 以及填充算术 —— 这三样里错一个，集合就对不上。
        let mut our_len_set = std::collections::BTreeSet::new();
        for seed in 0u8..16 {
            our_len_set.insert(
                spec.marshal(&ref_inputs_with_seed(&spec, seed))
                    .unwrap()
                    .len(),
            );
        }
        for l in &our_len_set {
            assert!(
                r.lens.contains(l),
                "{name}: 总长 {l} 不在参照观测到的 {:?} 里 —— 多半是某个公钥长度、GREASE-ECH 候选表或填充算术算错了",
                r.lens
            );
        }

        // ── 稳定性判断必须一致 ──
        let our_len_stable = our_len_set.len() == 1;
        assert_eq!(
            our_len_stable, r.len_stable,
            "{name}: len_stable 与参照不一致"
        );

        checked += 1;
    }

    assert_eq!(checked, reference.len());
    assert!(checked >= 39, "只对账了 {checked} 个预设 —— 少了就是漏了");
    // ⚠️ 下面两条不写死数字：加了预设就得回来改魔法数的断言，正是那种「一定会漂」的手写名录。
    // 改成拿**本轮的 Stable 计数**自己比自己。
    assert_eq!(
        order_matched, stable_count,
        "Stable 预设的顺序都对账了才成立"
    );
    assert_eq!(ja3_matched, stable_count);
    assert!(
        stable_count >= 30,
        "Stable 预设只有 {stable_count} 个 —— 少了对账对象"
    );
    assert!(reference.contains_key("chrome_133") && reference.contains_key("firefox_148"));
}

/// 夹具里出现的每一个名字，我们都必须有一个预设能对上 —— 反过来也要成立。
///
/// 这条挡的是「夹具更新了、我们的 id 表忘了跟上」：那种情况下对账测试会因为
/// 找不到 id 而 panic，但 `Custom`（空 spec）会安静地跳过，所以单列一条。
#[test]
fn reference_and_implemented_ids_are_in_bijection() {
    let reference = load_reference();
    let ours: Vec<String> = ClientHelloId::implemented()
        .iter()
        .filter(|id| !matches!(id, Id::Custom))
        .map(|id| id.name())
        .collect();
    let theirs: Vec<String> = reference.keys().cloned().collect();
    assert_eq!(
        ours.len(),
        theirs.len(),
        "数目不等：我们 {ours:?} / 参照 {theirs:?}"
    );
    for k in &theirs {
        assert!(ours.contains(k), "参照有 {k}，我们没有");
    }
    for k in &ours {
        assert!(theirs.contains(k), "我们有 {k}，参照没有");
    }
}

/// 反解我们自己的产出，再回放，必须逐字节相同 —— 对**所有**预设成立，
/// 而不只是 Chrome 133 / Firefox 148（那两条在 `src/hello/tests.rs` 里）。
#[test]
fn every_preset_round_trips_byte_exact() {
    let mut n = 0;
    for id in ClientHelloId::implemented() {
        let spec = ClientHelloSpec::from_preset(*id).unwrap();
        if spec.cipher_suites.is_empty() {
            continue; // Custom：空 spec，没有可回放的东西
        }
        let hello = spec.marshal(&ref_inputs(&spec)).unwrap();
        let parsed = ClientHelloSpec::from_bytes(hello.as_bytes())
            .unwrap_or_else(|e| panic!("{id}: 反解失败：{e}"));
        let replay = HandshakeInputs::for_replay(hello.as_bytes()).unwrap();
        let again = parsed.marshal(&replay).unwrap();
        assert_eq!(
            again.as_bytes(),
            hello.as_bytes(),
            "{id}: 往返不是逐字节相同"
        );
        n += 1;
    }
    let want = ClientHelloId::implemented()
        .iter()
        .filter(|id| !matches!(id, ClientHelloId::Custom))
        .count();
    assert_eq!(
        n, want,
        "只往返了 {n} 个预设，而 implemented() 里有 {want} 个静态预设"
    );
}
