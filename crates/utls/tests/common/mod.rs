//! 两个对账测试（`utls_conformance` 与 `utls_testdata`）共用的解析与掩码工具。
//!
//! 单列一个模块而不是各写一份：这里的**掩码口径**是「哪些字节是每连接随机的」这件事的
//! 唯一表述，而它曾经是踩出来的 —— 比如 GREASE 的扩展**类型**每连接都不同（拿它当
//! 映射的键必然配错对），`key_share` 的公钥字节不可比（只有长度可比）。
//! 两个测试各写一份，就等于把这份口径抄成两份、然后各自腐烂。
//!
//! 所有函数都只做**字节层**的事，不依赖任何 `utls` 内部类型。
#![allow(dead_code)] // 每个集成测试各自 `mod common;`，用不到的那些不该报警告。

use utls::hello::{ClientHelloId, ClientHelloSpec, HandshakeInputs};
use utls::values as v;

/// 规范输入：SNI 由调用方给、不给 ALPN
/// （用预设自带的）、按 `key_share` 的每个组给**长度正确**的哑公钥。
///
/// 长度必须真：它决定总长，进而决定 `BoringPaddingStyle` 要不要填充。
pub fn canonical_inputs(spec: &ClientHelloSpec, sni: Option<&str>) -> HandshakeInputs {
    canonical_inputs_with_seed(spec, sni, 0)
}

/// 同上，但换一个 seed —— 用来观测「总长/顺序随连接变化」这件事。
/// `seed` 是私有的（刻意的：调用方不该能把每连接变化关掉或固定），所以这里只能
/// 走公开的 `deterministic()`。
pub fn canonical_inputs_with_seed(
    spec: &ClientHelloSpec,
    sni: Option<&str>,
    seed: u8,
) -> HandshakeInputs {
    let mut inputs = HandshakeInputs::deterministic([seed; 32]);
    inputs.sni = sni.map(str::to_string);
    let groups: Vec<u16> = spec.key_share_groups();
    inputs.key_exchange = groups
        .into_iter()
        .map(|g| {
            let len = v::group_public_key_len(g)
                .unwrap_or_else(|| panic!("values::group_public_key_len 不认组 {g}"));
            (g, vec![0x5A; len])
        })
        .collect();
    inputs
}

/// 把 GREASE 扩展类型折成一个哨兵值，好让两侧的「类型 → 体长」表能对齐。
///
/// GREASE 的具体取值每连接都不同（那是它的用途），所以拿它当映射的键必然配错。
pub fn normalize_ext_type(t: u16) -> u16 {
    if v::is_grease(t) {
        v::GREASE_PLACEHOLDER
    } else {
        t
    }
}

/// 按 IANA 值判断一个 u16 是不是 GREASE。
pub fn is_grease_value(x: u16) -> bool {
    v::is_grease(x)
}

/// 把一个可能是 GREASE 的 u16 折成哨兵 —— GREASE 的**具体取值每连接都不同**，
/// 所以「我们抽到 0xEAEA、夹具里是 0x0A0A」不是缺陷，而两边都折成同一个值之后，
/// 剩下的差异才是缺陷。
pub fn normalize_u16(x: u16) -> u16 {
    if is_grease_value(x) {
        v::GREASE_PLACEHOLDER
    } else {
        x
    }
}

/// 折一个 u16 列表（密码套件、支持组、支持版本……都走它）。
pub fn normalize_u16_list(xs: &[u16]) -> Vec<u16> {
    xs.iter().copied().map(normalize_u16).collect()
}

// ── 按线序读一条 ClientHello 的各段 ─────────────────────────────────────────

/// 线字节 → `(legacy_version, random, session_id, 密码套件, 压缩方法, 扩展区起止)`。
pub struct Layout<'a> {
    pub legacy_version: [u8; 2],
    pub random: &'a [u8],
    pub session_id: &'a [u8],
    pub cipher_suites: Vec<u16>,
    pub compression_methods: &'a [u8],
    pub extensions: Vec<(u16, &'a [u8])>,
}

/// 拆开一条**完整的握手消息**（`type || u24 长度 || 体`）。
///
/// 越界即 panic：两个对账测试都拿它读固定形状的夹具，形状不对就该响。
pub fn layout(hello: &[u8]) -> Layout<'_> {
    assert_eq!(hello[0], 1, "不是 ClientHello（握手类型 {}）", hello[0]);
    let len = ((hello[1] as usize) << 16) | ((hello[2] as usize) << 8) | hello[3] as usize;
    assert_eq!(len + 4, hello.len(), "声明的握手长度与实际不符");
    let body = &hello[4..];
    let mut p = 2;
    let legacy_version = [body[0], body[1]];
    let random = &body[2..34];
    p += 32;
    let sid_len = body[p] as usize;
    p += 1;
    let session_id = &body[p..p + sid_len];
    p += sid_len;
    let cs_len = u16::from_be_bytes([body[p], body[p + 1]]) as usize;
    p += 2;
    let cipher_suites = (0..cs_len / 2)
        .map(|i| u16::from_be_bytes([body[p + i * 2], body[p + i * 2 + 1]]))
        .collect();
    p += cs_len;
    let cm_len = body[p] as usize;
    p += 1;
    let compression_methods = &body[p..p + cm_len];
    p += cm_len;
    let exts_len = u16::from_be_bytes([body[p], body[p + 1]]) as usize;
    p += 2;
    let region = &body[p..p + exts_len];
    let mut extensions = Vec::new();
    let mut q = 0usize;
    while q + 4 <= region.len() {
        let ty = u16::from_be_bytes([region[q], region[q + 1]]);
        let bl = u16::from_be_bytes([region[q + 2], region[q + 3]]) as usize;
        extensions.push((ty, &region[q + 4..q + 4 + bl]));
        q += 4 + bl;
    }
    assert_eq!(q, region.len(), "扩展区里有长度对不上的尾巴");
    Layout {
        legacy_version,
        random,
        session_id,
        cipher_suites,
        compression_methods,
        extensions,
    }
}

/// 从线字节里读出每个扩展的 `(类型, 体长)`，保持线序。
///
/// 为什么单列它：**JA3 只覆盖扩展类型，不覆盖体长**。所以「某个扩展体算错了几个字节」
/// 这类错误在 JA3 对账里完全隐形 —— 本仓就是这么漏过 `status_request` 少写 2 字节
/// 和第二个 GREASE 扩展少写 1 字节的。只有逐扩展体长能抓到。
pub fn wire_ext_lengths(hello: &[u8]) -> Vec<(u16, usize)> {
    layout(hello)
        .extensions
        .iter()
        .map(|(t, b)| (*t, b.len()))
        .collect()
}

/// 从线字节里读出每个扩展的 `(类型, 体)`。
pub fn wire_ext_bodies(hello: &[u8]) -> Vec<(u16, Vec<u8>)> {
    layout(hello)
        .extensions
        .iter()
        .map(|(t, b)| (*t, b.to_vec()))
        .collect()
}

/// 把**每连接变化**的字节折成哨兵，好让两侧的体内容可比。
///
/// 哪些是每连接变化的（因此**不可比**，只能比长度与结构）：
/// - GREASE 值：`supported_groups` / `supported_versions` / `key_share` 的组，
///   以及 GREASE 扩展**自身**的类型（类型那侧已经由 `normalize_ext_type` 处理）；
/// - `key_share` 的**公钥字节**：参照实现给的是真密钥，本仓给的是等长的哑字节；
/// - GREASE-ECH（`0xfe0d`）的整个体：config_id、封装密钥、载荷全是随机的。
///
/// 折完之后仍然能抓到的：**结构**、**长度**、**顺序**、以及一切非随机的字节
/// （SNI、ALPN、签名算法、点格式、status_request、压缩证书、ALPS……）。
/// 而这些正是「把 Opaque 升级成有类型的变体」可能弄错的地方。
pub fn normalize_body(ty: u16, body: &[u8]) -> Vec<u8> {
    const GREASE_SENTINEL: u16 = 0x0a0a;
    let norm_u16 = |x: u16| {
        if is_grease_value(x) {
            GREASE_SENTINEL
        } else {
            x
        }
    };
    match ty {
        x if x == v::EXT_SUPPORTED_GROUPS => {
            // u16 长度前缀 + u16 组
            let mut out = body.to_vec();
            let mut i = 2;
            while i + 1 < body.len() {
                let x = u16::from_be_bytes([body[i], body[i + 1]]);
                out[i..i + 2].copy_from_slice(&norm_u16(x).to_be_bytes());
                i += 2;
            }
            out
        }
        x if x == v::EXT_SUPPORTED_VERSIONS => {
            // u8 长度前缀 + u16 版本
            let mut out = body.to_vec();
            let mut i = 1;
            while i + 1 < body.len() {
                let x = u16::from_be_bytes([body[i], body[i + 1]]);
                out[i..i + 2].copy_from_slice(&norm_u16(x).to_be_bytes());
                i += 2;
            }
            out
        }
        x if x == v::EXT_KEY_SHARE => {
            // u16 列表长度 + 每项 (u16 组 + u16 公钥长 + 公钥)
            let mut out = Vec::with_capacity(body.len());
            out.extend_from_slice(&body[..2]);
            let mut i = 2;
            while i + 3 < body.len() {
                let g = u16::from_be_bytes([body[i], body[i + 1]]);
                let kl = u16::from_be_bytes([body[i + 2], body[i + 3]]) as usize;
                out.extend_from_slice(&norm_u16(g).to_be_bytes());
                out.extend_from_slice(&(kl as u16).to_be_bytes());
                out.extend(std::iter::repeat_n(0u8, kl)); // 公钥内容不可比，只留长度
                i += 4 + kl;
            }
            out
        }
        x if x == v::EXT_ENCRYPTED_CLIENT_HELLO => vec![0u8; body.len()],
        _ => body.to_vec(),
    }
}

/// 把整条 ClientHello 折成「可比形状」：随机数、会话 ID、GREASE 值与公钥都替换掉，
/// 其余逐字节保留。
///
/// `random` 与 `session_id` 传 `None` 表示**原样保留**（夹具里它们是固定值，可以直接比）。
pub fn comparable_shape(hello: &[u8], zero_random: bool, zero_session_id: bool) -> ComparableHello {
    let l = layout(hello);
    let mut ciphers = l.cipher_suites.clone();
    for c in ciphers.iter_mut() {
        if is_grease_value(*c) {
            *c = v::GREASE_PLACEHOLDER;
        }
    }
    ComparableHello {
        legacy_version: l.legacy_version,
        random: if zero_random {
            vec![0u8; l.random.len()]
        } else {
            l.random.to_vec()
        },
        session_id: if zero_session_id {
            vec![0u8; l.session_id.len()]
        } else {
            l.session_id.to_vec()
        },
        cipher_suites: ciphers,
        compression_methods: l.compression_methods.to_vec(),
        extensions: l
            .extensions
            .iter()
            .map(|(t, b)| (normalize_ext_type(*t), normalize_body(*t, b)))
            .collect(),
        total_len: hello.len(),
    }
}

/// 「可比形状」：见 [`comparable_shape`]。`Debug` 是为了让断言失败时能打印。
#[derive(Debug, PartialEq, Eq)]
pub struct ComparableHello {
    pub legacy_version: [u8; 2],
    pub random: Vec<u8>,
    pub session_id: Vec<u8>,
    pub cipher_suites: Vec<u16>,
    pub compression_methods: Vec<u8>,
    pub extensions: Vec<(u16, Vec<u8>)>,
    pub total_len: usize,
}

pub fn decode_hex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "十六进制串长度该是偶数：{s}");
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).expect("不是十六进制"))
        .collect()
}

/// 把 uTLS 的 `ClientHelloID.Str()`（夹具文件名里用的那个串，如 `Chrome-70`）
/// 映射到本仓的 id。
///
/// 只列**夹具里真正出现过**的那些：多列一个就等于替上游猜它有没有那个预设，
/// 而没列到的会在测试里以「未知预设串」响亮失败 —— 那才是上游加了夹具时该有的反应。
pub fn preset_from_utls_str(s: &str) -> Option<ClientHelloId> {
    Some(match s {
        "Chrome-58" => ClientHelloId::Chrome(58),
        "Chrome-70" => ClientHelloId::Chrome(70),
        "Firefox-55" => ClientHelloId::Firefox(55),
        "Firefox-63" => ClientHelloId::Firefox(63),
        "Golang-0" => ClientHelloId::Golang,
        _ => return None,
    })
}
