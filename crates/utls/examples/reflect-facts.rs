//! 指纹事实的**产地**。
//!
//! `zreflect/facts.py` 的 `_fingerprint_facts()` 跑这个程序，把 stdout 里的
//! `key=value` 行收进事实台账。于是**文档里的指纹值只能来自一次可复跑的测量**，
//! 不是谁手抄的 —— 这正是本仓接那套事实系统的核心理由：本项目的交付物本身
//! 就是一组必须可复跑的断言。
//!
//! ```sh
//! cargo run --quiet --example reflect-facts
//! cargo run --quiet --example reflect-facts | grep '^fp_chrome_133_ja3_md5='
//! ```
//!
//! 输出约定：每行 `key=value`；`#` 开头与不含 `=` 的行被忽略。
//! 键名**不带** `fp_` 前缀 —— 那是采集器（`zreflect/facts.py` 的 `_fingerprint_facts`）
//! 加的。两边都加就会得到 `fp_fp_…`，而那种键名看起来照样正常。
//!
//! # ⚠️ 键名里不许出现 `sha` / `hash` 配十六进制值
//!
//! 陈旧断言闸门（`check_stale.py`）把 **sha / hash / 校验 / 指纹** 当敏感词，
//! 而敏感词所在行里的 8–64 位十六进制串必须有出处，且台账只认 **64 位**的 sha。
//! 一个 32 位的 MD5 值如果和 `hash` 出现在同一行，就会被判成「无出处的 sha 断言」。
//! 所以这里用 `_ja3_md5`（`md5` 不在敏感词表里）。见 `AGENTS.md` 第一条。
//!
//! # 这里的密钥材料是哑的
//!
//! `key_exchange` 里的公钥长度是**真实的**（长度进指纹：它决定 ClientHello 总长），
//! 内容是填充字节 —— 这是序列化与指纹工具，不是密码学工具。

use std::collections::BTreeSet;

use utls::hello::{ClientHelloId, ClientHelloSpec, HandshakeInputs};
use utls::values as v;

/// 一次「测量」用的固定 seed。乱序预设的 JA3 随 seed 变，所以必须钉住一个值，
/// 否则这条事实每次都改口 —— 而改口守卫会（正确地）一直拦下来。
const MEASURE_SEED: u8 = 0;
/// 检查长度稳定性时扫多少个 seed。长度不稳定是缺陷，不是随机性。
const STABILITY_PROBES: u8 = 64;

fn main() {
    randomized_facts();
    for id in ClientHelloId::implemented() {
        let Ok(spec) = ClientHelloSpec::from_preset(*id) else {
            continue;
        };
        if spec.cipher_suites.is_empty() {
            // `Custom` 是空 spec，量不出指纹 —— 跳过而不是打一个空值。
            continue;
        }
        report(*id, &spec);
    }
}

/// 随机化族的指纹事实。
///
/// 随机化指纹**由种子定义**，所以固定种子之后它就是确定的 —— 于是可以和静态预设一样
/// 进台账。这很重要：`tests/utls_randomized.rs` 证明的是「与参照实现逐字段一致」，
/// 而这里把**我们自己的产出**钉进台账，于是将来任何一处取随机的水流被改动，
/// 都会以「改口」的形式被那两道守卫拦下来。
fn randomized_facts() {
    for id in ClientHelloId::randomized_family() {
        for seed in [0u8, 1, 2] {
            let Ok(spec) = ClientHelloSpec::randomized(*id, [seed; 32], &[]) else {
                continue;
            };
            let Some(hello) = spec.marshal(&inputs_for(&spec, seed)).ok() else {
                eprintln!("# {} seed={seed}: marshal 失败，跳过", id.name());
                continue;
            };
            let ja3 = hello.ja3();
            let tag = format!("{}_seed{seed}", id.name());
            println!("{tag}_ja3_md5={}", ja3.hash_hex());
            println!("{tag}_ja3_text={}", ja3.text());
            println!("{tag}_hello_len={}", hello.len());
        }
    }
}

fn report(id: ClientHelloId, spec: &ClientHelloSpec) {
    let name = id.name();
    let Some(hello) = spec.marshal(&inputs_for(spec, MEASURE_SEED)).ok() else {
        eprintln!("# {name}: marshal 失败，跳过");
        return;
    };
    let ja3 = hello.ja3();

    println!("{name}_ja3_md5={}", ja3.hash_hex());
    println!("{name}_ja3_text={}", ja3.text());
    println!("{name}_hello_len={}", hello.len());
    println!("{name}_cipher_count={}", ja3.cipher_suites.len());
    println!("{name}_ext_count={}", ja3.extensions.len());

    // 长度必须与 seed 无关（置换不改变长度）。
    let mut lens = BTreeSet::new();
    let mut ja3s = BTreeSet::new();
    for s in 0..STABILITY_PROBES {
        let Ok(h) = spec.marshal(&inputs_for(spec, s)) else {
            println!("{name}_len_stable=error");
            return;
        };
        lens.insert(h.len());
        ja3s.insert(h.ja3().hash_hex());
    }
    println!(
        "{name}_len_stable={}",
        if lens.len() == 1 { "yes" } else { "NO" }
    );
    // 乱序预设的 JA3 本来就会变（真实 Chrome 与 rustls 0.23 都如此）。
    // 这条事实把这个性质**写进台账**，免得有人把它当缺陷去「修」。
    println!(
        "{name}_ja3_stable={}",
        if ja3s.len() == 1 { "yes" } else { "no" }
    );
}

/// 按 spec 里的 `key_share` 组给出**长度正确**的哑公钥。
fn inputs_for(spec: &ClientHelloSpec, seed: u8) -> HandshakeInputs {
    let mut inputs = HandshakeInputs::deterministic([seed; 32]);
    inputs.sni = Some("example.com".into());
    // GREASE 条目不需要公钥（编码器给它一个字节的 {0}）。
    let groups: Vec<u16> = spec.key_share_groups();
    inputs.key_exchange = groups
        .into_iter()
        .map(|g| {
            // 长度必须真：它决定 ClientHello 总长，进而决定 BoringPaddingStyle 要不要填充。
            // 用 values 里那个公开的、**唯一**的长度表 —— 两处各写一份就会漂。
            let len = v::group_public_key_len(g)
                .unwrap_or_else(|| panic!("values::group_public_key_len 不认组 {g}"));
            (g, vec![0x5A; len])
        })
        .collect();
    inputs
}
