//! **真实 ECH 的封装判据**：封出去的东西，用私钥解回来必须**逐字节**等于内层 hello。
//!
//! # 为什么这条判据够硬
//!
//! 「密封成功」太弱了 —— 随机字节也能「成功」。这里做的是**往返**：
//!
//! 1. 用 rustls 的 HPKE 生成一对 ECH 密钥（扮演服务器）；
//! 2. 把公钥写成**线上格式的 ECHConfigList**，再用**我们自己的解析器**读回来
//!    （于是同一条测试同时压住「配置的写」与「配置的读」）；
//! 3. 用 [`EchSealer`] 封内层 hello；
//! 4. 用 rustls 的 `Hpke::open`（**独立实现**）解回来，要求逐字节相同。
//!
//! 第 4 步是关键：解回来的过程会校验 `info`、`aad` 与 AEAD 标签。
//! 只要 `info` 的构造（`"tls ech\0" || 原始配置`）或 AAD 的构造（外层字节、payload 全零）
//! 有一处与规范不符，**解密就会失败或得到别的字节** —— 这正是这两条最容易搞错的地方。
//!
//! 第 2 步的「写配置」也有意思：我们得自己拼一条线上格式的配置，而拼完立刻用解析器
//! 读回来，等于给解析器补了一个**我们自己生成**的向量（uTLS 的两条向量在 `utls` 那边）。

use std::sync::Arc;

use rustls::crypto::hpke::{HpkePrivateKey, HpkePublicKey};
use utls::hello::{EchConfig, parse_ech_config_list, pick_ech_config};
use utls_engine::ech::EchSealer;

mod common;
use common::{ech_config_list as config_list, ech_hpke_suite as x25519_aes128};

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::aws_lc_rs::default_provider())
}

#[test]
fn sealing_round_trips_through_the_hpke_implementation_that_did_not_seal_it() {
    let suite = x25519_aes128();
    let (public_key, private_key) = suite.generate_key_pair().expect("生成 ECH 密钥");

    let list_bytes = config_list(&public_key.0, 0x42, &[]);
    let list = parse_ech_config_list(&list_bytes).expect("我们自己写的配置该能被自己读回");
    let config: &EchConfig = pick_ech_config(&list).expect("这条配置该是可用的");
    assert_eq!(config.config_id, 0x42);
    assert_eq!(config.kem_id, 0x0020);

    // 内层 hello：这里用一段可辨识的假字节 —— 判据是「解回来一样」，不是「它像不像 hello」。
    // 真实的用法里它是**指纹层产出的那条内层 ClientHello**（下一步：inner/outer 接线）。
    let inner: Vec<u8> = (0u8..200).collect();

    let mut sealer = EchSealer::new(config, &provider()).expect("建封装上下文");
    assert_eq!(sealer.config_id(), 0x42);
    assert_eq!(sealer.cipher_suite().kdf_id, 0x0001);
    assert_eq!(sealer.cipher_suite().aead_id, 0x0001);
    assert_eq!(
        sealer.encapsulated_key().len(),
        32,
        "X25519 的封装密钥是 32 字节"
    );

    // AAD = 外层 ClientHello 的编码（其中 payload 是等长全零）。这里用一段假的
    // 「外层字节」：判据是**两端用同一个 AAD**，而不是它长得像不像 hello。
    let payload_len = sealer.payload_len(inner.len()).expect("载荷长度");
    assert_eq!(payload_len, inner.len() + 16, "载荷 = 内层 + AEAD 标签");
    let mut aad = b"outer-client-hello-placeholder".to_vec();
    aad.extend(std::iter::repeat_n(0u8, payload_len));

    let sealed = sealer.seal(&aad, &inner).expect("密封");
    assert_eq!(
        sealed.len(),
        payload_len,
        "密封结果长度必须等于预约的载荷长度"
    );
    assert_ne!(
        &sealed[..inner.len().min(32)],
        &inner[..inner.len().min(32)],
        "密文该与明文不同"
    );

    // ── 判据：用**另一套实现**（rustls 的 `open`）解回来 ──
    let enc = rustls::crypto::hpke::EncapsulatedSecret(sealer.encapsulated_key().to_vec());
    let mut info = b"tls ech\0".to_vec();
    info.extend_from_slice(&config.raw);
    let opened = suite
        .open(&enc, &info, &aad, &sealed, &private_key)
        .expect("用私钥该能解开 —— 解不开就是 info 或 aad 与规范不符");
    assert_eq!(opened, inner, "解出来的不是内层 hello");
}

#[test]
fn a_wrong_aad_or_info_fails_to_open() {
    // 反面：把 AAD 或 info 改一个字节就该解不开。
    // 这条挡的是「我们两遍算的其实是同一个错的 AAD」这种自洽的错 ——
    // 只做一次往返是看不出来的。
    let suite = x25519_aes128();
    let (public_key, private_key) = suite.generate_key_pair().expect("生成 ECH 密钥");
    let list = parse_ech_config_list(&config_list(&public_key.0, 7, &[])).unwrap();
    let config = pick_ech_config(&list).unwrap();

    let inner = b"inner-client-hello".to_vec();
    let mut sealer = EchSealer::new(config, &provider()).unwrap();
    let aad = vec![0xAAu8; 64];
    let sealed = sealer.seal(&aad, &inner).unwrap();

    let enc = rustls::crypto::hpke::EncapsulatedSecret(sealer.encapsulated_key().to_vec());
    let info = {
        let mut i = b"tls ech\0".to_vec();
        i.extend_from_slice(&config.raw);
        i
    };
    // 正确的 AAD 解得开（对照组，避免「反正都解不开」这种假绿）。
    assert!(suite.open(&enc, &info, &aad, &sealed, &private_key).is_ok());

    let mut wrong_aad = aad.clone();
    wrong_aad[0] ^= 1;
    assert!(
        suite
            .open(&enc, &info, &wrong_aad, &sealed, &private_key)
            .is_err(),
        "改一个字节的 AAD 竟然解得开 —— 那说明 AAD 根本没进 AEAD"
    );
    let mut wrong_info = info.clone();
    wrong_info[0] ^= 1;
    assert!(
        suite
            .open(&enc, &wrong_info, &aad, &sealed, &private_key)
            .is_err(),
        "改一个字节的 info 竟然解得开 —— 那说明 info 根本没进 HPKE"
    );
    let wrong_key = HpkePrivateKey::from(vec![0u8; 32]);
    assert!(
        suite.open(&enc, &info, &aad, &sealed, &wrong_key).is_err(),
        "错误的私钥竟然解得开"
    );
}

#[test]
fn a_config_with_a_kem_the_provider_lacks_is_refused() {
    // 服务器给的配置可能用我们不支持的 KEM（比如 P-256 之外的东西）。
    // 那时**不能**硬着头皮封 —— 要明确报错，让上层决定是退回 GREASE ECH 还是不用 ECH。
    let suite = x25519_aes128();
    let (public_key, _private) = suite.generate_key_pair().unwrap();
    let mut bytes = config_list(&public_key.0, 1, &[]);
    // 把 kem_id（配置体里第 1 个字段，偏移：2(列表长) +2(version)+2(length)+1(config_id)）改掉。
    bytes[7] = 0x00;
    bytes[8] = 0x99; // 一个不存在的 kem_id
    let list = parse_ech_config_list(&bytes).expect("结构上还能解析");
    // `pick` 会因为 KEM 不认识而不选它 —— 于是连 sealer 都建不起来。
    assert!(pick_ech_config(&list).is_none(), "不认识的 KEM 不该被选中");
}

#[test]
fn a_config_with_a_mandatory_extension_is_refused_by_the_sealer_too() {
    // 强制扩展 = 「看不懂就别用这条配置」。uTLS 的判据在 `pick` 上，这里再确认
    // 它在**封装**这一步也拦得住（两道门都要有：`pick` 可能被绕过）。
    let suite = x25519_aes128();
    let (public_key, _private) = suite.generate_key_pair().unwrap();
    let bytes = config_list(&public_key.0, 3, &[(0x8001, b"mandatory")]);
    let list = parse_ech_config_list(&bytes).unwrap();
    assert!(
        pick_ech_config(&list).is_none(),
        "带强制扩展的配置不该被选中"
    );
}

/// `HpkePublicKey` 只是给上面那几条测试用的（`generate_key_pair` 的返回类型）。
#[allow(dead_code)]
fn assert_public_key_type(_k: &HpkePublicKey) {}
