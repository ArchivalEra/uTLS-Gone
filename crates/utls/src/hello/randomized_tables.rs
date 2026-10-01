//! **自动生成 —— 不要手改。**
//!
//! 由 `crates/utls/tests/fixtures/gen-reference/extract-cipher-tables.py`
//! 从 Go uTLS 源码提取。重新生成：
//!
//! ```sh
//! python3 extract-cipher-tables.py /tmp/utls-ref/utls-master > randomized_tables.rs
//! ```
//!
//! 为什么这些数字不能手抄：见该脚本的文件头。

// uTLS 里 `defaultCipherSuites(true)`（= 下面这张偏好序减去 disabled/rsaKex/tdes）
// 算出来的结果**从未被使用** —— `p.CipherSuites` 随后被 `removeRandomCiphers` 的结果
// 覆盖。本仓因此不生成那两张表。为可追溯，把偏好序印在这里：
//   0xc02b TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
//   0xc02f TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
//   0xc02c TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
//   0xc030 TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
//   0xcca9 TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
//   0xcca8 TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
//   0xc009 TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
//   0xc013 TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
//   0xc00a TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
//   0xc014 TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
//   0x009c TLS_RSA_WITH_AES_128_GCM_SHA256
//   0x009d TLS_RSA_WITH_AES_256_GCM_SHA384
//   0x002f TLS_RSA_WITH_AES_128_CBC_SHA
//   0x0035 TLS_RSA_WITH_AES_256_CBC_SHA
//   0xc012 TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA
//   0x000a TLS_RSA_WITH_3DES_EDE_CBC_SHA
//   0xc023 TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
//   0xc027 TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
//   0x003c TLS_RSA_WITH_AES_128_CBC_SHA256
//   0xc007 TLS_ECDHE_ECDSA_WITH_RC4_128_SHA
//   0xc011 TLS_ECDHE_RSA_WITH_RC4_128_SHA
//   0x0005 TLS_RSA_WITH_RC4_128_SHA
// 减去（默认禁用）:
//   0xc023 TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
//   0xc007 TLS_ECDHE_ECDSA_WITH_RC4_128_SHA
//   0xc012 TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA
//   0xc027 TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
//   0xc011 TLS_ECDHE_RSA_WITH_RC4_128_SHA
//   0x000a TLS_RSA_WITH_3DES_EDE_CBC_SHA
//   0x002f TLS_RSA_WITH_AES_128_CBC_SHA
//   0x003c TLS_RSA_WITH_AES_128_CBC_SHA256
//   0x009c TLS_RSA_WITH_AES_128_GCM_SHA256
//   0x0035 TLS_RSA_WITH_AES_256_CBC_SHA
//   0x009d TLS_RSA_WITH_AES_256_GCM_SHA384
//   0x0005 TLS_RSA_WITH_RC4_128_SHA
// ⇒ `defaultCipherSuites(true)` 是 10 条。

/// Go `defaultCipherSuitesTLS13`（`defaults.go`）。
#[rustfmt::skip]
pub(crate) const DEFAULT_CIPHER_SUITES_TLS13: &[u16] = &[
    0x1301, // TLS_AES_128_GCM_SHA256
    0x1302, // TLS_AES_256_GCM_SHA384
    0x1303, // TLS_CHACHA20_POLY1305_SHA256
];

/// Go 的 `cipherSuites` 表，**按源码顺序**，第二项是 `flags & suiteTLS12 != 0`。
///
/// 顺序即语义：`shuffledCiphers` 用 `randomTag` 与「是否 TLS1.2」排序这张表，
/// 所以抄错顺序 = 抄错指纹。
#[rustfmt::skip]
pub(crate) const SUITE_TABLE: &[(u16, bool)] = &[
    (0xcca8, true ), // TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
    (0xcca9, true ), // TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
    (0xc02f, true ), // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    (0xc02b, true ), // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
    (0xc030, true ), // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    (0xc02c, true ), // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
    (0xc027, true ), // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
    (0xc013, false), // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
    (0xc023, true ), // TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
    (0xc009, false), // TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
    (0xc014, false), // TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
    (0xc00a, false), // TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
    (0x009c, true ), // TLS_RSA_WITH_AES_128_GCM_SHA256
    (0x009d, true ), // TLS_RSA_WITH_AES_256_GCM_SHA384
    (0x003c, true ), // TLS_RSA_WITH_AES_128_CBC_SHA256
    (0x002f, false), // TLS_RSA_WITH_AES_128_CBC_SHA
    (0x0035, false), // TLS_RSA_WITH_AES_256_CBC_SHA
    (0xc012, false), // TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA
    (0x000a, false), // TLS_RSA_WITH_3DES_EDE_CBC_SHA
    (0x0005, false), // TLS_RSA_WITH_RC4_128_SHA
    (0xc011, false), // TLS_ECDHE_RSA_WITH_RC4_128_SHA
    (0xc007, false), // TLS_ECDHE_ECDSA_WITH_RC4_128_SHA
];
