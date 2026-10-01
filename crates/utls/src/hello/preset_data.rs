//! 预设表的数据层：其余浏览器家族各一条。
//!
//! `preset.rs` 里已有 `chrome_133` 与 `firefox_148` 两条样板；本文件是它们的同类，
//! 只是条目多。样式、注释口径、出处写法都照抄那两条 —— **这里是数据，不是代码**。
//!
//! # 数值来源
//!
//! 全部来自 Go uTLS `master` 的 `u_parrots.go`（函数 `utlsIdToSpec`，第 43 行起）。
//! 每个函数头都写明它对应哪个 `case` 与行号区间；列表内部的出处用 `u_parrots.go:61-64`
//! 这种区间注释标出。**没有一个数字是凭记忆写的**。
//!
//! # 四条跨预设的注意事项
//!
//! 1. **乱序**：uTLS 用 `ShuffleChromeTLSExtensions`（`u_parrots.go:2944-2977`）包住扩展列表的
//!    那几个预设（`u_parrots.go:552/624/698/771/844/917` ⇒ Chrome 106/115_PQ/120/120_PQ/131/133）
//!    在这里表达为 [`Variability::Shuffled`]。它固定 GREASE / padding / PSK 的位置，
//!    其余两两置换 —— 与 `encode.rs` 的 `pinned` 语义逐条对应。
//!    ⚠️ 本仓的 PSK 扩展若以 `Opaque` 表达则**不**被 pin；已移植的预设里没有 PSK，故无影响。
//! 2. **填充**：uTLS 的 `BoringPaddingStyle`（`u_tls_extensions.go:1115-1126`）是
//!    **有条件的** —— 未填充长落在 `(0xff, 0x200)` 内才填到 `0x200`，否则整条扩展不发。
//!    本文件把它原样表达为 [`Padding::BoringStyle`]：**凡 Go 的 `case` 列了
//!    `UtlsPaddingExtension` 的地方，这里就列一条 `BoringStyle`**，发不发由编码器
//!    按未填充长自己判断。
//!    ⚠️ 这里曾经写成「按规范测量输入预先判定发不发」的硬编码分支，那是错的：同一个 spec
//!    在短 SNI 下该填、长 SNI 下不该填，硬编码只能对**一个** SNI 长度正确。
//!    现在由条件本身表达，于是它对所有输入都正确。两个「都要看」的条件仍然都在：
//!    `chrome_115_pq` 的 case 列了但 Kyber 公钥 1216 字节让它永远超区间（永不发），
//!    `ios_11_1` 的 case 根本没列（本来就不该有）—— 所以「存在性」与「发不发」
//!    是两件事，`preset.rs` 的填充测试断的是前者，编码器负责后者。
//! 3. **`GetSessionID` 在 marshal 路径上没有被读**：`u_parrots.go:93` 给 Chrome 58/62 设了
//!    `sha256.Sum256`，但会话 ID 一律是 32 字节随机（`u_parrots.go:3095-3100`），
//!    所以每条预设都是 [`SessionId::Random`]`(32)`。
//! 4. **`ReuseHybridAndClassicalKeyShares`**（Firefox 148，`u_parrots.go:1534`）是**引擎**的事：
//!    它让 X25519MLKEM768 与 X25519 复用同一份 X25519 密钥材料，本层不需要任何字段 ——
//!    调用方在 `inputs.key_exchange` 里给两个组喂同一份公钥即可（见 `firefox_148` 的注释）。
//!
//! # 怎么复核这些数字
//!
//! 抄错一个数字**不会编译失败**，所以这里有三层可复跑的检查：
//!
//! 1. `preset.rs` 的 `tests` 里**每条预置一个**扩展类型序列断言，外加密码套件去重、
//!    乱序集合、iOS 的重复 `PSSWithSHA384`、以及上面第 2 条那个填充biconditional；
//! 2. `cargo run --quiet --example reflect-facts` 产出每条预置的 JA3 ——
//!    密码套件与命名组的**数值**都在 JA3 里，可以直接与 Go 侧同预置的产出对数；
//! 3. 与 Go 逐字节对照只能在真实环境做（`AGENTS.md` 第二条）：本仓没有 Go 工具链，
//!    所以第 1、2 层是本地能证伪的全部，不要把它们的全绿当成「指纹对」。

use super::spec::{
    ApplicationSettingsAlps, ClientHelloSpec, CodePoint, CompressCertificate, DelegatedCredentials,
    EcPointFormats, Extension, GreaseEchOptions, KeyShare, Padding, RenegotiationInfo, SessionId,
    SessionTicket, Variability,
};
use crate::values as v;

/// Chrome 58 / 62。
///
/// 逐条对应 uTLS `u_parrots.go:45-94` 的 `case HelloChrome_58, HelloChrome_62`。
/// **TLS 1.2 封顶**（`TLSVersMax: VersionTLS12`，:47）⇒ 列表里没有 `supported_versions`、
/// 没有 `key_share`、没有 `psk_key_exchange_modes`：协商版本只由 `legacy_version` 表达。
/// 这也是唯一报 `TLS_RSA_WITH_3DES_EDE_CBC_SHA` 的 Chrome 家族成员。
///
/// ⚠️ 填充：Go 在此预置末尾列了 `BoringPaddingStyle`（:91），但对规范测量输入
/// （SNI `example.com`）未填充长 ≈ 223 < 0xff，`BoringPaddingStyle` 返回 `willPad=false`
/// ⇒ **Go 实际不发这个扩展**，所以这里也不发。见文件头的注意事项 2。
pub(crate) fn chrome_58_62() -> ClientHelloSpec {
    ClientHelloSpec {
        legacy_version: v::LEGACY_VERSION,
        // u_parrots.go:49-64
        cipher_suites: vec![
            CodePoint::Grease,
            v::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256.into(),
            v::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256.into(),
            v::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384.into(),
            v::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384.into(),
            v::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305.into(),
            v::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305.into(),
            v::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA.into(),
            v::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA.into(),
            v::TLS_RSA_WITH_AES_128_GCM_SHA256.into(),
            v::TLS_RSA_WITH_AES_256_GCM_SHA384.into(),
            v::TLS_RSA_WITH_AES_128_CBC_SHA.into(),
            v::TLS_RSA_WITH_AES_256_CBC_SHA.into(),
            v::TLS_RSA_WITH_3DES_EDE_CBC_SHA.into(),
        ],
        compression_methods: vec![v::COMPRESSION_NONE],
        // u_parrots.go:66-92
        extensions: vec![
            // &UtlsGREASEExtension{}
            Extension::Grease,
            // &RenegotiationInfoExtension{RenegotiateOnceAsClient} —— 体是「长度 0 的连接串」
            Extension::RenegotiationInfo(RenegotiationInfo {
                renegotiated_connection: Vec::new(),
            }),
            // &SNIExtension{}
            Extension::ServerName,
            // &ExtendedMasterSecretExtension{}
            Extension::ExtendedMasterSecret,
            // &SessionTicketExtension{} —— 无 ticket，体为空
            Extension::SessionTicket(SessionTicket { ticket: Vec::new() }),
            // &SignatureAlgorithmsExtension{9 项，含 PKCS1WithSHA1}
            Extension::SignatureAlgorithms(vec![
                v::ECDSA_WITH_P256_AND_SHA256.into(),
                v::PSS_WITH_SHA256.into(),
                v::PKCS1_WITH_SHA256.into(),
                v::ECDSA_WITH_P384_AND_SHA384.into(),
                v::PSS_WITH_SHA384.into(),
                v::PKCS1_WITH_SHA384.into(),
                v::PSS_WITH_SHA512.into(),
                v::PKCS1_WITH_SHA512.into(),
                v::PKCS1_WITH_SHA1.into(),
            ]),
            // &StatusRequestExtension{} —— OCSP + 两个零长度字段
            Extension::StatusRequest,
            // &SCTExtension{}
            Extension::SignedCertificateTimestamp,
            // &ALPNExtension{"h2","http/1.1"}
            Extension::Alpn(vec![b"h2".to_vec(), b"http/1.1".to_vec()]),
            // &FakeChannelIDExtension{} —— 新码点 30032，**体为空**
            Extension::ChannelId {
                old_codepoint: false,
            },
            // &SupportedPointsExtension{[]byte{0}}
            Extension::EcPointFormats(EcPointFormats {
                formats: vec![v::POINT_FORMAT_UNCOMPRESSED],
            }),
            // &SupportedCurvesExtension{GREASE, X25519, P256, P384}（:88-89）
            Extension::SupportedGroups(vec![
                CodePoint::Grease,
                v::X25519.into(),
                v::CURVE_P256.into(),
                v::CURVE_P384.into(),
            ]),
            // 第二个 &UtlsGREASEExtension{}（:90）
            Extension::Grease,
            // &UtlsPaddingExtension{BoringPaddingStyle}（:91）—— 发不发由条件本身决定
            Extension::Padding(Padding::BoringStyle),
        ],
        session_id: SessionId::Random(32),
        variability: Variability::Stable,
    }
}

/// Chrome 70。
///
/// 逐条对应 uTLS `u_parrots.go:95-166` 的 `case HelloChrome_70`。
/// 第一个带 TLS 1.3 的 Chrome 预置：`TLSVersMin: VersionTLS10, TLSVersMax: VersionTLS13`
/// （:97-98）⇒ 有 `supported_versions`（GREASE + 1.3/1.2/1.1/1.0）、`key_share`、
/// `psk_key_exchange_modes` 与 `compress_certificate`。
/// 扩展顺序与 Chrome 72 **不同**（这里 GREASE 之后是 RenegotiationInfo，然后是 SNI），
/// 而 70 的 `SupportedCurves` 在列表**后段** —— 这不是排版差异，是两代指纹的差别。
pub(crate) fn chrome_70() -> ClientHelloSpec {
    ClientHelloSpec {
        legacy_version: v::LEGACY_VERSION,
        // u_parrots.go:99-117
        cipher_suites: vec![
            CodePoint::Grease,
            v::TLS_AES_128_GCM_SHA256.into(),
            v::TLS_AES_256_GCM_SHA384.into(),
            v::TLS_CHACHA20_POLY1305_SHA256.into(),
            v::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256.into(),
            v::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256.into(),
            v::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384.into(),
            v::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384.into(),
            v::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305.into(),
            v::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305.into(),
            v::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA.into(),
            v::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA.into(),
            v::TLS_RSA_WITH_AES_128_GCM_SHA256.into(),
            v::TLS_RSA_WITH_AES_256_GCM_SHA384.into(),
            v::TLS_RSA_WITH_AES_128_CBC_SHA.into(),
            v::TLS_RSA_WITH_AES_256_CBC_SHA.into(),
            v::TLS_RSA_WITH_3DES_EDE_CBC_SHA.into(),
        ],
        compression_methods: vec![v::COMPRESSION_NONE],
        // u_parrots.go:121-165
        extensions: vec![
            Extension::Grease,
            Extension::RenegotiationInfo(RenegotiationInfo {
                renegotiated_connection: Vec::new(),
            }),
            Extension::ServerName,
            Extension::ExtendedMasterSecret,
            Extension::SessionTicket(SessionTicket { ticket: Vec::new() }),
            // &SignatureAlgorithmsExtension{9 项，含 PKCS1WithSHA1}（:127-137）
            Extension::SignatureAlgorithms(vec![
                v::ECDSA_WITH_P256_AND_SHA256.into(),
                v::PSS_WITH_SHA256.into(),
                v::PKCS1_WITH_SHA256.into(),
                v::ECDSA_WITH_P384_AND_SHA384.into(),
                v::PSS_WITH_SHA384.into(),
                v::PKCS1_WITH_SHA384.into(),
                v::PSS_WITH_SHA512.into(),
                v::PKCS1_WITH_SHA512.into(),
                v::PKCS1_WITH_SHA1.into(),
            ]),
            Extension::StatusRequest,
            Extension::SignedCertificateTimestamp,
            Extension::Alpn(vec![b"h2".to_vec(), b"http/1.1".to_vec()]),
            Extension::ChannelId {
                old_codepoint: false,
            },
            Extension::EcPointFormats(EcPointFormats {
                formats: vec![v::POINT_FORMAT_UNCOMPRESSED],
            }),
            // &KeyShareExtension{GREASE{0}, X25519}（:145-148）
            Extension::KeyShare(KeyShare::groups([CodePoint::Grease, v::X25519.into()])),
            // &PSKKeyExchangeModesExtension{psk_dhe_ke}
            Extension::PskKeyExchangeModes {
                modes: vec![v::PSK_MODE_DHE],
            },
            // &SupportedVersionsExtension{GREASE, 1.3, 1.2, 1.1, 1.0}（:150-155）
            Extension::SupportedVersions(vec![
                CodePoint::Grease,
                v::VERSION_TLS13.into(),
                v::VERSION_TLS12.into(),
                v::VERSION_TLS11.into(),
                v::VERSION_TLS10.into(),
            ]),
            // &SupportedCurvesExtension{GREASE, X25519, P256, P384}（:156-161）
            Extension::SupportedGroups(vec![
                CodePoint::Grease,
                v::X25519.into(),
                v::CURVE_P256.into(),
                v::CURVE_P384.into(),
            ]),
            // &UtlsCompressCertExtension{brotli}
            Extension::CompressCertificate(CompressCertificate {
                algorithms: vec![v::CERT_COMPRESSION_BROTLI],
            }),
            Extension::Grease,
            // &UtlsPaddingExtension{BoringPaddingStyle}（:164）—— 落在 (0xff, 0x200) 区间内，
            // 所以按 Go 实际行为填到 512 字节握手消息。
            Extension::Padding(Padding::BoringStyle),
        ],
        session_id: SessionId::Random(32),
        variability: Variability::Stable,
    }
}

/// Chrome 72。
///
/// 逐条对应 uTLS `u_parrots.go:167-240` 的 `case HelloChrome_72`。
/// 密码套件与 Chrome 70 逐字节相同，**扩展块整个重排**（:191 起）：
/// SNI 提到第 2 位、`SupportedCurves` 提到 `RenegotiationInfo` 之后、
/// 末尾多一个 `GREASE` 之前的位置关系也不同。这一条与 Chrome 70 是「顺序即指纹」的
/// 最好例子：两代之间没有任何算法差异，但 JA3 不同。
pub(crate) fn chrome_72() -> ClientHelloSpec {
    ClientHelloSpec {
        legacy_version: v::LEGACY_VERSION,
        // u_parrots.go:169-187（与 Chrome 70 相同）
        cipher_suites: vec![
            CodePoint::Grease,
            v::TLS_AES_128_GCM_SHA256.into(),
            v::TLS_AES_256_GCM_SHA384.into(),
            v::TLS_CHACHA20_POLY1305_SHA256.into(),
            v::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256.into(),
            v::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256.into(),
            v::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384.into(),
            v::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384.into(),
            v::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305.into(),
            v::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305.into(),
            v::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA.into(),
            v::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA.into(),
            v::TLS_RSA_WITH_AES_128_GCM_SHA256.into(),
            v::TLS_RSA_WITH_AES_256_GCM_SHA384.into(),
            v::TLS_RSA_WITH_AES_128_CBC_SHA.into(),
            v::TLS_RSA_WITH_AES_256_CBC_SHA.into(),
            v::TLS_RSA_WITH_3DES_EDE_CBC_SHA.into(),
        ],
        compression_methods: vec![v::COMPRESSION_NONE],
        // u_parrots.go:191-239
        extensions: vec![
            Extension::Grease,
            Extension::ServerName,
            Extension::ExtendedMasterSecret,
            Extension::RenegotiationInfo(RenegotiationInfo {
                renegotiated_connection: Vec::new(),
            }),
            Extension::SupportedGroups(vec![
                CodePoint::Grease,
                v::X25519.into(),
                v::CURVE_P256.into(),
                v::CURVE_P384.into(),
            ]),
            Extension::EcPointFormats(EcPointFormats {
                formats: vec![v::POINT_FORMAT_UNCOMPRESSED],
            }),
            Extension::SessionTicket(SessionTicket { ticket: Vec::new() }),
            Extension::Alpn(vec![b"h2".to_vec(), b"http/1.1".to_vec()]),
            Extension::StatusRequest,
            Extension::SignatureAlgorithms(vec![
                v::ECDSA_WITH_P256_AND_SHA256.into(),
                v::PSS_WITH_SHA256.into(),
                v::PKCS1_WITH_SHA256.into(),
                v::ECDSA_WITH_P384_AND_SHA384.into(),
                v::PSS_WITH_SHA384.into(),
                v::PKCS1_WITH_SHA384.into(),
                v::PSS_WITH_SHA512.into(),
                v::PKCS1_WITH_SHA512.into(),
                v::PKCS1_WITH_SHA1.into(),
            ]),
            Extension::SignedCertificateTimestamp,
            Extension::KeyShare(KeyShare::groups([CodePoint::Grease, v::X25519.into()])),
            Extension::PskKeyExchangeModes {
                modes: vec![v::PSK_MODE_DHE],
            },
            Extension::SupportedVersions(vec![
                CodePoint::Grease,
                v::VERSION_TLS13.into(),
                v::VERSION_TLS12.into(),
                v::VERSION_TLS11.into(),
                v::VERSION_TLS10.into(),
            ]),
            Extension::CompressCertificate(CompressCertificate {
                algorithms: vec![v::CERT_COMPRESSION_BROTLI],
            }),
            Extension::Grease,
            Extension::Padding(Padding::BoringStyle),
        ],
        session_id: SessionId::Random(32),
        variability: Variability::Stable,
    }
}

/// Chrome 83。
///
/// 逐条对应 uTLS `u_parrots.go:241-312` 的 `case HelloChrome_83`。
/// 相对 Chrome 72 的两处**数据**变化：密码套件去掉 3DES（16 项），
/// 签名算法去掉 `PKCS1WithSHA1`（8 项）；扩展块顺序与 72 相同。
pub(crate) fn chrome_83() -> ClientHelloSpec {
    ClientHelloSpec {
        legacy_version: v::LEGACY_VERSION,
        // u_parrots.go:243-260
        cipher_suites: vec![
            CodePoint::Grease,
            v::TLS_AES_128_GCM_SHA256.into(),
            v::TLS_AES_256_GCM_SHA384.into(),
            v::TLS_CHACHA20_POLY1305_SHA256.into(),
            v::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256.into(),
            v::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256.into(),
            v::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384.into(),
            v::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384.into(),
            v::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305.into(),
            v::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305.into(),
            v::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA.into(),
            v::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA.into(),
            v::TLS_RSA_WITH_AES_128_GCM_SHA256.into(),
            v::TLS_RSA_WITH_AES_256_GCM_SHA384.into(),
            v::TLS_RSA_WITH_AES_128_CBC_SHA.into(),
            v::TLS_RSA_WITH_AES_256_CBC_SHA.into(),
        ],
        compression_methods: vec![v::COMPRESSION_NONE],
        // u_parrots.go:264-311
        extensions: vec![
            Extension::Grease,
            Extension::ServerName,
            Extension::ExtendedMasterSecret,
            Extension::RenegotiationInfo(RenegotiationInfo {
                renegotiated_connection: Vec::new(),
            }),
            Extension::SupportedGroups(vec![
                CodePoint::Grease,
                v::X25519.into(),
                v::CURVE_P256.into(),
                v::CURVE_P384.into(),
            ]),
            Extension::EcPointFormats(EcPointFormats {
                formats: vec![v::POINT_FORMAT_UNCOMPRESSED],
            }),
            Extension::SessionTicket(SessionTicket { ticket: Vec::new() }),
            Extension::Alpn(vec![b"h2".to_vec(), b"http/1.1".to_vec()]),
            Extension::StatusRequest,
            // 8 项，**没有** PKCS1WithSHA1（:281-290）
            Extension::SignatureAlgorithms(vec![
                v::ECDSA_WITH_P256_AND_SHA256.into(),
                v::PSS_WITH_SHA256.into(),
                v::PKCS1_WITH_SHA256.into(),
                v::ECDSA_WITH_P384_AND_SHA384.into(),
                v::PSS_WITH_SHA384.into(),
                v::PKCS1_WITH_SHA384.into(),
                v::PSS_WITH_SHA512.into(),
                v::PKCS1_WITH_SHA512.into(),
            ]),
            Extension::SignedCertificateTimestamp,
            Extension::KeyShare(KeyShare::groups([CodePoint::Grease, v::X25519.into()])),
            Extension::PskKeyExchangeModes {
                modes: vec![v::PSK_MODE_DHE],
            },
            Extension::SupportedVersions(vec![
                CodePoint::Grease,
                v::VERSION_TLS13.into(),
                v::VERSION_TLS12.into(),
                v::VERSION_TLS11.into(),
                v::VERSION_TLS10.into(),
            ]),
            Extension::CompressCertificate(CompressCertificate {
                algorithms: vec![v::CERT_COMPRESSION_BROTLI],
            }),
            Extension::Grease,
            Extension::Padding(Padding::BoringStyle),
        ],
        session_id: SessionId::Random(32),
        variability: Variability::Stable,
    }
}

/// Chrome 87。
///
/// 逐条对应 uTLS `u_parrots.go:313-384` 的 `case HelloChrome_87`。
/// 与 Chrome 83 的密码套件、扩展列表、顺序**逐条相同** —— uTLS 里这是两份独立的
/// 字面量（不是别名），这里照抄成两个函数，以便将来任何一边变动都能各自显形。
pub(crate) fn chrome_87() -> ClientHelloSpec {
    ClientHelloSpec {
        legacy_version: v::LEGACY_VERSION,
        // u_parrots.go:315-332
        cipher_suites: vec![
            CodePoint::Grease,
            v::TLS_AES_128_GCM_SHA256.into(),
            v::TLS_AES_256_GCM_SHA384.into(),
            v::TLS_CHACHA20_POLY1305_SHA256.into(),
            v::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256.into(),
            v::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256.into(),
            v::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384.into(),
            v::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384.into(),
            v::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305.into(),
            v::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305.into(),
            v::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA.into(),
            v::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA.into(),
            v::TLS_RSA_WITH_AES_128_GCM_SHA256.into(),
            v::TLS_RSA_WITH_AES_256_GCM_SHA384.into(),
            v::TLS_RSA_WITH_AES_128_CBC_SHA.into(),
            v::TLS_RSA_WITH_AES_256_CBC_SHA.into(),
        ],
        compression_methods: vec![v::COMPRESSION_NONE],
        // u_parrots.go:336-383
        extensions: vec![
            Extension::Grease,
            Extension::ServerName,
            Extension::ExtendedMasterSecret,
            Extension::RenegotiationInfo(RenegotiationInfo {
                renegotiated_connection: Vec::new(),
            }),
            Extension::SupportedGroups(vec![
                CodePoint::Grease,
                v::X25519.into(),
                v::CURVE_P256.into(),
                v::CURVE_P384.into(),
            ]),
            Extension::EcPointFormats(EcPointFormats {
                formats: vec![v::POINT_FORMAT_UNCOMPRESSED],
            }),
            Extension::SessionTicket(SessionTicket { ticket: Vec::new() }),
            Extension::Alpn(vec![b"h2".to_vec(), b"http/1.1".to_vec()]),
            Extension::StatusRequest,
            Extension::SignatureAlgorithms(vec![
                v::ECDSA_WITH_P256_AND_SHA256.into(),
                v::PSS_WITH_SHA256.into(),
                v::PKCS1_WITH_SHA256.into(),
                v::ECDSA_WITH_P384_AND_SHA384.into(),
                v::PSS_WITH_SHA384.into(),
                v::PKCS1_WITH_SHA384.into(),
                v::PSS_WITH_SHA512.into(),
                v::PKCS1_WITH_SHA512.into(),
            ]),
            Extension::SignedCertificateTimestamp,
            Extension::KeyShare(KeyShare::groups([CodePoint::Grease, v::X25519.into()])),
            Extension::PskKeyExchangeModes {
                modes: vec![v::PSK_MODE_DHE],
            },
            Extension::SupportedVersions(vec![
                CodePoint::Grease,
                v::VERSION_TLS13.into(),
                v::VERSION_TLS12.into(),
                v::VERSION_TLS11.into(),
                v::VERSION_TLS10.into(),
            ]),
            Extension::CompressCertificate(CompressCertificate {
                algorithms: vec![v::CERT_COMPRESSION_BROTLI],
            }),
            Extension::Grease,
            Extension::Padding(Padding::BoringStyle),
        ],
        session_id: SessionId::Random(32),
        variability: Variability::Stable,
    }
}

/// Chrome 96。
///
/// 逐条对应 uTLS `u_parrots.go:385-457` 的 `case HelloChrome_96`。
/// 相对 Chrome 87 只多一条 `&ApplicationSettingsExtension{"h2"}`（ALPS，码点 **17513**，
/// :453）—— 位置在 `compress_certificate` 之后、尾部 GREASE 之前。
/// 这一条是 17513 与 17613 两代 ALPS 码点的分界，注意别抄到 Chrome 131/133 的 `New` 上。
pub(crate) fn chrome_96() -> ClientHelloSpec {
    ClientHelloSpec {
        legacy_version: v::LEGACY_VERSION,
        // u_parrots.go:387-404
        cipher_suites: vec![
            CodePoint::Grease,
            v::TLS_AES_128_GCM_SHA256.into(),
            v::TLS_AES_256_GCM_SHA384.into(),
            v::TLS_CHACHA20_POLY1305_SHA256.into(),
            v::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256.into(),
            v::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256.into(),
            v::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384.into(),
            v::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384.into(),
            v::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305.into(),
            v::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305.into(),
            v::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA.into(),
            v::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA.into(),
            v::TLS_RSA_WITH_AES_128_GCM_SHA256.into(),
            v::TLS_RSA_WITH_AES_256_GCM_SHA384.into(),
            v::TLS_RSA_WITH_AES_128_CBC_SHA.into(),
            v::TLS_RSA_WITH_AES_256_CBC_SHA.into(),
        ],
        compression_methods: vec![v::COMPRESSION_NONE],
        // u_parrots.go:408-456
        extensions: vec![
            Extension::Grease,
            Extension::ServerName,
            Extension::ExtendedMasterSecret,
            Extension::RenegotiationInfo(RenegotiationInfo {
                renegotiated_connection: Vec::new(),
            }),
            Extension::SupportedGroups(vec![
                CodePoint::Grease,
                v::X25519.into(),
                v::CURVE_P256.into(),
                v::CURVE_P384.into(),
            ]),
            Extension::EcPointFormats(EcPointFormats {
                formats: vec![v::POINT_FORMAT_UNCOMPRESSED],
            }),
            Extension::SessionTicket(SessionTicket { ticket: Vec::new() }),
            Extension::Alpn(vec![b"h2".to_vec(), b"http/1.1".to_vec()]),
            Extension::StatusRequest,
            Extension::SignatureAlgorithms(vec![
                v::ECDSA_WITH_P256_AND_SHA256.into(),
                v::PSS_WITH_SHA256.into(),
                v::PKCS1_WITH_SHA256.into(),
                v::ECDSA_WITH_P384_AND_SHA384.into(),
                v::PSS_WITH_SHA384.into(),
                v::PKCS1_WITH_SHA384.into(),
                v::PSS_WITH_SHA512.into(),
                v::PKCS1_WITH_SHA512.into(),
            ]),
            Extension::SignedCertificateTimestamp,
            Extension::KeyShare(KeyShare::groups([CodePoint::Grease, v::X25519.into()])),
            Extension::PskKeyExchangeModes {
                modes: vec![v::PSK_MODE_DHE],
            },
            Extension::SupportedVersions(vec![
                CodePoint::Grease,
                v::VERSION_TLS13.into(),
                v::VERSION_TLS12.into(),
                v::VERSION_TLS11.into(),
                v::VERSION_TLS10.into(),
            ]),
            Extension::CompressCertificate(CompressCertificate {
                algorithms: vec![v::CERT_COMPRESSION_BROTLI],
            }),
            // ALPS 旧码点 17513（:453）
            Extension::ApplicationSettings(ApplicationSettingsAlps {
                protocols: vec![b"h2".to_vec()],
            }),
            Extension::Grease,
            Extension::Padding(Padding::BoringStyle),
        ],
        session_id: SessionId::Random(32),
        variability: Variability::Stable,
    }
}

/// Chrome 100 / 102。
///
/// 逐条对应 uTLS `u_parrots.go:458-528` 的 `case HelloChrome_100, HelloChrome_102`。
/// 相对 Chrome 96 的**唯一**差别：`supported_versions` 从
/// GREASE+1.3/1.2/1.1/1.0 缩到 **GREASE+1.3/1.2**（:516-520）。
pub(crate) fn chrome_100_102() -> ClientHelloSpec {
    ClientHelloSpec {
        legacy_version: v::LEGACY_VERSION,
        // u_parrots.go:460-477
        cipher_suites: vec![
            CodePoint::Grease,
            v::TLS_AES_128_GCM_SHA256.into(),
            v::TLS_AES_256_GCM_SHA384.into(),
            v::TLS_CHACHA20_POLY1305_SHA256.into(),
            v::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256.into(),
            v::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256.into(),
            v::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384.into(),
            v::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384.into(),
            v::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305.into(),
            v::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305.into(),
            v::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA.into(),
            v::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA.into(),
            v::TLS_RSA_WITH_AES_128_GCM_SHA256.into(),
            v::TLS_RSA_WITH_AES_256_GCM_SHA384.into(),
            v::TLS_RSA_WITH_AES_128_CBC_SHA.into(),
            v::TLS_RSA_WITH_AES_256_CBC_SHA.into(),
        ],
        compression_methods: vec![v::COMPRESSION_NONE],
        // u_parrots.go:481-527
        extensions: vec![
            Extension::Grease,
            Extension::ServerName,
            Extension::ExtendedMasterSecret,
            Extension::RenegotiationInfo(RenegotiationInfo {
                renegotiated_connection: Vec::new(),
            }),
            Extension::SupportedGroups(vec![
                CodePoint::Grease,
                v::X25519.into(),
                v::CURVE_P256.into(),
                v::CURVE_P384.into(),
            ]),
            Extension::EcPointFormats(EcPointFormats {
                formats: vec![v::POINT_FORMAT_UNCOMPRESSED],
            }),
            Extension::SessionTicket(SessionTicket { ticket: Vec::new() }),
            Extension::Alpn(vec![b"h2".to_vec(), b"http/1.1".to_vec()]),
            Extension::StatusRequest,
            Extension::SignatureAlgorithms(vec![
                v::ECDSA_WITH_P256_AND_SHA256.into(),
                v::PSS_WITH_SHA256.into(),
                v::PKCS1_WITH_SHA256.into(),
                v::ECDSA_WITH_P384_AND_SHA384.into(),
                v::PSS_WITH_SHA384.into(),
                v::PKCS1_WITH_SHA384.into(),
                v::PSS_WITH_SHA512.into(),
                v::PKCS1_WITH_SHA512.into(),
            ]),
            Extension::SignedCertificateTimestamp,
            Extension::KeyShare(KeyShare::groups([CodePoint::Grease, v::X25519.into()])),
            Extension::PskKeyExchangeModes {
                modes: vec![v::PSK_MODE_DHE],
            },
            // 只报 1.3 与 1.2（:516-520）
            Extension::SupportedVersions(vec![
                CodePoint::Grease,
                v::VERSION_TLS13.into(),
                v::VERSION_TLS12.into(),
            ]),
            Extension::CompressCertificate(CompressCertificate {
                algorithms: vec![v::CERT_COMPRESSION_BROTLI],
            }),
            Extension::ApplicationSettings(ApplicationSettingsAlps {
                protocols: vec![b"h2".to_vec()],
            }),
            Extension::Grease,
            Extension::Padding(Padding::BoringStyle),
        ],
        session_id: SessionId::Random(32),
        variability: Variability::Stable,
    }
}

/// Chrome 106（`HelloChrome_106_Shuffle`）。
///
/// 逐条对应 uTLS `u_parrots.go:529-599` 的 `case HelloChrome_106_Shuffle`。
/// 数据与 Chrome 100/102 **逐条相同**（`diff` 核对过：两个 `case` 体只差
/// `ShuffleChromeTLSExtensions` 这层包装），差别只在扩展列表被
/// `ShuffleChromeTLSExtensions`（:552）包住 ⇒ 这里是 [`Variability::Shuffled`]。
/// uTLS 的注释（`u_common.go:626`）写明「TLS Extension shuffler enabled starting from 106」，
/// 所以 106 与 102 的差别**就是**这个行为，而不是内容。
/// 即便内容相同也照抄成一份独立字面量：两个预设共用一份数据的话，
/// 抄错 102 会让两条预设一起错，而按预设分列的测试就失去定位能力。
pub(crate) fn chrome_106_shuffle() -> ClientHelloSpec {
    ClientHelloSpec {
        legacy_version: v::LEGACY_VERSION,
        // u_parrots.go:531-547
        cipher_suites: vec![
            CodePoint::Grease,
            v::TLS_AES_128_GCM_SHA256.into(),
            v::TLS_AES_256_GCM_SHA384.into(),
            v::TLS_CHACHA20_POLY1305_SHA256.into(),
            v::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256.into(),
            v::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256.into(),
            v::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384.into(),
            v::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384.into(),
            v::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305.into(),
            v::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305.into(),
            v::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA.into(),
            v::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA.into(),
            v::TLS_RSA_WITH_AES_128_GCM_SHA256.into(),
            v::TLS_RSA_WITH_AES_256_GCM_SHA384.into(),
            v::TLS_RSA_WITH_AES_128_CBC_SHA.into(),
            v::TLS_RSA_WITH_AES_256_CBC_SHA.into(),
        ],
        compression_methods: vec![v::COMPRESSION_NONE],
        // u_parrots.go:552-598（ShuffleChromeTLSExtensions 包住）
        extensions: vec![
            Extension::Grease,
            Extension::ServerName,
            Extension::ExtendedMasterSecret,
            Extension::RenegotiationInfo(RenegotiationInfo {
                renegotiated_connection: Vec::new(),
            }),
            Extension::SupportedGroups(vec![
                CodePoint::Grease,
                v::X25519.into(),
                v::CURVE_P256.into(),
                v::CURVE_P384.into(),
            ]),
            Extension::EcPointFormats(EcPointFormats {
                formats: vec![v::POINT_FORMAT_UNCOMPRESSED],
            }),
            Extension::SessionTicket(SessionTicket { ticket: Vec::new() }),
            Extension::Alpn(vec![b"h2".to_vec(), b"http/1.1".to_vec()]),
            Extension::StatusRequest,
            Extension::SignatureAlgorithms(vec![
                v::ECDSA_WITH_P256_AND_SHA256.into(),
                v::PSS_WITH_SHA256.into(),
                v::PKCS1_WITH_SHA256.into(),
                v::ECDSA_WITH_P384_AND_SHA384.into(),
                v::PSS_WITH_SHA384.into(),
                v::PKCS1_WITH_SHA384.into(),
                v::PSS_WITH_SHA512.into(),
                v::PKCS1_WITH_SHA512.into(),
            ]),
            Extension::SignedCertificateTimestamp,
            Extension::KeyShare(KeyShare::groups([CodePoint::Grease, v::X25519.into()])),
            Extension::PskKeyExchangeModes {
                modes: vec![v::PSK_MODE_DHE],
            },
            Extension::SupportedVersions(vec![
                CodePoint::Grease,
                v::VERSION_TLS13.into(),
                v::VERSION_TLS12.into(),
            ]),
            Extension::CompressCertificate(CompressCertificate {
                algorithms: vec![v::CERT_COMPRESSION_BROTLI],
            }),
            Extension::ApplicationSettings(ApplicationSettingsAlps {
                protocols: vec![b"h2".to_vec()],
            }),
            Extension::Grease,
            Extension::Padding(Padding::BoringStyle),
        ],
        session_id: SessionId::Random(32),
        variability: Variability::Shuffled,
    }
}

/// Chrome 115（`HelloChrome_115_PQ`，PQ = Post-Quantum 密钥协商）。
///
/// 逐条对应 uTLS `u_parrots.go:601-673` 的 `case HelloChrome_115_PQ`。
/// 相对 Chrome 106 的三处数据变化：`supported_groups` 与 `key_share` 里插入
/// `X25519Kyber768Draft00`（**0x6399**，与 Chrome 131 的 `X25519MLKEM768` 不是同一个码点），
/// 而 `key_share` 报两个真密钥（Kyber 那份 1216 字节）。
/// ⚠️ uTLS 的版本串是 `"115_PQ"`（`u_common.go:639`），所以本仓用
/// [`ClientHelloId::ChromePq`](super::preset::ClientHelloId::ChromePq)`(115)` 指它，
/// 台账键名与 uTLS 一致。
///
/// ⚠️ 填充：Go 在末尾列了 `BoringPaddingStyle`（:671），但 Kyber 的公钥本身就有 1216 字节，
/// 未填充长 ≈ 1500 > 0x200 ⇒ `BoringPaddingStyle` 返回 `willPad=false`，**这个扩展永远不会发**。
/// 所以这里整条不发（与 `chrome_133` 对同一个条件的处置相同）。见文件头注意事项 2。
pub(crate) fn chrome_115_pq() -> ClientHelloSpec {
    ClientHelloSpec {
        legacy_version: v::LEGACY_VERSION,
        // u_parrots.go:603-619（与 Chrome 100 相同）
        cipher_suites: vec![
            CodePoint::Grease,
            v::TLS_AES_128_GCM_SHA256.into(),
            v::TLS_AES_256_GCM_SHA384.into(),
            v::TLS_CHACHA20_POLY1305_SHA256.into(),
            v::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256.into(),
            v::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256.into(),
            v::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384.into(),
            v::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384.into(),
            v::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305.into(),
            v::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305.into(),
            v::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA.into(),
            v::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA.into(),
            v::TLS_RSA_WITH_AES_128_GCM_SHA256.into(),
            v::TLS_RSA_WITH_AES_256_GCM_SHA384.into(),
            v::TLS_RSA_WITH_AES_128_CBC_SHA.into(),
            v::TLS_RSA_WITH_AES_256_CBC_SHA.into(),
        ],
        compression_methods: vec![v::COMPRESSION_NONE],
        // u_parrots.go:624-672（ShuffleChromeTLSExtensions 包住）
        extensions: vec![
            Extension::Grease,
            Extension::ServerName,
            Extension::ExtendedMasterSecret,
            Extension::RenegotiationInfo(RenegotiationInfo {
                renegotiated_connection: Vec::new(),
            }),
            // &SupportedCurvesExtension{GREASE, X25519Kyber768Draft00, X25519, P256, P384}
            Extension::SupportedGroups(vec![
                CodePoint::Grease,
                v::X25519_KYBER768_DRAFT00.into(),
                v::X25519.into(),
                v::CURVE_P256.into(),
                v::CURVE_P384.into(),
            ]),
            Extension::EcPointFormats(EcPointFormats {
                formats: vec![v::POINT_FORMAT_UNCOMPRESSED],
            }),
            Extension::SessionTicket(SessionTicket { ticket: Vec::new() }),
            Extension::Alpn(vec![b"h2".to_vec(), b"http/1.1".to_vec()]),
            Extension::StatusRequest,
            Extension::SignatureAlgorithms(vec![
                v::ECDSA_WITH_P256_AND_SHA256.into(),
                v::PSS_WITH_SHA256.into(),
                v::PKCS1_WITH_SHA256.into(),
                v::ECDSA_WITH_P384_AND_SHA384.into(),
                v::PSS_WITH_SHA384.into(),
                v::PKCS1_WITH_SHA384.into(),
                v::PSS_WITH_SHA512.into(),
                v::PKCS1_WITH_SHA512.into(),
            ]),
            Extension::SignedCertificateTimestamp,
            // &KeyShareExtension{GREASE{0}, X25519Kyber768Draft00, X25519}（:653-657）
            Extension::KeyShare(KeyShare::groups([
                CodePoint::Grease,
                v::X25519_KYBER768_DRAFT00.into(),
                v::X25519.into(),
            ])),
            Extension::PskKeyExchangeModes {
                modes: vec![v::PSK_MODE_DHE],
            },
            Extension::SupportedVersions(vec![
                CodePoint::Grease,
                v::VERSION_TLS13.into(),
                v::VERSION_TLS12.into(),
            ]),
            Extension::CompressCertificate(CompressCertificate {
                algorithms: vec![v::CERT_COMPRESSION_BROTLI],
            }),
            Extension::ApplicationSettings(ApplicationSettingsAlps {
                protocols: vec![b"h2".to_vec()],
            }),
            Extension::Grease,
            // &UtlsPaddingExtension{BoringPaddingStyle}（:671）
            Extension::Padding(Padding::BoringStyle),
        ],
        session_id: SessionId::Random(32),
        variability: Variability::Shuffled,
    }
}

/// Chrome 120（ECH 版）。
///
/// 逐条对应 uTLS `u_parrots.go:675-746` 的 `case HelloChrome_120`。
/// 相对 Chrome 106 多一条 `BoringGREASEECH()`（:742，在 ALPS 之后、尾部 GREASE 之前）。
/// 这也是第一批**带 GREASE ECH** 的预设之一。
///
/// ⚠️ 填充：Go 在末尾列了 `BoringPaddingStyle`（:744）。GREASE ECH 的体在 186–282 字节之间
/// 每连接变一次，未填充长因此在 0x200 上下来回 ⇒ Go 是否发 padding **随 seed 变**。
/// 本仓的模型表达不了「同一个 spec 有时发有时不发」，取的是**规范测量输入
/// （`examples/reflect-facts.rs`，seed 0）下 Go 的那一种**：见本函数末尾的实测注释。
pub(crate) fn chrome_120() -> ClientHelloSpec {
    ClientHelloSpec {
        legacy_version: v::LEGACY_VERSION,
        // u_parrots.go:677-693
        cipher_suites: vec![
            CodePoint::Grease,
            v::TLS_AES_128_GCM_SHA256.into(),
            v::TLS_AES_256_GCM_SHA384.into(),
            v::TLS_CHACHA20_POLY1305_SHA256.into(),
            v::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256.into(),
            v::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256.into(),
            v::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384.into(),
            v::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384.into(),
            v::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305.into(),
            v::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305.into(),
            v::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA.into(),
            v::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA.into(),
            v::TLS_RSA_WITH_AES_128_GCM_SHA256.into(),
            v::TLS_RSA_WITH_AES_256_GCM_SHA384.into(),
            v::TLS_RSA_WITH_AES_128_CBC_SHA.into(),
            v::TLS_RSA_WITH_AES_256_CBC_SHA.into(),
        ],
        compression_methods: vec![v::COMPRESSION_NONE],
        // u_parrots.go:698-745（ShuffleChromeTLSExtensions 包住）
        extensions: vec![
            Extension::Grease,
            Extension::ServerName,
            Extension::ExtendedMasterSecret,
            Extension::RenegotiationInfo(RenegotiationInfo {
                renegotiated_connection: Vec::new(),
            }),
            Extension::SupportedGroups(vec![
                CodePoint::Grease,
                v::X25519.into(),
                v::CURVE_P256.into(),
                v::CURVE_P384.into(),
            ]),
            Extension::EcPointFormats(EcPointFormats {
                formats: vec![v::POINT_FORMAT_UNCOMPRESSED],
            }),
            Extension::SessionTicket(SessionTicket { ticket: Vec::new() }),
            Extension::Alpn(vec![b"h2".to_vec(), b"http/1.1".to_vec()]),
            Extension::StatusRequest,
            Extension::SignatureAlgorithms(vec![
                v::ECDSA_WITH_P256_AND_SHA256.into(),
                v::PSS_WITH_SHA256.into(),
                v::PKCS1_WITH_SHA256.into(),
                v::ECDSA_WITH_P384_AND_SHA384.into(),
                v::PSS_WITH_SHA384.into(),
                v::PKCS1_WITH_SHA384.into(),
                v::PSS_WITH_SHA512.into(),
                v::PKCS1_WITH_SHA512.into(),
            ]),
            Extension::SignedCertificateTimestamp,
            Extension::KeyShare(KeyShare::groups([CodePoint::Grease, v::X25519.into()])),
            Extension::PskKeyExchangeModes {
                modes: vec![v::PSK_MODE_DHE],
            },
            Extension::SupportedVersions(vec![
                CodePoint::Grease,
                v::VERSION_TLS13.into(),
                v::VERSION_TLS12.into(),
            ]),
            Extension::CompressCertificate(CompressCertificate {
                algorithms: vec![v::CERT_COMPRESSION_BROTLI],
            }),
            Extension::ApplicationSettings(ApplicationSettingsAlps {
                protocols: vec![b"h2".to_vec()],
            }),
            // BoringGREASEECH()（:742）
            Extension::GreaseEch(GreaseEchOptions::chrome()),
            Extension::Grease,
            // &UtlsPaddingExtension{BoringPaddingStyle}（:744）—— 发不发随 GREASE ECH
            // 的载荷长度而变，而那个变化现在由条件本身表达，不再靠某一次实测去猜。
            Extension::Padding(Padding::BoringStyle),
        ],
        session_id: SessionId::Random(32),
        variability: Variability::Shuffled,
    }
}

/// Chrome 120（`HelloChrome_120_PQ`，PQ + ECH）。
///
/// 逐条对应 uTLS `u_parrots.go:748-820` 的 `case HelloChrome_120_PQ`。
/// = Chrome 120 + Kyber 组（`X25519Kyber768Draft00`）。
/// uTLS 的版本串是 `"120_PQ"`（`u_common.go:645`）⇒ 本仓用
/// [`ClientHelloId::ChromePq`](super::preset::ClientHelloId::ChromePq)`(120)`。
/// **注意 `case` 里本来就没有 padding**（:813-818 以 `GREASEECH` + `GREASE` 收尾）——
/// 与 `chrome_120` 不同，这不是省略，是 uTLS 数据里就没有。
pub(crate) fn chrome_120_pq() -> ClientHelloSpec {
    ClientHelloSpec {
        legacy_version: v::LEGACY_VERSION,
        // u_parrots.go:750-766
        cipher_suites: vec![
            CodePoint::Grease,
            v::TLS_AES_128_GCM_SHA256.into(),
            v::TLS_AES_256_GCM_SHA384.into(),
            v::TLS_CHACHA20_POLY1305_SHA256.into(),
            v::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256.into(),
            v::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256.into(),
            v::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384.into(),
            v::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384.into(),
            v::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305.into(),
            v::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305.into(),
            v::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA.into(),
            v::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA.into(),
            v::TLS_RSA_WITH_AES_128_GCM_SHA256.into(),
            v::TLS_RSA_WITH_AES_256_GCM_SHA384.into(),
            v::TLS_RSA_WITH_AES_128_CBC_SHA.into(),
            v::TLS_RSA_WITH_AES_256_CBC_SHA.into(),
        ],
        compression_methods: vec![v::COMPRESSION_NONE],
        // u_parrots.go:771-819（ShuffleChromeTLSExtensions 包住）
        extensions: vec![
            Extension::Grease,
            Extension::ServerName,
            Extension::ExtendedMasterSecret,
            Extension::RenegotiationInfo(RenegotiationInfo {
                renegotiated_connection: Vec::new(),
            }),
            Extension::SupportedGroups(vec![
                CodePoint::Grease,
                v::X25519_KYBER768_DRAFT00.into(),
                v::X25519.into(),
                v::CURVE_P256.into(),
                v::CURVE_P384.into(),
            ]),
            Extension::EcPointFormats(EcPointFormats {
                formats: vec![v::POINT_FORMAT_UNCOMPRESSED],
            }),
            Extension::SessionTicket(SessionTicket { ticket: Vec::new() }),
            Extension::Alpn(vec![b"h2".to_vec(), b"http/1.1".to_vec()]),
            Extension::StatusRequest,
            Extension::SignatureAlgorithms(vec![
                v::ECDSA_WITH_P256_AND_SHA256.into(),
                v::PSS_WITH_SHA256.into(),
                v::PKCS1_WITH_SHA256.into(),
                v::ECDSA_WITH_P384_AND_SHA384.into(),
                v::PSS_WITH_SHA384.into(),
                v::PKCS1_WITH_SHA384.into(),
                v::PSS_WITH_SHA512.into(),
                v::PKCS1_WITH_SHA512.into(),
            ]),
            Extension::SignedCertificateTimestamp,
            Extension::KeyShare(KeyShare::groups([
                CodePoint::Grease,
                v::X25519_KYBER768_DRAFT00.into(),
                v::X25519.into(),
            ])),
            Extension::PskKeyExchangeModes {
                modes: vec![v::PSK_MODE_DHE],
            },
            Extension::SupportedVersions(vec![
                CodePoint::Grease,
                v::VERSION_TLS13.into(),
                v::VERSION_TLS12.into(),
            ]),
            Extension::CompressCertificate(CompressCertificate {
                algorithms: vec![v::CERT_COMPRESSION_BROTLI],
            }),
            Extension::ApplicationSettings(ApplicationSettingsAlps {
                protocols: vec![b"h2".to_vec()],
            }),
            Extension::GreaseEch(GreaseEchOptions::chrome()),
            Extension::Grease,
        ],
        session_id: SessionId::Random(32),
        variability: Variability::Shuffled,
    }
}

/// Chrome 131。
///
/// 逐条对应 uTLS `u_parrots.go:821-893` 的 `case HelloChrome_131`。
/// = Chrome 120 + **ML-KEM 组**（`X25519MLKEM768`，码点 4588）+
/// **ALPS 仍是旧码点 17513**（:889 是 `ApplicationSettingsExtension`，不是 `…New`）。
/// ⚠️ 这一点极易抄错：`chrome_133`（:962）用的是**新**码点 17613，两条 `case` 的其余部分
/// 逐条相同（已用 `diff` 核对过：整个 `case` 体只差这一行）。把 131 抄成 `…New` 会得到
/// 一个「不存在的 Chrome」—— 线字节对不上，而代码里看不出任何异常。
/// 本 `case` 里**没有** padding（:886-891 以 `GREASEECH` + `GREASE` 收尾）。
pub(crate) fn chrome_131() -> ClientHelloSpec {
    ClientHelloSpec {
        legacy_version: v::LEGACY_VERSION,
        // u_parrots.go:823-839
        cipher_suites: vec![
            CodePoint::Grease,
            v::TLS_AES_128_GCM_SHA256.into(),
            v::TLS_AES_256_GCM_SHA384.into(),
            v::TLS_CHACHA20_POLY1305_SHA256.into(),
            v::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256.into(),
            v::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256.into(),
            v::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384.into(),
            v::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384.into(),
            v::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305.into(),
            v::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305.into(),
            v::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA.into(),
            v::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA.into(),
            v::TLS_RSA_WITH_AES_128_GCM_SHA256.into(),
            v::TLS_RSA_WITH_AES_256_GCM_SHA384.into(),
            v::TLS_RSA_WITH_AES_128_CBC_SHA.into(),
            v::TLS_RSA_WITH_AES_256_CBC_SHA.into(),
        ],
        compression_methods: vec![v::COMPRESSION_NONE],
        // u_parrots.go:844-892（ShuffleChromeTLSExtensions 包住）
        extensions: vec![
            Extension::Grease,
            Extension::ServerName,
            Extension::ExtendedMasterSecret,
            Extension::RenegotiationInfo(RenegotiationInfo {
                renegotiated_connection: Vec::new(),
            }),
            Extension::SupportedGroups(vec![
                CodePoint::Grease,
                v::X25519_MLKEM768.into(),
                v::X25519.into(),
                v::CURVE_P256.into(),
                v::CURVE_P384.into(),
            ]),
            Extension::EcPointFormats(EcPointFormats {
                formats: vec![v::POINT_FORMAT_UNCOMPRESSED],
            }),
            Extension::SessionTicket(SessionTicket { ticket: Vec::new() }),
            Extension::Alpn(vec![b"h2".to_vec(), b"http/1.1".to_vec()]),
            Extension::StatusRequest,
            Extension::SignatureAlgorithms(vec![
                v::ECDSA_WITH_P256_AND_SHA256.into(),
                v::PSS_WITH_SHA256.into(),
                v::PKCS1_WITH_SHA256.into(),
                v::ECDSA_WITH_P384_AND_SHA384.into(),
                v::PSS_WITH_SHA384.into(),
                v::PKCS1_WITH_SHA384.into(),
                v::PSS_WITH_SHA512.into(),
                v::PKCS1_WITH_SHA512.into(),
            ]),
            Extension::SignedCertificateTimestamp,
            Extension::KeyShare(KeyShare::groups([
                CodePoint::Grease,
                v::X25519_MLKEM768.into(),
                v::X25519.into(),
            ])),
            Extension::PskKeyExchangeModes {
                modes: vec![v::PSK_MODE_DHE],
            },
            Extension::SupportedVersions(vec![
                CodePoint::Grease,
                v::VERSION_TLS13.into(),
                v::VERSION_TLS12.into(),
            ]),
            Extension::CompressCertificate(CompressCertificate {
                algorithms: vec![v::CERT_COMPRESSION_BROTLI],
            }),
            // ALPS **旧**码点 17513（:889）—— 133 用的是新码点，别抄混。
            Extension::ApplicationSettings(ApplicationSettingsAlps {
                protocols: vec![b"h2".to_vec()],
            }),
            Extension::GreaseEch(GreaseEchOptions::chrome()),
            Extension::Grease,
        ],
        session_id: SessionId::Random(32),
        variability: Variability::Shuffled,
    }
}

/// Firefox 55 / 56。
///
/// 逐条对应 uTLS `u_parrots.go:967-1014` 的 `case HelloFirefox_55, HelloFirefox_56`。
/// **TLS 1.2 封顶**（`TLSVersMax: VersionTLS12`，:969）⇒ 没有 `supported_versions` /
/// `key_share` / `psk_key_exchange_modes`。
/// 这一条与 63/65 的差别不只是版本：55/56 报两个 `FAKE_TLS_DHE_RSA_*` 密码套件
/// （:982-983，**真实码点 0x0033/0x0039**），而 63/65 保留它们在列表更靠前的位置。
/// `GetSessionID: nil`（:1013）—— 与其它预设一样是 32 字节随机会话 ID。
///
/// ⚠️ 填充：Go 列了 `BoringPaddingStyle`（:1011），但本预置的未填充长 ≈ 0xd9 < 0xff
/// ⇒ `BoringPaddingStyle` 返回 `willPad=false`，**Go 实际不发**。这里因此不发。
/// 见文件头注意事项 2：SNI 变长会跨过 0xff 边界，那半边本层表达不了。
pub(crate) fn firefox_55_56() -> ClientHelloSpec {
    ClientHelloSpec {
        legacy_version: v::LEGACY_VERSION,
        // u_parrots.go:971-987
        cipher_suites: vec![
            v::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256.into(),
            v::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256.into(),
            v::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305.into(),
            v::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305.into(),
            v::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384.into(),
            v::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384.into(),
            v::TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA.into(),
            v::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA.into(),
            v::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA.into(),
            v::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA.into(),
            v::FAKE_TLS_DHE_RSA_WITH_AES_128_CBC_SHA.into(),
            v::FAKE_TLS_DHE_RSA_WITH_AES_256_CBC_SHA.into(),
            v::TLS_RSA_WITH_AES_128_CBC_SHA.into(),
            v::TLS_RSA_WITH_AES_256_CBC_SHA.into(),
            v::TLS_RSA_WITH_3DES_EDE_CBC_SHA.into(),
        ],
        compression_methods: vec![v::COMPRESSION_NONE],
        // u_parrots.go:989-1012
        extensions: vec![
            Extension::ServerName,
            Extension::ExtendedMasterSecret,
            Extension::RenegotiationInfo(RenegotiationInfo {
                renegotiated_connection: Vec::new(),
            }),
            // &SupportedCurvesExtension{X25519, P256, P384, P521}（:993）—— **无 GREASE**
            Extension::SupportedGroups(vec![
                v::X25519.into(),
                v::CURVE_P256.into(),
                v::CURVE_P384.into(),
                v::CURVE_P521.into(),
            ]),
            Extension::EcPointFormats(EcPointFormats {
                formats: vec![v::POINT_FORMAT_UNCOMPRESSED],
            }),
            Extension::SessionTicket(SessionTicket { ticket: Vec::new() }),
            Extension::Alpn(vec![b"h2".to_vec(), b"http/1.1".to_vec()]),
            Extension::StatusRequest,
            // 11 项（:998-1009）
            Extension::SignatureAlgorithms(vec![
                v::ECDSA_WITH_P256_AND_SHA256.into(),
                v::ECDSA_WITH_P384_AND_SHA384.into(),
                v::ECDSA_WITH_P521_AND_SHA512.into(),
                v::PSS_WITH_SHA256.into(),
                v::PSS_WITH_SHA384.into(),
                v::PSS_WITH_SHA512.into(),
                v::PKCS1_WITH_SHA256.into(),
                v::PKCS1_WITH_SHA384.into(),
                v::PKCS1_WITH_SHA512.into(),
                v::ECDSA_WITH_SHA1.into(),
                v::PKCS1_WITH_SHA1.into(),
            ]),
            // &UtlsPaddingExtension{BoringPaddingStyle}（:1011）
            Extension::Padding(Padding::BoringStyle),
        ],
        session_id: SessionId::Random(32),
        variability: Variability::Stable,
    }
}

/// Firefox 63 / 65。
///
/// 逐条对应 uTLS `u_parrots.go:1015-1085` 的 `case HelloFirefox_63, HelloFirefox_65`。
/// 第一个带 TLS 1.3 的 Firefox：`supported_versions` 报
/// **1.3/1.2/1.1/1.0**（注意 99 之后缩到只有 1.3/1.2），`key_share` 报
/// **X25519 与 P-256 两个真密钥**，并且首次出现 `record_size_limit`（假扩展）与
/// `psk_key_exchange_modes`。曲线表末尾是两个 FFDHE 群（0x0100/0x0101，
/// uTLS 源码里写作 `CurveID(FakeFFDHE2048)`/`FakeFFDHE3072`）。
pub(crate) fn firefox_63_65() -> ClientHelloSpec {
    ClientHelloSpec {
        legacy_version: v::LEGACY_VERSION,
        // u_parrots.go:1019-1038
        cipher_suites: vec![
            v::TLS_AES_128_GCM_SHA256.into(),
            v::TLS_CHACHA20_POLY1305_SHA256.into(),
            v::TLS_AES_256_GCM_SHA384.into(),
            v::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256.into(),
            v::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256.into(),
            v::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305.into(),
            v::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305.into(),
            v::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384.into(),
            v::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384.into(),
            v::TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA.into(),
            v::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA.into(),
            v::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA.into(),
            v::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA.into(),
            v::FAKE_TLS_DHE_RSA_WITH_AES_128_CBC_SHA.into(),
            v::FAKE_TLS_DHE_RSA_WITH_AES_256_CBC_SHA.into(),
            v::TLS_RSA_WITH_AES_128_CBC_SHA.into(),
            v::TLS_RSA_WITH_AES_256_CBC_SHA.into(),
            v::TLS_RSA_WITH_3DES_EDE_CBC_SHA.into(),
        ],
        compression_methods: vec![v::COMPRESSION_NONE],
        // u_parrots.go:1042-1084
        extensions: vec![
            Extension::ServerName,
            Extension::ExtendedMasterSecret,
            Extension::RenegotiationInfo(RenegotiationInfo {
                renegotiated_connection: Vec::new(),
            }),
            Extension::SupportedGroups(vec![
                v::X25519.into(),
                v::CURVE_P256.into(),
                v::CURVE_P384.into(),
                v::CURVE_P521.into(),
                v::FFDHE2048.into(),
                v::FFDHE3072.into(),
            ]),
            Extension::EcPointFormats(EcPointFormats {
                formats: vec![v::POINT_FORMAT_UNCOMPRESSED],
            }),
            Extension::SessionTicket(SessionTicket { ticket: Vec::new() }),
            Extension::Alpn(vec![b"h2".to_vec(), b"http/1.1".to_vec()]),
            Extension::StatusRequest,
            // &KeyShareExtension{X25519, CurveP256}（:1060-1063）—— 两个组都真发密钥
            Extension::KeyShare(KeyShare::groups([v::X25519.into(), v::CURVE_P256.into()])),
            // 报 1.3/1.2/1.1/1.0（:1064-1068）
            Extension::SupportedVersions(vec![
                v::VERSION_TLS13.into(),
                v::VERSION_TLS12.into(),
                v::VERSION_TLS11.into(),
                v::VERSION_TLS10.into(),
            ]),
            Extension::SignatureAlgorithms(vec![
                v::ECDSA_WITH_P256_AND_SHA256.into(),
                v::ECDSA_WITH_P384_AND_SHA384.into(),
                v::ECDSA_WITH_P521_AND_SHA512.into(),
                v::PSS_WITH_SHA256.into(),
                v::PSS_WITH_SHA384.into(),
                v::PSS_WITH_SHA512.into(),
                v::PKCS1_WITH_SHA256.into(),
                v::PKCS1_WITH_SHA384.into(),
                v::PKCS1_WITH_SHA512.into(),
                v::ECDSA_WITH_SHA1.into(),
                v::PKCS1_WITH_SHA1.into(),
            ]),
            Extension::PskKeyExchangeModes {
                modes: vec![v::PSK_MODE_DHE],
            },
            // &FakeRecordSizeLimitExtension{Limit: 0x4001} —— 只广播，不受支持
            Extension::RecordSizeLimit { limit: 0x4001 },
            Extension::Padding(Padding::BoringStyle),
        ],
        session_id: SessionId::Random(32),
        variability: Variability::Stable,
    }
}

/// Firefox 99。
///
/// 逐条对应 uTLS `u_parrots.go:1086-1167` 的 `case HelloFirefox_99`。
/// 相对 63/65 的三处数据变化：密码套件里的两个 `FAKE_TLS_DHE_RSA_*` 换成
/// `TLS_RSA_WITH_AES_128/256_GCM_SHA256/384`（:1104-1105）；
/// 新增 `FakeDelegatedCredentialsExtension`（码点 34，:1131-1138）；
/// `supported_versions` 仍报 1.3/1.2/1.1/1.0（:1143-1148）—— 缩到 1.3/1.2 是 102 才开始。
pub(crate) fn firefox_99() -> ClientHelloSpec {
    ClientHelloSpec {
        legacy_version: v::LEGACY_VERSION,
        // u_parrots.go:1090-1109
        cipher_suites: vec![
            v::TLS_AES_128_GCM_SHA256.into(),
            v::TLS_CHACHA20_POLY1305_SHA256.into(),
            v::TLS_AES_256_GCM_SHA384.into(),
            v::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256.into(),
            v::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256.into(),
            v::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305.into(),
            v::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305.into(),
            v::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384.into(),
            v::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384.into(),
            v::TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA.into(),
            v::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA.into(),
            v::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA.into(),
            v::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA.into(),
            v::TLS_RSA_WITH_AES_128_GCM_SHA256.into(),
            v::TLS_RSA_WITH_AES_256_GCM_SHA384.into(),
            v::TLS_RSA_WITH_AES_128_CBC_SHA.into(),
            v::TLS_RSA_WITH_AES_256_CBC_SHA.into(),
            v::TLS_RSA_WITH_3DES_EDE_CBC_SHA.into(),
        ],
        compression_methods: vec![v::COMPRESSION_NONE],
        // u_parrots.go:1113-1166
        extensions: vec![
            Extension::ServerName,
            Extension::ExtendedMasterSecret,
            Extension::RenegotiationInfo(RenegotiationInfo {
                renegotiated_connection: Vec::new(),
            }),
            Extension::SupportedGroups(vec![
                v::X25519.into(),
                v::CURVE_P256.into(),
                v::CURVE_P384.into(),
                v::CURVE_P521.into(),
                v::FFDHE2048.into(),
                v::FFDHE3072.into(),
            ]),
            Extension::EcPointFormats(EcPointFormats {
                formats: vec![v::POINT_FORMAT_UNCOMPRESSED],
            }),
            Extension::SessionTicket(SessionTicket { ticket: Vec::new() }),
            Extension::Alpn(vec![b"h2".to_vec(), b"http/1.1".to_vec()]),
            Extension::StatusRequest,
            // &FakeDelegatedCredentialsExtension{4 项}（:1131-1138）
            Extension::DelegatedCredentials(DelegatedCredentials {
                schemes: vec![
                    v::ECDSA_WITH_P256_AND_SHA256,
                    v::ECDSA_WITH_P384_AND_SHA384,
                    v::ECDSA_WITH_P521_AND_SHA512,
                    v::ECDSA_WITH_SHA1,
                ],
            }),
            Extension::KeyShare(KeyShare::groups([v::X25519.into(), v::CURVE_P256.into()])),
            Extension::SupportedVersions(vec![
                v::VERSION_TLS13.into(),
                v::VERSION_TLS12.into(),
                v::VERSION_TLS11.into(),
                v::VERSION_TLS10.into(),
            ]),
            Extension::SignatureAlgorithms(vec![
                v::ECDSA_WITH_P256_AND_SHA256.into(),
                v::ECDSA_WITH_P384_AND_SHA384.into(),
                v::ECDSA_WITH_P521_AND_SHA512.into(),
                v::PSS_WITH_SHA256.into(),
                v::PSS_WITH_SHA384.into(),
                v::PSS_WITH_SHA512.into(),
                v::PKCS1_WITH_SHA256.into(),
                v::PKCS1_WITH_SHA384.into(),
                v::PKCS1_WITH_SHA512.into(),
                v::ECDSA_WITH_SHA1.into(),
                v::PKCS1_WITH_SHA1.into(),
            ]),
            Extension::PskKeyExchangeModes {
                modes: vec![v::PSK_MODE_DHE],
            },
            Extension::RecordSizeLimit { limit: 0x4001 },
            Extension::Padding(Padding::BoringStyle),
        ],
        session_id: SessionId::Random(32),
        variability: Variability::Stable,
    }
}

/// Firefox 102。
///
/// 逐条对应 uTLS `u_parrots.go:1168-1246` 的 `case HelloFirefox_102`。
/// 相对 Firefox 99：去掉了 `TLS_RSA_WITH_3DES_EDE_CBC_SHA`（17 项），
/// `supported_versions` 缩到 **1.3/1.2**，且 **ALPN 只报 `h2`**（:1210）——
/// 这是 102 独有的中间态（99 与 105 都报 h2 + http/1.1）。
pub(crate) fn firefox_102() -> ClientHelloSpec {
    ClientHelloSpec {
        legacy_version: v::LEGACY_VERSION,
        // u_parrots.go:1172-1190
        cipher_suites: vec![
            v::TLS_AES_128_GCM_SHA256.into(),
            v::TLS_CHACHA20_POLY1305_SHA256.into(),
            v::TLS_AES_256_GCM_SHA384.into(),
            v::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256.into(),
            v::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256.into(),
            v::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305.into(),
            v::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305.into(),
            v::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384.into(),
            v::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384.into(),
            v::TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA.into(),
            v::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA.into(),
            v::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA.into(),
            v::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA.into(),
            v::TLS_RSA_WITH_AES_128_GCM_SHA256.into(),
            v::TLS_RSA_WITH_AES_256_GCM_SHA384.into(),
            v::TLS_RSA_WITH_AES_128_CBC_SHA.into(),
            v::TLS_RSA_WITH_AES_256_CBC_SHA.into(),
        ],
        compression_methods: vec![v::COMPRESSION_NONE],
        // u_parrots.go:1194-1245
        extensions: vec![
            Extension::ServerName,
            Extension::ExtendedMasterSecret,
            Extension::RenegotiationInfo(RenegotiationInfo {
                renegotiated_connection: Vec::new(),
            }),
            Extension::SupportedGroups(vec![
                v::X25519.into(),
                v::CURVE_P256.into(),
                v::CURVE_P384.into(),
                v::CURVE_P521.into(),
                v::FFDHE2048.into(),
                v::FFDHE3072.into(),
            ]),
            Extension::EcPointFormats(EcPointFormats {
                formats: vec![v::POINT_FORMAT_UNCOMPRESSED],
            }),
            Extension::SessionTicket(SessionTicket { ticket: Vec::new() }),
            // ALPN 只有 h2（:1210）
            Extension::Alpn(vec![b"h2".to_vec()]),
            Extension::StatusRequest,
            Extension::DelegatedCredentials(DelegatedCredentials {
                schemes: vec![
                    v::ECDSA_WITH_P256_AND_SHA256,
                    v::ECDSA_WITH_P384_AND_SHA384,
                    v::ECDSA_WITH_P521_AND_SHA512,
                    v::ECDSA_WITH_SHA1,
                ],
            }),
            Extension::KeyShare(KeyShare::groups([v::X25519.into(), v::CURVE_P256.into()])),
            Extension::SupportedVersions(vec![v::VERSION_TLS13.into(), v::VERSION_TLS12.into()]),
            Extension::SignatureAlgorithms(vec![
                v::ECDSA_WITH_P256_AND_SHA256.into(),
                v::ECDSA_WITH_P384_AND_SHA384.into(),
                v::ECDSA_WITH_P521_AND_SHA512.into(),
                v::PSS_WITH_SHA256.into(),
                v::PSS_WITH_SHA384.into(),
                v::PSS_WITH_SHA512.into(),
                v::PKCS1_WITH_SHA256.into(),
                v::PKCS1_WITH_SHA384.into(),
                v::PKCS1_WITH_SHA512.into(),
                v::ECDSA_WITH_SHA1.into(),
                v::PKCS1_WITH_SHA1.into(),
            ]),
            Extension::PskKeyExchangeModes {
                modes: vec![v::PSK_MODE_DHE],
            },
            Extension::RecordSizeLimit { limit: 0x4001 },
            Extension::Padding(Padding::BoringStyle),
        ],
        session_id: SessionId::Random(32),
        variability: Variability::Stable,
    }
}

/// Firefox 105。
///
/// 逐条对应 uTLS `u_parrots.go:1247-1353` 的 `case HelloFirefox_105`。
/// 数据与 Firefox 102 相同（17 项密码套件、1.3/1.2 版本、委托凭证、记录大小上限），
/// 差别只有两处、且**都不进线字节的第一层**：
///
/// 1. **ALPN 回到 `h2` + `http/1.1`**（:1295-1300）—— 这一处进字节，是唯一的真实差别；
/// 2. `TLSVersMin` 从 1.0 变 1.2（:1249）—— 本仓的模型不携带它（`legacy_version` 恒为
///    0x0303，协商版本只看 `supported_versions`，两者都是 1.3/1.2），所以数据上没有对应字段。
///
/// 源里曲线表写的是裸值 `256, 257`（:1285-1286），与 0x0100/0x0101 是同一对 FFDHE 群。
/// 与 106 同理：即便与 102 高度重合也照抄成独立字面量，好让两边的测试各自定位。
pub(crate) fn firefox_105() -> ClientHelloSpec {
    ClientHelloSpec {
        legacy_version: v::LEGACY_VERSION,
        // u_parrots.go:1251-1269（与 Firefox 102 相同）
        cipher_suites: vec![
            v::TLS_AES_128_GCM_SHA256.into(),
            v::TLS_CHACHA20_POLY1305_SHA256.into(),
            v::TLS_AES_256_GCM_SHA384.into(),
            v::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256.into(),
            v::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256.into(),
            v::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305.into(),
            v::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305.into(),
            v::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384.into(),
            v::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384.into(),
            v::TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA.into(),
            v::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA.into(),
            v::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA.into(),
            v::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA.into(),
            v::TLS_RSA_WITH_AES_128_GCM_SHA256.into(),
            v::TLS_RSA_WITH_AES_256_GCM_SHA384.into(),
            v::TLS_RSA_WITH_AES_128_CBC_SHA.into(),
            v::TLS_RSA_WITH_AES_256_CBC_SHA.into(),
        ],
        compression_methods: vec![v::COMPRESSION_NONE],
        // u_parrots.go:1273-1352
        extensions: vec![
            Extension::ServerName,
            Extension::ExtendedMasterSecret,
            Extension::RenegotiationInfo(RenegotiationInfo {
                renegotiated_connection: Vec::new(),
            }),
            // 256/257 就是 0x0100/0x0101（:1285-1286）
            Extension::SupportedGroups(vec![
                v::X25519.into(),
                v::CURVE_P256.into(),
                v::CURVE_P384.into(),
                v::CURVE_P521.into(),
                v::FFDHE2048.into(),
                v::FFDHE3072.into(),
            ]),
            Extension::EcPointFormats(EcPointFormats {
                formats: vec![v::POINT_FORMAT_UNCOMPRESSED],
            }),
            Extension::SessionTicket(SessionTicket { ticket: Vec::new() }),
            Extension::Alpn(vec![b"h2".to_vec(), b"http/1.1".to_vec()]),
            Extension::StatusRequest,
            Extension::DelegatedCredentials(DelegatedCredentials {
                schemes: vec![
                    v::ECDSA_WITH_P256_AND_SHA256,
                    v::ECDSA_WITH_P384_AND_SHA384,
                    v::ECDSA_WITH_P521_AND_SHA512,
                    v::ECDSA_WITH_SHA1,
                ],
            }),
            Extension::KeyShare(KeyShare::groups([v::X25519.into(), v::CURVE_P256.into()])),
            Extension::SupportedVersions(vec![v::VERSION_TLS13.into(), v::VERSION_TLS12.into()]),
            Extension::SignatureAlgorithms(vec![
                v::ECDSA_WITH_P256_AND_SHA256.into(),
                v::ECDSA_WITH_P384_AND_SHA384.into(),
                v::ECDSA_WITH_P521_AND_SHA512.into(),
                v::PSS_WITH_SHA256.into(),
                v::PSS_WITH_SHA384.into(),
                v::PSS_WITH_SHA512.into(),
                v::PKCS1_WITH_SHA256.into(),
                v::PKCS1_WITH_SHA384.into(),
                v::PKCS1_WITH_SHA512.into(),
                v::ECDSA_WITH_SHA1.into(),
                v::PKCS1_WITH_SHA1.into(),
            ]),
            Extension::PskKeyExchangeModes {
                modes: vec![v::PSK_MODE_DHE],
            },
            Extension::RecordSizeLimit { limit: 0x4001 },
            Extension::Padding(Padding::BoringStyle),
        ],
        session_id: SessionId::Random(32),
        variability: Variability::Stable,
    }
}

/// Firefox 120。
///
/// 逐条对应 uTLS `u_parrots.go:1354-1468` 的 `case HelloFirefox_120`。
/// 与 Firefox 105 逐条相同，**只加了一条 GREASE ECH**（:1454-1466）：
/// 两个候选套件（HKDF-SHA256 + AES-128-GCM / ChaCha20-Poly1305）、
/// **单一**载荷长度 223（⇒ 体长恒为 223+16=239）。
/// 这一条**没有 padding 扩展** —— 不是省略，uTLS 的 `case` 里就没有。
/// 它也是 `firefox_148` 的前身：148 在此之上把 ML-KEM 组插到最前、加上 `SCT`、
/// 并用 `ReuseHybridAndClassicalKeyShares` 让两个组共用一份 X25519 密钥。
pub(crate) fn firefox_120() -> ClientHelloSpec {
    ClientHelloSpec {
        legacy_version: v::LEGACY_VERSION,
        // u_parrots.go:1358-1376（与 Firefox 105 相同）
        cipher_suites: vec![
            v::TLS_AES_128_GCM_SHA256.into(),
            v::TLS_CHACHA20_POLY1305_SHA256.into(),
            v::TLS_AES_256_GCM_SHA384.into(),
            v::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256.into(),
            v::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256.into(),
            v::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305.into(),
            v::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305.into(),
            v::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384.into(),
            v::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384.into(),
            v::TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA.into(),
            v::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA.into(),
            v::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA.into(),
            v::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA.into(),
            v::TLS_RSA_WITH_AES_128_GCM_SHA256.into(),
            v::TLS_RSA_WITH_AES_256_GCM_SHA384.into(),
            v::TLS_RSA_WITH_AES_128_CBC_SHA.into(),
            v::TLS_RSA_WITH_AES_256_CBC_SHA.into(),
        ],
        compression_methods: vec![v::COMPRESSION_NONE],
        // u_parrots.go:1380-1467
        extensions: vec![
            Extension::ServerName,
            Extension::ExtendedMasterSecret,
            Extension::RenegotiationInfo(RenegotiationInfo {
                renegotiated_connection: Vec::new(),
            }),
            Extension::SupportedGroups(vec![
                v::X25519.into(),
                v::CURVE_P256.into(),
                v::CURVE_P384.into(),
                v::CURVE_P521.into(),
                v::FFDHE2048.into(),
                v::FFDHE3072.into(),
            ]),
            Extension::EcPointFormats(EcPointFormats {
                formats: vec![v::POINT_FORMAT_UNCOMPRESSED],
            }),
            Extension::SessionTicket(SessionTicket { ticket: Vec::new() }),
            Extension::Alpn(vec![b"h2".to_vec(), b"http/1.1".to_vec()]),
            Extension::StatusRequest,
            Extension::DelegatedCredentials(DelegatedCredentials {
                schemes: vec![
                    v::ECDSA_WITH_P256_AND_SHA256,
                    v::ECDSA_WITH_P384_AND_SHA384,
                    v::ECDSA_WITH_P521_AND_SHA512,
                    v::ECDSA_WITH_SHA1,
                ],
            }),
            Extension::KeyShare(KeyShare::groups([v::X25519.into(), v::CURVE_P256.into()])),
            Extension::SupportedVersions(vec![v::VERSION_TLS13.into(), v::VERSION_TLS12.into()]),
            Extension::SignatureAlgorithms(vec![
                v::ECDSA_WITH_P256_AND_SHA256.into(),
                v::ECDSA_WITH_P384_AND_SHA384.into(),
                v::ECDSA_WITH_P521_AND_SHA512.into(),
                v::PSS_WITH_SHA256.into(),
                v::PSS_WITH_SHA384.into(),
                v::PSS_WITH_SHA512.into(),
                v::PKCS1_WITH_SHA256.into(),
                v::PKCS1_WITH_SHA384.into(),
                v::PKCS1_WITH_SHA512.into(),
                v::ECDSA_WITH_SHA1.into(),
                v::PKCS1_WITH_SHA1.into(),
            ]),
            Extension::PskKeyExchangeModes {
                modes: vec![v::PSK_MODE_DHE],
            },
            Extension::RecordSizeLimit { limit: 0x4001 },
            // &GREASEEncryptedClientHelloExtension{2 套件, 载荷 223}（:1454-1466）
            Extension::GreaseEch(GreaseEchOptions::firefox()),
        ],
        session_id: SessionId::Random(32),
        variability: Variability::Stable,
    }
}

/// iOS 11.1。
///
/// 逐条对应 uTLS `u_parrots.go:1592-1650` 的 `case HelloIOS_11_1`。
/// **TLS 1.2 封顶**（`TLSVersMax: VersionTLS12`，:1594）⇒ 没有 `supported_versions` /
/// `key_share` / `psk_key_exchange_modes`，也没有 padding。这一条的两个独有记号：
///
/// - `NPNExtension{}`（:1637）—— 老式 `next_protocol_negotiation`（**码点 13172**），体为空；
/// - ALPN 报 **7 个**协议名，含 `h2-16`…`h2-14` 与 `spdy/3.1`、`spdy/3`（:1639）。
///
/// 三个 `DISABLED_TLS_*` 密码套件（:1599/1606/1613）是**真实码点**，
/// 只是 Go 实现里没有对应算法（见 `values.rs` 的说明）。
pub(crate) fn ios_11_1() -> ClientHelloSpec {
    ClientHelloSpec {
        legacy_version: v::LEGACY_VERSION,
        // u_parrots.go:1596-1617
        cipher_suites: vec![
            v::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384.into(),
            v::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256.into(),
            v::DISABLED_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384.into(),
            v::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256.into(),
            v::TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA.into(),
            v::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA.into(),
            v::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305.into(),
            v::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384.into(),
            v::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256.into(),
            v::DISABLED_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384.into(),
            v::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256.into(),
            v::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA.into(),
            v::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA.into(),
            v::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305.into(),
            v::TLS_RSA_WITH_AES_256_GCM_SHA384.into(),
            v::TLS_RSA_WITH_AES_128_GCM_SHA256.into(),
            v::DISABLED_TLS_RSA_WITH_AES_256_CBC_SHA256.into(),
            v::TLS_RSA_WITH_AES_128_CBC_SHA256.into(),
            v::TLS_RSA_WITH_AES_256_CBC_SHA.into(),
            v::TLS_RSA_WITH_AES_128_CBC_SHA.into(),
        ],
        compression_methods: vec![v::COMPRESSION_NONE],
        // u_parrots.go:1621-1649
        extensions: vec![
            // RenegotiationInfo 在 SNI **之前** —— 与 Chrome 家族的顺序相反
            Extension::RenegotiationInfo(RenegotiationInfo {
                renegotiated_connection: Vec::new(),
            }),
            Extension::ServerName,
            Extension::ExtendedMasterSecret,
            // 9 项，含 PKCS1WithSHA1（:1625-1635）
            Extension::SignatureAlgorithms(vec![
                v::ECDSA_WITH_P256_AND_SHA256.into(),
                v::PSS_WITH_SHA256.into(),
                v::PKCS1_WITH_SHA256.into(),
                v::ECDSA_WITH_P384_AND_SHA384.into(),
                v::PSS_WITH_SHA384.into(),
                v::PKCS1_WITH_SHA384.into(),
                v::PSS_WITH_SHA512.into(),
                v::PKCS1_WITH_SHA512.into(),
                v::PKCS1_WITH_SHA1.into(),
            ]),
            Extension::StatusRequest,
            // &NPNExtension{}（:1637）—— 体为空
            Extension::Npn,
            Extension::SignedCertificateTimestamp,
            Extension::Alpn(vec![
                b"h2".to_vec(),
                b"h2-16".to_vec(),
                b"h2-15".to_vec(),
                b"h2-14".to_vec(),
                b"spdy/3.1".to_vec(),
                b"spdy/3".to_vec(),
                b"http/1.1".to_vec(),
            ]),
            Extension::EcPointFormats(EcPointFormats {
                formats: vec![v::POINT_FORMAT_UNCOMPRESSED],
            }),
            Extension::SupportedGroups(vec![
                v::X25519.into(),
                v::CURVE_P256.into(),
                v::CURVE_P384.into(),
                v::CURVE_P521.into(),
            ]),
        ],
        session_id: SessionId::Random(32),
        variability: Variability::Stable,
    }
}

/// iOS 12.1。
///
/// 逐条对应 uTLS `u_parrots.go:1651-1712` 的 `case HelloIOS_12_1`。
/// 仍**没有** `supported_versions` / `key_share`（TLS 1.2 家族），但密码套件多了三项
/// 3DES 系列（:1674-1676，其中 `0xc008` 是 `FAKE_TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA`）。
/// ⚠️ **签名算法表里 `PSSWithSHA384` 出现两次**（:1691-1692）—— 那是 uTLS 源里的原样，
/// 不是抄写重复。列表内的重复值必须保留：JA3 的签名算法段是逐项拼接的字符串。
pub(crate) fn ios_12_1() -> ClientHelloSpec {
    ClientHelloSpec {
        legacy_version: v::LEGACY_VERSION,
        // u_parrots.go:1653-1677
        cipher_suites: vec![
            v::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384.into(),
            v::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256.into(),
            v::DISABLED_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384.into(),
            v::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256.into(),
            v::TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA.into(),
            v::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA.into(),
            v::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305.into(),
            v::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384.into(),
            v::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256.into(),
            v::DISABLED_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384.into(),
            v::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256.into(),
            v::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA.into(),
            v::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA.into(),
            v::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305.into(),
            v::TLS_RSA_WITH_AES_256_GCM_SHA384.into(),
            v::TLS_RSA_WITH_AES_128_GCM_SHA256.into(),
            v::DISABLED_TLS_RSA_WITH_AES_256_CBC_SHA256.into(),
            v::TLS_RSA_WITH_AES_128_CBC_SHA256.into(),
            v::TLS_RSA_WITH_AES_256_CBC_SHA.into(),
            v::TLS_RSA_WITH_AES_128_CBC_SHA.into(),
            // 源里写作裸值 0xc008（:1674）
            v::FAKE_TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA.into(),
            v::TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA.into(),
            v::TLS_RSA_WITH_3DES_EDE_CBC_SHA.into(),
        ],
        compression_methods: vec![v::COMPRESSION_NONE],
        // u_parrots.go:1681-1711
        extensions: vec![
            Extension::RenegotiationInfo(RenegotiationInfo {
                renegotiated_connection: Vec::new(),
            }),
            Extension::ServerName,
            Extension::ExtendedMasterSecret,
            // 11 项，其中 PSSWithSHA384 重复（:1685-1697）
            Extension::SignatureAlgorithms(vec![
                v::ECDSA_WITH_P256_AND_SHA256.into(),
                v::PSS_WITH_SHA256.into(),
                v::PKCS1_WITH_SHA256.into(),
                v::ECDSA_WITH_P384_AND_SHA384.into(),
                v::ECDSA_WITH_SHA1.into(),
                v::PSS_WITH_SHA384.into(),
                v::PSS_WITH_SHA384.into(),
                v::PKCS1_WITH_SHA384.into(),
                v::PSS_WITH_SHA512.into(),
                v::PKCS1_WITH_SHA512.into(),
                v::PKCS1_WITH_SHA1.into(),
            ]),
            Extension::StatusRequest,
            Extension::Npn,
            Extension::SignedCertificateTimestamp,
            Extension::Alpn(vec![
                b"h2".to_vec(),
                b"h2-16".to_vec(),
                b"h2-15".to_vec(),
                b"h2-14".to_vec(),
                b"spdy/3.1".to_vec(),
                b"spdy/3".to_vec(),
                b"http/1.1".to_vec(),
            ]),
            Extension::EcPointFormats(EcPointFormats {
                formats: vec![v::POINT_FORMAT_UNCOMPRESSED],
            }),
            Extension::SupportedGroups(vec![
                v::X25519.into(),
                v::CURVE_P256.into(),
                v::CURVE_P384.into(),
                v::CURVE_P521.into(),
            ]),
        ],
        session_id: SessionId::Random(32),
        variability: Variability::Stable,
    }
}

/// iOS 13。
///
/// 逐条对应 uTLS `u_parrots.go:1713-1789` 的 `case HelloIOS_13`。
/// 进入 TLS 1.3：密码套件以三个 TLS 1.3 套件开头，扩展里出现 `key_share`（**只有 X25519**）、
/// `psk_key_exchange_modes` 与 `supported_versions`（**1.3/1.2/1.1/1.0**），
/// 并且**去掉了 NPN**。签名算法表里 `PSSWithSHA384` 依旧重复（:1756-1757）。
/// 这是唯一报 `supported_versions` 里带 1.1/1.0 的 iOS 预设 —— 14 才有 GREASE。
pub(crate) fn ios_13() -> ClientHelloSpec {
    ClientHelloSpec {
        legacy_version: v::LEGACY_VERSION,
        // u_parrots.go:1715-1742
        cipher_suites: vec![
            v::TLS_AES_128_GCM_SHA256.into(),
            v::TLS_AES_256_GCM_SHA384.into(),
            v::TLS_CHACHA20_POLY1305_SHA256.into(),
            v::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384.into(),
            v::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256.into(),
            v::DISABLED_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384.into(),
            v::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256.into(),
            v::TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA.into(),
            v::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA.into(),
            v::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305.into(),
            v::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384.into(),
            v::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256.into(),
            v::DISABLED_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384.into(),
            v::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256.into(),
            v::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA.into(),
            v::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA.into(),
            v::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305.into(),
            v::TLS_RSA_WITH_AES_256_GCM_SHA384.into(),
            v::TLS_RSA_WITH_AES_128_GCM_SHA256.into(),
            v::DISABLED_TLS_RSA_WITH_AES_256_CBC_SHA256.into(),
            v::TLS_RSA_WITH_AES_128_CBC_SHA256.into(),
            v::TLS_RSA_WITH_AES_256_CBC_SHA.into(),
            v::TLS_RSA_WITH_AES_128_CBC_SHA.into(),
            v::FAKE_TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA.into(),
            v::TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA.into(),
            v::TLS_RSA_WITH_3DES_EDE_CBC_SHA.into(),
        ],
        compression_methods: vec![v::COMPRESSION_NONE],
        // u_parrots.go:1746-1788
        extensions: vec![
            Extension::RenegotiationInfo(RenegotiationInfo {
                renegotiated_connection: Vec::new(),
            }),
            Extension::ServerName,
            Extension::ExtendedMasterSecret,
            Extension::SignatureAlgorithms(vec![
                v::ECDSA_WITH_P256_AND_SHA256.into(),
                v::PSS_WITH_SHA256.into(),
                v::PKCS1_WITH_SHA256.into(),
                v::ECDSA_WITH_P384_AND_SHA384.into(),
                v::ECDSA_WITH_SHA1.into(),
                v::PSS_WITH_SHA384.into(),
                v::PSS_WITH_SHA384.into(),
                v::PKCS1_WITH_SHA384.into(),
                v::PSS_WITH_SHA512.into(),
                v::PKCS1_WITH_SHA512.into(),
                v::PKCS1_WITH_SHA1.into(),
            ]),
            Extension::StatusRequest,
            Extension::SignedCertificateTimestamp,
            Extension::Alpn(vec![b"h2".to_vec(), b"http/1.1".to_vec()]),
            Extension::EcPointFormats(EcPointFormats {
                formats: vec![v::POINT_FORMAT_UNCOMPRESSED],
            }),
            // 只有一个组、且只有 X25519（:1769-1771）
            Extension::KeyShare(KeyShare::groups([v::X25519.into()])),
            Extension::PskKeyExchangeModes {
                modes: vec![v::PSK_MODE_DHE],
            },
            Extension::SupportedVersions(vec![
                v::VERSION_TLS13.into(),
                v::VERSION_TLS12.into(),
                v::VERSION_TLS11.into(),
                v::VERSION_TLS10.into(),
            ]),
            // SupportedCurves 排在 supported_versions **之后**（:1781-1786）—— iOS 独有顺序
            Extension::SupportedGroups(vec![
                v::X25519.into(),
                v::CURVE_P256.into(),
                v::CURVE_P384.into(),
                v::CURVE_P521.into(),
            ]),
            Extension::Padding(Padding::BoringStyle),
        ],
        session_id: SessionId::Random(32),
        variability: Variability::Stable,
    }
}

/// iOS 14。
///
/// 逐条对应 uTLS `u_parrots.go` 的 `case HelloIOS_14`（上游该 case 无逐行注释，
/// 差别都对照 `HelloIOS_13` 标注）。与 13 相比多了四处 **GREASE**：
/// 密码套件表头、`supported_groups` 表头、`key_share` 表头、`supported_versions` 表头，
/// 外加首尾两个 GREASE **扩展**；并且 signature_algorithms 里 `PSS_WITH_SHA384`
/// **出现了两次** —— 上游原样，这里也原样（抄预设不是修预设）。
pub(crate) fn ios_14() -> ClientHelloSpec {
    ClientHelloSpec {
        legacy_version: v::LEGACY_VERSION,
        cipher_suites: vec![
            CodePoint::Grease,
            v::TLS_AES_128_GCM_SHA256.into(),
            v::TLS_AES_256_GCM_SHA384.into(),
            v::TLS_CHACHA20_POLY1305_SHA256.into(),
            v::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384.into(),
            v::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256.into(),
            v::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305.into(),
            v::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384.into(),
            v::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256.into(),
            v::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305.into(),
            v::DISABLED_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384.into(),
            v::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256.into(),
            v::TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA.into(),
            v::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA.into(),
            v::DISABLED_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384.into(),
            v::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256.into(),
            v::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA.into(),
            v::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA.into(),
            v::TLS_RSA_WITH_AES_256_GCM_SHA384.into(),
            v::TLS_RSA_WITH_AES_128_GCM_SHA256.into(),
            v::DISABLED_TLS_RSA_WITH_AES_256_CBC_SHA256.into(),
            v::TLS_RSA_WITH_AES_128_CBC_SHA256.into(),
            v::TLS_RSA_WITH_AES_256_CBC_SHA.into(),
            v::TLS_RSA_WITH_AES_128_CBC_SHA.into(),
            // 上游写的是裸值 0xc008 —— 名字表里它是 ECDHE_ECDSA_WITH_3DES
            // （FAKE_ 前缀是我们对「Go 已禁用」套件的记法）。
            v::FAKE_TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA.into(),
            v::TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA.into(),
            v::TLS_RSA_WITH_3DES_EDE_CBC_SHA.into(),
        ],
        compression_methods: vec![v::COMPRESSION_NONE],
        extensions: vec![
            Extension::Grease,
            Extension::ServerName,
            Extension::ExtendedMasterSecret,
            Extension::RenegotiationInfo(RenegotiationInfo {
                renegotiated_connection: Vec::new(),
            }),
            Extension::SupportedGroups(vec![
                CodePoint::Grease,
                v::X25519.into(),
                v::CURVE_P256.into(),
                v::CURVE_P384.into(),
                v::CURVE_P521.into(),
            ]),
            Extension::EcPointFormats(EcPointFormats {
                formats: vec![v::POINT_FORMAT_UNCOMPRESSED],
            }),
            Extension::Alpn(vec![b"h2".to_vec(), b"http/1.1".to_vec()]),
            Extension::StatusRequest,
            Extension::SignatureAlgorithms(vec![
                v::ECDSA_WITH_P256_AND_SHA256.into(),
                v::PSS_WITH_SHA256.into(),
                v::PKCS1_WITH_SHA256.into(),
                v::ECDSA_WITH_P384_AND_SHA384.into(),
                v::ECDSA_WITH_SHA1.into(),
                v::PSS_WITH_SHA384.into(),
                v::PSS_WITH_SHA384.into(),
                v::PKCS1_WITH_SHA384.into(),
                v::PSS_WITH_SHA512.into(),
                v::PKCS1_WITH_SHA512.into(),
                v::PKCS1_WITH_SHA1.into(),
            ]),
            Extension::SignedCertificateTimestamp,
            Extension::KeyShare(KeyShare::groups([CodePoint::Grease, v::X25519.into()])),
            Extension::PskKeyExchangeModes {
                modes: vec![v::PSK_MODE_DHE],
            },
            Extension::SupportedVersions(vec![
                CodePoint::Grease,
                v::VERSION_TLS13.into(),
                v::VERSION_TLS12.into(),
                v::VERSION_TLS11.into(),
                v::VERSION_TLS10.into(),
            ]),
            Extension::Grease,
            Extension::Padding(Padding::BoringStyle),
        ],
        session_id: SessionId::Random(32),
        variability: Variability::Stable,
    }
}

/// Android 11 OkHttp。
///
/// 逐条对应 uTLS `u_parrots.go:1875-1920` 的 `case HelloAndroid_11_OkHttp`。
/// 最短的一条：**7 个扩展**，没有 ALPN、没有 SCT、没有 `supported_versions`、
/// 没有 padding、没有 GREASE —— 曲线表里连 GREASE 占位都没有。
/// 这是 JA3 与「浏览器预设」直觉差异最大的一条：没有 ALPN 意味着 `0x0010` 缺席。
/// ⚠️ `&RenegotiationInfoExtension{}`（:1897）**没有**写 `Renegotiation:` 字段，
/// 但体与 `RenegotiateOnceAsClient` 相同（uTLS `u_tls_extensions.go:1653-1668` 的 `Read`
/// 只读 `RenegotiatedConnection`）⇒ 仍是 `[0]`。
pub(crate) fn android_11_okhttp() -> ClientHelloSpec {
    ClientHelloSpec {
        legacy_version: v::LEGACY_VERSION,
        // u_parrots.go:1877-1890
        cipher_suites: vec![
            v::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256.into(),
            v::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384.into(),
            // 源里写作裸值 0xcca9（:1880）
            v::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305.into(),
            v::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256.into(),
            v::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384.into(),
            // 源里写作裸值 0xcca8（:1883）
            v::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305.into(),
            v::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA.into(),
            v::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA.into(),
            v::TLS_RSA_WITH_AES_128_GCM_SHA256.into(),
            v::TLS_RSA_WITH_AES_256_GCM_SHA384.into(),
            v::TLS_RSA_WITH_AES_128_CBC_SHA.into(),
            v::TLS_RSA_WITH_AES_256_CBC_SHA.into(),
        ],
        compression_methods: vec![v::COMPRESSION_NONE],
        // u_parrots.go:1894-1919
        extensions: vec![
            Extension::ServerName,
            Extension::ExtendedMasterSecret,
            Extension::RenegotiationInfo(RenegotiationInfo {
                renegotiated_connection: Vec::new(),
            }),
            Extension::SupportedGroups(vec![
                v::X25519.into(),
                v::CURVE_P256.into(),
                v::CURVE_P384.into(),
            ]),
            Extension::EcPointFormats(EcPointFormats {
                formats: vec![v::POINT_FORMAT_UNCOMPRESSED],
            }),
            Extension::StatusRequest,
            Extension::SignatureAlgorithms(vec![
                v::ECDSA_WITH_P256_AND_SHA256.into(),
                v::PSS_WITH_SHA256.into(),
                v::PKCS1_WITH_SHA256.into(),
                v::ECDSA_WITH_P384_AND_SHA384.into(),
                v::PSS_WITH_SHA384.into(),
                v::PKCS1_WITH_SHA384.into(),
                v::PSS_WITH_SHA512.into(),
                v::PKCS1_WITH_SHA512.into(),
                v::PKCS1_WITH_SHA1.into(),
            ]),
        ],
        session_id: SessionId::Random(32),
        variability: Variability::Stable,
    }
}

/// Edge 85（Chromium 内核）。
///
/// 逐条对应 uTLS `u_parrots.go:1921-2022` 的 `case HelloEdge_85`。
/// 与 Chrome 96 的数据**几乎相同**，两处差别：`supported_versions` 报
/// GREASE+**1.3/1.2/1.1/1.0**（:2003-2010），**没有 ALPS**。
/// uTLS 把 `HelloEdge_Auto` 指向 85 并把 106 注释为「seems to be incompatible with this library」
/// （`u_common.go:657-658`）—— 本仓照抄两个 `case`，不做取舍。
pub(crate) fn edge_85() -> ClientHelloSpec {
    ClientHelloSpec {
        legacy_version: v::LEGACY_VERSION,
        // u_parrots.go:1923-1939
        cipher_suites: vec![
            CodePoint::Grease,
            v::TLS_AES_128_GCM_SHA256.into(),
            v::TLS_AES_256_GCM_SHA384.into(),
            v::TLS_CHACHA20_POLY1305_SHA256.into(),
            v::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256.into(),
            v::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256.into(),
            v::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384.into(),
            v::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384.into(),
            v::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305.into(),
            v::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305.into(),
            v::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA.into(),
            v::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA.into(),
            v::TLS_RSA_WITH_AES_128_GCM_SHA256.into(),
            v::TLS_RSA_WITH_AES_256_GCM_SHA384.into(),
            v::TLS_RSA_WITH_AES_128_CBC_SHA.into(),
            v::TLS_RSA_WITH_AES_256_CBC_SHA.into(),
        ],
        compression_methods: vec![v::COMPRESSION_NONE],
        // u_parrots.go:1944-2021
        extensions: vec![
            Extension::Grease,
            Extension::ServerName,
            Extension::ExtendedMasterSecret,
            Extension::RenegotiationInfo(RenegotiationInfo {
                renegotiated_connection: Vec::new(),
            }),
            Extension::SupportedGroups(vec![
                CodePoint::Grease,
                v::X25519.into(),
                v::CURVE_P256.into(),
                v::CURVE_P384.into(),
            ]),
            Extension::EcPointFormats(EcPointFormats {
                formats: vec![v::POINT_FORMAT_UNCOMPRESSED],
            }),
            Extension::SessionTicket(SessionTicket { ticket: Vec::new() }),
            Extension::Alpn(vec![b"h2".to_vec(), b"http/1.1".to_vec()]),
            Extension::StatusRequest,
            Extension::SignatureAlgorithms(vec![
                v::ECDSA_WITH_P256_AND_SHA256.into(),
                v::PSS_WITH_SHA256.into(),
                v::PKCS1_WITH_SHA256.into(),
                v::ECDSA_WITH_P384_AND_SHA384.into(),
                v::PSS_WITH_SHA384.into(),
                v::PKCS1_WITH_SHA384.into(),
                v::PSS_WITH_SHA512.into(),
                v::PKCS1_WITH_SHA512.into(),
            ]),
            Extension::SignedCertificateTimestamp,
            Extension::KeyShare(KeyShare::groups([CodePoint::Grease, v::X25519.into()])),
            Extension::PskKeyExchangeModes {
                modes: vec![v::PSK_MODE_DHE],
            },
            // GREASE + 1.3/1.2/1.1/1.0（:2003-2010）—— 与 Chrome 96 相同
            Extension::SupportedVersions(vec![
                CodePoint::Grease,
                v::VERSION_TLS13.into(),
                v::VERSION_TLS12.into(),
                v::VERSION_TLS11.into(),
                v::VERSION_TLS10.into(),
            ]),
            Extension::CompressCertificate(CompressCertificate {
                algorithms: vec![v::CERT_COMPRESSION_BROTLI],
            }),
            Extension::Grease,
            Extension::Padding(Padding::BoringStyle),
        ],
        session_id: SessionId::Random(32),
        variability: Variability::Stable,
    }
}

/// Edge 106（Chromium 内核）。
///
/// 逐条对应 uTLS `u_parrots.go:2023-2129` 的 `case HelloEdge_106`。
/// 数据与 Chrome 100/102 **逐条相同**（`diff` 核对过：只差 `case` 头与 `TLSVersMin/Max`
/// 那两行的显式取值，:2025-2026）—— 版本列表缩到 GREASE+1.3/1.2 并加上 ALPS 17513。
/// 也照抄成独立字面量，理由同 `chrome_106_shuffle`。
pub(crate) fn edge_106() -> ClientHelloSpec {
    ClientHelloSpec {
        legacy_version: v::LEGACY_VERSION,
        // u_parrots.go:2028-2043
        cipher_suites: vec![
            CodePoint::Grease,
            v::TLS_AES_128_GCM_SHA256.into(),
            v::TLS_AES_256_GCM_SHA384.into(),
            v::TLS_CHACHA20_POLY1305_SHA256.into(),
            v::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256.into(),
            v::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256.into(),
            v::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384.into(),
            v::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384.into(),
            v::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305.into(),
            v::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305.into(),
            v::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA.into(),
            v::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA.into(),
            v::TLS_RSA_WITH_AES_128_GCM_SHA256.into(),
            v::TLS_RSA_WITH_AES_256_GCM_SHA384.into(),
            v::TLS_RSA_WITH_AES_128_CBC_SHA.into(),
            v::TLS_RSA_WITH_AES_256_CBC_SHA.into(),
        ],
        compression_methods: vec![v::COMPRESSION_NONE],
        // u_parrots.go:2048-2128
        extensions: vec![
            Extension::Grease,
            Extension::ServerName,
            Extension::ExtendedMasterSecret,
            Extension::RenegotiationInfo(RenegotiationInfo {
                renegotiated_connection: Vec::new(),
            }),
            Extension::SupportedGroups(vec![
                CodePoint::Grease,
                v::X25519.into(),
                v::CURVE_P256.into(),
                v::CURVE_P384.into(),
            ]),
            Extension::EcPointFormats(EcPointFormats {
                formats: vec![v::POINT_FORMAT_UNCOMPRESSED],
            }),
            Extension::SessionTicket(SessionTicket { ticket: Vec::new() }),
            Extension::Alpn(vec![b"h2".to_vec(), b"http/1.1".to_vec()]),
            Extension::StatusRequest,
            Extension::SignatureAlgorithms(vec![
                v::ECDSA_WITH_P256_AND_SHA256.into(),
                v::PSS_WITH_SHA256.into(),
                v::PKCS1_WITH_SHA256.into(),
                v::ECDSA_WITH_P384_AND_SHA384.into(),
                v::PSS_WITH_SHA384.into(),
                v::PKCS1_WITH_SHA384.into(),
                v::PSS_WITH_SHA512.into(),
                v::PKCS1_WITH_SHA512.into(),
            ]),
            Extension::SignedCertificateTimestamp,
            Extension::KeyShare(KeyShare::groups([CodePoint::Grease, v::X25519.into()])),
            Extension::PskKeyExchangeModes {
                modes: vec![v::PSK_MODE_DHE],
            },
            Extension::SupportedVersions(vec![
                CodePoint::Grease,
                v::VERSION_TLS13.into(),
                v::VERSION_TLS12.into(),
            ]),
            Extension::CompressCertificate(CompressCertificate {
                algorithms: vec![v::CERT_COMPRESSION_BROTLI],
            }),
            Extension::ApplicationSettings(ApplicationSettingsAlps {
                protocols: vec![b"h2".to_vec()],
            }),
            Extension::Grease,
            Extension::Padding(Padding::BoringStyle),
        ],
        session_id: SessionId::Random(32),
        variability: Variability::Stable,
    }
}

/// Safari 16.0。
///
/// 逐条对应 uTLS `u_parrots.go:2130-2241` 的 `case HelloSafari_16_0`。
/// 两个 Safari 独有的记号：密码套件表**以 `GREASE` 开头但没有 `TLS_*` 前三项的排序差异**
/// （1.3 三个套件在 TLS 1.2 套件**之前**，且 ECDSA 排在 RSA 之前），
/// 以及 `compress_certificate` 只报 **zlib**（:2231-2235，Chrome 报 brotli）。
/// 签名算法表里 `PSSWithSHA384` 重复（:2195-2196，与 iOS 同源）。
/// ⚠️ Safari_Auto 在 uTLS 里指向 26.3（`u_common.go:660`），不是这一条。
pub(crate) fn safari_16_0() -> ClientHelloSpec {
    ClientHelloSpec {
        legacy_version: v::LEGACY_VERSION,
        // u_parrots.go:2134-2156
        cipher_suites: vec![
            CodePoint::Grease,
            v::TLS_AES_128_GCM_SHA256.into(),
            v::TLS_AES_256_GCM_SHA384.into(),
            v::TLS_CHACHA20_POLY1305_SHA256.into(),
            v::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384.into(),
            v::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256.into(),
            v::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305.into(),
            v::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384.into(),
            v::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256.into(),
            v::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305.into(),
            v::TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA.into(),
            v::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA.into(),
            v::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA.into(),
            v::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA.into(),
            v::TLS_RSA_WITH_AES_256_GCM_SHA384.into(),
            v::TLS_RSA_WITH_AES_128_GCM_SHA256.into(),
            v::TLS_RSA_WITH_AES_256_CBC_SHA.into(),
            v::TLS_RSA_WITH_AES_128_CBC_SHA.into(),
            v::FAKE_TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA.into(),
            v::TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA.into(),
            v::TLS_RSA_WITH_3DES_EDE_CBC_SHA.into(),
        ],
        compression_methods: vec![v::COMPRESSION_NONE],
        // u_parrots.go:2160-2240
        extensions: vec![
            Extension::Grease,
            Extension::ServerName,
            Extension::ExtendedMasterSecret,
            Extension::RenegotiationInfo(RenegotiationInfo {
                renegotiated_connection: Vec::new(),
            }),
            // GREASE 之后是 X25519, P256, P384, **P521**（:2167-2174）
            Extension::SupportedGroups(vec![
                CodePoint::Grease,
                v::X25519.into(),
                v::CURVE_P256.into(),
                v::CURVE_P384.into(),
                v::CURVE_P521.into(),
            ]),
            Extension::EcPointFormats(EcPointFormats {
                formats: vec![v::POINT_FORMAT_UNCOMPRESSED],
            }),
            Extension::Alpn(vec![b"h2".to_vec(), b"http/1.1".to_vec()]),
            Extension::StatusRequest,
            // 11 项，PSSWithSHA384 重复（:2188-2202）
            Extension::SignatureAlgorithms(vec![
                v::ECDSA_WITH_P256_AND_SHA256.into(),
                v::PSS_WITH_SHA256.into(),
                v::PKCS1_WITH_SHA256.into(),
                v::ECDSA_WITH_P384_AND_SHA384.into(),
                v::ECDSA_WITH_SHA1.into(),
                v::PSS_WITH_SHA384.into(),
                v::PSS_WITH_SHA384.into(),
                v::PKCS1_WITH_SHA384.into(),
                v::PSS_WITH_SHA512.into(),
                v::PKCS1_WITH_SHA512.into(),
                v::PKCS1_WITH_SHA1.into(),
            ]),
            Extension::SignedCertificateTimestamp,
            Extension::KeyShare(KeyShare::groups([CodePoint::Grease, v::X25519.into()])),
            Extension::PskKeyExchangeModes {
                modes: vec![v::PSK_MODE_DHE],
            },
            Extension::SupportedVersions(vec![
                CodePoint::Grease,
                v::VERSION_TLS13.into(),
                v::VERSION_TLS12.into(),
                v::VERSION_TLS11.into(),
                v::VERSION_TLS10.into(),
            ]),
            // 只报 zlib（:2231-2235）
            Extension::CompressCertificate(CompressCertificate {
                algorithms: vec![v::CERT_COMPRESSION_ZLIB],
            }),
            Extension::Grease,
            Extension::Padding(Padding::BoringStyle),
        ],
        session_id: SessionId::Random(32),
        variability: Variability::Stable,
    }
}

/// Safari 26.3。
///
/// 逐条对应 uTLS `u_parrots.go:2242-2351` 的 `case HelloSafari_26_3`。
/// 相对 16.0：曲线与 `key_share` 都加上 `X25519MLKEM768`（在最前），
/// 版本列表缩到 GREASE+1.3/1.2，`compress_certificate` 仍只报 zlib，
/// **没有 padding**（:2344-2349 以 `compress_certificate` + `GREASE` 收尾）。
/// **密码套件的 1.3 三项顺序变了**：这里是 AES-256-GCM 在前、AES-128-GCM 在后
/// （:2248-2250），与 16.0 的 128-在前正好相反 —— 这种顺序差异只有逐条抄才看得见。
/// `HelloSafari_Auto` 指向本预设（`u_common.go:660`）。
pub(crate) fn safari_26_3() -> ClientHelloSpec {
    ClientHelloSpec {
        legacy_version: v::LEGACY_VERSION,
        // u_parrots.go:2246-2268
        cipher_suites: vec![
            CodePoint::Grease,
            v::TLS_AES_256_GCM_SHA384.into(),
            v::TLS_CHACHA20_POLY1305_SHA256.into(),
            v::TLS_AES_128_GCM_SHA256.into(),
            v::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384.into(),
            v::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256.into(),
            v::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305.into(),
            v::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384.into(),
            v::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256.into(),
            v::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305.into(),
            v::TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA.into(),
            v::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA.into(),
            v::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA.into(),
            v::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA.into(),
            v::TLS_RSA_WITH_AES_256_GCM_SHA384.into(),
            v::TLS_RSA_WITH_AES_128_GCM_SHA256.into(),
            v::TLS_RSA_WITH_AES_256_CBC_SHA.into(),
            v::TLS_RSA_WITH_AES_128_CBC_SHA.into(),
            v::FAKE_TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA.into(),
            v::TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA.into(),
            v::TLS_RSA_WITH_3DES_EDE_CBC_SHA.into(),
        ],
        compression_methods: vec![v::COMPRESSION_NONE],
        // u_parrots.go:2272-2350
        extensions: vec![
            Extension::Grease,
            Extension::ServerName,
            Extension::ExtendedMasterSecret,
            Extension::RenegotiationInfo(RenegotiationInfo {
                renegotiated_connection: Vec::new(),
            }),
            Extension::SupportedGroups(vec![
                CodePoint::Grease,
                v::X25519_MLKEM768.into(),
                v::X25519.into(),
                v::CURVE_P256.into(),
                v::CURVE_P384.into(),
                v::CURVE_P521.into(),
            ]),
            Extension::EcPointFormats(EcPointFormats {
                formats: vec![v::POINT_FORMAT_UNCOMPRESSED],
            }),
            Extension::Alpn(vec![b"h2".to_vec(), b"http/1.1".to_vec()]),
            Extension::StatusRequest,
            // **10 项**（比 16.0 少一个 PKCS1WithSHA1），PSSWithSHA384 仍重复（:2301-2313）
            Extension::SignatureAlgorithms(vec![
                v::ECDSA_WITH_P256_AND_SHA256.into(),
                v::PSS_WITH_SHA256.into(),
                v::PKCS1_WITH_SHA256.into(),
                v::ECDSA_WITH_P384_AND_SHA384.into(),
                v::PSS_WITH_SHA384.into(),
                v::PSS_WITH_SHA384.into(),
                v::PKCS1_WITH_SHA384.into(),
                v::PSS_WITH_SHA512.into(),
                v::PKCS1_WITH_SHA512.into(),
                v::PKCS1_WITH_SHA1.into(),
            ]),
            Extension::SignedCertificateTimestamp,
            Extension::KeyShare(KeyShare::groups([
                CodePoint::Grease,
                v::X25519_MLKEM768.into(),
                v::X25519.into(),
            ])),
            Extension::PskKeyExchangeModes {
                modes: vec![v::PSK_MODE_DHE],
            },
            Extension::SupportedVersions(vec![
                CodePoint::Grease,
                v::VERSION_TLS13.into(),
                v::VERSION_TLS12.into(),
            ]),
            Extension::CompressCertificate(CompressCertificate {
                algorithms: vec![v::CERT_COMPRESSION_ZLIB],
            }),
            Extension::Grease,
        ],
        session_id: SessionId::Random(32),
        variability: Variability::Stable,
    }
}

/// 360 浏览器 7.5（IE/Chrome 混合内核）。
///
/// 逐条对应 uTLS `u_parrots.go:2352-2423` 的 `case Hello360_7_5`。
/// **TLS 1.2 封顶**、**没有 GREASE**、**没有 padding**。
/// 这一条的数据最「老」：`RC4` 系列的密码套件、`spdy/2`、老码点的 `channel_id`（**30031**）、
/// 以及两个 DSA 签名算法（`FakeSHA256WithDSA`/`FakeSHA1WithDSA`）。
/// 它是 `Hello360_Auto` 指向的那条（`u_common.go:663`）。
pub(crate) fn browser360_7_5() -> ClientHelloSpec {
    ClientHelloSpec {
        legacy_version: v::LEGACY_VERSION,
        // u_parrots.go:2354-2375
        cipher_suites: vec![
            v::TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA.into(),
            v::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA.into(),
            v::FAKE_TLS_DHE_RSA_WITH_AES_256_CBC_SHA.into(),
            v::FAKE_TLS_DHE_RSA_WITH_AES_256_CBC_SHA256.into(),
            v::TLS_RSA_WITH_AES_256_CBC_SHA.into(),
            v::DISABLED_TLS_RSA_WITH_AES_256_CBC_SHA256.into(),
            v::TLS_ECDHE_ECDSA_WITH_RC4_128_SHA.into(),
            v::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA.into(),
            v::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256.into(),
            v::TLS_ECDHE_RSA_WITH_RC4_128_SHA.into(),
            v::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA.into(),
            v::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256.into(),
            v::FAKE_TLS_DHE_RSA_WITH_AES_128_CBC_SHA.into(),
            v::FAKE_TLS_DHE_RSA_WITH_AES_128_CBC_SHA256.into(),
            v::FAKE_TLS_DHE_DSS_WITH_AES_128_CBC_SHA.into(),
            v::TLS_RSA_WITH_RC4_128_SHA.into(),
            v::FAKE_TLS_RSA_WITH_RC4_128_MD5.into(),
            v::TLS_RSA_WITH_AES_128_CBC_SHA.into(),
            v::TLS_RSA_WITH_AES_128_CBC_SHA256.into(),
            v::TLS_RSA_WITH_3DES_EDE_CBC_SHA.into(),
        ],
        compression_methods: vec![v::COMPRESSION_NONE],
        // u_parrots.go:2379-2422
        extensions: vec![
            Extension::ServerName,
            Extension::RenegotiationInfo(RenegotiationInfo {
                renegotiated_connection: Vec::new(),
            }),
            // 只有三个朴素曲线（:2384-2389）
            Extension::SupportedGroups(vec![
                v::CURVE_P256.into(),
                v::CURVE_P384.into(),
                v::CURVE_P521.into(),
            ]),
            Extension::EcPointFormats(EcPointFormats {
                formats: vec![v::POINT_FORMAT_UNCOMPRESSED],
            }),
            Extension::SessionTicket(SessionTicket { ticket: Vec::new() }),
            Extension::Npn,
            Extension::Alpn(vec![
                b"spdy/2".to_vec(),
                b"spdy/3".to_vec(),
                b"spdy/3.1".to_vec(),
                b"http/1.1".to_vec(),
            ]),
            // &FakeChannelIDExtension{OldExtensionID: true} ⇒ **30031**（:2406-2408）
            Extension::ChannelId {
                old_codepoint: true,
            },
            Extension::StatusRequest,
            // 8 项：RSA 在前，两个 DSA 在末尾（:2410-2421）
            Extension::SignatureAlgorithms(vec![
                v::PKCS1_WITH_SHA256.into(),
                v::PKCS1_WITH_SHA384.into(),
                v::PKCS1_WITH_SHA1.into(),
                v::ECDSA_WITH_P256_AND_SHA256.into(),
                v::ECDSA_WITH_P384_AND_SHA384.into(),
                v::ECDSA_WITH_SHA1.into(),
                v::FAKE_SHA256_WITH_DSA.into(),
                v::FAKE_SHA1_WITH_DSA.into(),
            ]),
        ],
        session_id: SessionId::Random(32),
        variability: Variability::Stable,
    }
}

/// 360 浏览器 11.0（极速版，Chromium 内核）。
///
/// 逐条对应 uTLS `u_parrots.go:2424-2532` 的 `case Hello360_11_0`。
/// = Chrome 70 的密码套件（含 3DES）+ Chrome 96 的扩展块，
/// 但有**两个 360 独有**的差异：`channel_id` 用的是**新**码点 30032 且位置在 `SCT` 之后
/// （:2492-2494），`supported_versions` 报 GREASE+1.3/1.2/1.1/1.0。
/// uTLS 把它注释为「seems to be incompatible with this library」（`u_common.go:663`）。
pub(crate) fn browser360_11_0() -> ClientHelloSpec {
    ClientHelloSpec {
        legacy_version: v::LEGACY_VERSION,
        // u_parrots.go:2428-2445
        cipher_suites: vec![
            CodePoint::Grease,
            v::TLS_AES_128_GCM_SHA256.into(),
            v::TLS_AES_256_GCM_SHA384.into(),
            v::TLS_CHACHA20_POLY1305_SHA256.into(),
            v::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256.into(),
            v::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256.into(),
            v::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384.into(),
            v::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384.into(),
            v::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305.into(),
            v::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305.into(),
            v::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA.into(),
            v::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA.into(),
            v::TLS_RSA_WITH_AES_128_GCM_SHA256.into(),
            v::TLS_RSA_WITH_AES_256_GCM_SHA384.into(),
            v::TLS_RSA_WITH_AES_128_CBC_SHA.into(),
            v::TLS_RSA_WITH_AES_256_CBC_SHA.into(),
            v::TLS_RSA_WITH_3DES_EDE_CBC_SHA.into(),
        ],
        compression_methods: vec![v::COMPRESSION_NONE],
        // u_parrots.go:2450-2531
        extensions: vec![
            Extension::Grease,
            Extension::ServerName,
            Extension::ExtendedMasterSecret,
            Extension::RenegotiationInfo(RenegotiationInfo {
                renegotiated_connection: Vec::new(),
            }),
            Extension::SupportedGroups(vec![
                CodePoint::Grease,
                v::X25519.into(),
                v::CURVE_P256.into(),
                v::CURVE_P384.into(),
            ]),
            Extension::EcPointFormats(EcPointFormats {
                formats: vec![v::POINT_FORMAT_UNCOMPRESSED],
            }),
            Extension::SessionTicket(SessionTicket { ticket: Vec::new() }),
            Extension::Alpn(vec![b"h2".to_vec(), b"http/1.1".to_vec()]),
            Extension::StatusRequest,
            // 9 项（含 PKCS1WithSHA1）
            Extension::SignatureAlgorithms(vec![
                v::ECDSA_WITH_P256_AND_SHA256.into(),
                v::PSS_WITH_SHA256.into(),
                v::PKCS1_WITH_SHA256.into(),
                v::ECDSA_WITH_P384_AND_SHA384.into(),
                v::PSS_WITH_SHA384.into(),
                v::PKCS1_WITH_SHA384.into(),
                v::PSS_WITH_SHA512.into(),
                v::PKCS1_WITH_SHA512.into(),
                v::PKCS1_WITH_SHA1.into(),
            ]),
            Extension::SignedCertificateTimestamp,
            // &FakeChannelIDExtension{OldExtensionID: false} ⇒ **30032**（:2492-2494）
            Extension::ChannelId {
                old_codepoint: false,
            },
            Extension::KeyShare(KeyShare::groups([CodePoint::Grease, v::X25519.into()])),
            Extension::PskKeyExchangeModes {
                modes: vec![v::PSK_MODE_DHE],
            },
            Extension::SupportedVersions(vec![
                CodePoint::Grease,
                v::VERSION_TLS13.into(),
                v::VERSION_TLS12.into(),
                v::VERSION_TLS11.into(),
                v::VERSION_TLS10.into(),
            ]),
            Extension::CompressCertificate(CompressCertificate {
                algorithms: vec![v::CERT_COMPRESSION_BROTLI],
            }),
            Extension::Grease,
            Extension::Padding(Padding::BoringStyle),
        ],
        session_id: SessionId::Random(32),
        variability: Variability::Stable,
    }
}

/// QQ 浏览器 11.1（Chromium 内核）。
///
/// 逐条对应 uTLS `u_parrots.go:2533-2641` 的 `case HelloQQ_11_1`。
/// 等于 Chrome 96 的密码套件（无 3DES）加 **8 项签名算法**（无 PKCS1WithSHA1），
/// 再加 ALPS 17513 与 GREASE+1.3/1.2/1.1/1.0 的版本列表。
/// 与 Chrome 96 的差别只有签名算法少一项；与 360_11_0 的差别是**没有** channel_id。
pub(crate) fn qq_11_1() -> ClientHelloSpec {
    ClientHelloSpec {
        legacy_version: v::LEGACY_VERSION,
        // u_parrots.go:2537-2553
        cipher_suites: vec![
            CodePoint::Grease,
            v::TLS_AES_128_GCM_SHA256.into(),
            v::TLS_AES_256_GCM_SHA384.into(),
            v::TLS_CHACHA20_POLY1305_SHA256.into(),
            v::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256.into(),
            v::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256.into(),
            v::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384.into(),
            v::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384.into(),
            v::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305.into(),
            v::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305.into(),
            v::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA.into(),
            v::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA.into(),
            v::TLS_RSA_WITH_AES_128_GCM_SHA256.into(),
            v::TLS_RSA_WITH_AES_256_GCM_SHA384.into(),
            v::TLS_RSA_WITH_AES_128_CBC_SHA.into(),
            v::TLS_RSA_WITH_AES_256_CBC_SHA.into(),
        ],
        compression_methods: vec![v::COMPRESSION_NONE],
        // u_parrots.go:2558-2640
        extensions: vec![
            Extension::Grease,
            Extension::ServerName,
            Extension::ExtendedMasterSecret,
            Extension::RenegotiationInfo(RenegotiationInfo {
                renegotiated_connection: Vec::new(),
            }),
            Extension::SupportedGroups(vec![
                CodePoint::Grease,
                v::X25519.into(),
                v::CURVE_P256.into(),
                v::CURVE_P384.into(),
            ]),
            Extension::EcPointFormats(EcPointFormats {
                formats: vec![v::POINT_FORMAT_UNCOMPRESSED],
            }),
            Extension::SessionTicket(SessionTicket { ticket: Vec::new() }),
            Extension::Alpn(vec![b"h2".to_vec(), b"http/1.1".to_vec()]),
            Extension::StatusRequest,
            // 8 项（无 PKCS1WithSHA1，:2586-2596）
            Extension::SignatureAlgorithms(vec![
                v::ECDSA_WITH_P256_AND_SHA256.into(),
                v::PSS_WITH_SHA256.into(),
                v::PKCS1_WITH_SHA256.into(),
                v::ECDSA_WITH_P384_AND_SHA384.into(),
                v::PSS_WITH_SHA384.into(),
                v::PKCS1_WITH_SHA384.into(),
                v::PSS_WITH_SHA512.into(),
                v::PKCS1_WITH_SHA512.into(),
            ]),
            Extension::SignedCertificateTimestamp,
            Extension::KeyShare(KeyShare::groups([CodePoint::Grease, v::X25519.into()])),
            Extension::PskKeyExchangeModes {
                modes: vec![v::PSK_MODE_DHE],
            },
            Extension::SupportedVersions(vec![
                CodePoint::Grease,
                v::VERSION_TLS13.into(),
                v::VERSION_TLS12.into(),
                v::VERSION_TLS11.into(),
                v::VERSION_TLS10.into(),
            ]),
            Extension::CompressCertificate(CompressCertificate {
                algorithms: vec![v::CERT_COMPRESSION_BROTLI],
            }),
            Extension::ApplicationSettings(ApplicationSettingsAlps {
                protocols: vec![b"h2".to_vec()],
            }),
            Extension::Grease,
            Extension::Padding(Padding::BoringStyle),
        ],
        session_id: SessionId::Random(32),
        variability: Variability::Stable,
    }
}

/// Chrome 100 / 112 的 `_PSK_` 变体（`HelloChrome_100_PSK`、`HelloChrome_112_PSK_Shuf`）。
///
/// 实测（`u_parrots.go:2642-2783` 两个 case + 参照产出）：它们与 `chrome_100_102()` 的
/// **密码套件、签名算法、曲线、key_share、版本、ALPS、压缩证书逐字相同**，差别只有两处：
/// 1. **没有填充扩展**（Go 的 case 根本没列它 —— 不是「窗口外」，是压根没有）；
/// 2. 末尾多一条**空 PSK 标记**。
///
/// ⚠️ 100_PSK 是 **Stable**（它的 case 没有包 `ShuffleChromeTLSExtensions`），
/// 而 112_PSK 是 Shuffled —— 两条的 spec 内容相同、乱序策略不同，所以这里分成两个函数
/// 在 `spec_of` 里分派（见那里的 100|112 分支与 112 的乱序覆盖）。
fn chrome_psk_common() -> ClientHelloSpec {
    let mut spec = chrome_100_102();
    spec.extensions
        .retain(|e| !matches!(e, Extension::Padding(_)));
    spec.extensions
        .push(Extension::PreSharedKey(super::spec::PreSharedKey::empty()));
    spec
}

/// `HelloChrome_100_PSK`：Stable。
pub(crate) fn chrome_psk_stable() -> ClientHelloSpec {
    chrome_psk_common()
}

/// `HelloChrome_114_Padding_PSK_Shuf`：与 `chrome_106_shuffle()` 相同，**保留填充**，
/// 末尾加一条空 PSK 标记。填充在 PSK **之前**（RFC 8446 §4.2.11 要求 PSK 最后）。
pub(crate) fn chrome_psk_padding() -> ClientHelloSpec {
    let mut spec = chrome_106_shuffle();
    spec.extensions
        .push(Extension::PreSharedKey(super::spec::PreSharedKey::empty()));
    spec
}

/// `HelloChrome_115_PQ_PSK`：与 `chrome_115_pq()` 相同（它本来就没有填充扩展），
/// 末尾加一条空 PSK 标记。
pub(crate) fn chrome_psk_pq() -> ClientHelloSpec {
    let mut spec = chrome_115_pq();
    spec.extensions
        .push(Extension::PreSharedKey(super::spec::PreSharedKey::empty()));
    spec
}
