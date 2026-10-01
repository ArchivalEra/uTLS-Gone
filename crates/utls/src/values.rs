//! 具名常量：密码套件、命名组、签名算法、扩展类型、TLS 版本、GREASE。
//!
//! **数值来源**：Go uTLS `master`（`refraction-networking/utls`）的 `common.go`（stdlib 副本）、
//! `u_common.go`（uTLS 追加）与 `u_tls_extensions.go`，逐条抄录。
//!
//! 为什么每个数字都要出处：**改这些数字就是改指纹**。一个抄错的密码套件码点不会编译失败，
//! 它只会让产出的 ClientHello 与目标浏览器差一点点 —— 而那是最难查的那种错。
//! 本文件的取值方式是 `crates/utls/src/values.rs` 头部注释 + 台账里的 `fp_*` 事实。

/// GREASE 占位符（RFC 8701）。`0x?a?a` 形态，每连接被替换成具体值。
///
/// 出处：uTLS `u_common.go` 的 `GREASE_PLACEHOLDER = 0x0a0a`。
pub const GREASE_PLACEHOLDER: u16 = 0x0a0a;

/// 该值是否为 GREASE：`(v & 0x0f0f) == 0x0a0a`。
///
/// 出处：uTLS `u_common.go` 的 `isGREASEUint16`。
pub const fn is_grease(v: u16) -> bool {
    v & 0x0f0f == 0x0a0a
}

/// GREASE 的 16 个合法值，按 `0x0a0a, 0x1a1a, … 0xfafa` 顺序。
pub const GREASE_VALUES: [u16; 16] = [
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
    0xcaca, 0xdada, 0xeaea, 0xfafa,
];

// ── TLS 版本（uTLS `common.go`）─────────────────────────────────────────────
pub const VERSION_TLS10: u16 = 0x0301;
pub const VERSION_TLS11: u16 = 0x0302;
pub const VERSION_TLS12: u16 = 0x0303;
pub const VERSION_TLS13: u16 = 0x0304;

/// ClientHello 的 `legacy_version` 字段：TLS 1.2 及以上一律填 `0x0303`。
///
/// 出处：RFC 8446 §4.1.2「legacy_version: MUST be set to 0x0303」。真实客户端版本
/// 由 `supported_versions` 扩展表达。
pub const LEGACY_VERSION: u16 = 0x0303;

// ── 密码套件（Go `cipher_suites.go` 与 `common.go`）─────────────────────────
pub const TLS_RSA_WITH_AES_128_CBC_SHA: u16 = 0x002f;
pub const TLS_RSA_WITH_AES_256_CBC_SHA: u16 = 0x0035;
pub const TLS_RSA_WITH_AES_128_GCM_SHA256: u16 = 0x009c;
pub const TLS_RSA_WITH_AES_256_GCM_SHA384: u16 = 0x009d;
/// 出处：Go `cipher_suites.go:693`（`TLS_RSA_WITH_RC4_128_SHA`）。
pub const TLS_RSA_WITH_RC4_128_SHA: u16 = 0x0005;
/// 出处：Go `cipher_suites.go:694`（`TLS_RSA_WITH_3DES_EDE_CBC_SHA`）。
pub const TLS_RSA_WITH_3DES_EDE_CBC_SHA: u16 = 0x000a;
/// 出处：Go `cipher_suites.go:697`（`TLS_RSA_WITH_AES_128_CBC_SHA256`）。
pub const TLS_RSA_WITH_AES_128_CBC_SHA256: u16 = 0x003c;
/// 出处：Go `cipher_suites.go:700`（`TLS_ECDHE_ECDSA_WITH_RC4_128_SHA`）。
pub const TLS_ECDHE_ECDSA_WITH_RC4_128_SHA: u16 = 0xc007;
/// 出处：Go `cipher_suites.go:703`（`TLS_ECDHE_RSA_WITH_RC4_128_SHA`）。
pub const TLS_ECDHE_RSA_WITH_RC4_128_SHA: u16 = 0xc011;
/// 出处：Go `cipher_suites.go:704`（`TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA`）。
pub const TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA: u16 = 0xc012;
/// 出处：Go `cipher_suites.go:707`（`TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256`）。
pub const TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256: u16 = 0xc023;
/// 出处：Go `cipher_suites.go:708`（`TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256`）。
pub const TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256: u16 = 0xc027;

// 下面这组名字带 `DISABLED_` / `FAKE_` 前缀，但它们**都是真实线上码点**
// （iOS 与 360 浏览器真的报它们）。名字只说明 uTLS 的 Go 实现里没有对应算法可用，
// 不影响线字节 —— 预设表只管把码点写出去。
/// 出处：uTLS `u_common.go:58`（`DISABLED_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384`）。
pub const DISABLED_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384: u16 = 0xc024;
/// 出处：uTLS `u_common.go:59`。
pub const DISABLED_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384: u16 = 0xc028;
/// 出处：uTLS `u_common.go:60`。
pub const DISABLED_TLS_RSA_WITH_AES_256_CBC_SHA256: u16 = 0x003d;
/// 出处：uTLS `u_common.go:65`（`FAKE_TLS_DHE_RSA_WITH_AES_128_CBC_SHA`）。
pub const FAKE_TLS_DHE_RSA_WITH_AES_128_CBC_SHA: u16 = 0x0033;
/// 出处：uTLS `u_common.go:66`。
pub const FAKE_TLS_DHE_RSA_WITH_AES_256_CBC_SHA: u16 = 0x0039;
/// 出处：uTLS `u_common.go:67`（`FAKE_TLS_RSA_WITH_RC4_128_MD5`）。
pub const FAKE_TLS_RSA_WITH_RC4_128_MD5: u16 = 0x0004;
/// 出处：uTLS `u_common.go:69`。
pub const FAKE_TLS_DHE_DSS_WITH_AES_128_CBC_SHA: u16 = 0x0032;
/// 出处：uTLS `u_common.go:70`。
pub const FAKE_TLS_DHE_RSA_WITH_AES_256_CBC_SHA256: u16 = 0x006b;
/// 出处：uTLS `u_common.go:71`。
pub const FAKE_TLS_DHE_RSA_WITH_AES_128_CBC_SHA256: u16 = 0x0067;
/// 出处：uTLS `u_common.go:75`（`FAKE_TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA`）。
pub const FAKE_TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA: u16 = 0xc008;
pub const TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA: u16 = 0xc009;
pub const TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA: u16 = 0xc00a;
pub const TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA: u16 = 0xc013;
pub const TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA: u16 = 0xc014;
pub const TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: u16 = 0xc02b;
pub const TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: u16 = 0xc02c;
pub const TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256: u16 = 0xc02f;
pub const TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384: u16 = 0xc030;
pub const TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305: u16 = 0xcca8;
pub const TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305: u16 = 0xcca9;
pub const TLS_AES_128_GCM_SHA256: u16 = 0x1301;
pub const TLS_AES_256_GCM_SHA384: u16 = 0x1302;
pub const TLS_CHACHA20_POLY1305_SHA256: u16 = 0x1303;

/// `TLS_EMPTY_RENEGOTIATION_INFO_SCSV`。rustls 会**无条件**追加它，而那会改变 JA3 ——
/// 所以 fork 必须能被要求省略它（见 README「为什么必须 fork」）。
pub const TLS_EMPTY_RENEGOTIATION_INFO_SCSV: u16 = 0x00ff;

// ── 命名组 / 曲线（Go `common.go`, uTLS `u_common.go`）──────────────────────
pub const CURVE_P256: u16 = 23;
pub const CURVE_P384: u16 = 24;
pub const CURVE_P521: u16 = 25;
pub const X25519: u16 = 29;
/// FFDHE 有限域群。Firefox 会报它们（uTLS 的 Firefox 预置里写作裸值 `0x0100`/`0x0101`）。
pub const FFDHE2048: u16 = 0x0100;
pub const FFDHE3072: u16 = 0x0101;
pub const SECP256R1_MLKEM768: u16 = 4587;
pub const X25519_MLKEM768: u16 = 4588;
pub const SECP384R1_MLKEM1024: u16 = 4589;
/// Chrome 115/120 的混合组（Kyber 草案版，与 `X25519_MLKEM768` 不是同一个码点）。
///
/// 出处：uTLS `u_common.go:92`（`X25519Kyber768Draft00 CurveID = 0x6399`）。
pub const X25519_KYBER768_DRAFT00: u16 = 0x6399;

// ── 签名算法（Go `common.go`）───────────────────────────────────────────────
pub const PKCS1_WITH_SHA1: u16 = 0x0201;
pub const ECDSA_WITH_SHA1: u16 = 0x0203;
pub const PKCS1_WITH_SHA256: u16 = 0x0401;
pub const PKCS1_WITH_SHA384: u16 = 0x0501;
pub const PKCS1_WITH_SHA512: u16 = 0x0601;
pub const ECDSA_WITH_P256_AND_SHA256: u16 = 0x0403;
pub const ECDSA_WITH_P384_AND_SHA384: u16 = 0x0503;
pub const ECDSA_WITH_P521_AND_SHA512: u16 = 0x0603;
pub const PSS_WITH_SHA256: u16 = 0x0804;
pub const PSS_WITH_SHA384: u16 = 0x0805;
pub const PSS_WITH_SHA512: u16 = 0x0806;
/// DSA 的两个草案期码点 —— 360_7_5 会报它们（uTLS 名字带 `Fake` 前缀）。
///
/// 出处：uTLS `u_common.go:113-114`（`FakeSHA1WithDSA` / `FakeSHA256WithDSA`）。
pub const FAKE_SHA1_WITH_DSA: u16 = 0x0202;
pub const FAKE_SHA256_WITH_DSA: u16 = 0x0402;

// ── 扩展类型（Go `common.go`；uTLS 追加的三个见下）──────────────────────────
pub const EXT_SERVER_NAME: u16 = 0;
pub const EXT_STATUS_REQUEST: u16 = 5;
pub const EXT_SUPPORTED_GROUPS: u16 = 10; // RFC 8446 里叫 supported_groups
pub const EXT_EC_POINT_FORMATS: u16 = 11;
pub const EXT_SIGNATURE_ALGORITHMS: u16 = 13;
pub const EXT_ALPN: u16 = 16;
pub const EXT_STATUS_REQUEST_V2: u16 = 17;
pub const EXT_SCT: u16 = 18;
pub const EXT_PADDING: u16 = 21;
pub const EXT_EXTENDED_MASTER_SECRET: u16 = 23;
pub const EXT_COMPRESS_CERTIFICATE: u16 = 27;
pub const EXT_DELEGATED_CREDENTIALS: u16 = 34;
pub const EXT_SESSION_TICKET: u16 = 35;
pub const EXT_PRE_SHARED_KEY: u16 = 41;
pub const EXT_EARLY_DATA: u16 = 42;
pub const EXT_SUPPORTED_VERSIONS: u16 = 43;
pub const EXT_COOKIE: u16 = 44;
pub const EXT_PSK_KEY_EXCHANGE_MODES: u16 = 45;
pub const EXT_CERTIFICATE_AUTHORITIES: u16 = 47;
pub const EXT_SIGNATURE_ALGORITHMS_CERT: u16 = 50;
pub const EXT_KEY_SHARE: u16 = 51;
pub const EXT_QUIC_TRANSPORT_PARAMETERS: u16 = 57;
pub const EXT_RENEGOTIATION_INFO: u16 = 0xff01;

/// 非 IANA 分配（uTLS `u_common.go`）。
pub const EXT_APPLICATION_SETTINGS: u16 = 17513;
pub const EXT_APPLICATION_SETTINGS_NEW: u16 = 17613;
/// `next_protocol_negotiation`（NPN，draft-agl-tls-nextprotoneg-04）。体为空。
///
/// Go stdlib 在 2019 年 11 月移除了它，但真实 iOS 11/12 与 360_7_5 仍在报。
/// 出处：uTLS `u_common.go:35`（`extensionNextProtoNeg uint16 = 13172`）。
pub const EXT_NPN: u16 = 13172;
/// `channel_id` 的两个历史码点（非 IANA 分配），体为空。
///
/// 出处：uTLS `u_common.go:52-53`（`fakeOldExtensionChannelID` / `fakeExtensionChannelID`）。
pub const EXT_CHANNEL_ID_OLD: u16 = 30031;
pub const EXT_CHANNEL_ID: u16 = 30032;
/// draft-ietf-tls-esni-17（uTLS `u_common.go`）。
pub const EXT_ENCRYPTED_CLIENT_HELLO: u16 = 0xfe0d;
pub const EXT_ECH_OUTER_EXTENSIONS: u16 = 0xfd00;

// ── 其它 ───────────────────────────────────────────────────────────────────
/// 压缩方法：`compressionNone`。浏览器一律只报这一个。
pub const COMPRESSION_NONE: u8 = 0;
/// 点格式：`pointFormatUncompressed`。
pub const POINT_FORMAT_UNCOMPRESSED: u8 = 0;
/// `psk_dhe_ke`（Go `common.go` 的 `pskModeDHE`）。
pub const PSK_MODE_DHE: u8 = 1;
/// 证书压缩算法：brotli（uTLS `u_common.go` 的 `CertCompressionBrotli`）。
pub const CERT_COMPRESSION_BROTLI: u16 = 0x0002;
/// 证书压缩算法：zlib / zstd（Firefox 预置会报这三个）。
pub const CERT_COMPRESSION_ZLIB: u16 = 0x0001;
pub const CERT_COMPRESSION_ZSTD: u16 = 0x0003;
/// `record_size_limit`（RFC 8449）。uTLS 给它的常量名带 `fake` 前缀，因为它只被**广播**，
/// 不受支持 —— 服务端若回显它，连接会断。
pub const EXT_RECORD_SIZE_LIMIT: u16 = 0x001c;
/// `status_request` 的类型：OCSP。
pub const STATUS_TYPE_OCSP: u8 = 1;
/// SNI 的 `name_type`：host_name。
pub const SNI_NAME_TYPE_HOST_NAME: u8 = 0;
/// ECH 的 `ClientHelloType`：outer（uTLS `ech.go` 的 `OuterClientHello`）。
pub const ECH_OUTER_CLIENT_HELLO: u8 = 0;
/// HPKE `HKDF-SHA256`（uTLS GREASE ECH 用的候选套件 KDF）。
pub const HPKE_KDF_HKDF_SHA256: u16 = 0x0001;
/// HPKE `AEAD_AES_128_GCM`。
pub const HPKE_AEAD_AES_128_GCM: u16 = 0x0001;
/// HPKE `AEAD_CHACHA20_POLY1305`（Firefox 的 GREASE ECH 把它列为第二个候选）。
pub const HPKE_AEAD_CHACHA20_POLY1305: u16 = 0x0003;
/// X25519 的 HPKE 封装密钥长度。
pub const X25519_ENCAPSULATED_KEY_LEN: usize = 32;
/// BoringSSL 风格填充（uTLS `BoringPaddingStyle`）的目标长度：**整条握手消息** 512 字节。
///
/// 出处：uTLS `u_tls_extensions.go:1115-1129` —— 当 `0xff < 未填充长 < 0x200` 时
/// 填到 `0x200`（填充体长 = `0x200 - 未填充长 - 4`，那 4 字节是 padding 扩展自身的头）。
/// 调用点 `u_conn.go:611` 传入的正是「含 4 字节握手头的整条消息长度」。
///
/// ⚠️ 该函数是**有条件的**：未填充长不在 `(0xff, 0x200)` 区间里时它返回 `willPad=false`，
/// 整个扩展**不发**。条件那半边由 [`Padding::BoringStyle`] 表达 —— 见 `spec.rs` 与
/// `encode.rs` 里的实现，不要在这里再写一遍。
///
/// [`Padding::BoringStyle`]: crate::hello::Padding::BoringStyle
pub const PADDING_TARGET_BORING: u16 = 0x200;
/// `BoringPaddingStyle` 的**下**门槛：未填充长必须**严格大于**它才可能填充。
pub const BORING_PAD_BAND_LOW: usize = 0xff;

/// 某命名组的**公钥长度**（字节）—— 给 `HandshakeInputs::key_exchange` 用。
///
/// 为什么这个函数值得公开：**长度进指纹**。它决定 ClientHello 的总长，而总长又决定
/// `BoringPaddingStyle` 要不要填充、填多少。给一个「差不多」的长度，会得到一个
/// **只在某些 SNI 长度上正确**的指纹 —— 那是最难查的一类错。而它正是「拿参照实现的
/// 产出来对账」能抓到的错（见 `tests/utls_conformance.rs`）。
///
/// 未收录的组返回 `None`，**不猜**。混合组是「经典部分 + KEM 封装密钥」之和。
pub const fn group_public_key_len(group: u16) -> Option<usize> {
    Some(match group {
        X25519 => 32,
        CURVE_P256 => 65,  // 未压缩点：1 + 2×32
        CURVE_P384 => 97,  // 1 + 2×48
        CURVE_P521 => 133, // 1 + 2×66
        X25519_MLKEM768 => 32 + 1184,
        // Kyber768 草案的封装密钥与 ML-KEM-768 同为 1184 字节。
        X25519_KYBER768_DRAFT00 => 32 + 1184,
        SECP256R1_MLKEM768 => 65 + 1184,
        SECP384R1_MLKEM1024 => 97 + 1568,
        _ => return None,
    })
}
