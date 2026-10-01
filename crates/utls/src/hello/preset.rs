//! 浏览器预设表。
//!
//! **这一层是数据，不是代码。** 新增一个浏览器版本 = 往预设表加一条 + 过一遍黄金值，
//! **不新增任何接口**（`AGENTS.md` 第四条）。
//!
//! # 两个文件的分工
//!
//! - 本文件是**命名层 + 两条样板**：`ClientHelloId`（名字与版本的映射）、`spec_of`（分派）、
//!   以及 `chrome_133` / `firefox_148` 这两条最早落地的预置；
//! - [`preset_data`](super::preset_data) 是**数据层**：其余每个浏览器版本一条
//!   `pub(crate) fn`，逐条抄自 Go uTLS。新加预置往那里加。
//!
//! # 数值来源
//!
//! Go uTLS `master` 的 `u_parrots.go`（函数 `utlsIdToSpec`）与 `u_common.go`，逐条抄录。
//! 改动这里的任何一个数字都会改变指纹，而「改了就会变」这件事由台账里的 `fp_*` 事实
//! 负责显形 —— 那些事实由 `examples/reflect-facts.rs` 跑出来，不是手抄的。
//!
//! # 已实现 / 未实现
//!
//! `u_parrots.go` 里**已落地**：Chrome 58/62/70/72/83/87/96/100/102/106/115_PQ/120/120_PQ/131/133、
//! Firefox 55/56/63/65/99/102/105/120/148、iOS 11.1/12.1/13、Android 11 OkHttp、
//! Edge 85/106、Safari 16.0/26.3、360 7.5/11.0、QQ 11.1 —— 共 35 条，见 [`ClientHelloId::implemented`]。
//!
//! **刻意未实现的**（返回 [`SpecError::PresetUnavailable`]，不静默降级）：
//!
//! - `HelloRandomized` / `HelloRandomizedALPN` / `HelloRandomizedNoALPN`：uTLS 用一张
//!   带权重的生成器（`u_parrots.go` 的 `Weights`）产出，那是**引擎**级的随机化，
//!   不是一条固定的 spec；
//! - `HelloGolang`：uTLS 里它是「用 Go stdlib 的 ClientHello」。在 Rust 里对应
//!   「用 rustls 自己的 ClientHello」——那正好是**不使用本 crate** 时得到的东西，
//!   所以这里不可能有它的 spec；
//! - `HelloChrome_100_PSK` / `112_PSK` / `114_PSK` / `115_PQ_PSK`（四个 `_PSK_` 变体）：
//!   它们依赖 `PreSharedKeyExtension` 的 **binder** 与「必须排最后」的位置约束，
//!   本层的模型还没有 PSK 扩展 —— **宁可不做，也不发一条没有 binder 的假 PSK**；
//! - 未列出的版本号（例如 `Chrome(999)` / `Ios(14)`）：uTLS 里没有对应版本串，
//!   而**猜一个最近邻**会让调用方以为自己在模仿 Chrome 120，实际发出去的是别的版本 ——
//!   这种错在指纹上看得见、在代码里看不见。
//!
//! `HelloChrome_106_Shuffle` **是**实现了的（就是 [`ClientHelloId::Chrome`]`(106)`，
//! 也是 uTLS 里唯一的 106）。

use super::preset_data as pd;
use super::spec::{
    ApplicationSettingsAlps, ClientHelloSpec, CodePoint, CompressCertificate, DelegatedCredentials, EcPointFormats, Extension, GreaseEchOptions, RenegotiationInfo, SessionId, SessionTicket, SpecError, Variability,
};
use crate::values as v;

/// 一个浏览器指纹的名字。
///
/// 与 uTLS 的 `ClientHelloID` 同构：家族 + 版本。`Auto` 语义在 uTLS 里是编译期常量
/// （「最新一个我们有的版本」），这里用显式版本号表达 —— 因为「最新的那个」会随手
/// 升级而漂移，而指纹不该有这种隐式漂移。
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
#[non_exhaustive]
pub enum ClientHelloId {
    Chrome(u16),
    /// `HelloChrome_115_PQ` / `HelloChrome_120_PQ` —— 版本串里带 `"_PQ"` 的那两个。
    ///
    /// 单列一个变体是因为 uTLS 的版本字段是**字符串**（`u_common.go:639/645` 的
    /// `"115_PQ"` / `"120_PQ"`），而 `Chrome(u16)` 装不下那个后缀：
    /// 若把 120_PQ 塞进 `Chrome(120)`，它就与**普通** Chrome 120 撞成同一个名字，
    /// 而台账键名会指着一份不是它的数据。
    ChromePq(u16),
    /// Chrome 的 `_PSK_` 变体（uTLS 的 `HelloChrome_100_PSK` / `_112_PSK_Shuf` /
    /// `_114_Padding_PSK_Shuf` / `_115_PQ_PSK`）。
    ///
    /// uTLS 自己的评语是「Beta：加了 PSK 扩展，但 uTLS 不提供完整 PSK 支持，自担风险」。
    /// 实测：这些预设**在没有会话时直接报错**（`tls: empty psk detected; …`）。
    /// 本层发的是 uTLS 给出的替代形态（不发空 PSK），见 [`Extension::PreSharedKey(super::spec::PreSharedKey::empty())`]。
    ChromePsk(u16),
    Firefox(u16),
    Safari(u16),
    Ios(u16),
    Android(u16),
    Edge(u16),
    Browser360(u16),
    Qq(u16),
    /// 随机化指纹，ALPN 由**加权掷币**决定（uTLS 的 `HelloRandomized`）。
    ///
    /// ⚠️ 这三个随机化 ID **不能**走 `from_preset` —— 它们需要种子。
    /// 用 [`ClientHelloSpec::randomized`]。
    Randomized,
    /// 随机化指纹，**总是**带 ALPN（uTLS 的 `HelloRandomizedALPN`）。
    RandomizedAlpn,
    /// 随机化指纹，**从不**带 ALPN（uTLS 的 `HelloRandomizedNoALPN`）。
    RandomizedNoAlpn,
    /// uTLS 的 `HelloGolang`：**用引擎自己的默认值**。
    ///
    /// 在 uTLS 里它意味着「用 Go stdlib 的 ClientHello」。在 Rust 里对应的是
    /// 「用 rustls 自己的 ClientHello」—— 那正好是**不使用本 crate** 时得到的东西，
    /// 所以这里不可能有它的 spec，返回 `PresetUnavailable` 是唯一诚实的结果。
    Golang,
    /// uTLS 的 `HelloCustom`：空 spec，由调用方填。
    Custom,
}

impl ClientHelloId {
    /// 用于台账键名与日志的稳定名字。
    pub fn name(self) -> String {
        use ClientHelloId::*;
        match self {
            Chrome(n) => format!("chrome_{n}"),
            // 与 uTLS 的版本串同形：`chrome_115_pq` / `chrome_120_pq`。
            ChromePq(n) => format!("chrome_{n}_pq"),
            ChromePsk(n) => format!("chrome_{n}_psk"),
            Firefox(n) => format!("firefox_{n}"),
            Safari(n) => format!("safari_{n}"),
            Ios(n) => format!("ios_{n}"),
            Android(n) => format!("android_{n}"),
            Edge(n) => format!("edge_{n}"),
            Browser360(n) => format!("360_{n}"),
            Qq(n) => format!("qq_{n}"),
            Randomized => "randomized".into(),
            RandomizedAlpn => "randomized_alpn".into(),
            RandomizedNoAlpn => "randomized_no_alpn".into(),
            Golang => "golang".into(),
            Custom => "custom".into(),
        }
    }

    /// 本 crate **已实现**的预设。台账与黄金值只遍历它 ——
    /// 遍历一个「声明了但没实现」的清单会让事实里出现空缺，而空缺看起来像通过。
    ///
    /// 版本号的口径与 uTLS 的版本串一致，只取主版本：`HelloIOS_11_1` 的版本串是
    /// `"111"`（`u_common.go:649`），这里记 `Ios(11)`；`HelloSafari_16_0` 记 `Safari(16)`。
    /// 唯一的例外是带 `_PQ` 后缀的两个，见 [`ClientHelloId::ChromePq`]。
    pub const fn implemented() -> &'static [ClientHelloId] {
        &[
            ClientHelloId::Chrome(58),
            ClientHelloId::Chrome(62),
            ClientHelloId::Chrome(70),
            ClientHelloId::Chrome(72),
            ClientHelloId::Chrome(83),
            ClientHelloId::Chrome(87),
            ClientHelloId::Chrome(96),
            ClientHelloId::Chrome(100),
            ClientHelloId::Chrome(102),
            ClientHelloId::Chrome(106),
            ClientHelloId::ChromePq(115),
            ClientHelloId::Chrome(120),
            ClientHelloId::ChromePq(120),
            // ── `_PSK_` 变体（Chrome 120 之后没有新的；见 u_parrots.go 的四个 case）──
            ClientHelloId::ChromePsk(100),
            ClientHelloId::ChromePsk(112),
            ClientHelloId::ChromePsk(114),
            ClientHelloId::ChromePsk(115),
            ClientHelloId::Chrome(131),
            ClientHelloId::Chrome(133),
            ClientHelloId::Firefox(55),
            ClientHelloId::Firefox(56),
            ClientHelloId::Firefox(63),
            ClientHelloId::Firefox(65),
            ClientHelloId::Firefox(99),
            ClientHelloId::Firefox(102),
            ClientHelloId::Firefox(105),
            ClientHelloId::Firefox(120),
            ClientHelloId::Firefox(148),
            ClientHelloId::Ios(11),
            ClientHelloId::Ios(12),
            ClientHelloId::Ios(13),
            ClientHelloId::Android(11),
            ClientHelloId::Edge(85),
            ClientHelloId::Edge(106),
            ClientHelloId::Safari(16),
            ClientHelloId::Safari(26),
            ClientHelloId::Browser360(7),
            ClientHelloId::Browser360(11),
            ClientHelloId::Qq(11),
            ClientHelloId::Custom,
        ]
    }
}

impl ClientHelloId {
    /// uTLS 的三个随机化 ID（`HelloRandomized{,ALPN,NoALPN}`）。
    ///
    /// 它们**不**能用 `from_preset` —— 随机化指纹由种子定义，没有种子就没有指纹。
    /// 用 [`ClientHelloSpec::randomized`](super::ClientHelloSpec::randomized)。
    pub const fn randomized_family() -> &'static [ClientHelloId] {
        &[
            ClientHelloId::Randomized,
            ClientHelloId::RandomizedAlpn,
            ClientHelloId::RandomizedNoAlpn,
        ]
    }

    /// 是否属于「需要种子的随机化族」。
    pub const fn is_randomized(self) -> bool {
        matches!(
            self,
            ClientHelloId::Randomized
                | ClientHelloId::RandomizedAlpn
                | ClientHelloId::RandomizedNoAlpn
        )
    }
}

impl core::fmt::Display for ClientHelloId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.name())
    }
}

pub(crate) fn spec_of(id: ClientHelloId) -> Result<ClientHelloSpec, SpecError> {
    if matches!(id, ClientHelloId::Golang) {
        // 显式结论：见 `SpecError::EngineDefined` 的说明。不是「没做」，是「不适用」。
        return Err(SpecError::EngineDefined(id));
    }
    if id.is_randomized() {
        // 明确报错，而不是「未实现」—— 它是实现的，只是需要种子。
        return Err(SpecError::RandomizedNeedsSeed(id));
    }
    match id {
        // ── Chrome ────────────────────────────────────────────────────────────
        ClientHelloId::Chrome(58 | 62) => Ok(pd::chrome_58_62()),
        ClientHelloId::Chrome(70) => Ok(pd::chrome_70()),
        ClientHelloId::Chrome(72) => Ok(pd::chrome_72()),
        ClientHelloId::Chrome(83) => Ok(pd::chrome_83()),
        ClientHelloId::Chrome(87) => Ok(pd::chrome_87()),
        ClientHelloId::Chrome(96) => Ok(pd::chrome_96()),
        ClientHelloId::Chrome(100 | 102) => Ok(pd::chrome_100_102()),
        // uTLS 只有 `HelloChrome_106_Shuffle` 这一个 106（`u_common.go:626`）。
        ClientHelloId::Chrome(106) => Ok(pd::chrome_106_shuffle()),
        ClientHelloId::Chrome(120) => Ok(pd::chrome_120()),
        ClientHelloId::Chrome(131) => Ok(pd::chrome_131()),
        ClientHelloId::Chrome(133) => Ok(chrome_133()),
        ClientHelloId::ChromePq(115) => Ok(pd::chrome_115_pq()),
        ClientHelloId::ChromePsk(100) => Ok(pd::chrome_psk_stable()),
        ClientHelloId::ChromePsk(112) => {
            // 112_PSK 的内容与 100_PSK 相同，但它**包在乱序里**（`_Shuf`）。
            let mut spec = pd::chrome_psk_stable();
            spec.variability = Variability::Shuffled;
            Ok(spec)
        }
        ClientHelloId::ChromePsk(114) => Ok(pd::chrome_psk_padding()),
        ClientHelloId::ChromePsk(115) => Ok(pd::chrome_psk_pq()),
        ClientHelloId::ChromePq(120) => Ok(pd::chrome_120_pq()),
        // ── Firefox ───────────────────────────────────────────────────────────
        ClientHelloId::Firefox(55 | 56) => Ok(pd::firefox_55_56()),
        ClientHelloId::Firefox(63 | 65) => Ok(pd::firefox_63_65()),
        ClientHelloId::Firefox(99) => Ok(pd::firefox_99()),
        ClientHelloId::Firefox(102) => Ok(pd::firefox_102()),
        ClientHelloId::Firefox(105) => Ok(pd::firefox_105()),
        ClientHelloId::Firefox(120) => Ok(pd::firefox_120()),
        ClientHelloId::Firefox(148) => Ok(firefox_148()),
        // ── 移动端 ────────────────────────────────────────────────────────────
        // uTLS 的版本串是 `"111"`（= 11.1），这里记 `Ios(11)`；12.1 记 `Ios(12)`。
        ClientHelloId::Ios(11) => Ok(pd::ios_11_1()),
        ClientHelloId::Ios(12) => Ok(pd::ios_12_1()),
        ClientHelloId::Ios(13) => Ok(pd::ios_13()),
        ClientHelloId::Android(11) => Ok(pd::android_11_okhttp()),
        // ── 其它 ──────────────────────────────────────────────────────────────
        ClientHelloId::Edge(85) => Ok(pd::edge_85()),
        ClientHelloId::Edge(106) => Ok(pd::edge_106()),
        ClientHelloId::Safari(16) => Ok(pd::safari_16_0()),
        ClientHelloId::Safari(26) => Ok(pd::safari_26_3()),
        ClientHelloId::Browser360(7) => Ok(pd::browser360_7_5()),
        ClientHelloId::Browser360(11) => Ok(pd::browser360_11_0()),
        ClientHelloId::Qq(11) => Ok(pd::qq_11_1()),
        ClientHelloId::Custom => Ok(ClientHelloSpec::empty()),
        _ => Err(SpecError::PresetUnavailable(id)),
    }
}

/// Chrome 133。
///
/// 逐条对应 uTLS `u_parrots.go:894` 的 `case HelloChrome_133`。
/// 扩展顺序在 uTLS 里由 `ShuffleChromeTLSExtensions` 打乱 —— 所以这里列出的顺序是
/// **被打乱之前**的规范顺序，而乱序由 [`Variability::Shuffled`] 表达（GREASE / 填充 /
/// PSK 三类位置固定，其余互相置换）。
fn chrome_133() -> ClientHelloSpec {
    ClientHelloSpec {
        legacy_version: v::LEGACY_VERSION,
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
        extensions: vec![
            // &UtlsGREASEExtension{}
            Extension::Grease,
            // &SNIExtension{} —— 体来自 inputs.sni
            Extension::ServerName,
            // &ExtendedMasterSecretExtension{} —— 体为空
            Extension::ExtendedMasterSecret,
            // &RenegotiationInfoExtension{RenegotiateOnceAsClient} —— 体是「长度为 0 的连接串」
            Extension::RenegotiationInfo(RenegotiationInfo { renegotiated_connection: Vec::new() }),
            // &SupportedCurvesExtension{[]CurveID{GREASE, X25519MLKEM768, X25519, P256, P384}}
            Extension::SupportedGroups(vec![
                CodePoint::Grease,
                v::X25519_MLKEM768.into(),
                v::X25519.into(),
                v::CURVE_P256.into(),
                v::CURVE_P384.into(),
            ]),
            // &SupportedPointsExtension{[]byte{0}} —— 体是「长度 1 + pointFormatUncompressed」
            Extension::EcPointFormats(EcPointFormats { formats: vec![v::POINT_FORMAT_UNCOMPRESSED] }),
            // &SessionTicketExtension{} —— 无 ticket，体为空
            Extension::SessionTicket(SessionTicket { ticket: Vec::new() }),
            // &ALPNExtension{"h2","http/1.1"}
            Extension::Alpn(vec![b"h2".to_vec(), b"http/1.1".to_vec()]),
            // &StatusRequestExtension{} —— OCSP + 两个零长度字段
            Extension::StatusRequest,
            // &SignatureAlgorithmsExtension{8 项}
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
            // &SCTExtension{} —— 体为空
            Extension::SignedCertificateTimestamp,
            // &KeyShareExtension{GREASE{0}, X25519MLKEM768, X25519}
            Extension::KeyShare(vec![
                CodePoint::Grease,
                v::X25519_MLKEM768.into(),
                v::X25519.into(),
            ]),
            // &PSKKeyExchangeModesExtension{psk_dhe_ke}
            Extension::PskKeyExchangeModes { modes: vec![v::PSK_MODE_DHE] },
            // &SupportedVersionsExtension{GREASE, TLS1.3, TLS1.2}
            Extension::SupportedVersions(vec![
                CodePoint::Grease,
                v::VERSION_TLS13.into(),
                v::VERSION_TLS12.into(),
            ]),
            // &UtlsCompressCertExtension{brotli}
            Extension::CompressCertificate(CompressCertificate { algorithms: vec![v::CERT_COMPRESSION_BROTLI] }),
            // &ApplicationSettingsExtensionNew{"h2"}（ALPS，码点 17613）
            Extension::ApplicationSettingsNew(ApplicationSettingsAlps { protocols: vec![b"h2".to_vec()] }),
            // BoringGREASEECH()
            Extension::GreaseEch(GreaseEchOptions::chrome()),
            // &UtlsGREASEExtension{}
            Extension::Grease,
        ],
        // Chrome 在 TLS 1.3 兼容模式下带 32 字节随机 legacy_session_id。
        session_id: SessionId::Random(32),
        variability: Variability::Shuffled,
    }
}

/// Firefox 148。
///
/// 逐条对应 uTLS `u_parrots.go:1469` 的 `case HelloFirefox_148`。
/// 与 Chrome 133 有两个**结构性**差别，值得单独记住：
///
/// 1. **完全不乱序**（Firefox 不调用 `ShuffleChromeTLSExtensions`）⇒ JA3 跨连接稳定；
/// 2. **完全不用 GREASE** —— 扩展、密码套件、支持版本、支持组里一个占位符都没有。
///
/// 所以这两个预置恰好是一对样板：Chrome 133 是「Shuffled + GREASE」，
/// Firefox 148 是「Stable + 无 GREASE」。任何关于乱序或 GREASE 的回归，
/// 都应该能在这两条之间看出差别。
///
/// `key_share` 里 `X25519MLKEM768` 与 `X25519` 共用同一份 X25519 密钥材料
/// （uTLS 的 `ReuseHybridAndClassicalKeyShares`）—— 那是**引擎**的事：
/// 调用方在 `inputs.key_exchange` 里给两个组喂同一个 32 字节 X25519 公钥即可，
/// 本层的模型不需要为此加任何东西。
fn firefox_148() -> ClientHelloSpec {
    ClientHelloSpec {
        legacy_version: v::LEGACY_VERSION,
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
        extensions: vec![
            Extension::ServerName,
            Extension::ExtendedMasterSecret,
            Extension::RenegotiationInfo(RenegotiationInfo { renegotiated_connection: Vec::new() }),
            Extension::SupportedGroups(vec![
                v::X25519_MLKEM768.into(),
                v::X25519.into(),
                v::CURVE_P256.into(),
                v::CURVE_P384.into(),
                v::CURVE_P521.into(),
                v::FFDHE2048.into(),
                v::FFDHE3072.into(),
            ]),
            Extension::EcPointFormats(EcPointFormats { formats: vec![v::POINT_FORMAT_UNCOMPRESSED] }),
            Extension::Alpn(vec![b"h2".to_vec(), b"http/1.1".to_vec()]),
            Extension::StatusRequest,
            // &FakeDelegatedCredentialsExtension{4 个签名算法}
            Extension::DelegatedCredentials(DelegatedCredentials { schemes: vec![v::ECDSA_WITH_P256_AND_SHA256, v::ECDSA_WITH_P384_AND_SHA384, v::ECDSA_WITH_P521_AND_SHA512, v::ECDSA_WITH_SHA1,] }),
            Extension::SignedCertificateTimestamp,
            Extension::KeyShare(vec![
                v::X25519_MLKEM768.into(),
                v::X25519.into(),
                v::CURVE_P256.into(),
            ]),
            // Firefox **不**在版本列表里放 GREASE。
            Extension::SupportedVersions(vec![
                v::VERSION_TLS13.into(),
                v::VERSION_TLS12.into(),
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
            // &FakeRecordSizeLimitExtension{Limit: 0x4001} —— 只广播，不受支持。
            Extension::RecordSizeLimit { limit: 0x4001 },
            // &UtlsCompressCertExtension{zlib, brotli, zstd}
            Extension::CompressCertificate(CompressCertificate { algorithms: vec![ v::CERT_COMPRESSION_ZLIB, v::CERT_COMPRESSION_BROTLI, v::CERT_COMPRESSION_ZSTD, ] }),
            // GREASEEncryptedClientHelloExtension：2 个候选套件、**单一**载荷长度。
            // 与 Chrome 的 4 个候选长度相比，这一条决定了 Firefox 的总长是恒定的。
            Extension::GreaseEch(GreaseEchOptions::firefox()),
        ],
        session_id: SessionId::Random(32),
        variability: Variability::Stable,
    }
}




#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chrome_133_has_the_expected_extension_types() {
        // 打乱之前的规范顺序（对照 uTLS `u_parrots.go` 的 HelloChrome_133）。
        let spec = chrome_133();
        let types: Vec<Option<u16>> =
            spec.extensions.iter().map(|e| e.wire_type()).collect();
        assert_eq!(
            types,
            vec![
                None,                                // GREASE（类型每连接才定）
                Some(v::EXT_SERVER_NAME),            // 0
                Some(v::EXT_EXTENDED_MASTER_SECRET), // 23
                Some(v::EXT_RENEGOTIATION_INFO),     // 0xff01
                Some(v::EXT_SUPPORTED_GROUPS),       // 10
                Some(v::EXT_EC_POINT_FORMATS),       // 11
                Some(v::EXT_SESSION_TICKET),         // 35
                Some(v::EXT_ALPN),                   // 16
                Some(v::EXT_STATUS_REQUEST),         // 5
                Some(v::EXT_SIGNATURE_ALGORITHMS),   // 13
                Some(v::EXT_SCT),                    // 18
                Some(v::EXT_KEY_SHARE),              // 51
                Some(v::EXT_PSK_KEY_EXCHANGE_MODES), // 45
                Some(v::EXT_SUPPORTED_VERSIONS),     // 43
                Some(v::EXT_COMPRESS_CERTIFICATE),   // 27
                Some(v::EXT_APPLICATION_SETTINGS_NEW), // 17613
                Some(v::EXT_ENCRYPTED_CLIENT_HELLO), // 0xfe0d（GREASE ECH）
                None,                                // GREASE
            ]
        );
    }

    #[test]
    fn chrome_133_cipher_list_is_16_entries_with_leading_grease() {
        let spec = chrome_133();
        assert_eq!(spec.cipher_suites.len(), 16);
        assert_eq!(spec.cipher_suites[0], CodePoint::Grease);
        assert_eq!(spec.cipher_suites[1], CodePoint::Fixed(v::TLS_AES_128_GCM_SHA256));
        assert_eq!(spec.cipher_suites[15], CodePoint::Fixed(v::TLS_RSA_WITH_AES_256_CBC_SHA));
    }

    #[test]
    fn alps_body_matches_the_documented_shape() {
        // 走**公开接口**断言编码出来的体字节，而不是测一个内部辅助函数 ——
        // 这样断言的就是别人真正会拿到的东西。
        //
        // 出处：Go `u_tls_extensions.go` 的 `applicationSettingsExtension.Read`。
        // `["h2"]` ⇒ 体是 `00 03 02 68 32`（五字节：ALPS 长度 3、然后一条 2 字节协议名）。
        let mut spec = ClientHelloSpec::empty();
        spec.cipher_suites = vec![CodePoint::Fixed(v::TLS_AES_128_GCM_SHA256)];
        spec.extensions = vec![
            Extension::ServerName,
            Extension::ApplicationSettings(ApplicationSettingsAlps {
                protocols: vec![b"h2".to_vec()],
            }),
        ];
        let mut i = crate::hello::HandshakeInputs::deterministic([0; 32]);
        i.sni = Some("example.com".into());
        let hello = spec.marshal(&i).unwrap();
        // 布局：`44 69`（类型 17513）| `00 05`（扩展长度）| 五字节体。
        // 搜「类型 + 长度」四字节，免得撞上别处的 44 69。
        let raw = hello.as_bytes();
        let pos = raw
            .windows(4)
            .position(|w| w == [0x44, 0x69, 0x00, 0x05])
            .expect("没有 ALPS 扩展（或它的长度不是 5）");
        assert_eq!(
            &raw[pos + 4..pos + 9],
            &[0x00, 0x03, 0x02, b'h', b'2'],
            "ALPS 的体：00 03（ALPS 长度）| 02 68 32（\"h2\"）"
        );
    }

    #[test]
    fn chrome_psk_variants_have_the_expected_extension_types() {
        // 四个 `_PSK_` case：`u_parrots.go:2642`（100）、`:2713`（112）、`:2784`（114）、`:2857`（115）。
        // 100/112 **没有填充**；114 有填充且**在 PSK 之前**；115_PQ 本来就没有填充。
        // 四条都以**空 PSK 标记**收尾（类型 41）—— 那是 RFC 8446 §4.2.11 的位置约束。
        let base = pd::chrome_psk_stable();
        let types: Vec<Option<u16>> = base.extensions.iter().map(|e| e.wire_type()).collect();
        assert_eq!(
            types,
            vec![
                None,
                Some(v::EXT_SERVER_NAME),
                Some(v::EXT_EXTENDED_MASTER_SECRET),
                Some(v::EXT_RENEGOTIATION_INFO),
                Some(v::EXT_SUPPORTED_GROUPS),
                Some(v::EXT_EC_POINT_FORMATS),
                Some(v::EXT_SESSION_TICKET),
                Some(v::EXT_ALPN),
                Some(v::EXT_STATUS_REQUEST),
                Some(v::EXT_SIGNATURE_ALGORITHMS),
                Some(v::EXT_SCT),
                Some(v::EXT_KEY_SHARE),
                Some(v::EXT_PSK_KEY_EXCHANGE_MODES),
                Some(v::EXT_SUPPORTED_VERSIONS),
                Some(v::EXT_COMPRESS_CERTIFICATE),
                Some(v::EXT_APPLICATION_SETTINGS),
                None,
                Some(v::EXT_PRE_SHARED_KEY),
            ],
            "chrome_100_psk / chrome_112_psk 的扩展类型序"
        );
        assert!(
            !types.contains(&Some(v::EXT_PADDING)),
            "100/112 的 case 里没有填充扩展"
        );

        // 114：与 106 相同（**含填充**），末尾加 PSK。
        let p114 = pd::chrome_psk_padding();
        let t114: Vec<Option<u16>> = p114.extensions.iter().map(|e| e.wire_type()).collect();
        let p106 = pd::chrome_106_shuffle();
        let mut want106: Vec<Option<u16>> = p106.extensions.iter().map(|e| e.wire_type()).collect();
        want106.push(Some(v::EXT_PRE_SHARED_KEY));
        assert_eq!(t114, want106, "chrome_114_psk 应当是 106 加一条末尾 PSK");
        let pad = t114.iter().position(|t| *t == Some(v::EXT_PADDING)).unwrap();
        assert_eq!(
            t114.len() - 1,
            t114.iter().rposition(|t| *t == Some(v::EXT_PRE_SHARED_KEY)).unwrap(),
            "PSK 必须在最后"
        );
        assert!(pad < t114.len() - 1, "填充必须在 PSK 之前");

        // 115_PQ：与 chrome_115_pq 相同（无填充），末尾加 PSK。
        let p115 = pd::chrome_psk_pq();
        let mut want115: Vec<Option<u16>> =
            pd::chrome_115_pq().extensions.iter().map(|e| e.wire_type()).collect();
        want115.push(Some(v::EXT_PRE_SHARED_KEY));
        assert_eq!(
            p115.extensions.iter().map(|e| e.wire_type()).collect::<Vec<_>>(),
            want115
        );
    }

    #[test]
    fn psk_variants_have_the_right_variability() {
        // 实测（参照产出）：100_PSK 的 `ja3_stable=true`（Stable），112/114/115 都是 Shuffled。
        let stable = spec_of(ClientHelloId::ChromePsk(100)).unwrap();
        assert_eq!(stable.variability, Variability::Stable, "HelloChrome_100_PSK 没有包乱序");
        for v in [112u16, 114, 115] {
            let s = spec_of(ClientHelloId::ChromePsk(v)).unwrap();
            assert_eq!(s.variability, Variability::Shuffled, "chrome_{v}_psk 该是乱序的");
        }
    }

    #[test]
    fn psk_not_last_is_rejected() {
        // RFC 8446 §4.2.11 的位置约束是**声明层**的错误，不该等到组装时才发现。
        let mut spec = pd::chrome_psk_stable();
        let psk = spec.extensions.pop().unwrap();
        spec.extensions.insert(0, psk);
        let err = spec.marshal(&crate::hello::HandshakeInputs::deterministic([0; 32])).unwrap_err();
        assert!(
            matches!(err, SpecError::PreSharedKeyNotLast { index: 0, .. }),
            "PSK 挪到最前面该报位置错，实际是 {err:?}"
        );
    }

    #[test]
    fn unimplemented_presets_error_instead_of_falling_back() {
        // 未实现的**具体版本**（uTLS 里没有这些版本串）与引擎侧的两个：
        // `Golang` 在 Rust 侧对应「用 rustls 自己的 ClientHello」，本 crate 产不出来。
        let e = spec_of(ClientHelloId::Chrome(999)).unwrap_err();
        assert!(matches!(e, SpecError::PresetUnavailable(ClientHelloId::Chrome(999))));
        assert!(matches!(
            spec_of(ClientHelloId::Ios(14)).unwrap_err(),
            SpecError::PresetUnavailable(ClientHelloId::Ios(14))
        ));
        // `Golang` 不是「未实现」，是「在本架构里不适用」—— 结论已写进错误变体。
        assert!(matches!(
            spec_of(ClientHelloId::Golang).unwrap_err(),
            SpecError::EngineDefined(ClientHelloId::Golang)
        ));
    }

    #[test]
    fn every_implemented_preset_has_a_spec_and_every_other_id_does_not() {
        // 反向断言：`implemented()` 里列的每一个都必须真能产出 spec。
        // 只有正向断言的话，往清单里加一个「声明了但没实现」的名字不会被发现 ——
        // 而那正是这份清单存在的理由。
        for id in ClientHelloId::implemented() {
            assert!(spec_of(*id).is_ok(), "implemented() 声明了 {id}，但 spec_of 产不出来");
        }
        // 清单里**没有**的相邻版本必须报错（不许静默降级）。
        for id in [ClientHelloId::Chrome(999), ClientHelloId::Firefox(999), ClientHelloId::Ios(14)] {
            assert!(!ClientHelloId::implemented().contains(&id));
            assert!(spec_of(id).is_err(), "{id} 不在清单里，却产出了 spec");
        }
        // `Chrome(115)` 也是错的，而理由与上面不同：uTLS **只有** `"115_PQ"` 这一个 115
        // （`u_common.go:639`），所以「普通 115」在参照实现里根本不存在 ——
        // 把它映射到 `ChromePq(115)` 会让 `Chrome(115)` 这个键名悄悄指着一份不是它的数据。
        assert!(spec_of(ClientHelloId::Chrome(115)).is_err());
        assert!(spec_of(ClientHelloId::ChromePq(115)).is_ok());
    }

    #[test]
    fn preset_names_are_unique_and_stable() {
        // 台账键名是事实系统的键：两个预设撞名 ⇒ 后一个覆盖前一个，
        // 而覆盖后的台账看起来完全正常。`ChromePq` 这个变体就是为它加的。
        let mut names: Vec<String> = ClientHelloId::implemented().iter().map(|i| i.name()).collect();
        let before = names.len();
        names.sort();
        names.dedup();
        assert_eq!(names.len(), before, "implemented() 里有重名");
        assert_eq!(ClientHelloId::ChromePq(120).name(), "chrome_120_pq");
        assert_eq!(ClientHelloId::Chrome(120).name(), "chrome_120");
        assert_eq!(ClientHelloId::ChromePq(115).name(), "chrome_115_pq");
    }

    // ── 每条预置的扩展类型序列（`preset_data.rs` 的抄录）──────────────────────
    //
    // 为什么这一大堆断言是本文件最值钱的测试：抄错一个数字**不会编译失败**，
    // 只会让产出的 ClientHello 与目标浏览器差一点点 —— 那是最难查的那种错。
    // 而扩展类型序列是本地能证伪的那一半（另一半是与 Go 的逐字节对照，
    // 只能在真实环境里做，见 AGENTS.md 第二条）。

    use crate::hello::preset_data as pd;
    use crate::hello::Padding;
    /// 打乱**之前**的规范扩展类型序列。`None` = GREASE（类型每连接才定）。
    fn types(spec: &ClientHelloSpec) -> Vec<Option<u16>> {
        spec.extensions.iter().map(|e| e.wire_type()).collect()
    }

    /// 逐条断言扩展类型序列。写成宏是为了让「Go 源里那一行的顺序」与
    /// 「这里的顺序」在视觉上一一对应。
    macro_rules! assert_ext_types {
        ($spec:expr, [$($t:expr),* $(,)?]) => {
            assert_eq!(types(&$spec), vec![$($t),*])
        };
    }

    #[test]
    fn chrome_58_62_has_the_expected_extension_types() {
        // u_parrots.go:66-92。末尾的 padding 在该预置下永不发出（见 preset_data 的函数头）。
        assert_ext_types!(pd::chrome_58_62(), [
            None,                                  // :67  GREASE
            Some(v::EXT_RENEGOTIATION_INFO),       // :68
            Some(v::EXT_SERVER_NAME),              // :69
            Some(v::EXT_EXTENDED_MASTER_SECRET),   // :70
            Some(v::EXT_SESSION_TICKET),           // :71
            Some(v::EXT_SIGNATURE_ALGORITHMS),     // :72
            Some(v::EXT_STATUS_REQUEST),           // :83
            Some(v::EXT_SCT),                      // :84
            Some(v::EXT_ALPN),                     // :85
            Some(v::EXT_CHANNEL_ID),               // :86  新码点 30032
            Some(v::EXT_EC_POINT_FORMATS),         // :87
            Some(v::EXT_SUPPORTED_GROUPS),         // :88
            None,                                  // :90  GREASE
                    Some(v::EXT_PADDING),                  // Go 的 case 末尾列了 BoringPaddingStyle
]);
    }

    #[test]
    fn chrome_70_has_the_expected_extension_types() {
        // u_parrots.go:121-165
        assert_ext_types!(pd::chrome_70(), [
            None,                                  // :122 GREASE
            Some(v::EXT_RENEGOTIATION_INFO),       // :123
            Some(v::EXT_SERVER_NAME),              // :124
            Some(v::EXT_EXTENDED_MASTER_SECRET),   // :125
            Some(v::EXT_SESSION_TICKET),           // :126
            Some(v::EXT_SIGNATURE_ALGORITHMS),     // :127
            Some(v::EXT_STATUS_REQUEST),           // :138
            Some(v::EXT_SCT),                      // :139
            Some(v::EXT_ALPN),                     // :140
            Some(v::EXT_CHANNEL_ID),               // :141
            Some(v::EXT_EC_POINT_FORMATS),         // :142
            Some(v::EXT_KEY_SHARE),                // :145
            Some(v::EXT_PSK_KEY_EXCHANGE_MODES),   // :149
            Some(v::EXT_SUPPORTED_VERSIONS),       // :150
            Some(v::EXT_SUPPORTED_GROUPS),         // :156
            Some(v::EXT_COMPRESS_CERTIFICATE),     // :162
            None,                                  // :163 GREASE
            Some(v::EXT_PADDING),                  // :164
        ]);
    }

    #[test]
    fn chrome_72_has_the_expected_extension_types() {
        // u_parrots.go:191-239 —— 与 Chrome 70 是同一堆扩展的**另一个顺序**
        assert_ext_types!(pd::chrome_72(), [
            None,                                  // :192 GREASE
            Some(v::EXT_SERVER_NAME),              // :193
            Some(v::EXT_EXTENDED_MASTER_SECRET),   // :194
            Some(v::EXT_RENEGOTIATION_INFO),       // :195
            Some(v::EXT_SUPPORTED_GROUPS),         // :196
            Some(v::EXT_EC_POINT_FORMATS),         // :202
            Some(v::EXT_SESSION_TICKET),           // :205
            Some(v::EXT_ALPN),                     // :206
            Some(v::EXT_STATUS_REQUEST),           // :207
            Some(v::EXT_SIGNATURE_ALGORITHMS),     // :208
            Some(v::EXT_SCT),                      // :219
            Some(v::EXT_KEY_SHARE),                // :220
            Some(v::EXT_PSK_KEY_EXCHANGE_MODES),   // :224
            Some(v::EXT_SUPPORTED_VERSIONS),       // :227
            Some(v::EXT_COMPRESS_CERTIFICATE),     // :234
            None,                                  // :237 GREASE
            Some(v::EXT_PADDING),                  // :238
        ]);
    }

    #[test]
    fn chrome_83_and_87_have_the_expected_extension_types() {
        // u_parrots.go:264-311（83）与 :336-383（87）—— 两条逐条相同，仍分开断言
        let expected = vec![
            None,
            Some(v::EXT_SERVER_NAME),
            Some(v::EXT_EXTENDED_MASTER_SECRET),
            Some(v::EXT_RENEGOTIATION_INFO),
            Some(v::EXT_SUPPORTED_GROUPS),
            Some(v::EXT_EC_POINT_FORMATS),
            Some(v::EXT_SESSION_TICKET),
            Some(v::EXT_ALPN),
            Some(v::EXT_STATUS_REQUEST),
            Some(v::EXT_SIGNATURE_ALGORITHMS),
            Some(v::EXT_SCT),
            Some(v::EXT_KEY_SHARE),
            Some(v::EXT_PSK_KEY_EXCHANGE_MODES),
            Some(v::EXT_SUPPORTED_VERSIONS),
            Some(v::EXT_COMPRESS_CERTIFICATE),
            None,
            Some(v::EXT_PADDING),
        ];
        assert_eq!(types(&pd::chrome_83()), expected, "chrome_83");
        assert_eq!(types(&pd::chrome_87()), expected, "chrome_87");
    }

    #[test]
    fn chrome_96_100_102_106_have_the_expected_extension_types() {
        // u_parrots.go:408-456（96）、:481-527（100/102）、:552-598（106）。
        // 四条的类型序列相同 —— 差别在 supported_versions 的内容（96 多报 1.1/1.0）
        // 与是否乱序（106）。那些差别由下面几条测试单列。
        let expected = vec![
            None,
            Some(v::EXT_SERVER_NAME),
            Some(v::EXT_EXTENDED_MASTER_SECRET),
            Some(v::EXT_RENEGOTIATION_INFO),
            Some(v::EXT_SUPPORTED_GROUPS),
            Some(v::EXT_EC_POINT_FORMATS),
            Some(v::EXT_SESSION_TICKET),
            Some(v::EXT_ALPN),
            Some(v::EXT_STATUS_REQUEST),
            Some(v::EXT_SIGNATURE_ALGORITHMS),
            Some(v::EXT_SCT),
            Some(v::EXT_KEY_SHARE),
            Some(v::EXT_PSK_KEY_EXCHANGE_MODES),
            Some(v::EXT_SUPPORTED_VERSIONS),
            Some(v::EXT_COMPRESS_CERTIFICATE),
            Some(v::EXT_APPLICATION_SETTINGS), // :453 / :524 / :595 —— 旧码点 17513
            None,
            Some(v::EXT_PADDING),
        ];
        assert_eq!(types(&pd::chrome_96()), expected, "chrome_96");
        assert_eq!(types(&pd::chrome_100_102()), expected, "chrome_100_102");
        assert_eq!(types(&pd::chrome_106_shuffle()), expected, "chrome_106_shuffle");

        // 96 报 GREASE+1.3/1.2/1.1/1.0；100/102/106 缩到 GREASE+1.3/1.2。
        let versions = |spec: &ClientHelloSpec| -> Option<Vec<CodePoint>> {
            spec.extensions.iter().find_map(|e| match e {
                Extension::SupportedVersions(x) => Some(x.clone()),
                _ => None,
            })
        };
        assert_eq!(versions(&pd::chrome_96()).unwrap().len(), 5);
        assert_eq!(versions(&pd::chrome_100_102()).unwrap().len(), 3);
        assert_eq!(versions(&pd::chrome_106_shuffle()).unwrap().len(), 3);
        // 乱序只在 106（`u_parrots.go:552` 的 ShuffleChromeTLSExtensions）。
        assert_eq!(pd::chrome_96().variability, Variability::Stable);
        assert_eq!(pd::chrome_100_102().variability, Variability::Stable);
        assert_eq!(pd::chrome_106_shuffle().variability, Variability::Shuffled);
    }

    #[test]
    fn chrome_115_pq_has_the_expected_extension_types() {
        // u_parrots.go:624-672。注意**没有 padding**（Kyber 公钥 1216 字节 ⇒ 超出 0x200）。
        assert_ext_types!(pd::chrome_115_pq(), [
            None,
            Some(v::EXT_SERVER_NAME),
            Some(v::EXT_EXTENDED_MASTER_SECRET),
            Some(v::EXT_RENEGOTIATION_INFO),
            Some(v::EXT_SUPPORTED_GROUPS),
            Some(v::EXT_EC_POINT_FORMATS),
            Some(v::EXT_SESSION_TICKET),
            Some(v::EXT_ALPN),
            Some(v::EXT_STATUS_REQUEST),
            Some(v::EXT_SIGNATURE_ALGORITHMS),
            Some(v::EXT_SCT),
            Some(v::EXT_KEY_SHARE),
            Some(v::EXT_PSK_KEY_EXCHANGE_MODES),
            Some(v::EXT_SUPPORTED_VERSIONS),
            Some(v::EXT_COMPRESS_CERTIFICATE),
            Some(v::EXT_APPLICATION_SETTINGS),
            None,
                    Some(v::EXT_PADDING),                  // Go 的 case 末尾列了 BoringPaddingStyle
]);
    }

    #[test]
    fn chrome_120_and_120_pq_have_the_expected_extension_types() {
        // u_parrots.go:698-745（120）与 :771-819（120_PQ）—— GREASE ECH 在 ALPS 之后
        let expected = vec![
            None,
            Some(v::EXT_SERVER_NAME),
            Some(v::EXT_EXTENDED_MASTER_SECRET),
            Some(v::EXT_RENEGOTIATION_INFO),
            Some(v::EXT_SUPPORTED_GROUPS),
            Some(v::EXT_EC_POINT_FORMATS),
            Some(v::EXT_SESSION_TICKET),
            Some(v::EXT_ALPN),
            Some(v::EXT_STATUS_REQUEST),
            Some(v::EXT_SIGNATURE_ALGORITHMS),
            Some(v::EXT_SCT),
            Some(v::EXT_KEY_SHARE),
            Some(v::EXT_PSK_KEY_EXCHANGE_MODES),
            Some(v::EXT_SUPPORTED_VERSIONS),
            Some(v::EXT_COMPRESS_CERTIFICATE),
            Some(v::EXT_APPLICATION_SETTINGS),
            Some(v::EXT_ENCRYPTED_CLIENT_HELLO),
            None,
            Some(v::EXT_PADDING),                  // BoringPaddingStyle，条件由模型判断
        ];
        // ⚠️ 两个 case **不是**只差 GREASE-ECH：`chrome_120` 的 case 末尾列了
        // `UtlsPaddingExtension`（:744），而 `chrome_120_PQ` 的 case（:771-819）
        // **没有列**。所以它们不能共用一个期望数组。
        let mut expected_pq = expected.clone();
        expected_pq.pop();
        assert_eq!(types(&pd::chrome_120()), expected, "chrome_120");
        assert_eq!(types(&pd::chrome_120_pq()), expected_pq, "chrome_120_pq");
        assert_eq!(pd::chrome_120().variability, Variability::Shuffled);
        assert_eq!(pd::chrome_120_pq().variability, Variability::Shuffled);
    }

    #[test]
    fn chrome_131_differs_from_133_only_in_the_alps_codepoint() {
        // u_parrots.go:844-892（131，ALPS **旧**码点 :889）与 :917-965（133，新码点 :962）。
        // `diff` 两个 case 体只差这一行 —— 这条测试就是那个 diff 的可编译版本。
        let c131 = pd::chrome_131();
        let c133 = chrome_133();
        assert_ext_types!(c131, [
            None,
            Some(v::EXT_SERVER_NAME),
            Some(v::EXT_EXTENDED_MASTER_SECRET),
            Some(v::EXT_RENEGOTIATION_INFO),
            Some(v::EXT_SUPPORTED_GROUPS),
            Some(v::EXT_EC_POINT_FORMATS),
            Some(v::EXT_SESSION_TICKET),
            Some(v::EXT_ALPN),
            Some(v::EXT_STATUS_REQUEST),
            Some(v::EXT_SIGNATURE_ALGORITHMS),
            Some(v::EXT_SCT),
            Some(v::EXT_KEY_SHARE),
            Some(v::EXT_PSK_KEY_EXCHANGE_MODES),
            Some(v::EXT_SUPPORTED_VERSIONS),
            Some(v::EXT_COMPRESS_CERTIFICATE),
            Some(v::EXT_APPLICATION_SETTINGS), // :889 旧码点！
            Some(v::EXT_ENCRYPTED_CLIENT_HELLO),
            None,
        ]);
        assert_eq!(
            c133.extensions[15].wire_type(),
            Some(v::EXT_APPLICATION_SETTINGS_NEW),
            "chrome_133 用的应是新码点 17613"
        );
        // 除 ALPS 那一项外，两个 spec 的其余部分逐字段相同。
        let mut a = c131.clone();
        let b = c133;
        a.extensions[15] = b.extensions[15].clone();
        assert_eq!(a, b, "131 与 133 除 ALPS 码点外应逐条相同");
    }

    #[test]
    fn firefox_55_56_has_the_expected_extension_types() {
        // u_parrots.go:989-1012。末尾 padding 在该预置下永不发出（见 preset_data 的函数头）。
        assert_ext_types!(pd::firefox_55_56(), [
            Some(v::EXT_SERVER_NAME),              // :990
            Some(v::EXT_EXTENDED_MASTER_SECRET),   // :991
            Some(v::EXT_RENEGOTIATION_INFO),       // :992
            Some(v::EXT_SUPPORTED_GROUPS),         // :993
            Some(v::EXT_EC_POINT_FORMATS),         // :994
            Some(v::EXT_SESSION_TICKET),           // :995
            Some(v::EXT_ALPN),                     // :996
            Some(v::EXT_STATUS_REQUEST),           // :997
            Some(v::EXT_SIGNATURE_ALGORITHMS),     // :998
                    Some(v::EXT_PADDING),                  // Go 的 case 末尾列了 BoringPaddingStyle
]);
    }

    #[test]
    fn firefox_63_65_has_the_expected_extension_types() {
        // u_parrots.go:1042-1084 —— key_share 在 signature_algorithms **之前**
        assert_ext_types!(pd::firefox_63_65(), [
            Some(v::EXT_SERVER_NAME),              // :1043
            Some(v::EXT_EXTENDED_MASTER_SECRET),   // :1044
            Some(v::EXT_RENEGOTIATION_INFO),       // :1045
            Some(v::EXT_SUPPORTED_GROUPS),         // :1046
            Some(v::EXT_EC_POINT_FORMATS),         // :1054
            Some(v::EXT_SESSION_TICKET),           // :1057
            Some(v::EXT_ALPN),                     // :1058
            Some(v::EXT_STATUS_REQUEST),           // :1059
            Some(v::EXT_KEY_SHARE),                // :1060
            Some(v::EXT_SUPPORTED_VERSIONS),       // :1064
            Some(v::EXT_SIGNATURE_ALGORITHMS),     // :1069
            Some(v::EXT_PSK_KEY_EXCHANGE_MODES),   // :1082
            Some(v::EXT_RECORD_SIZE_LIMIT),        // :1083
            Some(v::EXT_PADDING),                  // :1084
        ]);
    }

    #[test]
    fn firefox_99_102_105_have_the_expected_extension_types() {
        // u_parrots.go:1113-1166（99）、:1194-1245（102）、:1273-1352（105）—— 三条顺序相同
        let expected = vec![
            Some(v::EXT_SERVER_NAME),
            Some(v::EXT_EXTENDED_MASTER_SECRET),
            Some(v::EXT_RENEGOTIATION_INFO),
            Some(v::EXT_SUPPORTED_GROUPS),
            Some(v::EXT_EC_POINT_FORMATS),
            Some(v::EXT_SESSION_TICKET),
            Some(v::EXT_ALPN),
            Some(v::EXT_STATUS_REQUEST),
            Some(v::EXT_DELEGATED_CREDENTIALS), // :1131 / :1212 / :1302
            Some(v::EXT_KEY_SHARE),
            Some(v::EXT_SUPPORTED_VERSIONS),
            Some(v::EXT_SIGNATURE_ALGORITHMS),
            Some(v::EXT_PSK_KEY_EXCHANGE_MODES),
            Some(v::EXT_RECORD_SIZE_LIMIT),
            Some(v::EXT_PADDING),
        ];
        assert_eq!(types(&pd::firefox_99()), expected, "firefox_99");
        assert_eq!(types(&pd::firefox_102()), expected, "firefox_102");
        assert_eq!(types(&pd::firefox_105()), expected, "firefox_105");

        // 三者之间的**数据**差别只有 ALPN 与版本列表：102 只报 h2，105 回到两个协议。
        let alpn = |spec: &ClientHelloSpec| -> Option<Vec<Vec<u8>>> {
            spec.extensions.iter().find_map(|e| match e {
                Extension::Alpn(l) => Some(l.clone()),
                _ => None,
            })
        };
        assert_eq!(alpn(&pd::firefox_99()).unwrap().len(), 2);
        assert_eq!(alpn(&pd::firefox_102()).unwrap(), vec![b"h2".to_vec()]);
        assert_eq!(alpn(&pd::firefox_105()).unwrap().len(), 2);
        assert_eq!(pd::firefox_102().cipher_suites.len(), 17);
        assert_eq!(pd::firefox_99().cipher_suites.len(), 18);
    }

    #[test]
    fn firefox_120_has_the_expected_extension_types() {
        // u_parrots.go:1380-1467 —— 末尾是 GREASE ECH，**没有 padding**
        assert_ext_types!(pd::firefox_120(), [
            Some(v::EXT_SERVER_NAME),
            Some(v::EXT_EXTENDED_MASTER_SECRET),
            Some(v::EXT_RENEGOTIATION_INFO),
            Some(v::EXT_SUPPORTED_GROUPS),
            Some(v::EXT_EC_POINT_FORMATS),
            Some(v::EXT_SESSION_TICKET),
            Some(v::EXT_ALPN),
            Some(v::EXT_STATUS_REQUEST),
            Some(v::EXT_DELEGATED_CREDENTIALS),
            Some(v::EXT_KEY_SHARE),
            Some(v::EXT_SUPPORTED_VERSIONS),
            Some(v::EXT_SIGNATURE_ALGORITHMS),
            Some(v::EXT_PSK_KEY_EXCHANGE_MODES),
            Some(v::EXT_RECORD_SIZE_LIMIT),
            Some(v::EXT_ENCRYPTED_CLIENT_HELLO), // :1454
        ]);
    }

    #[test]
    fn ios_11_1_and_12_1_have_the_expected_extension_types() {
        // u_parrots.go:1621-1649（11.1）与 :1681-1711（12.1）—— RenegotiationInfo 在 SNI 之前
        let expected = vec![
            Some(v::EXT_RENEGOTIATION_INFO),
            Some(v::EXT_SERVER_NAME),
            Some(v::EXT_EXTENDED_MASTER_SECRET),
            Some(v::EXT_SIGNATURE_ALGORITHMS),
            Some(v::EXT_STATUS_REQUEST),
            Some(v::EXT_NPN), // 码点 13172
            Some(v::EXT_SCT),
            Some(v::EXT_ALPN),
            Some(v::EXT_EC_POINT_FORMATS),
            Some(v::EXT_SUPPORTED_GROUPS),
        ];
        assert_eq!(types(&pd::ios_11_1()), expected, "ios_11_1");
        assert_eq!(types(&pd::ios_12_1()), expected, "ios_12_1");
        // 两条都没有 supported_versions（TLS 1.2 封顶）。
        assert!(!expected.contains(&Some(v::EXT_SUPPORTED_VERSIONS)));
    }

    #[test]
    fn ios_13_has_the_expected_extension_types() {
        // u_parrots.go:1746-1788 —— supported_groups 排在 supported_versions **之后**
        assert_ext_types!(pd::ios_13(), [
            Some(v::EXT_RENEGOTIATION_INFO),       // :1747
            Some(v::EXT_SERVER_NAME),              // :1748
            Some(v::EXT_EXTENDED_MASTER_SECRET),   // :1749
            Some(v::EXT_SIGNATURE_ALGORITHMS),     // :1750
            Some(v::EXT_STATUS_REQUEST),           // :1763
            Some(v::EXT_SCT),                      // :1764
            Some(v::EXT_ALPN),                     // :1765
            Some(v::EXT_EC_POINT_FORMATS),         // :1766
            Some(v::EXT_KEY_SHARE),                // :1769
            Some(v::EXT_PSK_KEY_EXCHANGE_MODES),   // :1772
            Some(v::EXT_SUPPORTED_VERSIONS),       // :1775
            Some(v::EXT_SUPPORTED_GROUPS),         // :1781
            Some(v::EXT_PADDING),                  // :1787
        ]);
    }

    #[test]
    fn android_11_okhttp_has_the_expected_extension_types() {
        // u_parrots.go:1894-1919 —— 7 条，**没有 ALPN / SCT / supported_versions / GREASE**
        assert_ext_types!(pd::android_11_okhttp(), [
            Some(v::EXT_SERVER_NAME),              // :1895
            Some(v::EXT_EXTENDED_MASTER_SECRET),   // :1896
            Some(v::EXT_RENEGOTIATION_INFO),       // :1897
            Some(v::EXT_SUPPORTED_GROUPS),         // :1899
            Some(v::EXT_EC_POINT_FORMATS),         // :1904
            Some(v::EXT_STATUS_REQUEST),           // :1907
            Some(v::EXT_SIGNATURE_ALGORITHMS),     // :1908
        ]);
    }

    #[test]
    fn edge_85_has_the_expected_extension_types() {
        // u_parrots.go:1944-2021 —— 与 Chrome 96 只差 supported_versions 的内容与没有 ALPS
        assert_ext_types!(pd::edge_85(), [
            None,
            Some(v::EXT_SERVER_NAME),
            Some(v::EXT_EXTENDED_MASTER_SECRET),
            Some(v::EXT_RENEGOTIATION_INFO),
            Some(v::EXT_SUPPORTED_GROUPS),
            Some(v::EXT_EC_POINT_FORMATS),
            Some(v::EXT_SESSION_TICKET),
            Some(v::EXT_ALPN),
            Some(v::EXT_STATUS_REQUEST),
            Some(v::EXT_SIGNATURE_ALGORITHMS),
            Some(v::EXT_SCT),
            Some(v::EXT_KEY_SHARE),
            Some(v::EXT_PSK_KEY_EXCHANGE_MODES),
            Some(v::EXT_SUPPORTED_VERSIONS),
            Some(v::EXT_COMPRESS_CERTIFICATE),
            None,
            Some(v::EXT_PADDING),
        ]);
    }

    #[test]
    fn edge_106_has_the_expected_extension_types() {
        // u_parrots.go:2048-2128 —— 与 Chrome 100/102 逐条相同
        assert_ext_types!(pd::edge_106(), [
            None,
            Some(v::EXT_SERVER_NAME),
            Some(v::EXT_EXTENDED_MASTER_SECRET),
            Some(v::EXT_RENEGOTIATION_INFO),
            Some(v::EXT_SUPPORTED_GROUPS),
            Some(v::EXT_EC_POINT_FORMATS),
            Some(v::EXT_SESSION_TICKET),
            Some(v::EXT_ALPN),
            Some(v::EXT_STATUS_REQUEST),
            Some(v::EXT_SIGNATURE_ALGORITHMS),
            Some(v::EXT_SCT),
            Some(v::EXT_KEY_SHARE),
            Some(v::EXT_PSK_KEY_EXCHANGE_MODES),
            Some(v::EXT_SUPPORTED_VERSIONS),
            Some(v::EXT_COMPRESS_CERTIFICATE),
            Some(v::EXT_APPLICATION_SETTINGS),
            None,
            Some(v::EXT_PADDING),
        ]);
    }

    #[test]
    fn safari_16_0_has_the_expected_extension_types() {
        // u_parrots.go:2160-2240 —— **没有 session_ticket**，padding 在最后
        assert_ext_types!(pd::safari_16_0(), [
            None,
            Some(v::EXT_SERVER_NAME),
            Some(v::EXT_EXTENDED_MASTER_SECRET),
            Some(v::EXT_RENEGOTIATION_INFO),
            Some(v::EXT_SUPPORTED_GROUPS),
            Some(v::EXT_EC_POINT_FORMATS),
            Some(v::EXT_ALPN),
            Some(v::EXT_STATUS_REQUEST),
            Some(v::EXT_SIGNATURE_ALGORITHMS),
            Some(v::EXT_SCT),
            Some(v::EXT_KEY_SHARE),
            Some(v::EXT_PSK_KEY_EXCHANGE_MODES),
            Some(v::EXT_SUPPORTED_VERSIONS),
            Some(v::EXT_COMPRESS_CERTIFICATE),
            None,
            Some(v::EXT_PADDING),
        ]);
    }

    #[test]
    fn safari_26_3_has_the_expected_extension_types() {
        // u_parrots.go:2272-2350 —— 末尾是 compress_certificate + GREASE，**没有 padding**
        assert_ext_types!(pd::safari_26_3(), [
            None,
            Some(v::EXT_SERVER_NAME),
            Some(v::EXT_EXTENDED_MASTER_SECRET),
            Some(v::EXT_RENEGOTIATION_INFO),
            Some(v::EXT_SUPPORTED_GROUPS),
            Some(v::EXT_EC_POINT_FORMATS),
            Some(v::EXT_ALPN),
            Some(v::EXT_STATUS_REQUEST),
            Some(v::EXT_SIGNATURE_ALGORITHMS),
            Some(v::EXT_SCT),
            Some(v::EXT_KEY_SHARE),
            Some(v::EXT_PSK_KEY_EXCHANGE_MODES),
            Some(v::EXT_SUPPORTED_VERSIONS),
            Some(v::EXT_COMPRESS_CERTIFICATE),
            None,
        ]);
        // Safari 26.3 的两个独有记号：1.3 套件里 AES-256 在 AES-128 **之前**，
        // 且 compress_certificate 只报 zlib。
        assert_eq!(pd::safari_26_3().cipher_suites[1], CodePoint::Fixed(v::TLS_AES_256_GCM_SHA384));
        assert_eq!(pd::safari_16_0().cipher_suites[1], CodePoint::Fixed(v::TLS_AES_128_GCM_SHA256));
    }

    #[test]
    fn browser360_7_5_has_the_expected_extension_types() {
        // u_parrots.go:2379-2422 —— 无 GREASE、无 padding、老码点 channel_id
        assert_ext_types!(pd::browser360_7_5(), [
            Some(v::EXT_SERVER_NAME),              // :2380
            Some(v::EXT_RENEGOTIATION_INFO),       // :2381
            Some(v::EXT_SUPPORTED_GROUPS),         // :2384
            Some(v::EXT_EC_POINT_FORMATS),         // :2391
            Some(v::EXT_SESSION_TICKET),           // :2396
            Some(v::EXT_NPN),                      // :2397
            Some(v::EXT_ALPN),                     // :2398
            Some(v::EXT_CHANNEL_ID_OLD),           // :2406 码点 30031
            Some(v::EXT_STATUS_REQUEST),           // :2409
            Some(v::EXT_SIGNATURE_ALGORITHMS),     // :2410
        ]);
    }

    #[test]
    fn browser360_11_0_has_the_expected_extension_types() {
        // u_parrots.go:2450-2531 —— channel_id（新码点）夹在 SCT 与 key_share 之间
        assert_ext_types!(pd::browser360_11_0(), [
            None,
            Some(v::EXT_SERVER_NAME),
            Some(v::EXT_EXTENDED_MASTER_SECRET),
            Some(v::EXT_RENEGOTIATION_INFO),
            Some(v::EXT_SUPPORTED_GROUPS),
            Some(v::EXT_EC_POINT_FORMATS),
            Some(v::EXT_SESSION_TICKET),
            Some(v::EXT_ALPN),
            Some(v::EXT_STATUS_REQUEST),
            Some(v::EXT_SIGNATURE_ALGORITHMS),
            Some(v::EXT_SCT),
            Some(v::EXT_CHANNEL_ID),               // :2492 码点 30032
            Some(v::EXT_KEY_SHARE),
            Some(v::EXT_PSK_KEY_EXCHANGE_MODES),
            Some(v::EXT_SUPPORTED_VERSIONS),
            Some(v::EXT_COMPRESS_CERTIFICATE),
            None,
            Some(v::EXT_PADDING),
        ]);
    }

    #[test]
    fn qq_11_1_has_the_expected_extension_types() {
        // u_parrots.go:2558-2640 —— 与 Chrome 96 同形，**没有** channel_id
        assert_ext_types!(pd::qq_11_1(), [
            None,
            Some(v::EXT_SERVER_NAME),
            Some(v::EXT_EXTENDED_MASTER_SECRET),
            Some(v::EXT_RENEGOTIATION_INFO),
            Some(v::EXT_SUPPORTED_GROUPS),
            Some(v::EXT_EC_POINT_FORMATS),
            Some(v::EXT_SESSION_TICKET),
            Some(v::EXT_ALPN),
            Some(v::EXT_STATUS_REQUEST),
            Some(v::EXT_SIGNATURE_ALGORITHMS),
            Some(v::EXT_SCT),
            Some(v::EXT_KEY_SHARE),
            Some(v::EXT_PSK_KEY_EXCHANGE_MODES),
            Some(v::EXT_SUPPORTED_VERSIONS),
            Some(v::EXT_COMPRESS_CERTIFICATE),
            Some(v::EXT_APPLICATION_SETTINGS),
            None,
            Some(v::EXT_PADDING),
        ]);
        // 与 Chrome 96 的唯一数据差别：签名算法少一个 PKCS1WithSHA1。
        assert_eq!(pd::qq_11_1().cipher_suites, pd::chrome_96().cipher_suites);
        let sigs = |spec: &ClientHelloSpec| -> Vec<CodePoint> {
            spec.extensions
                .iter()
                .find_map(|e| match e {
                    Extension::SignatureAlgorithms(l) => Some(l.clone()),
                    _ => None,
                })
                .unwrap()
        };
        assert_eq!(sigs(&pd::qq_11_1()).len(), 8);
        assert_eq!(sigs(&pd::chrome_96()).len(), 8);
        assert!(sigs(&pd::chrome_72()).len() == 9);
    }

    // ── 跨预设的**行为**断言（不是数据抄录）────────────────────────────────

    /// 规范测量输入：与 `examples/reflect-facts.rs` 同口径（seed 0、SNI `example.com`）。
    ///
    /// 公钥长度是**真实的**（它们进指纹：决定 ClientHello 总长），内容是哑的。
    fn canonical_inputs(spec: &ClientHelloSpec) -> crate::hello::HandshakeInputs {
        let mut inputs = crate::hello::HandshakeInputs::deterministic([0u8; 32]);
        inputs.sni = Some("example.com".into());
        let mut groups: Vec<u16> = Vec::new();
        for e in &spec.extensions {
            if let Extension::KeyShare(cps) = e {
                for cp in cps {
                    if let CodePoint::Fixed(g) = cp
                        && !v::is_grease(*g)
                    {
                        groups.push(*g);
                    }
                }
            }
        }
        inputs.key_exchange = groups.into_iter().map(|g| (g, vec![0x5A; key_len(g)])).collect();
        inputs
    }

    /// 各命名组的公钥长度（与 `examples/reflect-facts.rs` 同表）。
    fn key_len(group: u16) -> usize {
        match group {
            v::CURVE_P256 => 65,
            // ML-KEM-768 / Kyber768 封装密钥各 1184 字节，再加 X25519 的 32。
            v::X25519_MLKEM768 => 32 + 1184,
            v::X25519_KYBER768_DRAFT00 => 32 + 1184,
            _ => 32,
        }
    }

    /// 去掉填充体之后的握手消息总长 —— 就是 uTLS `BoringPaddingStyle` 收到的那个
    /// 「未填充长」（调用点 `u_conn.go:611`：`headerLength + 4 + extensionsLen + 2`）。
    ///
    /// 用 `Padding::None`（体为空）代替删掉扩展：扩展头 4 字节仍在，
    /// 正好等于「padding 扩展在场但体为 0」的那个基准。
    fn unpadded_len(spec: &ClientHelloSpec) -> Option<usize> {
        let mut probe = spec.clone();
        for e in &mut probe.extensions {
            if let Extension::Padding(p) = e {
                *p = Padding::None;
            }
        }
        let inputs = canonical_inputs(&probe);
        probe.marshal(&inputs).ok().map(|h| h.len())
    }

    /// 每条预置的填充决策必须与 uTLS 在同一输入下一致。两件事要分开：
    ///
    /// 1. **Go 的 `case` 里有没有列 `UtlsPaddingExtension{BoringPaddingStyle}`** ——
    ///    那是数据（下面的 `true`/`false` 就是逐条对照 `u_parrots.go` 抄的），
    ///    没有它就没有填充可言，未填充长落在哪都不补；
    /// 2. **有它的那些**，`BoringPaddingStyle`（`u_tls_extensions.go:1115-1129`）只在
    ///    未填充长 ∈ `(0xff, 0x200)` 时才发。落在区间里 ⇒ 我们也必须在，且总长恰好 0x200；
    ///    落在区间外 ⇒ Go 不发，我们也必须不在。
    ///
    /// 这条测试把「数据里有没有 padding 那一项」从**记忆**变成**可复算**的断言。
    /// 它同时是 `preset_data.rs` 文件头注意事项 2 的执行体：本层表达不了
    /// 「同一个 spec 随 SNI 变长决定发不发」，所以这里只钉住规范输入下那一种，
    /// 并把区间条件本身写下来 —— 换了 SNI 长度，条件就该重算。
    ///
    /// ⚠️ `ios_11_1` 这类「未填充长恰好在区间内、但 Go 的 `case` 根本没列 padding」的条目
    /// 正是第 1 条存在的理由：只看区间会得出「该发」的错结论。
    #[test]
    fn padding_presence_matches_the_go_source_and_the_boring_style_band() {
        // (名字, Go 的 case 里是否列了 BoringPaddingStyle padding)
        let all: Vec<(&str, bool, ClientHelloSpec)> = vec![
            ("chrome_58_62", true, pd::chrome_58_62()),
            ("chrome_70", true, pd::chrome_70()),
            ("chrome_72", true, pd::chrome_72()),
            ("chrome_83", true, pd::chrome_83()),
            ("chrome_87", true, pd::chrome_87()),
            ("chrome_96", true, pd::chrome_96()),
            ("chrome_100_102", true, pd::chrome_100_102()),
            ("chrome_106_shuffle", true, pd::chrome_106_shuffle()),
            ("chrome_115_pq", true, pd::chrome_115_pq()),
            ("chrome_120", true, pd::chrome_120()),
            ("chrome_120_pq", false, pd::chrome_120_pq()),
            ("chrome_131", false, pd::chrome_131()),
            ("firefox_55_56", true, pd::firefox_55_56()),
            ("firefox_63_65", true, pd::firefox_63_65()),
            ("firefox_99", true, pd::firefox_99()),
            ("firefox_102", true, pd::firefox_102()),
            ("firefox_105", true, pd::firefox_105()),
            ("firefox_120", false, pd::firefox_120()),
            ("ios_11_1", false, pd::ios_11_1()),
            ("ios_12_1", false, pd::ios_12_1()),
            ("ios_13", true, pd::ios_13()),
            ("android_11_okhttp", false, pd::android_11_okhttp()),
            ("edge_85", true, pd::edge_85()),
            ("edge_106", true, pd::edge_106()),
            ("safari_16_0", true, pd::safari_16_0()),
            ("safari_26_3", false, pd::safari_26_3()),
            ("browser360_7_5", false, pd::browser360_7_5()),
            ("browser360_11_0", true, pd::browser360_11_0()),
            ("qq_11_1", true, pd::qq_11_1()),
        ];
        for (name, go_lists_padding, spec) in all {
            let has_padding =
                spec.extensions.iter().any(|e| matches!(e, Extension::Padding(_)));
            let base = unpadded_len(&spec).unwrap_or_else(|| panic!("{name}: 未填充长算不出来"));
            // 规范里的**存在性**：Go 的 case 列了 `BoringPaddingStyle` ⇒ 本预置也必须列一条
            // `Padding::BoringStyle`（发不发由条件本身在 encode 时决定，不由预置预先判定）。
            assert_eq!(
                has_padding, go_lists_padding,
                "{name}: 未填充长 {base}，Go 的 case {}列 padding，而本预置里{} \
                 —— 存在性必须与规范一致，发不发是另一件事",
                if go_lists_padding { "有" } else { "没有" },
                if has_padding { "有" } else { "没有" },
            );
        }
    }

    /// 每条预置都要能真的产出一条 ClientHello，且扩展类型序列里**没有重复**
    /// （GREASE 除外）—— 重复类型是抄错一行的典型症状。
    #[test]
    fn every_preset_marshals_and_has_no_duplicate_extension_types() {
        for id in ClientHelloId::implemented() {
            let spec = ClientHelloSpec::from_preset(*id).unwrap_or_else(|e| panic!("{id}: {e}"));
            if spec.cipher_suites.is_empty() {
                continue; // Custom：空 spec，量不出指纹
            }
            let hello = spec
                .marshal(&canonical_inputs(&spec))
                .unwrap_or_else(|e| panic!("{id}: marshal 失败：{e}"));
            assert!(hello.len() > 4, "{id}: 产出的握手消息过短");

            let mut seen: Vec<u16> = Vec::new();
            for t in types(&spec).into_iter().flatten() {
                assert!(!seen.contains(&t), "{id}: 扩展类型 {t} 出现两次");
                seen.push(t);
            }
        }
    }

    /// 密码套件列表里除 GREASE 之外不得有重复。
    #[test]
    fn every_preset_has_no_duplicate_cipher_suites() {
        for id in ClientHelloId::implemented() {
            let spec = ClientHelloSpec::from_preset(*id).unwrap();
            if spec.cipher_suites.is_empty() {
                continue;
            }
            let mut seen: Vec<u16> = Vec::new();
            for c in &spec.cipher_suites {
                if let CodePoint::Fixed(x) = c {
                    assert!(!seen.contains(x), "{id}: 密码套件 {x} 出现两次");
                    seen.push(*x);
                }
            }
        }
    }

    /// 只有 uTLS 明确调了 `ShuffleChromeTLSExtensions` 的那些 `case` 才是乱序的
    /// （`u_parrots.go:552/624/698/771/844/917`）—— 一条反向断言，防止「顺手也乱序」。
    #[test]
    fn only_the_shuffled_chrome_presets_are_shuffled() {
        let shuffled: Vec<&str> = [
            ("chrome_106_shuffle", pd::chrome_106_shuffle()),
            ("chrome_115_pq", pd::chrome_115_pq()),
            ("chrome_120", pd::chrome_120()),
            ("chrome_120_pq", pd::chrome_120_pq()),
            ("chrome_131", pd::chrome_131()),
            ("chrome_133", chrome_133()),
        ]
        .into_iter()
        .filter(|(_, s)| s.variability == Variability::Shuffled)
        .map(|(n, _)| n)
        .collect();
        assert_eq!(
            shuffled,
            vec![
                "chrome_106_shuffle",
                "chrome_115_pq",
                "chrome_120",
                "chrome_120_pq",
                "chrome_131",
                "chrome_133"
            ]
        );
        for (name, spec) in [
            ("chrome_58_62", pd::chrome_58_62()),
            ("chrome_70", pd::chrome_70()),
            ("chrome_72", pd::chrome_72()),
            ("chrome_83", pd::chrome_83()),
            ("chrome_87", pd::chrome_87()),
            ("chrome_96", pd::chrome_96()),
            ("chrome_100_102", pd::chrome_100_102()),
            ("firefox_63_65", pd::firefox_63_65()),
            ("safari_16_0", pd::safari_16_0()),
        ] {
            assert_eq!(spec.variability, Variability::Stable, "{name} 不该乱序");
        }
    }

    /// iOS 12.1 / 13 的签名算法表里 `PSSWithSHA384` 出现**两次**
    /// （uTLS `u_parrots.go:1691-1692` 的原样）。单列断言，
    /// 免得有人看到「重复」把它当抄写错误删掉 —— 删了就不是那条指纹了。
    #[test]
    fn ios_signature_algorithms_keep_the_duplicate_pss_with_sha384() {
        for (name, spec) in [("ios_12_1", pd::ios_12_1()), ("ios_13", pd::ios_13())] {
            let Some(Extension::SignatureAlgorithms(list)) =
                spec.extensions.iter().find(|e| matches!(e, Extension::SignatureAlgorithms(_)))
            else {
                panic!("{name}: 没有签名算法扩展");
            };
            let dup = list.iter().filter(|c| **c == CodePoint::Fixed(v::PSS_WITH_SHA384)).count();
            assert_eq!(dup, 2, "{name}: PSSWithSHA384 应当出现两次（uTLS 源里就是两次）");
        }
    }
}
