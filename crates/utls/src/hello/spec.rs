//! ClientHello 的声明式模型：一条 ClientHello 长什么样，以及它长不成什么样。

use super::{ClientHello, ClientHelloId, HandshakeInputs, encode, parse, preset, randomized};

/// 一个可能被 GREASE 占用的码点位置。
///
/// 用「位置」而不是「布尔开关」来表达可 GREASE：这样 GREASE 出现在列表的第几位
/// 是模型里看得见的事实（它影响 JA3 之外的一切），而调用方不需要维护一个平行的布尔数组。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CodePoint {
    Fixed(u16),
    /// 每连接从 16 个 `0x?a?a` 里取一个（同一条 ClientHello 内，同一类别共用一个值）。
    Grease,
}

impl CodePoint {
    pub(crate) fn resolve(self, grease: u16) -> u16 {
        match self {
            CodePoint::Fixed(v) => v,
            CodePoint::Grease => grease,
        }
    }
}

impl From<u16> for CodePoint {
    fn from(v: u16) -> Self {
        CodePoint::Fixed(v)
    }
}

/// `key_share` 扩展的声明：**要报哪些组**，以及其中一对是否**共用密钥材料**。
///
/// # 为什么需要 `reuse`
///
/// uTLS 的 `ReuseHybridAndClassicalKeyShares(hybrid, classical)`（`u_public.go:656`）在
/// *预设*里给混合组与经典组打一对哨兵标记，`ApplyPreset` 消费它，于是**一份 X25519 材料
/// 同时喂给两个条目**：线上 `key_share` 里混合组公钥的**末 32 字节**与那个独立经典组的
/// 公钥**逐字节相同**。这是**真实 Firefox 的做法**，也是 uTLS 的
/// `TestParrotFingerprintsReuseHybridClassicalKeyShare`（`u_parrots_test.go:63`）断言的事。
///
/// 只有 `Firefox(148)` 用它（`u_parrots.go:1535` 是上游唯一的使用点）——
/// 所以 Chrome 131 那种 `[GREASE, 4588, X25519]` 的 `key_share` **不能**被这条规则
/// 顺带命中：它发的不是同一份材料。这一点由 `mixed_group_handshake.rs` 的互补判据钉住。
///
/// ⚠️ **密钥材料是引擎的事**：本层只声明「这两个组共用」，真正的接线在
/// `utls-engine`（它才持有密钥交换）。见该 crate 里 `plan()` 的注释。
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct KeyShare {
    /// 要报的组，按线序（GREASE 位置也算指纹的一部分）。
    pub groups: Vec<CodePoint>,
    /// `Some((hybrid, classical))` ⇒ 混合组公钥的经典半分与经典组**共用同一份材料**。
    pub reuse: Option<(u16, u16)>,
}

impl KeyShare {
    /// 只报组、不共用材料（绝大多数预设）。
    ///
    /// 收 `impl Into<Vec<CodePoint>>` 是为了让调用点既能写 `vec![…]` 也能写数组字面量
    /// `[…]`（`From<[T; N]> for Vec<T>` 已存在）—— 本仓的格式化会按上下文改写这两种写法，
    /// 收窄成 `Vec` 会让其中一种编译不过。
    pub fn groups(groups: impl Into<Vec<CodePoint>>) -> Self {
        Self {
            groups: groups.into(),
            reuse: None,
        }
    }

    /// 声明 `hybrid` 与 `classical` 共用密钥材料（uTLS `ReuseHybridAndClassicalKeyShares`）。
    pub fn reusing(mut self, hybrid: u16, classical: u16) -> Self {
        self.reuse = Some((hybrid, classical));
        self
    }
}

/// 填充（`padding` 扩展，类型 21）策略。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Padding {
    /// 体长为 0，但**扩展本身存在**（写出 `00 15 00 00`）。
    ///
    /// 这与「整个扩展不存在」是两件事，两者都要能表达：真实抓包里确实有体长为 0 的
    /// padding 扩展，而 `BoringStyle` 在窗口外时是**整个不发**。反解器产出体长为 0 的
    /// padding 时用 `Fixed(0)`，不要用这个 —— 见 `parse.rs` 的往返契约。
    None,
    /// 体恰好这么多零字节。
    Fixed(u16),
    /// 把**整条握手消息**（`type` + 3 字节长度 + 体）填到恰好这个总长，
    /// 与 SNI / ALPN / 密钥材料 / session id 的长度无关。
    ///
    /// ⚠️ 基准是**握手消息**而非整条 TLS record —— 两者差 5 字节的 record 头。
    /// 这个口径尚未对真实字节标定，见 `questions/02-padding-length-baseline.md`。
    FillTo(u16),
    /// uTLS 的 `BoringPaddingStyle`（`u_tls_extensions.go:1115-1126`）—— **有条件的**填充。
    ///
    /// ```text
    /// 未填充长 ∈ (0xff, 0x200) ⇒ 填充体 = 0x200 - 未填充长（该值 ≥ 5 时再减 4，否则取 1）
    /// 否则                    ⇒ 整条扩展**不发**
    /// ```
    ///
    /// 「未填充长」是**不含本扩展**的整条握手消息长 —— 于是它与 SNI 长度挂钩：
    /// 短 SNI 落进窗口就要填充，长 SNI 落出去就不填。所以这个策略**必须**由模型表达，
    /// 不能由每条预设按「规范测量输入」硬编码一个分支 —— 那会得到一个只在那个
    /// 特定 SNI 长度上正确的指纹。
    BoringStyle,
}

// ── 结构化扩展集（见 `extensions.rs`）──────────────────────────────────────
//
// 每个结构体对应 uTLS `u_tls_extensions.go` 里的一个 `TLSExtension` 实现。
// 字段名尽量与 uTLS 一致，好让两边对照时不需翻译。

/// `status_request`（RFC 6066）。uTLS 的 `StatusRequestExtension` **没有字段** ——
/// 它恒定产出 OCSP 类型 + 两个零长度字段。别的形状（带 responder id）本模型不表达，
/// 反解时回落成 `Opaque`。
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct StatusRequest;

/// `extended_master_secret`（RFC 7627）。体恒为空。
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ExtendedMasterSecret;

/// `renegotiation_info`（RFC 5746）。体是 `u8 长度 + 已协商过的连接串`。
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RenegotiationInfo {
    pub renegotiated_connection: Vec<u8>,
}

/// `session_ticket`（RFC 5077）。体就是 ticket 本身（没有长度前缀）。
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SessionTicket {
    pub ticket: Vec<u8>,
}

/// 一个 PSK identity：`u16 长度 + label + u32 obfuscated_ticket_age`。
///
/// `label` 就是 ticket 本身（对 TLS 1.3 的 resumption 而言）。`obfuscated_ticket_age`
/// 是「ticket 年龄（毫秒）+ 服务器给的 `age_add`」，按 RFC 8446 §4.2.11.1 混淆 ——
/// 引擎算它，本层只写它。
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PskIdentity {
    pub label: Vec<u8>,
    pub obfuscated_ticket_age: u32,
}

/// `pre_shared_key`（RFC 8446 §4.2.11）的体。
///
/// ```text
/// u16 identities_len
///   per identity: u16 label_len | label | u32 obfuscated_ticket_age
/// u16 binders_len
///   per binder:   u8 binder_len | binder
/// ```
///
/// # 三条与 uTLS 逐条对齐的语义
///
/// 1. **`identities` 或 `binders` 任一为空 ⇒ 整个扩展零字节**，但槽位保留
///    （uTLS `pskExtLen()` 的 `if len(identities) == 0 || len(binders) == 0 { return 0 }`）。
///    「没有会话」就是 [`PreSharedKey::empty`] 这个形态。
/// 2. **binder 的占位值是「全零 + 哈希长度」**：uTLS 的 `InitializeByUtls` 里
///    `make([]byte, e.cipherSuite.hash.Size())`。先按占位值序列化、算出真 binder、
///    再逐字节替换 —— 两次序列化的**长度必须相同**，否则整个 hello 的哈希都变了。
///    所以 [`PreSharedKey::placeholder`] 造的就是这个形态。
/// 3. **binder 数量必须等于 identity 数量**（RFC 8446：每个 identity 恰好一个 binder）。
///    uTLS 的写循环不校验这一点（它两个列表各自求和），所以一个不匹配的 spec 在 uTLS
///    那边会产出**畸形**字节。本层选择报错（[`SpecError::BinderCountMismatch`]）：
///    那条错误改变不了任何「合法 spec 产出的字节」，但能挡住一类静默的畸形。
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PreSharedKey {
    pub identities: Vec<PskIdentity>,
    /// 每个 identity 一个 binder。占位值见 [`PreSharedKey::placeholder`]。
    pub binders: Vec<Vec<u8>>,
}

impl PreSharedKey {
    /// 没有会话的槽位：零 identity、零 binder ⇒ **不写字节**（uTLS 的 `Len() == 0`）。
    pub const fn empty() -> Self {
        PreSharedKey {
            identities: Vec::new(),
            binders: Vec::new(),
        }
    }

    /// 「还没有算出真 binder」的形态：**全零占位、长度 = 会话哈希的长度**。
    ///
    /// 这是 uTLS 的两遍序列化里的第一遍所用的形状（`InitializeByUtls` 里的
    /// `make([]byte, hash.Size())`）。哈希长度由调用方给 —— 本层不引密码学。
    pub fn placeholder(identities: Vec<PskIdentity>, binder_len: usize) -> Self {
        let binders = vec![vec![0u8; binder_len]; identities.len()];
        PreSharedKey {
            identities,
            binders,
        }
    }

    /// 会不会写出字节（uTLS 的 `pskExtLen() != 0`）。
    pub fn is_emitted(&self) -> bool {
        !self.identities.is_empty() && !self.binders.is_empty()
    }

    /// 把真 binder 换进去。**数量必须与 identity 相同**（见类型文档第 3 条）。
    pub fn set_binders(&mut self, binders: Vec<Vec<u8>>) -> Result<(), SpecError> {
        if binders.len() != self.identities.len() {
            return Err(SpecError::BinderCountMismatch {
                identities: self.identities.len(),
                binders: binders.len(),
            });
        }
        self.binders = binders;
        Ok(())
    }
}

/// `cookie`（RFC 8446 §4.2.2）。体是 `u16 长度 + cookie`。
///
/// 它只在 **HelloRetryRequest** 的来回里出现：服务器在 HRR 里给一个 cookie，客户端在第二飞里
/// 原样回显。uTLS 的 `CookieExtension` 是同一形状。
///
/// ⚠️ RFC 要求 cookie 非空（`<1..2^16-1>`），但这里**不校验** —— 与 `SessionTicket` 同理：
/// 本层是「把这些字节按这个形状写出去」的层，而「这个 cookie 合不合法」是服务器的事。
/// 加了校验就会让「原样回放一段捕获」在某些字节上失败，那比少一条断言糟。
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CookieExtension {
    pub cookie: Vec<u8>,
}

/// `ec_point_formats`（RFC 4492）。体是 `u8 长度 + 点格式`。
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct EcPointFormats {
    pub formats: Vec<u8>,
}

/// `compress_certificate`（RFC 8879）。体是 `u8 长度 + u16 算法`。
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CompressCertificate {
    pub algorithms: Vec<u16>,
}

/// ALPS（`application_settings`）的体：`u16 长度 + (u8 长度 + 协议名)*`。
///
/// 两个码点（17513 旧 / 17613 新）**体逐字节相同**，只有类型不同 ——
/// 在 uTLS 里也是两个独立的类型。
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ApplicationSettingsAlps {
    pub protocols: Vec<Vec<u8>>,
}

/// `signed_certificate_timestamp`（RFC 6962）。体恒为空。
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SignedCertificateTimestamp;

/// `signature_algorithms_cert`（RFC 8446）。体是 `u16 长度 + u16 算法`。
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SignatureAlgorithmsCert {
    pub schemes: Vec<u16>,
}

/// `delegated_credentials`（draft-ietf-tls-subcerts）。体是 `u16 长度 + u16 算法`。
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct DelegatedCredentials {
    pub schemes: Vec<u16>,
}

/// 一个扩展槽位。
///
/// 有些变体只带「位置」，体在 `marshal` 时从 [`HandshakeInputs`] 或本类型的字段算出来
/// （`ServerName` / `Alpn` / `KeyShare` / `Padding` / `Grease` / `GreaseEch`）。
/// 其余一律走 [`Extension::Opaque`] —— 未知扩展原样保留，这是「对真实互联网通用」的来源。
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Extension {
    /// 一个 GREASE 扩展（类型本身是 GREASE 值，体为空）。Chrome 在首尾各放一个。
    Grease,
    Padding(Padding),
    /// `server_name`。**只带位置，名字来自 `inputs.sni`。**
    ///
    /// 这里刻意没有名字字段：uTLS 预设里写的就是 `&SNIExtension{}`（`ServerName` 为空串），
    /// 空串在 `ApplyPreset` 里被 `config.ServerName` 填上（`u_parrots.go:3116-3118`）。
    /// 于是「预设的槽位」与「连接的名字」天然分离 —— 本类型就是那个槽位。
    ///
    /// ⚠️ **空名字与 IP 字面量都不是错误，而是「零字节的扩展」**：uTLS 的
    /// `SNIExtension.Len()` 先过 `hostnameInSNI()`，空串或 IP 字面量都返回空 ⇒ 长度 0 ⇒
    /// 线上不写字节，但**这个槽位仍在列表里参与洗牌抽取**（Go 的写循环照常遍历它，
    /// `Read` 返回 `(0, io.EOF)`）。三条 uTLS 自带夹具同证此事：
    /// `…-Chrome-70-EmptyServerName`、`…-Chrome-70-ServerNameIP`、
    /// `…-HelloRetryRequest-Chrome-70`（其 config 来自不设 `ServerName` 的 `testConfig`）
    /// 的扩展列表里都**没有**类型 0，而同预设的正常夹具里有。
    ServerName,
    /// `application_layer_protocol_negotiation`。
    ///
    /// 字段是**预设建议的协议列表**（Chrome 是 `h2, http/1.1`）。`inputs.alpn` 非空时
    /// **覆盖**它 —— ALPN 属于连接（引擎知道这次要谈什么协议），但它同时又是指纹的一部分
    /// （`0x0010` 在不在，是 JA3 的一个字段）。两处都空 ⇒ 整个扩展被省略。
    Alpn(Vec<Vec<u8>>),
    SupportedVersions(Vec<CodePoint>),
    SupportedGroups(Vec<CodePoint>),
    SignatureAlgorithms(Vec<CodePoint>),
    /// `key_share`，体里的公钥来自 `inputs.key_exchange`。
    ///
    /// 除了组列表，它还带一个「哪一对共用密钥材料」的声明 —— 见 [`KeyShare`]。
    KeyShare(KeyShare),
    /// `quic_transport_parameters`（码点 39）：TLS over QUIC 时**客户端的传输参数**。
    ///
    /// 上游的 `QUICTransportParametersExtension` 由 preset 路径填这个扩展
    /// （`u_quic.go` 注释：用 preset 时 `SetTransportParameters` 不走
    /// `quic.transportParams`）—— 所以它属于指纹的一部分。这里存**原始字节**
    /// （编码交给 [`crate::quic`] 的 `TransportParameters::marshal`，bytes 由调用方给）。
    /// rustls 的 QUIC 服务端要求 ClientHello 必须带它，否则握手直接失败 ——
    /// 这就是「指纹化 QUIC 客户端」必须走本扩展的原因。
    QuicTransportParameters(Vec<u8>),
    /// `early_data`（RFC 8446 §4.2.10）：**零长度**体，只在恢复握手提供 0-RTT 时
    /// 与 PSK 一起出现。上游自建路径在 `prepare_resumption` 里加
    /// （`u_conn.rs` 的 `exts.early_data_request`）；外供路径由调用方在 spec 里声明
    /// —— 它会改变指纹（扩展多一条），所以必须显式。
    EarlyData,
    /// uTLS 的 GREASE ECH（`0xfe0d`）：GREASE 用的假 ECH。
    ///
    /// 候选集**随预设不同**：Chrome 列 1 个候选套件与 4 个载荷长度（⇒ 总长每连接会变），
    /// Firefox 列 2 个候选套件与 1 个载荷长度（⇒ 总长恒定）。把它硬编码成 Chrome 的那套
    /// 就会把 Firefox 的指纹抄错，所以候选集是数据、由调用方给。
    ///
    /// uTLS 会为它做一次真实的 HPKE 封装（用一个哑 X25519 公钥）；这里生成
    /// **结构相同、长度分布相同**的随机字节。对指纹而言有意义的是结构与长度，
    /// 因为 GREASE 的语义就是「服务端必须忽略它」——
    /// 见 `encode.rs` 里 `grease_ech_body` 的注释。
    GreaseEch(GreaseEchOptions),
    /// `pre_shared_key`（RFC 8446 §4.2.11）—— **包括「还没有会话」的那种形态**。
    ///
    /// uTLS 只有一个 PSK 扩展类型（`UtlsPreSharedKeyExtension`），它「发不发」由
    /// `pskExtLen()` 决定：`identities` 或 `binders` 任一为空 ⇒ **长度 0 ⇒ 不写字节**，
    /// 但槽位留在列表里。所以本层也只留一个变体：[`PreSharedKey::empty`] 就是那个
    /// 「没有会话」的槽位，`_PSK_` 预设列在末尾的是它。
    ///
    /// # 没有会话时到底发什么
    ///
    /// 实测：uTLS 在 `OmitEmptyPsk = false`（默认）且没有会话时**直接报错** ——
    /// `tls: empty psk detected; remove the psk extension for this connection or set OmitEmptyPsk`。
    /// 错误信息自己给了两条出路，其中一条就是「这条连接不要发 PSK」。
    /// 本层的取法：**不发**（等价于 `OmitEmptyPsk = true`）—— 一个纯序列化器没有
    /// 「拒绝服务」的立场；而**真正的** PSK（带 identities 与 binders）现在是这个变体的
    /// 另一个形态，由 session/resumption 那条路填进来。
    ///
    /// ⚠️ 零字节的槽位仍然**参与乱序的那次抽取**（uTLS 的洗牌把它当位置固定的元素，
    /// 照抽不误）。所以编码器必须把它留在列表里、只是**不写出字节** —— 提前删掉会让
    /// 后续抽取错位，而那种错在乱序预设上是看不见的（顺序不比、0 字节不影响长度）。
    PreSharedKey(PreSharedKey),
    /// `status_request`：恒定五字节的 OCSP 请求（uTLS `StatusRequestExtension`）。
    StatusRequest,
    /// `extended_master_secret`（体空）。
    ExtendedMasterSecret,
    /// `renegotiation_info`。
    RenegotiationInfo(RenegotiationInfo),
    /// `session_ticket`。
    SessionTicket(SessionTicket),
    /// `cookie`（HRR 来回里回显服务器给的 cookie）。
    Cookie(CookieExtension),
    /// `ec_point_formats`。
    EcPointFormats(EcPointFormats),
    /// `compress_certificate`。
    CompressCertificate(CompressCertificate),
    /// ALPS，**旧**码点 17513（uTLS `ApplicationSettingsExtension`）。
    ApplicationSettings(ApplicationSettingsAlps),
    /// ALPS，**新**码点 17613（uTLS `ApplicationSettingsExtensionNew`）。
    ApplicationSettingsNew(ApplicationSettingsAlps),
    /// `signed_certificate_timestamp`（体空）。
    SignedCertificateTimestamp,
    /// `psk_key_exchange_modes`。
    PskKeyExchangeModes {
        modes: Vec<u8>,
    },
    /// `record_size_limit`（RFC 8449）。uTLS 只**广播**它、不支持它。
    RecordSizeLimit {
        limit: u16,
    },
    /// `signature_algorithms_cert`。
    SignatureAlgorithmsCert(SignatureAlgorithmsCert),
    /// `delegated_credentials`。
    DelegatedCredentials(DelegatedCredentials),
    /// `next_protocol_negotiation`（NPN）。uTLS 的体**恒为空**。
    Npn,
    /// ChannelID。体恒为空；`old_codepoint` 决定用 30031 还是 30032。
    ChannelId {
        old_codepoint: bool,
    },
    /// 任意扩展：类型 + 原始体，逐字节原样写出。
    Opaque {
        id: u16,
        body: Vec<u8>,
    },
}

/// GREASE ECH 的候选集。
///
/// 出处：uTLS `u_parrots.go` 里各预设给 `GREASEEncryptedClientHelloExtension` 传的
/// `CandidateCipherSuites` / `CandidatePayloadLens`。
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct GreaseEchOptions {
    /// 候选 `(KDF id, AEAD id)` 对，每连接抽一个。
    pub cipher_suites: Vec<(u16, u16)>,
    /// 候选载荷长度（**不含** AEAD tag；编码时按套件加 tag 长度）。
    pub payload_lens: Vec<u16>,
}

impl GreaseEchOptions {
    /// uTLS 的 `BoringGREASEECH()` —— Chrome 家族用它：1 个套件、4 个载荷长度。
    pub fn chrome() -> Self {
        GreaseEchOptions {
            cipher_suites: vec![(
                crate::values::HPKE_KDF_HKDF_SHA256,
                crate::values::HPKE_AEAD_AES_128_GCM,
            )],
            payload_lens: vec![128, 160, 192, 224],
        }
    }

    /// Firefox 预置的那套：2 个候选套件、**单一**载荷长度（223 ⇒ 体长 +16 = 239）。
    pub fn firefox() -> Self {
        GreaseEchOptions {
            cipher_suites: vec![
                (
                    crate::values::HPKE_KDF_HKDF_SHA256,
                    crate::values::HPKE_AEAD_AES_128_GCM,
                ),
                (
                    crate::values::HPKE_KDF_HKDF_SHA256,
                    crate::values::HPKE_AEAD_CHACHA20_POLY1305,
                ),
            ],
            payload_lens: vec![223],
        }
    }
}

impl Extension {
    /// 该扩展的线类型。
    ///
    /// `Grease` 返回 `None` —— 它的类型**每连接才定**（从 16 个 `0x?a?a` 里取值），
    /// 所以静态地问「它是什么类型」是没有答案的。其余变体都是固定类型。
    ///
    /// 这是给调用方（与测试）用的读接口：想在不序列化的情况下知道「这条 spec 会发出
    /// 哪些扩展类型」时用它。
    pub fn wire_type(&self) -> Option<u16> {
        use crate::values as v;
        Some(match self {
            Extension::Grease => return None,
            Extension::Padding(_) => v::EXT_PADDING,
            Extension::ServerName => v::EXT_SERVER_NAME,
            Extension::Alpn(_) => v::EXT_ALPN,
            Extension::SupportedVersions(_) => v::EXT_SUPPORTED_VERSIONS,
            Extension::SupportedGroups(_) => v::EXT_SUPPORTED_GROUPS,
            Extension::SignatureAlgorithms(_) => v::EXT_SIGNATURE_ALGORITHMS,
            Extension::KeyShare(_) => v::EXT_KEY_SHARE,
            Extension::GreaseEch(_) => v::EXT_ENCRYPTED_CLIENT_HELLO,
            Extension::PreSharedKey(_) => v::EXT_PRE_SHARED_KEY,
            Extension::QuicTransportParameters(_) => v::EXT_QUIC_TRANSPORT_PARAMETERS,
            Extension::EarlyData => v::EXT_EARLY_DATA,
            Extension::StatusRequest => v::EXT_STATUS_REQUEST,
            Extension::ExtendedMasterSecret => v::EXT_EXTENDED_MASTER_SECRET,
            Extension::RenegotiationInfo(_) => v::EXT_RENEGOTIATION_INFO,
            Extension::SessionTicket(_) => v::EXT_SESSION_TICKET,
            Extension::Cookie(_) => v::EXT_COOKIE,
            Extension::EcPointFormats(_) => v::EXT_EC_POINT_FORMATS,
            Extension::CompressCertificate(_) => v::EXT_COMPRESS_CERTIFICATE,
            Extension::ApplicationSettings(_) => v::EXT_APPLICATION_SETTINGS,
            Extension::ApplicationSettingsNew(_) => v::EXT_APPLICATION_SETTINGS_NEW,
            Extension::SignedCertificateTimestamp => v::EXT_SCT,
            Extension::PskKeyExchangeModes { .. } => v::EXT_PSK_KEY_EXCHANGE_MODES,
            Extension::RecordSizeLimit { .. } => v::EXT_RECORD_SIZE_LIMIT,
            Extension::SignatureAlgorithmsCert(_) => v::EXT_SIGNATURE_ALGORITHMS_CERT,
            Extension::DelegatedCredentials(_) => v::EXT_DELEGATED_CREDENTIALS,
            Extension::Npn => v::EXT_NPN,
            Extension::ChannelId { old_codepoint } => {
                if *old_codepoint {
                    v::EXT_CHANNEL_ID_OLD
                } else {
                    v::EXT_CHANNEL_ID
                }
            }
            Extension::Opaque { id, .. } => *id,
        })
    }
}

/// 扩展顺序的每连接策略。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Variability {
    /// 顺序固定。JA3 因此**跨连接稳定**。
    Stable,
    /// 顺序每连接置换（Chrome 106+ 起的行为）。
    ///
    /// 这**不是**缺陷：真实 Chrome 就是这样，rustls 0.23 起也这样做。
    /// 后果是 JA3 不稳定而 **JA4 稳定** —— 置换是顺序不敏感的哈希天然吸收掉的。
    /// GREASE / 填充 / PSK 三类扩展位置固定（与 uTLS 的 `ShuffleChromeTLSExtensions` 同语义）。
    Shuffled,
}

/// `legacy_session_id` 的内容。
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum SessionId {
    Empty,
    /// 这么多个**随机**字节（Chrome / Firefox / iOS 用 32）。
    Random(u8),
    Fixed(Vec<u8>),
}

/// 一条 ClientHello 的完整声明。
///
/// # 调用方必须知道的（不在签名里的事实）
///
/// - **顺序即指纹。** `cipher_suites` 与 `extensions` 的写出顺序就是它们给定的顺序；
///   本 crate 只会在 `Variability::Shuffled` 时置换扩展，置换规则见
///   [`Variability::Shuffled`]。
/// - **字段可变是刻意的。** 引擎的 HRR 路径必须能改这个 spec，而「拷一个预设再剪改」
///   正是这个库存在的理由；换成 builder 会多出二十个什么都没隐藏的方法。
///   代价是非法 spec 在 `marshal` 时才报错 —— 预设与 `from_bytes` 产出的永远合法。
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ClientHelloSpec {
    /// ClientHello 体开头的 `legacy_version` 字段（真实浏览器一律 `0x0303`）。
    ///
    /// **它不从 `SupportedVersions` 扩展推导**：那是两个独立的线字段，
    /// 而推导会在「legacy 是 0x0301 却报了 TLS 1.3」这类真实抓包上算错。
    /// 协商版本只由 `SupportedVersions` 扩展表达（那里的顺序与 GREASE 位置才是指纹）。
    pub legacy_version: u16,
    pub cipher_suites: Vec<CodePoint>,
    pub compression_methods: Vec<u8>,
    pub extensions: Vec<Extension>,
    pub session_id: SessionId,
    pub variability: Variability,
}

impl ClientHelloSpec {
    /// 空的 spec：`HelloCustom` 的等价物 —— 由调用方填。
    /// 它**marshal 会失败**（没有密码套件），这是刻意的：空 spec 不是一条能用的 ClientHello。
    pub fn empty() -> Self {
        ClientHelloSpec {
            legacy_version: crate::values::LEGACY_VERSION,
            cipher_suites: Vec::new(),
            compression_methods: vec![crate::values::COMPRESSION_NONE],
            extensions: Vec::new(),
            session_id: SessionId::Empty,
            variability: Variability::Stable,
        }
    }

    /// 按浏览器预设构造。未知版本 / 未实现的预设返回错误，**不会静默降级到别的版本**。
    ///
    /// ⚠️ 随机化那三个（`Randomized` / `RandomizedAlpn` / `RandomizedNoAlpn`）会返回
    /// [`SpecError::RandomizedNeedsSeed`] —— 用 [`Self::randomized`]。
    pub fn from_preset(id: ClientHelloId) -> Result<Self, SpecError> {
        preset::spec_of(id)
    }

    /// uTLS 的 `HelloRandomized*`：从种子生成一份**加权随机**指纹。
    ///
    /// **同一个 `seed` 永远产出同一份 spec** —— 这正是它与参照实现可逐字段对账的前提
    /// （见 `tests/utls-randomized.json`）。
    ///
    /// `alpn` 是 ALPN 的候选（uTLS 的 `config.NextProtos`）；为空且抽中 ALPN 时用
    /// uTLS 的默认值 `h2, http/1.1`。
    pub fn randomized(
        id: ClientHelloId,
        seed: [u8; 32],
        alpn: &[Vec<u8>],
    ) -> Result<Self, SpecError> {
        randomized::generate(id, &seed, alpn, &randomized::DEFAULT_WEIGHTS)
    }

    /// 同 [`Self::randomized`]，但**每次调用换一个随机种子** —— uTLS 的
    /// `applyPresetByID` 对随机化 ID 就是这么做的（`ClientHelloID.Seed` 为 nil 时
    /// 用 `NewPRNGSeed()` 现取一个）。
    ///
    /// 所以这个方法产出的指纹**每次都不同**（那是随机化族的本意）。要可复现就用
    /// [`Self::randomized`] 自己给种子。
    pub fn randomized_os(id: ClientHelloId, alpn: &[Vec<u8>]) -> Result<Self, SpecError> {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).expect("OS 熵源不可用，无法产生随机化指纹的种子");
        Self::randomized(id, seed, alpn)
    }

    /// 同上，但用自定义权重（uTLS 的 `ClientHelloID.Weights`）。
    pub fn randomized_with(
        id: ClientHelloId,
        seed: [u8; 32],
        alpn: &[Vec<u8>],
        weights: &super::Weights,
    ) -> Result<Self, SpecError> {
        randomized::generate(id, &seed, alpn, weights)
    }

    /// 从已序列化的 ClientHello 反解出 spec（`Fingerprinter` 的核心）。
    ///
    /// 入参是**握手消息**（`type(1) || u24 || body`），不是整条 TLS record ——
    /// 剥掉 5 字节 record 头是调用方的事（那是另一个模块的职责）。
    ///
    /// ⚠️ **反解不出「混合/经典共用材料」那对声明**（[`KeyShare::reuse`]）：它在线上
    /// 只表现为两个条目里出现同一串字节，而那串字节**每连接都随机** ——
    /// 分不清「共用」与「恰好相同」。所以反解出来的 spec 一律 `reuse: None`，
    /// 与 uTLS 的 `Fingerprinter` 同一取舍（它也不还原 `ReuseHybridAndClassicalKeyShares`）。
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ParseError> {
        parse::parse_client_hello(bytes)
    }

    /// `key_share` 里要报的组：按线序、**去掉 GREASE**、去重。
    ///
    /// 这是「引擎要为哪些组准备密钥交换」的唯一口径。做成方法而不是让各处各写一遍，
    /// 是因为它曾经在几个地方各写了一遍（`utls_randomized` / 测试的 `common` /
    /// 预设自测）—— 而 `key_share` 的模型一改，那些份就会**静默地**
    /// 各错各的（`KeyShare::reuse` 那次就是这样被编译器抓出来的）。
    pub fn key_share_groups(&self) -> Vec<u16> {
        let mut out: Vec<u16> = Vec::new();
        for e in &self.extensions {
            if let Extension::KeyShare(ks) = e {
                for cp in &ks.groups {
                    if let CodePoint::Fixed(g) = cp
                        && !crate::values::is_grease(*g)
                        && !out.contains(g)
                    {
                        out.push(*g);
                    }
                }
            }
        }
        out
    }

    /// `Some((hybrid, classical))` ⇒ 这条 spec 声明了
    /// uTLS `ReuseHybridAndClassicalKeyShares`（见 [`KeyShare::reuse`]）。
    pub fn key_share_reuse(&self) -> Option<(u16, u16)> {
        self.extensions.iter().find_map(|e| match e {
            Extension::KeyShare(ks) => ks.reuse,
            _ => None,
        })
    }

    /// uTLS 的 `AlwaysAddPadding()`（`u_common.go:274-287`）。
    ///
    /// 确保这条 spec 有一条 `BoringPaddingStyle` 填充。**已经有一条就什么都不做**；
    /// 否则插在 **PSK 之前**（RFC 8446 §4.2.11 要求 PSK 最后），没有 PSK 就追加到末尾。
    ///
    /// 「插在 PSK 之前」不是细节：uTLS 的 `AlwaysAddPadding` 专门为它写了一个分支，
    /// 而 `HelloChrome_114_Padding_PSK_Shuf` 的 case 里也正是这个顺序（填充 → PSK）。
    pub fn always_add_padding(&mut self) {
        if self
            .extensions
            .iter()
            .any(|e| matches!(e, Extension::Padding(_)))
        {
            return; // 已经有一条，什么都不做
        }
        // 有 PSK 就插在它前面（PSK 必须最后），否则追加到末尾。
        let at = self.psk_position().unwrap_or(self.extensions.len());
        self.extensions
            .insert(at, Extension::Padding(Padding::BoringStyle));
    }

    /// uTLS 的 `Config.AlwaysIncludePSK` 对 spec 做的那个变更（`ApplyPreset` 里的分支）：
    /// 若**没有** PSK 扩展，就在**末尾**补一条空的（RFC 8446 §4.2.11 要求 PSK 最后）。
    ///
    /// 返回是否补了。uTLS 只在 `MaxVersion >= TLS13` 时补 —— 这一点由调用方决定，
    /// 因为版本在本仓由 `SupportedVersions` 扩展表达（见 `legacy_version` 的说明）。
    pub fn always_add_psk(&mut self) -> bool {
        if self.psk_position().is_some() {
            return false;
        }
        self.extensions
            .push(Extension::PreSharedKey(PreSharedKey::empty()));
        true
    }

    /// PSK 扩展在列表里的位置（没有则 `None`）。
    pub fn psk_position(&self) -> Option<usize> {
        self.extensions
            .iter()
            .position(|e| matches!(e, Extension::PreSharedKey(_)))
    }

    /// uTLS 的 `UConn.RemoveSNIExtension()`（`u_conn.go:280`）：**把 server_name 这个槽位
    /// 从列表里删掉**，而不是让它变成零字节。
    ///
    /// 与「名字为空」的区别只在**槽位数量**上：对 `Stable` 预设，删掉槽位与发出零字节的
    /// 结果逐字节相同（置换是恒等，0 字节不占长），所以 uTLS 自带的
    /// `…-Chrome-70-OmitSNI` 与 `…-Chrome-70-EmptyServerName` 两条夹具**完全一样**；
    /// 对 `Shuffled` 预设两者不同 —— 少一个槽位就少一次抽取。
    /// 这个区别由 `utls_testdata` 对账里的那条交叉断言钉住。
    ///
    /// 返回是否删掉了（uTLS 在 `HelloGolang` 上调用会报错，本层没有那个分支：
    /// `Golang` 根本没有 spec，见 [`SpecError::EngineDefined`]）。
    pub fn remove_server_name(&mut self) -> bool {
        let before = self.extensions.len();
        self.extensions
            .retain(|e| !matches!(e, Extension::ServerName));
        self.extensions.len() != before
    }

    /// uTLS 的 `processHelloRetryRequest` 对 spec 做的那处改动
    /// （`handshake_client_tls13.go:340-400`）：**`key_share` 只留服务器选中的那一个组**。
    ///
    /// 逐条对应那边的前置检查（三条各自的报错在 uTLS 里是三条不同的文案）：
    ///
    /// 1. spec 里**必须有** `key_share` 扩展 —— uTLS 是遍历 `uconn.Extensions` 找不到就报
    ///    `"uTLS: received HelloRetryRequest, but keyshare not found among client's …"`；
    /// 2. 选中的组**必须在 `supported_groups` 里** —— 否则 `"tls: server selected unsupported group"`；
    /// 3. 选中的组**原本不能已经在 `key_share` 里** —— 否则
    ///    `"tls: server sent an unnecessary HelloRetryRequest key_share"`。
    ///
    /// 改动本身只有一处：`KeyShares` 变成 `[selected_group]`（GREASE 条目与其余组都去掉，
    /// uTLS 那边是 `ks.KeyShares = keyShares(hs.hello.keyShares).ToPublic()`，而
    /// `hs.hello.keyShares` 已经被 `hello.keyShares[:1]` 截成一个）。
    ///
    /// **填充不用碰**：`BoringPaddingStyle` 在 `marshal` 时按总长重算，
    /// 而第二飞的总长与第一飞相同（key_share 长出来的部分由填充让出来）——
    /// uTLS 自带夹具的 HRR 那条 `Flow 3` 就是证据：key_share 43 → 71 字节、
    /// padding 221 → 193 字节、整条消息仍是 508 字节的握手体。
    ///
    /// **输入必须复用**（同一个 [`HandshakeInputs`]）：RFC 8446 §4.1.2 要求第二飞只改
    /// key_share / cookie / PSK / padding，其余（含 GREASE 与乱序）逐字节相同。
    /// 所以本方法**不消耗任何随机数** —— 它只改 spec。
    ///
    /// 调用方还要保证 `inputs.key_exchange` 里有 selected_group 的公钥
    /// （否则 marshal 会报 [`SpecError::MissingKeyExchange`]）。
    pub fn for_hello_retry(&self, selected_group: u16) -> Result<ClientHelloSpec, SpecError> {
        let Some(at) = self
            .extensions
            .iter()
            .position(|e| matches!(e, Extension::KeyShare(_)))
        else {
            return Err(SpecError::HelloRetryWithoutKeyShare);
        };

        let offered = self
            .extensions
            .iter()
            .find_map(|e| match e {
                Extension::SupportedGroups(cps) => Some(cps.clone()),
                _ => None,
            })
            .unwrap_or_default();
        let offered: Vec<u16> = offered
            .iter()
            .filter_map(|c| match c {
                // GREASE 占位符不是「一个组」：uTLS 那边 `hello.supportedCurves` 里
                // 那个 GREASE 值已经落成具体值，而服务器不可能选中它。
                CodePoint::Fixed(g) if !crate::values::is_grease(*g) => Some(*g),
                _ => None,
            })
            .collect();
        if !offered.contains(&selected_group) {
            return Err(SpecError::HelloRetryUnsupportedGroup(selected_group));
        }

        if let Extension::KeyShare(ks) = &self.extensions[at]
            && ks
                .groups
                .iter()
                .any(|c| matches!(c, CodePoint::Fixed(g) if *g == selected_group))
        {
            return Err(SpecError::HelloRetryRedundantKeyShare(selected_group));
        }

        let mut retry = self.clone();
        // HRR 之后 `key_share` 只剩选中的那个组 ⇒ 复用那对声明随之消失
        // （RFC 8446 §4.1.4：第二飞只带一项，「两个组共用材料」在这条飞上不存在）。
        retry.extensions[at] =
            Extension::KeyShare(KeyShare::groups([CodePoint::Fixed(selected_group)]));
        Ok(retry)
    }

    /// uTLS 在 HRR 里收到 cookie 时的处理（`handshake_client_tls13.go:412-432`）：
    /// spec 里已有 `CookieExtension` 就写进去，没有就**插一条新的**。
    ///
    /// ⚠️ **插入位置是个取舍，而且是刻意的**：uTLS 从一条**独立的 OS 熵流**里抽
    /// `Intn(len(extensions) - 2)`（`newPRNG()`），也就是「插在倒数第三个位置之前，
    /// 好让 PSK 仍然在最后」。所以**uTLS 自己的 cookie 形态也不可复现** ——
    /// 它每次插在不同的位置，而位置进指纹。
    ///
    /// 我们的取法：**位置由调用方给**（`index`），理由有两条 ——
    /// ① 从连接流里抽会**多消耗随机数**，于是 GREASE 与乱序跟着变，
    ///    而 RFC 8446 §4.1.2 只允许第二飞改 key_share / cookie / PSK / padding；
    /// ② 抽出来的位置分布是 `[0, len-3]` 上的均匀分布，把「哪一次抽到哪个位置」
    ///    交给调用方，分布不变而行为可复现 —— 对指纹更诚实。
    ///
    /// `index` 超出 `[0, len-2]` 时报错（uTLS 那边是
    /// `"cookieIndex >= len(hs.uconn.Extensions)"`）。
    pub fn with_cookie(&self, cookie: &[u8], index: usize) -> Result<ClientHelloSpec, SpecError> {
        let mut out = self.clone();
        for e in out.extensions.iter_mut() {
            if let Extension::Cookie(c) = e {
                c.cookie = cookie.to_vec();
                return Ok(out);
            }
        }
        // 没有 cookie 扩展 ⇒ 插一条新的，且**不得插到最后两位**
        // （uTLS 用 `len - 2` 当上界，为的是 PSK 仍在最后）。
        if index + 2 > out.extensions.len() {
            return Err(SpecError::CookieIndexOutOfRange {
                index,
                len: out.extensions.len(),
            });
        }
        out.extensions.insert(
            index,
            Extension::Cookie(CookieExtension {
                cookie: cookie.to_vec(),
            }),
        );
        Ok(out)
    }

    /// 序列化。
    ///
    /// 纯函数：`(spec, inputs)` 相同则任何进程、任何平台上输出逐字节相同。
    /// 不观测时间、线程、环境或全局 RNG。
    pub fn marshal(&self, inputs: &HandshakeInputs) -> Result<ClientHello, SpecError> {
        encode::marshal(self, inputs)
    }
}

/// 序列化失败的原因。**每一条都是「这条 ClientHello 本来就不该被发出去」**，
/// 而不是「引擎暂时不行」。
#[derive(Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum SpecError {
    /// `key_share` 里点了这个组，但 `inputs.key_exchange` 里没有它的公钥。
    ///
    /// **绝不降级**去发一个更短的 key_share —— 那是悄悄换掉了指纹。
    MissingKeyExchange(u16),
    ServerNameTooLong(usize),
    AlpnProtocolTooLong(usize),
    EmptyCipherSuites,
    EmptyCompressionMethods,
    NoExtensions,
    SessionIdTooLong(usize),
    /// 同一个扩展类型出现两次（GREASE 例外）。
    DuplicateExtension(u16),
    /// 超过 2 个 GREASE 扩展：uTLS 只有两个占位值，第三个没有对应的随机值可用。
    TooManyGreaseExtensions(usize),
    /// PSK 扩展**必须在最后**（RFC 8446 §4.2.11）。uTLS 的每个 `_PSK_` 预设也都把它列在末尾。
    PreSharedKeyNotLast {
        index: usize,
        len: usize,
    },
    /// binder 数量与 identity 数量不等 —— RFC 8446 §4.2.11 要求「每个 identity 恰好一个
    /// binder」，不等就是畸形消息。uTLS 的写循环不校验这一点（两个列表各自求和），
    /// 所以本层报错比逐字节照抄更严：它挡住的是一类**畸形**，不是一个合法产物。
    BinderCountMismatch {
        identities: usize,
        binders: usize,
    },
    /// 收到 HRR 要发第二飞，但 spec 里没有 `key_share` 扩展可改。
    /// 对应 uTLS 的 `"uTLS: received HelloRetryRequest, but keyshare not found among client's …"`。
    HelloRetryWithoutKeyShare,
    /// HRR 选中的组不在 `supported_groups` 里 —— uTLS 的 `"tls: server selected unsupported group"`。
    HelloRetryUnsupportedGroup(u16),
    /// HRR 选中的组**第一飞已经给过共享密钥**了 —— 那次 HRR 是多余的。
    /// 对应 uTLS 的 `"tls: server sent an unnecessary HelloRetryRequest key_share"`。
    HelloRetryRedundantKeyShare(u16),
    /// 插 cookie 的位置越界：不得插到最后两位（uTLS 用 `len - 2` 当上界，为的是 PSK 仍在最后）。
    CookieIndexOutOfRange {
        index: usize,
        len: usize,
    },
    PaddingTargetUnreachable {
        target: u16,
    },
    /// 扩展体或整条消息超出各自长度字段的表示范围。
    TooLong {
        what: &'static str,
        len: usize,
    },
    /// QUIC 传输参数的 `Fake` 逃生口没有给 ID —— 上游在这里 panic
    /// （`u_quic_transport_parameters.go:367`）；本 crate 把「发不出去」交成错误。
    QuicFakeParameterWithoutId,
    /// 预设的版本不存在，或该预设尚未实现。
    PresetUnavailable(ClientHelloId),
    /// 这是随机化预设，而随机化指纹**由种子定义** —— 没有种子就没有指纹。
    /// 用 [`ClientHelloSpec::randomized`]。
    RandomizedNeedsSeed(ClientHelloId),
    /// 这个预设**在本架构里没有对应的 spec，而且这不是待实现项**。
    ///
    /// 目前只有 uTLS 的 `HelloGolang`：它的意思是「用引擎自己的 ClientHello」。
    /// 在 uTLS 里那是 Go 标准库 `crypto/tls` 的产出；在我们的分层里则对应
    /// 「用 rustls 自己的 ClientHello」—— 也就是**不使用本 crate 的指纹层**。
    /// 所以它不是一个「还没做的预设」，而是一个**明确的不适用项**。
    EngineDefined(ClientHelloId),
}

impl core::fmt::Display for SpecError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            SpecError::MissingKeyExchange(g) => {
                write!(
                    f,
                    "key_share 需要组 {g} 的公钥，但 inputs.key_exchange 里没有"
                )
            }
            SpecError::ServerNameTooLong(n) => write!(f, "SNI 长 {n} 字节，上限 255"),
            SpecError::BinderCountMismatch {
                identities,
                binders,
            } => write!(
                f,
                "PSK 有 {identities} 个 identity 却有 {binders} 个 binder ——                  RFC 8446 §4.2.11 要求每个 identity 恰好一个"
            ),
            SpecError::HelloRetryWithoutKeyShare => write!(
                f,
                "要发 HelloRetryRequest 的第二飞，但 spec 里没有 key_share 扩展\
                 （uTLS: keyshare not found among client's extensions）"
            ),
            SpecError::HelloRetryUnsupportedGroup(g) => write!(
                f,
                "HRR 选了组 {g}，但它不在 supported_groups 里\
                 （uTLS: server selected unsupported group）"
            ),
            SpecError::HelloRetryRedundantKeyShare(g) => write!(
                f,
                "HRR 选了组 {g}，而第一飞已经给过它的共享密钥 —— 那次 HRR 是多余的\
                 （uTLS: server sent an unnecessary HelloRetryRequest key_share）"
            ),
            SpecError::CookieIndexOutOfRange { index, len } => write!(
                f,
                "cookie 要插在第 {index} 位，但扩展只有 {len} 个 —— 不得插到最后两位\
                 （uTLS 用 len - 2 当上界，为的是 PSK 仍在最后）"
            ),
            SpecError::AlpnProtocolTooLong(n) => write!(f, "ALPN 协议名长 {n} 字节，上限 255"),
            SpecError::EmptyCipherSuites => write!(f, "没有密码套件"),
            SpecError::EmptyCompressionMethods => write!(f, "没有压缩方法"),
            SpecError::NoExtensions => write!(f, "没有扩展"),
            SpecError::SessionIdTooLong(n) => write!(f, "legacy_session_id 长 {n} 字节，上限 32"),
            SpecError::DuplicateExtension(t) => write!(f, "扩展类型 {t} 出现了两次"),
            SpecError::PreSharedKeyNotLast { index, len } => write!(
                f,
                "pre_shared_key 在第 {index} 位（共 {len} 个扩展），而 RFC 8446 §4.2.11 \
                 要求它必须是最后一个"
            ),
            SpecError::TooManyGreaseExtensions(n) => {
                write!(f, "GREASE 扩展有 {n} 个，uTLS 的占位表只支持 2 个")
            }
            SpecError::PaddingTargetUnreachable { target } => {
                write!(f, "填充目标 {target} 小于未填充长度，达不到")
            }
            SpecError::TooLong { what, len } => write!(f, "{what} 长 {len} 字节，超出长度字段"),
            SpecError::QuicFakeParameterWithoutId => {
                write!(
                    f,
                    "QUIC 的 Fake 传输参数必须给一个非零 ID —— 静默发参数 0 是畸形"
                )
            }
            SpecError::PresetUnavailable(id) => write!(f, "预设 {id} 不存在或尚未实现"),
            SpecError::EngineDefined(id) => write!(
                f,
                "{id} 的意思是「用引擎自己的 ClientHello」—— 在本架构里等于不使用本 crate \
                 的指纹层，所以它没有 spec（这是结论，不是待办）"
            ),
            SpecError::RandomizedNeedsSeed(id) => write!(
                f,
                "{id} 是随机化预设：它由种子定义，所以不能从 from_preset 拿 —— \
                 用 ClientHelloSpec::randomized(id, seed, alpn)"
            ),
        }
    }
}

impl std::error::Error for SpecError {}

/// 反解失败的原因。
#[derive(Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum ParseError {
    /// 字节不够读完一个字段。
    Truncated { needed: usize, got: usize },
    /// 握手类型不是 ClientHello(1)。
    NotAClientHello(u8),
    /// 声明的长度与实际不符。
    LengthMismatch { declared: u64, actual: u64 },
    /// 结构对不上（例如扩展体里嵌套的长度字段自相矛盾）。
    Malformed(&'static str),
}

impl core::fmt::Display for ParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ParseError::Truncated { needed, got } => {
                write!(f, "需要 {needed} 字节，只有 {got}")
            }
            ParseError::NotAClientHello(t) => write!(f, "握手类型是 {t}，不是 ClientHello(1)"),
            ParseError::LengthMismatch { declared, actual } => {
                write!(f, "声明长度 {declared}，实际 {actual}")
            }
            ParseError::Malformed(w) => write!(f, "结构对不上：{w}"),
        }
    }
}

impl std::error::Error for ParseError {}

impl From<ParseError> for SpecError {
    fn from(e: ParseError) -> Self {
        // 反解失败在 marshal 语境里就是「这条 spec 不该被发出去」。
        // 保留原文以便日志能说清是哪一种结构问题。
        match e {
            ParseError::Truncated { needed, got } => SpecError::TooLong {
                what: "输入（解析用）",
                len: needed.saturating_sub(got),
            },
            _ => SpecError::NoExtensions,
        }
    }
}
