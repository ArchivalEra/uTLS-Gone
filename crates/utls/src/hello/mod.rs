//! ClientHello 的数据模型与公开接口。
//!
//! 这个模块是**引擎无关**的：它不引用任何 TLS 引擎的类型，产出的是字节。
//! 深模块的意义在这里 —— 调用方只需学 [`ClientHelloSpec`] / [`Extension`] /
//! [`HandshakeInputs`] / [`ClientHello`] 四个名字，而背后藏着：约 20 个浏览器预设、
//! 一个手写序列化器、一个手写反解器、GREASE 选择与替换、乱序置换、填充算术、
//! 若干种长度前缀编码与结构校验。
//!
//! 三个入口：
//!
//! ```
//! use utls::{ClientHelloId, ClientHelloSpec, HandshakeInputs};
//! use utls::values as v;
//!
//! // 一条 Chrome 133 的指纹。构造一次，可跨连接共享。
//! let spec = ClientHelloSpec::from_preset(ClientHelloId::Chrome(133)).unwrap();
//!
//! // 每连接的输入：SNI、密钥交换公钥（由引擎提供）、以及每连接变化。
//! // 公钥长度是**真实的** —— 长度进指纹（它决定 ClientHello 的总长）。
//! let mut inputs = HandshakeInputs::deterministic([7u8; 32]);
//! inputs.sni = Some("example.com".into());
//! inputs.key_exchange = vec![
//!     (v::X25519, vec![0xAA; 32]),
//!     (v::X25519_MLKEM768, vec![0xBB; 32 + 1184]),
//! ];
//!
//! // ALPN 没给 ⇒ 用预设自带的 (h2, http/1.1)。
//! let hello = spec.marshal(&inputs).unwrap();
//! assert_eq!(hello.as_bytes()[0], 1); // handshake type = ClientHello
//! assert_eq!(hello.ja3().ssl_version, v::LEGACY_VERSION);
//! ```

mod ech;
mod encode;
mod extensions;
mod parse;
mod preset;
mod preset_data;
mod randomized;
mod randomized_tables;
mod spec;
mod stream;
#[cfg(test)]
mod tests;

pub use ech::{aead_supported, hpke_aead_tag_len, kdf_supported, kem_public_key_len,
               parse_ech_config_list,
               pick_ech_config, valid_dns_name, EchConfig, EchExtension, EchParseError,
               HpkeSymmetricCipherSuite};
// `hostname_in_sni` 是「写字节之前」的语义步骤；ECH 的内层（引擎侧构造）也要用它
// 决定「内层带不带 SNI 扩展」—— 见 `encode` 里它自己的说明。
pub use encode::hostname_in_sni;
pub use preset::ClientHelloId;
pub use randomized::{Weights, DEFAULT_WEIGHTS};
pub use spec::{ApplicationSettingsAlps, ClientHelloSpec, CodePoint, CompressCertificate,
               CookieExtension, DelegatedCredentials, EcPointFormats, ExtendedMasterSecret,
               Extension, GreaseEchOptions, Padding, ParseError, PreSharedKey, PskIdentity,
               RenegotiationInfo, SessionId, SessionTicket, SignedCertificateTimestamp,
               SignatureAlgorithmsCert, SpecError, StatusRequest, Variability};

/// 一条已序列化的 ClientHello：`type(1) || u24 长度 || 体`。
///
/// 这正是握手记录的载荷，也正是被哈希进 transcript 的那串字节 —— 所以引擎拿它
/// 直接写入并 `update` transcript 即可，**不要在它之后再做字节级修补**：
/// rustls 会校验 HelloRetryRequest 的一致性，而修补会破坏它。
#[derive(Clone, PartialEq, Eq)]
pub struct ClientHello {
    bytes: Vec<u8>,
}

impl ClientHello {
    pub(crate) fn from_bytes_unchecked(bytes: Vec<u8>) -> Self {
        ClientHello { bytes }
    }

    /// 完整握手消息（含 4 字节握手头）。引擎要写的就是它。
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// **RFC 8446 §4.2.11.2 的 `Truncate(ClientHello)`**：binder 要哈希的那一段的长度。
    ///
    /// 规则是「截到 `PreSharedKeyExtension.identities` 字段为止」——
    /// 也就是**连 binders 向量自己的 `u16` 长度字段都不要**。
    /// Go 的实现是这个形状（`handshake_messages.go` 的 `marshalWithoutBinders`）：
    ///
    /// ```text
    /// bindersLen := 2                       // uint16 长度前缀
    /// for _, b := range m.pskBinders { bindersLen += 1 + len(b) }
    /// return fullMessage[:len(fullMessage)-bindersLen]
    /// ```
    ///
    /// 返回 `None` 表示这条 hello 里没有 `pre_shared_key`（或它不是合法形状）。
    /// **binder 的计算必须用这个长度**，而不是「整条消息除去 binder 字节」——
    /// 差的就是那 2 字节的长度字段，而它错了会让 binder 静默地验不过。
    pub fn psk_transcript_len(&self) -> Option<usize> {
        psk_transcript_len(&self.bytes)
    }

    /// 这条 ClientHello 的 JA3。
    ///
    /// 放在这里而不是只放测试里：它是本项目**唯一**能让「预设对不对」变成一条
    /// 可复跑断言的东西（见 `AGENTS.md` 第二条：指纹的正确性只能在真实环境验，
    /// 而 JA3 是与外部工具对数的那把尺子）。
    pub fn ja3(&self) -> crate::Ja3 {
        crate::ja3::ja3_of_client_hello(&self.bytes)
    }
}

/// 同上，但直接对**字节**算 —— 引擎手里只有外供的字节，没有 `ClientHello` 包装
/// （`ClientHelloPlan` 的字段就是 `Vec<u8>`）。判据只有这一份实现。
pub fn psk_transcript_len(hello: &[u8]) -> Option<usize> {
    let len = ((hello[1] as usize) << 16) | ((hello[2] as usize) << 8) | hello[3] as usize;
    let body = hello.get(4..4 + len)?;
    let mut p = 2 + 32;
    p += 1 + *body.get(p)? as usize;
    let cs = u16::from_be_bytes([*body.get(p)?, *body.get(p + 1)?]) as usize;
    p += 2 + cs;
    p += 1 + *body.get(p)? as usize;
    let n = u16::from_be_bytes([*body.get(p)?, *body.get(p + 1)?]) as usize;
    p += 2;
    let region = body.get(p..p + n)?;
    let mut q = 0usize;
    while q + 4 <= region.len() {
        let ty = u16::from_be_bytes([region[q], region[q + 1]]);
        let bl = u16::from_be_bytes([region[q + 2], region[q + 3]]) as usize;
        if ty == crate::values::EXT_PRE_SHARED_KEY {
            // 扩展体：`u16 identities_len || identities || u16 binders_len || binders`
            let ext_body = region.get(q + 4..q + 4 + bl)?;
            let ids_len = u16::from_be_bytes([*ext_body.first()?, *ext_body.get(1)?]) as usize;
            // 4（握手头）+ p（到扩展区为止）+ q（本扩展前的偏移）+ 4（扩展头）
            // + 2（identities 长度字段）+ ids_len ⇒ **binders 长度字段的起点**。
            return Some(4 + p + q + 4 + 2 + ids_len);
        }
        q += 4 + bl;
    }
    None
}

impl AsRef<[u8]> for ClientHello {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl core::fmt::Debug for ClientHello {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // 默认的 Vec<u8> Debug 会打出几百个数字，没法看。
        write!(f, "ClientHello({} bytes)", self.bytes.len())
    }
}

/// 一条 ClientHello 的每连接输入。
///
/// 这里**同时**装着「外部世界给的东西」（SNI / ALPN / 密钥交换公钥 / 客户端随机数）
/// 和「每连接要变的东西」（私有 seed）。把它们放在一起是有意的：
///
/// - `marshal(&self, &inputs)` 因此是**纯函数** —— 同参数逐字节相同；
/// - HRR 第二飞只要**复用同一个 inputs**，GREASE 与乱序就自动逐字节复现
///   （RFC 8446 §4.1.2 要求第二飞只许改 key_share/cookie/PSK/padding）。
///   ⚠️ 为第二飞**重建** `HandshakeInputs` 是协议违规，而编译器抓不到它。
///
/// # 密码学随机数与「每连接变化」是两条路
///
/// [`client_random`](Self::client_random) 是**安全相关**的（它进密钥调度），
/// 由 OS 熵直接给；而 [`seed`](Self) 只驱动指纹的每连接变化（GREASE / 乱序 / 填充），
/// 走的是一个非密码学 PRNG —— 这两件事混在一条流里会让「可复现」和「不可预测」
/// 互相污染，所以它们被刻意分开。
#[derive(Clone, Debug)]
pub struct HandshakeInputs {
    /// 不填 ⇒ 不发送 server_name 扩展（连 IP 字面量时的合法情形，也正是 JA4 里那个 `i` 标志）。
    pub sni: Option<String>,
    /// 空 ⇒ 不发送 ALPN 扩展。
    pub alpn: Vec<Vec<u8>>,
    /// `(命名组, 公钥字节)`。`KeyShare` 扩展会按此顺序取公钥；缺哪个组就报
    /// [`SpecError::MissingKeyExchange`]。
    pub key_exchange: Vec<(u16, Vec<u8>)>,
    /// ClientHello 的 32 字节随机数。**安全相关**：生产路径上必须来自 CSPRNG。
    pub client_random: [u8; 32],
    /// 每连接变化的来源。**私有** —— 调用方通过 [`HandshakeInputs::os`] 或
    /// [`HandshakeInputs::deterministic`] 造它，于是不可能忘记给它。
    pub(crate) seed: [u8; 32],
}

impl HandshakeInputs {
    /// 用 OS 熵源产生客户端随机数与每连接变化。**本 crate 唯一的非纯调用。**
    ///
    /// 失败即 panic：熵源不可用时的「优雅降级」只能是写一个可预测的随机数，
    /// 那等于把「每连接不同」悄悄变成常量 —— 而那种故障在指纹上是看得见的
    /// （JA3 会稳定下来），却在本地毫无征兆。宁可响。
    pub fn os() -> Self {
        let mut client_random = [0u8; 32];
        let mut seed = [0u8; 32];
        getrandom::fill(&mut client_random).expect("OS 熵源不可用，无法产生客户端随机数");
        getrandom::fill(&mut seed).expect("OS 熵源不可用，无法产生每连接变化");
        HandshakeInputs { sni: None, alpn: Vec::new(), key_exchange: Vec::new(), client_random, seed }
    }

    /// **回放**一条已捕获的 ClientHello 所需的输入。
    ///
    /// 客户端随机数不属于 spec（它是每连接的输入），所以「反解 → 重新编码」要逐字节
    /// 相同，就必须把捕获里的那 32 字节带回来。这个构造函数就是干这个的 ——
    /// 免得每个调用方都自己从第 6 个字节开始抠 32 字节，各抠各的、各错各的。
    ///
    /// 返回 `None` 表示入参不是一个结构完整的 ClientHello —— **不猜**。
    /// 注意它**不填** SNI / ALPN / key_exchange：反解出的 spec 里这些已是 `Opaque` 的
    /// 固定字节（见 `parse` 模块头的契约），所以回放不需要它们。
    pub fn for_replay(hello: &[u8]) -> Option<Self> {
        // type(1) || u24 长度 || legacy_version(2) || random(32)……
        if hello.len() < 38 || hello[0] != 1 {
            return None;
        }
        let declared = ((hello[1] as usize) << 16) | ((hello[2] as usize) << 8) | hello[3] as usize;
        if hello.len() != 4 + declared {
            return None;
        }
        let mut client_random = [0u8; 32];
        client_random.copy_from_slice(&hello[6..38]);
        Some(HandshakeInputs {
            sni: None,
            alpn: Vec::new(),
            key_exchange: Vec::new(),
            client_random,
            // seed 只驱动 GREASE / 乱序 / 填充；回放时它们在 spec 里已是固定值，
            // 所以 seed 取什么都一样 —— 取 0 只是为了让失败信息更好读。
            seed: [0u8; 32],
        })
    }

    /// 完全确定：同 seed + 同 spec ⇒ 逐字节相同的 ClientHello。
    ///
    /// ⚠️ **客户端随机数也由 seed 派生**，所以它**可预测**。
    /// 只用于测试、夹具与 pcap 复现，**不要用于生产连接**。
    pub fn deterministic(seed: [u8; 32]) -> Self {
        // 用一个**独立的**流实例派生随机数，免得占用主流的抽取序列 ——
        // 否则改动随机数的派生就会移动 GREASE 的取值，让黄金字节到处漂。
        let mut s = stream::Stream::new(&seed);
        let mut client_random = [0u8; 32];
        s.fill(&mut client_random);
        HandshakeInputs { sni: None, alpn: Vec::new(), key_exchange: Vec::new(), client_random, seed }
    }

    pub(crate) fn stream(&self) -> stream::Stream {
        stream::Stream::new(&self.seed)
    }
}
