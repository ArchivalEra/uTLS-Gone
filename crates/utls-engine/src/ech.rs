//! **真实 ECH 的封装侧**：HPKE 把内层 ClientHello 封给服务器的公钥。
//!
//! 本 crate 是引擎侧，所以密码学**在这里**（`utls` 那边一行都没有，见那边的 `ech` 模块）。
//! 用 rustls 的 HPKE 实现而不是自己写 —— 与「key exchange 交给引擎的密码学提供者」
//! 同一条纪律：我们不实现密码学，只决定**怎么用**。
//!
//! # 线格式与 AAD（这一节是照着 rustls 的实现逐条核对的）
//!
//! 外层 ClientHello 里的 `encrypted_client_hello`（`0xfe0d`）扩展：
//!
//! ```text
//! uint8 type;                             // 0 = ClientHelloOuter，1 = ClientHelloInner
//! HpkeSymmetricCipherSuite cipher_suite;  // u16 kdf_id || u16 aead_id   （只有 outer 有）
//! uint8 config_id;                        //                            （只有 outer 有）
//! opaque enc<0..2^16-1>;                  // HPKE 封装密钥（X25519 32 字节，HRR 的 second flight 为空）
//! opaque payload<1..2^16-1>;              // 密封的内层 ClientHello（含 AEAD 标签）
//! ```
//!
//! ⚠️ **第一个字节是 outer/inner 的类型位**，而 inner 形态**只有这一个字节**（没有其余字段）。
//! 这一条是**实测**发现的：本仓先按「没有类型位」的格式拼了外层扩展，结果 rustls 的解析器
//! 把 `kdf_id` 的高字节当类型读，整条 ClientHello 解不开（`InvalidMessage(MessageTooShort)`）。
//! 两个参照实现都写这一位：rustls `msgs/handshake.rs::EncryptedClientHello::encode`
//! （`EchClientHelloType::ClientHelloOuter.encode()`）与 uTLS `ech.go::generateOuterECHExt`
//! （`b.AddUint8(0) // outer`），常量是 `outerECHExt = 0` / `innerECHExt = 1`。
//! 于是**内层 hello 里也要放这条扩展，体就是 `[1]`**（draft-ietf-tls-esni-18 §6.1 规则 4）。
//!
//! 两条容易搞错、而**错了就静默失败**的规则：
//!
//! 1. **`info` = `"tls ech\0" || <整条 ECHConfig 的原始字节>`**
//!    （draft-ietf-tls-esni-17 §6.1；rustls `client/ech.rs::hpke_info` 逐字如此）。
//!    所以配置的原始字节必须留着，`utls::hello::EchConfig::raw` 就是为它留的。
//! 2. **`aad` = 外层 ClientHello 的编码，且其中的 payload 字段是等长的全零**
//!    （rustls `client/ech.rs::ech_hello`：先放一个 `vec![0; payload_len]`、
//!    `outer_hello.get_encoding()` 当 AAD，再算真载荷）。长度是
//!    `内层长度 + AEAD 标签长`，所以**先量长度、再算 AAD、最后密封**这个顺序不能换。
//!    载荷长度因此是固定的 ⇒ 密封只是**原地替换那一段字节**，长度字段一个都不动
//!    （与 PSK binder 是同一套「只改内容不改长度」的理由）。
//!
//! # 状态（曾是「还没做的」，现在是「做了、怎么判的」）
//!
//! 「让引擎把它当成一次**真的** ECH 提议」由 fork 第八处能力承担（`EchState::from_supplied`：
//! 外供路径拿调用方的内层建转录与随机数，走 rustls 的接受/拒绝判定）。内层的**模型**
//! 在 `build_inner_client_hello_body`（uTLS 的诚实 hello，见那边的出处表）；
//! 验收走过三层：内层与 uTLS 的产出**逐字节**相同（`tests/ech_inner_utls.rs`）、
//! uTLS 自家 ECH 服务端上完整握手被接受（`tests/ech_utls_server.rs`）、
//! 真实端点（Cloudflare / DEfO）`EchStatus::Accepted`（`tests/ech_e2e.rs`）。
//! 接受语义的排查结论以本文件与判据为准。

use std::sync::Arc;

use rustls::crypto::CryptoProvider;
use rustls::crypto::aws_lc_rs::hpke::ALL_SUPPORTED_SUITES;
use rustls::crypto::hpke::{Hpke, HpkePublicKey, HpkeSealer};
use utls::hello::{CodePoint, EchConfig, Extension, HpkeSymmetricCipherSuite, hpke_aead_tag_len};

/// 一次 ECH 提议的封装状态。
///
/// `HpkeSealer::seal` 是 `&mut self`（RFC 9180 的上下文只能封一次），所以这里也是
/// `&mut` —— 想再封一条就得重新 `new`（`enc` 也会变）。
pub struct EchSealer {
    suite: &'static dyn Hpke,
    config_id: u8,
    cipher_suite: HpkeSymmetricCipherSuite,
    enc: Vec<u8>,
    sealer: Box<dyn HpkeSealer + 'static>,
}

impl core::fmt::Debug for EchSealer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("EchSealer")
            .field("config_id", &self.config_id)
            .field("cipher_suite", &self.cipher_suite)
            .field("enc_len", &self.enc.len())
            .finish()
    }
}

impl EchSealer {
    /// 按一条配置建封装上下文（`SetupBaseS`）。
    ///
    /// `_provider` 目前只用于将来走 `CryptoProvider` 的 HPKE（0.23.45 里 HPKE 是
    /// 按套件列在 `ALL_SUPPORTED_SUITES` 上的静态表，还没有 provider 字段）；
    /// 留着这个参数是为了调用点不必改签名。
    pub fn new(config: &EchConfig, _provider: &Arc<CryptoProvider>) -> Result<Self, rustls::Error> {
        let wanted_suite = config
            .first_usable_suite()
            .ok_or_else(|| general("utls-engine: 这条 ECH 配置里没有我们能用的 HPKE 套件"))?;

        let suite = ALL_SUPPORTED_SUITES
            .iter()
            .copied()
            .find(|s| {
                u16::from(s.suite().kem) == config.kem_id
                    && u16::from(s.suite().sym.kdf_id) == wanted_suite.kdf_id
                    && u16::from(s.suite().sym.aead_id) == wanted_suite.aead_id
            })
            .ok_or_else(|| {
                general(&format!(
                    "utls-engine: HPKE 提供者没有 (kem 0x{:04x}, kdf 0x{:04x}, aead 0x{:04x}) 这套",
                    config.kem_id, wanted_suite.kdf_id, wanted_suite.aead_id
                ))
            })?;

        // `info = "tls ech\0" || 整条 ECHConfig`（见模块头第 1 条）。
        let mut info = Vec::with_capacity(config.raw.len() + 8);
        info.extend_from_slice(b"tls ech\0");
        info.extend_from_slice(&config.raw);

        let (enc, sealer) = suite.setup_sealer(&info, &HpkePublicKey(config.public_key.clone()))?;
        Ok(EchSealer {
            suite,
            config_id: config.config_id,
            cipher_suite: HpkeSymmetricCipherSuite {
                kdf_id: wanted_suite.kdf_id,
                aead_id: wanted_suite.aead_id,
            },
            enc: enc.0,
            sealer,
        })
    }

    /// 载荷长度 = 内层 hello 长 + AEAD 标签长。
    ///
    /// 这个数**必须先知道**：AAD 里要放一个等长的全零 payload，所以长度确定之前
    /// 算不出 AAD，而算不出 AAD 就封不了。顺序：内层 → 长度 → 外层(零载荷) → AAD → 密封。
    pub fn payload_len(&self, inner_len: usize) -> Result<usize, rustls::Error> {
        let tag = hpke_aead_tag_len(self.cipher_suite.aead_id)
            .ok_or_else(|| general("utls-engine: 不认识的 AEAD，拿不到标签长度"))?;
        Ok(inner_len + tag)
    }

    /// 配置 id（写进外层扩展）。
    pub fn config_id(&self) -> u8 {
        self.config_id
    }

    /// `(kdf_id, aead_id)`（写进外层扩展）。
    pub fn cipher_suite(&self) -> HpkeSymmetricCipherSuite {
        self.cipher_suite
    }

    /// 封装密钥 `enc`（写进外层扩展；X25519 是 32 字节）。
    pub fn encapsulated_key(&self) -> &[u8] {
        &self.enc
    }

    /// 密封一段内层 hello，`aad` 是**外层 hello 的编码**（见模块头第 2 条）。
    pub fn seal(&mut self, aad: &[u8], inner: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        let out = self.sealer.seal(aad, inner)?;
        // 长度必须是「内层 + 标签」—— 外层扩展的长度字段是按它写的，
        // 这里差一个字节就整条 hello 错位（而且**只有真解一次**才发现得了）。
        let want = self.payload_len(inner.len())?;
        if out.len() != want {
            return Err(general(&format!(
                "utls-engine: HPKE 密封结果长 {} 字节，而按 (内层 {} + 标签) 该是 {}",
                out.len(),
                inner.len(),
                want
            )));
        }
        Ok(out)
    }

    /// 这套 HPKE 是否 FIPS 兼容（只为日志/诊断）。
    pub fn fips(&self) -> bool {
        self.suite.fips()
    }
}

/// **外层** ECH 扩展的体（含类型位）。
///
/// 放在这里而不是散在调用点：这个格式有两个参照实现逐字节对齐（见模块头），
/// 而它错一个字节的后果是「整条 hello 解不开」—— rustls 与 uTLS 各自只接受
/// 自己那种写法，所以它必须有**一处**定义 + 一条逐字节的判据。
///
/// `payload` 在**算 AAD 那一遍**要传等长的全零（长度 = 内层长 + AEAD 标签长），
/// 密封完再把真载荷写回同一段 —— 长度不变，所以其余字节一个都不动。
pub fn outer_ech_extension_body(
    cipher_suite: HpkeSymmetricCipherSuite,
    config_id: u8,
    enc: &[u8],
    payload: &[u8],
) -> Vec<u8> {
    let mut b = Vec::with_capacity(1 + 4 + 1 + 2 + enc.len() + 2 + payload.len());
    b.push(0); // type = ClientHelloOuter（uTLS: `b.AddUint8(0) // outer`）
    b.extend_from_slice(&cipher_suite.kdf_id.to_be_bytes());
    b.extend_from_slice(&cipher_suite.aead_id.to_be_bytes());
    b.push(config_id);
    b.extend_from_slice(&(enc.len() as u16).to_be_bytes());
    b.extend_from_slice(enc);
    b.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    b.extend_from_slice(payload);
    b
}

/// **内层** ECH 扩展的体：只有一个类型位（`1`），没有别的字段。
///
/// draft-ietf-tls-esni-18 §6.1 规则 4：内层 hello 里也要放这条扩展，用它标明
/// 「这条是被保护的那条」。uTLS 的 `parseECHExt` 对 `innerECHExt` 直接要求
/// `s.Empty()` —— 多一个字节都算畸形。
pub fn inner_ech_extension_body() -> Vec<u8> {
    vec![1]
}

fn general(msg: &str) -> rustls::Error {
    rustls::Error::General(msg.into())
}

// ── 内层 hello 的构造（uTLS 的模型：诚实的 hello + 预设的四个字段）──────────

/// 内层的**诚实输入** —— 这一份来自引擎，**不是**来自浏览器的指纹 spec。
///
/// # 为什么内层不是「外层的过滤版」
///
/// 这是本轮最重要的发现，而它的出处是 uTLS 自己的代码：内层是
/// `UConn.MarshalClientHello()` 里 `uconn.makeClientHello()` 产出的那条 hello
/// —— 那是个**按 `crypto/tls` 的默认值新造的** ClientHello（`handshake_client.go:44`），
/// 然后只把**四个字段**从预设里抄进去：
///
/// ```text
/// inner.keyShares                     = 预设的 keyShares
/// inner.supportedSignatureAlgorithms  = 预设的
/// inner.sessionId                     = 预设的（不进密文，只进转录）
/// inner.supportedCurves               = 预设的
/// ```
///
/// （`u_conn.go:564-568`。）其余的一切 —— **cipher suites、supported_versions、ALPN、
/// 扩展集合与顺序** —— 都是「这个客户端在没有 ECH 时会诚实地说什么」，
/// 于是内层根本不带 GREASE、不带 Chrome 那 17 条套件、也不带
/// `compress_certificate`/`ChannelID`/`renegotiation_info`/`EMS`/`session_ticket`。
///
/// 本仓第一版把内层造成了「Chrome-70 spec 去掉几条扩展」——**那是 rustls 的做法，
/// 不是 uTLS 的做法**（rustls 的 `encode_inner_hello` 以**外层**为模板）。两者的差别
/// 不是风格：服务端解出来的内层就是它接下来要谈的那条 ClientHello，所以内层的
/// **扩展集合、顺序、套件、版本**全都是判据的一部分。
///
/// 对照物是 uTLS 探针的原始输出（`ech_inner_probe_test.go`，128 字节）：
///
/// ```text
/// 0303 <random32> 00 | 0006 1301 1303 1302 | 01 00 | exts:
///   0000(SNI) 0012(SCT) fe0d(ECH=[1]) 002b(supported_versions=[0304])
///   fd00(marker=[13,5,51,10]) | 18 字节补零
/// ```
///
/// 我们的产出要与它**逐字节**相同（`tests/ech_inner_utls.rs` 那条测试就是判据）。
pub struct InnerHelloInputs<'a> {
    /// 内层要放的 SNI —— **真实名字**（外层放的是配置里的公开名）。
    /// `None` 或 IP 字面量 ⇒ 内层不带 SNI 扩展（uTLS 的 `hostnameInSNI` 语义）。
    pub sni: Option<&'a str>,
    /// 内层要放的 ALPN（引擎的诚实列表）。空 ⇒ 不带。
    pub alpn: &'a [Vec<u8>],
    /// 内层的 cipher suites：引擎**真正支持**的那些（uTLS 取的是 `config.cipherSuites()`）。
    /// 空 ⇒ 报错（内层一条套件都不报，服务器没法谈）。
    pub cipher_suites: &'a [u16],
    /// **外层** hello 的扩展类型，按线序。marker 里那串类型要按**它**排序 ——
    /// 服务器的解码器是沿外层做**单调查找**的（Go 的 `decodeInnerClientHello`：
    /// 下标 `i` 只增不减），所以 marker 的顺序必须与外层顺序**同构**。
    pub outer_ext_order: &'a [u16],
    /// 配置里的 `maximum_name_length`（决定补零量）。
    pub maximum_name_length: u8,
    /// 这次连接有没有 PSK。有才在内层里放 `psk_key_exchange_modes`
    /// （Go 只在 `loadSession` 里设它，见 `handshake_client.go:380`）。
    pub resuming: bool,
}

/// 内层 hello 的**两种形态**（见 `build_inner_client_hello_body` 的说明）。
pub struct InnerHellos {
    /// **加密进去**的那份：可压缩扩展被换成了 `0xfd00` 标记。
    pub sealed: Vec<u8>,
    /// 末尾要补的零字节数（补零只进密文，不进转录）。
    pub pad: usize,
    /// **转录**用的那份：可压缩扩展仍然内联 —— 服务器重建内层时正是这个形态。
    pub expanded: Vec<u8>,
}

/// `ECHOuterExtensions`（draft-ietf-tls-esni-18）：体是 `u8 长度 + u16 类型列表`。
const EXT_ECH_OUTER_EXTENSIONS: u16 = 0xfd00;

/// 把可压缩扩展收成一条 `0xfd00` 的体。
fn ech_outer_extensions_body(types: &[u16]) -> Vec<u8> {
    let mut b = Vec::with_capacity(1 + types.len() * 2);
    b.push((types.len() * 2) as u8);
    for t in types {
        b.extend_from_slice(&t.to_be_bytes());
    }
    b
}

/// 内层 hello 的**体**（不含 4 字节握手头、session id 为空、末尾补零到 32 的倍数）。
///
/// # 逐条对应的出处（uTLS 的 `makeClientHello` + `marshalMsgReorderOuterExts`）
///
/// | 内层里的东西 | 出处 |
/// |---|---|
/// | `legacy_version = 0x0303` | Go 把 `maxVersion` **封顶到 TLS 1.2**（兼容） |
/// | 内联扩展的**顺序** | Go 的字段顺序：SNI, SCT, ECH, ALPN, supported_versions, marker, PSK |
/// | SNI = 真名 | `serverName: hostnameInSNI(config.ServerName)` |
/// | SCT（空体） | `scts: true` —— Go 恒为真 |
/// | ECH = `[1]` | §6.1 规则 4 |
/// | ALPN | `alpnProtocols: config.NextProtos`（诚实列表；**不压缩**：uTLS 那里写着 `if echInner && false`） |
/// | `supported_versions = [0x0304]` | `config.supportedVersions()`（ECH 要求 MinVersion ≥ 1.3） |
/// | marker `0xfd00` | 可压缩扩展收成一条，**类型按外层线序** |
/// | **没有** GREASE / EMS / session_ticket / ec_point_formats / renegotiation_info / ChannelID / compress_certificate | 它们只是**指纹**的东西，内层是诚实的 hello |
/// | 补零 | `31 - ((len + pad - 1) % 32)`，`pad = max(0, L - nameLen)`（无 SNI 时 `L + 9`） |
///
/// 返回密封形态（未补零）+ 要补多少零，以及**转录形态**（可压缩扩展内联回原位）。
pub fn build_inner_client_hello_body(
    outer_spec: &utls::hello::ClientHelloSpec,
    inputs: &utls::hello::HandshakeInputs,
    inner: &InnerHelloInputs<'_>,
) -> Result<InnerHellos, rustls::Error> {
    if inner.cipher_suites.is_empty() {
        return Err(general(
            "utls-engine: 内层没有可报的 cipher suites（引擎一条都给不出）",
        ));
    }

    // 内层的输入：SNI 换真名、ALPN 换诚实列表。其余（随机数、key_exchange）与外层**同源**
    // —— uTLS 也从同一份 hello 里取 keyShares，所以公钥是同一把。
    let mut inner_inputs = inputs.clone();
    inner_inputs.sni = inner.sni.map(str::to_string);
    inner_inputs.alpn = inner.alpn.to_vec();

    // ① marker 要列哪些类型：诚实的内层**有**的 ∩ 外层**有**的，按**外层线序**排。
    //
    //    「诚实的内层有的」= Go 那些字段非空的那几个（`ocspStapling: true` ⇒ 5 恒有、
    //    `supportedCurves`/`supportedSignatureAlgorithms`/`supportedSignatureAlgorithmsCert`
    //    非空 ⇒ 10/13/50 恒有、TLS 1.3 ⇒ 51 恒有；45 只在复用会话时才有，44 只在 HRR 后）。
    //    「外层有的」这一半不能省：uTLS 的重排循环会**丢掉外层没有的类型**
    //    （`slices.Contains(echOuterExts, ext)` 的过滤），而服务器沿外层做单调查找，
    //    列一个外层没有的类型就是自找 `illegal_parameter`。
    let mut present = vec![5u16, 10, 13, 50, 51];
    if inner.resuming {
        present.push(45);
    }
    let mut compressed: Vec<u16> = Vec::new();
    for t in inner.outer_ext_order {
        if present.contains(t) && !compressed.contains(t) {
            compressed.push(*t);
        }
    }

    // ② 密封形态的 spec：只放**诚实**的那几条扩展，顺序照 Go 的字段顺序
    //    （与 uTLS 的产出逐字节对齐 —— 判据是 `ech_inner_utls.rs` 那条逐字节测试）。
    //
    //    排查记录（防重推）：OpenSSL 系（DEfO）服务器拒我们时，曾怀疑过「内层要按
    //    外层线序保序」—— 单独改顺序**无效**（test.defo.ie 仍拒），真正元凶是
    //    GREASE keyshare（见 [`super::FingerprintClient::scrub_grease_key_share`] 的
    //    逐变量二分）。所以这里保持 uTLS 的原序，不做偏离。
    let has_sni = inner
        .sni
        .is_some_and(|n| !utls::hello::hostname_in_sni(n).is_empty());
    let mut spec = utls::hello::ClientHelloSpec {
        legacy_version: utls::values::LEGACY_VERSION,
        cipher_suites: inner
            .cipher_suites
            .iter()
            .copied()
            .map(CodePoint::Fixed)
            .collect(),
        compression_methods: vec![utls::values::COMPRESSION_NONE],
        extensions: Vec::new(),
        session_id: utls::hello::SessionId::Empty,
        variability: utls::hello::Variability::Stable,
    };
    if has_sni {
        spec.extensions.push(Extension::ServerName);
    }
    spec.extensions.push(Extension::SignedCertificateTimestamp);
    spec.extensions.push(Extension::Opaque {
        id: 0xfe0d,
        body: inner_ech_extension_body(),
    });
    if !inner.alpn.is_empty() {
        spec.extensions.push(Extension::Alpn(inner.alpn.to_vec()));
    }
    spec.extensions
        .push(Extension::SupportedVersions(vec![CodePoint::Fixed(0x0304)]));
    let marker_at = (!compressed.is_empty()).then_some(spec.extensions.len());
    if !compressed.is_empty() {
        spec.extensions.push(Extension::Opaque {
            id: EXT_ECH_OUTER_EXTENSIONS,
            body: ech_outer_extensions_body(&compressed),
        });
    }

    let message = spec
        .marshal(&inner_inputs)
        .map_err(|e| general(&format!("utls-engine: 内层 hello 序列化失败：{e}")))?
        .into_bytes();
    // 去掉 4 字节握手头（uTLS: `h = h[4:]`）。
    let body = message[4..].to_vec();

    // ③ 转录形态：把标记换成**外层**里那些扩展的真身（服务器重建时正是拿外层的字节
    //    填进来的，`decodeInnerClientHello` 的 `recon` 循环）。位置就在标记那里、
    //    顺序就是 marker 的顺序 —— 于是这一份与服务器的重建**逐字节**相同。
    let mut expanded = Vec::new();
    if let Some(marker_at) = marker_at {
        let mut expanded_spec = spec.clone();
        expanded_spec.extensions.remove(marker_at);
        let mut ins: Vec<Extension> = Vec::new();
        for t in &compressed {
            if let Some(e) = outer_spec
                .extensions
                .iter()
                .find(|e| e.wire_type() == Some(*t))
            {
                ins.push(e.clone());
            }
        }
        for (k, e) in ins.into_iter().enumerate() {
            expanded_spec.extensions.insert(marker_at + k, e);
        }
        let msg = expanded_spec
            .marshal(&inner_inputs)
            .map_err(|e| general(&format!("utls-engine: 内层转录形态序列化失败：{e}")))?
            .into_bytes();
        expanded = msg[4..].to_vec();
    }

    // ④ 补零：uTLS 的原式，逐字照抄（`encodeInnerClientHelloReorderOuterExts`）。
    let name_len = if has_sni {
        inner
            .sni
            .map(|n| utls::hello::hostname_in_sni(n).len())
            .unwrap_or(0)
    } else {
        0
    };
    let pad0 = if has_sni {
        usize::from(inner.maximum_name_length).saturating_sub(name_len)
    } else {
        usize::from(inner.maximum_name_length) + 9
    };
    let pad = 31 - ((body.len() + pad0 - 1) % 32);
    Ok(InnerHellos {
        sealed: body,
        pad,
        expanded,
    })
}
