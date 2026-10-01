//! **Encrypted ClientHello 的配置面**：`ECHConfigList` 的解析与选用。
//!
//! 这一层刻意只有**数据**：解析、校验、挑一个能用的配置。真正的 HPKE 封装属于引擎
//! （它才有密码学），本 crate 一行密码学都没有 —— 与「公钥由调用方给」是同一条纪律。
//!
//! # 判据是 uTLS 自己的 `ech_test.go`
//!
//! uTLS 的 ECH 测试**只测解析与选用**（`parseECHConfigList` / `pickECHConfig`），
//! 而且是两条带具体十六进制向量的用例。所以本模块的 `parse` / `pick` 逐条对齐
//! `ech.go` 里那两个函数，并用**同样的向量**做判据（见本文件的测试）——
//! 那比我自己造向量强，因为它是上游认下的。
//!
//! # 几处「照抄而不是改好」的语义
//!
//! 1. **未知版本是「跳过」，不是错误**：`parseECHConfig` 见到 `version != 0xfe0d`
//!    就返回 `skip = true`，由列表那一层按 `length+4` 前进。这是 ECH 的版本协商方式
//!    （draft-ietf-tls-esni-18 §4），不是容错。
//! 2. **列表长度必须恰好等于剩余字节数**，否则整条列表报 `malformed ECHConfigList`。
//! 3. **带「强制」位的扩展直接跳过整个配置**（高位置 1 表示 mandatory，
//!    而我们一个扩展也不支持）—— 见 `pick`。
//! 4. `valid_dns_name` 与 RFC 的 DNS 规则**不完全一致**：uTLS 那份没有校验单个 label
//!    的长度上限，只有整体 ≤253、≥2 个 label、字符集合与连字符位置。照抄。

/// ECH 的扩展类型码（`encrypted_client_hello`）。
pub const EXT_ENCRYPTED_CLIENT_HELLO: u16 = 0xfe0d;

/// 一个 HPKE 对称密码套件（`HpkeSymmetricCipherSuite`，RFC 9180 §7.2 的两个 id）。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct HpkeSymmetricCipherSuite {
    pub kdf_id: u16,
    pub aead_id: u16,
}

/// 配置里的一条未知扩展。
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct EchExtension {
    pub ext_type: u16,
    pub data: Vec<u8>,
}

impl EchExtension {
    /// 高位置 1 ⇒ 这个扩展是**强制**的（draft-ietf-tls-esni-18 §4.1）。
    ///
    /// uTLS 的判据就是这一位：它一个扩展都不支持，所以见到强制的就跳过整个配置。
    pub fn is_mandatory(&self) -> bool {
        self.ext_type & (1 << 15) != 0
    }
}

/// 一条 `ECHConfig`。
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct EchConfig {
    /// **这条配置的原始字节**（含 version 与 length，按 length 字段截齐）。
    ///
    /// 为什么要留着它：HPKE 的 `info` 参数是 `"tls ech\0" || ECHConfig`
    /// （draft-ietf-tls-esni-17 §6.1，rustls 的 `hpke_info()` 逐字如此），
    /// 而 `ECHCConfig` 在那里指的是**完整编码**，不是字段拼回去的东西 ——
    /// 未知扩展、填充之类的字节都得原样带上。uTLS 的 `echConfig.raw` 也是这个用途。
    pub raw: Vec<u8>,
    pub version: u16,
    pub config_id: u8,
    pub kem_id: u16,
    pub public_key: Vec<u8>,
    pub cipher_suites: Vec<HpkeSymmetricCipherSuite>,
    pub maximum_name_length: u8,
    pub public_name: Vec<u8>,
    pub extensions: Vec<EchExtension>,
}

/// 解析 `ECHConfigList` 失败的原因。
///
/// 文案与 uTLS 的两条一致：整条列表坏了是一种，单条配置某个字段坏了是另一种
/// （并且点名是哪个字段 —— 那比「解析失败」有用得多）。
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum EchParseError {
    /// `tls: malformed ECHConfigList` —— 外层长度字段与实际不符。
    MalformedList,
    /// `tls: malformed ECHConfig` —— 列表里剩下的字节不足 4（放不下 version+length）。
    TruncatedConfig,
    /// `tls: malformed ECHConfig, invalid <field>` —— 某条配置的第 `field` 个字段坏了。
    InvalidField { field: &'static str },
}

impl core::fmt::Display for EchParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            EchParseError::MalformedList => write!(f, "tls: malformed ECHConfigList"),
            EchParseError::TruncatedConfig => write!(f, "tls: malformed ECHConfig"),
            EchParseError::InvalidField { field } => {
                write!(f, "tls: malformed ECHConfig, invalid {field} field")
            }
        }
    }
}

/// 一个游标读取器 —— 与 Go 的 `cryptobyte.String` 的用法一一对应（读到越界即失败）。
struct Reader<'a> {
    b: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn new(b: &'a [u8]) -> Self {
        Reader { b, at: 0 }
    }

    fn remaining(&self) -> usize {
        self.b.len().saturating_sub(self.at)
    }

    fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    fn u8(&mut self) -> Option<u8> {
        let v = *self.b.get(self.at)?;
        self.at += 1;
        Some(v)
    }

    fn u16(&mut self) -> Option<u16> {
        let hi = self.u8()?;
        let lo = self.u8()?;
        Some(u16::from_be_bytes([hi, lo]))
    }

    /// `ReadUint8LengthPrefixed`
    fn u8_prefixed(&mut self) -> Option<&'a [u8]> {
        let n = self.u8()? as usize;
        self.take(n)
    }

    /// `ReadUint16LengthPrefixed`
    fn u16_prefixed(&mut self) -> Option<&'a [u8]> {
        let n = self.u16()? as usize;
        self.take(n)
    }

    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let out = self.b.get(self.at..self.at + n)?;
        self.at += n;
        Some(out)
    }
}

/// 解析一条 `ECHConfig`（`enc` 是**含** version/length 的那一段）。
///
/// 返回 `Ok(None)` 表示「版本不认识，跳过这条」（uTLS 的 `skip = true`）——
/// 那**不是**错误。`Err` 才是真的坏了。
fn parse_one(enc: &[u8]) -> Result<Option<EchConfig>, EchParseError> {
    let mut r = Reader::new(enc);
    let version = r
        .u16()
        .ok_or(EchParseError::InvalidField { field: "version" })?;
    let length = r
        .u16()
        .ok_or(EchParseError::InvalidField { field: "length" })?;
    if enc.len() < usize::from(length) + 4 {
        return Err(EchParseError::InvalidField { field: "length" });
    }
    if version != EXT_ENCRYPTED_CLIENT_HELLO {
        // 未知版本：跳过（**不是**错误）—— ECH 的版本协商就靠这个。
        return Ok(None);
    }

    let field = |f: &'static str| EchParseError::InvalidField { field: f };
    let config_id = r.u8().ok_or_else(|| field("config_id"))?;
    let kem_id = r.u16().ok_or_else(|| field("kem_id"))?;
    let public_key = r
        .u16_prefixed()
        .ok_or_else(|| field("public_key"))?
        .to_vec();

    let suites_raw = r.u16_prefixed().ok_or_else(|| field("cipher_suites"))?;
    let mut sr = Reader::new(suites_raw);
    let mut cipher_suites = Vec::new();
    while !sr.is_empty() {
        let kdf_id = sr.u16().ok_or_else(|| field("cipher_suites kdf_id"))?;
        let aead_id = sr.u16().ok_or_else(|| field("cipher_suites aead_id"))?;
        cipher_suites.push(HpkeSymmetricCipherSuite { kdf_id, aead_id });
    }

    let maximum_name_length = r.u8().ok_or_else(|| field("maximum_name_length"))?;
    let public_name = r
        .u8_prefixed()
        .ok_or_else(|| field("public_name"))?
        .to_vec();

    let exts_raw = r.u16_prefixed().ok_or_else(|| field("extensions"))?;
    let mut er = Reader::new(exts_raw);
    let mut extensions = Vec::new();
    while !er.is_empty() {
        let ext_type = er.u16().ok_or_else(|| field("extensions type"))?;
        let data = er
            .u16_prefixed()
            .ok_or_else(|| field("extensions data"))?
            .to_vec();
        extensions.push(EchExtension { ext_type, data });
    }

    Ok(Some(EchConfig {
        raw: enc[..usize::from(length) + 4].to_vec(),
        version,
        config_id,
        kem_id,
        public_key,
        cipher_suites,
        maximum_name_length,
        public_name,
        extensions,
    }))
}

/// 解析一份 `ECHConfigList`（draft-ietf-tls-esni-18 §4）。
///
/// 返回值**只含版本认识的配置**，顺序与输入一致（uTLS 的 `parseECHConfigList`）。
pub fn parse_ech_config_list(data: &[u8]) -> Result<Vec<EchConfig>, EchParseError> {
    let mut r = Reader::new(data);
    let declared = r.u16().ok_or(EchParseError::MalformedList)? as usize;
    if declared != data.len().saturating_sub(2) {
        return Err(EchParseError::MalformedList);
    }
    let mut out = Vec::new();
    while !r.is_empty() {
        // 剩下不足 4 字节 ⇒ 连 version+length 都放不下。
        if r.remaining() < 4 {
            return Err(EchParseError::TruncatedConfig);
        }
        let rest = &data[r.at..];
        let config_len = usize::from(u16::from_be_bytes([rest[2], rest[3]]));
        // 版本不认识的配置直接跳过（`parse_one` 返回 `None`）—— 这是 ECH 的版本协商。
        if let Some(cfg) = parse_one(rest)? {
            out.push(cfg);
        }
        // ⚠️ 前进的是**声明长度**，不是实际消费的长度：跳过的配置根本没被解析，
        // 只能按它自己声明的长度走（uTLS 的 `s = s[configLen+4:]`）。
        r.take(config_len + 4)
            .ok_or(EchParseError::TruncatedConfig)?;
    }
    Ok(out)
}

/// 本层认识的 KEM（RFC 9180 §7.1）：P-256 与 X25519。
///
/// 与引擎的能力无关 —— 那是 `Hpke` 那边的事；这里只回答「这个 id 是不是一个
/// 我们认得的 KEM」，`pick` 用它筛配置。长度用于校验 `public_key`。
pub fn kem_public_key_len(kem_id: u16) -> Option<usize> {
    match kem_id {
        0x0010 => Some(65), // DHKEM(P-256, HKDF-SHA256)
        0x0020 => Some(32), // DHKEM(X25519, HKDF-SHA256)
        _ => None,
    }
}

/// 本层认识的 KDF（RFC 9180 §7.2）。
pub fn kdf_supported(kdf_id: u16) -> bool {
    matches!(kdf_id, 0x0001..=0x0003) // HKDF-SHA256 / SHA384 / SHA512
}

/// 本层认识的 AEAD（RFC 9180 §7.3）。
pub fn aead_supported(aead_id: u16) -> bool {
    matches!(aead_id, 0x0001..=0x0003) // AES-128-GCM / AES-256-GCM / ChaCha20Poly1305
}

/// AEAD 的认证标签长度（RFC 9180 §7.3 的 `Nt`）。
///
/// 我们支持的三种**都是 16**，所以这里可以是一个常量 —— 但写成函数是为了让
/// 「载荷长度 = 内层 hello 长 + 标签长」这句话在调用点看得见，而不是散落的 `+ 16`。
/// （本 crate 的 GREASE ECH 那边已经有一份同样的 `AEAD_TAG_LEN`。）
pub fn hpke_aead_tag_len(aead_id: u16) -> Option<usize> {
    match aead_id {
        0x0001..=0x0003 => Some(16),
        _ => None,
    }
}

/// uTLS 的 `validDNSName`：**照抄**，包括它没做的那件事。
///
/// 它只校验：整体 ≤253、至少两个 label、每个 label 非空、字符是字母数字或连字符、
/// 连字符不在首尾。**没有**校验单个 label ≤63 —— 那是真实的 DNS 规则，而 uTLS 这份
/// 没写。多校验一条会让「uTLS 会用的配置我们不用」，于是同一条 ECH 连接的走向不同；
/// 这种差异在指纹上是看得见的，所以宁可照抄。
pub fn valid_dns_name(name: &str) -> bool {
    if name.len() > 253 {
        return false;
    }
    let labels: Vec<&str> = name.split('.').collect();
    if labels.len() <= 1 {
        return false;
    }
    for label in labels {
        if label.is_empty() {
            return false;
        }
        let n = label.len();
        for (i, c) in label.char_indices() {
            if c == '-' && (i == 0 || i == n - 1) {
                return false;
            }
            if !(c.is_ascii_alphanumeric() || c == '-') {
                return false;
            }
        }
    }
    true
}

impl EchConfig {
    /// 这条配置**能不能用**（uTLS 的 `pickECHConfig` 里那个 for 循环体）。
    ///
    /// 四条判据，顺序与 uTLS 相同：
    /// 1. `public_name` 是个合法 DNS 名；
    /// 2. 没有**强制**扩展（我们一个扩展都不支持，见 [`EchExtension::is_mandatory`]）；
    /// 3. `kem_id` 认识，且 `public_key` 的长度与该 KEM 相符；
    /// 4. 至少有一个认识的 `(kdf, aead)` 套件。
    pub fn is_usable(&self) -> bool {
        valid_dns_name(core::str::from_utf8(&self.public_name).unwrap_or("\u{fffd}"))
            && !self.extensions.iter().any(|e| e.is_mandatory())
            && kem_public_key_len(self.kem_id) == Some(self.public_key.len())
            && self
                .cipher_suites
                .iter()
                .any(|s| kdf_supported(s.kdf_id) && aead_supported(s.aead_id))
    }

    /// 这条配置里第一个能用的套件（uTLS 也是「第一个能用的」，不设偏好）。
    pub fn first_usable_suite(&self) -> Option<HpkeSymmetricCipherSuite> {
        self.cipher_suites
            .iter()
            .copied()
            .find(|s| kdf_supported(s.kdf_id) && aead_supported(s.aead_id))
    }
}

/// uTLS 的 `pickECHConfig`：挑**第一条**能用的配置。
///
/// 「能用」的定义见 [`EchConfig::is_usable`] —— 注意 `TestSkipBadConfigs` 那条用例：
/// 列表里有一条结构上解析通过、但**用不了**（强制扩展 / 公钥长度不符）的配置，
/// 而 `pick` 必须返回 `None` 而不是把连接弄坏。
pub fn pick_ech_config(list: &[EchConfig]) -> Option<&EchConfig> {
    list.iter().find(|c| c.is_usable())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// uTLS `ech_test.go::TestDecodeECHConfigLists` 的向量，**逐字节照抄**。
    /// 出处：`refraction-networking/utls` 的 `ech_test.go:19-22`。
    const UTLS_VECTORS: &[(&str, usize)] = &[
        (
            "0045fe0d0041590020002092a01233db2218518ccbbbbc24df20686af417b37388de6460e94011974777090004000100010012636c6f7564666c6172652d6563682e636f6d0000",
            1,
        ),
        (
            "0105badd00050504030201fe0d0066000010004104e62b69e2bf659f97be2f1e0d948a4cd5976bb7a91e0d46fbdda9a91e9ddcba5a01e7d697a80a18f9c3c4a31e56e27c8348db161a1cf51d7ef1942d4bcf7222c1000c000100010001000200010003400e7075626c69632e6578616d706c650000fe0d003d00002000207d661615730214aeee70533366f36a609ead65c0c208e62322346ab5bcd8de1c000411112222400e7075626c69632e6578616d706c650000fe0d004d000020002085bd6a03277c25427b52e269e0c77a8eb524ba1eb3d2f132662d4b0ac6cb7357000c000100010001000200010003400e7075626c69632e6578616d706c650008aaaa000474657374",
            3,
        ),
    ];

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).expect("十六进制"))
            .collect()
    }

    #[test]
    fn utls_vectors_parse_to_the_same_config_count() {
        // 判据就是 uTLS 自己的断言：**解析出的配置条数**。
        for (hex_list, want) in UTLS_VECTORS {
            let list =
                parse_ech_config_list(&unhex(hex_list)).unwrap_or_else(|e| panic!("解析失败：{e}"));
            assert_eq!(list.len(), *want, "配置条数与 uTLS 的不一致");
        }
    }

    #[test]
    fn the_first_utls_vector_parses_field_by_field() {
        // 光数条数不够：字段错位也可能恰好凑出同样多的配置（长度前缀是会「自洽」的）。
        // 所以把第一条向量的每个字段都钉住 —— 它是一条真实的 Cloudflare 配置。
        let list = parse_ech_config_list(&unhex(UTLS_VECTORS[0].0)).unwrap();
        let c = &list[0];
        assert_eq!(c.version, EXT_ENCRYPTED_CLIENT_HELLO, "version 该是 0xfe0d");
        assert_eq!(c.config_id, 0x59);
        assert_eq!(c.kem_id, 0x0020, "DHKEM(X25519, HKDF-SHA256)");
        assert_eq!(c.public_key.len(), 32);
        assert_eq!(
            c.cipher_suites,
            vec![HpkeSymmetricCipherSuite {
                kdf_id: 0x0001,
                aead_id: 0x0001
            }],
            "一个套件：HKDF-SHA256 + AES-128-GCM"
        );
        assert_eq!(c.maximum_name_length, 0);
        assert_eq!(c.public_name, b"cloudflare-ech.com".to_vec());
        assert!(c.extensions.is_empty());
        // 这条配置是能用的。
        assert!(c.is_usable());
        assert_eq!(pick_ech_config(&list).map(|c| c.config_id), Some(0x59));
    }

    #[test]
    fn a_config_with_an_unknown_version_is_skipped_not_an_error() {
        // 第二条向量的第一条配置版本是 `badd`（不认识）—— uTLS 数出 3 条，
        // 而列表里其实有 4 条。所以「未知版本跳过」这条语义必须成立，
        // 否则条数会变成 4（或直接报错）。
        let list = parse_ech_config_list(&unhex(UTLS_VECTORS[1].0)).unwrap();
        assert_eq!(list.len(), 3);
        assert!(
            list.iter().all(|c| c.version == EXT_ENCRYPTED_CLIENT_HELLO),
            "跳过之后的列表里不该留下未知版本的配置"
        );
        // 第二条向量里前三条的 KEM 各不相同，最后一条带强制扩展。
        assert_eq!(list[0].kem_id, 0x0010, "P-256");
        assert_eq!(list[1].kem_id, 0x0020, "X25519");
    }

    #[test]
    fn utls_skip_bad_configs_vector_picks_nothing() {
        // uTLS `TestSkipBadConfigs`：`parseECHConfigList` 成功（结构上过得去），
        // 但 `pickECHConfig` 必须返回「没得用」—— 那条配置的 `public_key` 长度
        // 与它的 KEM 不符，而另一条带**强制**扩展。把连接弄坏不是选项。
        let hex_list = "00c8badd00050504030201fe0d0029006666000401020304000c000100010001000200010003400e7075626c69632e6578616d706c650000fe0d003d000020002072e8a23b7aef67832bcc89d652e3870a60f88ca684ec65d6eace6b61f136064c000411112222400e7075626c69632e6578616d706c650000fe0d004d00002000200ce95810a81d8023f41e83679bc92701b2acd46c75869f95c72bc61c6b12297c000c000100010001000200010003400e7075626c69632e6578616d706c650008aaaa000474657374";
        let list = parse_ech_config_list(&unhex(hex_list)).expect("结构上该能解析");
        assert!(
            pick_ech_config(&list).is_none(),
            "uTLS 的判据是「一条都不该选中」；选中了就说明我们的可用性判据比上游松"
        );
        // 逐条说明为什么都不能用（这样失败时不用再猜是哪一条）。
        for (i, c) in list.iter().enumerate() {
            let reasons = [
                (!valid_dns_name(core::str::from_utf8(&c.public_name).unwrap_or("")))
                    .then_some("public_name"),
                c.extensions
                    .iter()
                    .any(|e| e.is_mandatory())
                    .then_some("强制扩展"),
                (kem_public_key_len(c.kem_id) != Some(c.public_key.len())).then_some("公钥长度"),
                (c.first_usable_suite().is_none()).then_some("没有可用套件"),
            ]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();
            assert!(!reasons.is_empty(), "第 {i} 条被判为可用，但它该被跳过");
        }
    }

    #[test]
    fn malformed_lists_are_rejected_with_the_upstream_wording() {
        // 外层长度字段与实际不符 ⇒ 整条列表坏（uTLS 的 `errMalformedECHConfigList`）。
        let e = parse_ech_config_list(&[0x00, 0x05, 0xfe, 0x0d]).unwrap_err();
        assert_eq!(e, EchParseError::MalformedList);
        assert_eq!(format!("{e}"), "tls: malformed ECHConfigList");
        // 空输入连长度字段都没有 ⇒ 同一条错误。
        assert_eq!(
            parse_ech_config_list(&[]).unwrap_err(),
            EchParseError::MalformedList
        );
        // 长度对得上但没有配置 ⇒ 空列表（不是错误）。
        assert!(parse_ech_config_list(&[0x00, 0x00]).unwrap().is_empty());
        // 列表里剩不足 4 字节 ⇒ `malformed ECHConfig`。
        let e = parse_ech_config_list(&[0x00, 0x03, 0xfe, 0x0d, 0x00]).unwrap_err();
        assert_eq!(e, EchParseError::TruncatedConfig);
        assert_eq!(format!("{e}"), "tls: malformed ECHConfig");
        // 单条配置声明了比实际更长的身体 ⇒ 点名 `length` 字段。
        // （手写而不是从向量上砍：砍出来的字节多半先撞上外层长度校验，
        // 那样测到的是 `MalformedList`，不是这里想验的「配置内部坏了」。）
        // 外层长度必须与实长自洽（`declared == len-2`），否则先撞上 `MalformedList`。
        let bad = [0x00, 0x06, 0xfe, 0x0d, 0x00, 0x04, 0xaa, 0xbb];
        let e = parse_ech_config_list(&bad).unwrap_err();
        assert_eq!(e, EchParseError::InvalidField { field: "length" });
        assert_eq!(
            format!("{e}"),
            "tls: malformed ECHConfig, invalid length field"
        );
        // 同理，`kem_id` 缺失：version/length 说这条配置有 1 字节，而后面什么都没有，
        // 于是 `config_id` 读不出来。
        let bad = [0x00, 0x04, 0xfe, 0x0d, 0x00, 0x00];
        let e = parse_ech_config_list(&bad).unwrap_err();
        assert_eq!(e, EchParseError::InvalidField { field: "config_id" });
        assert_eq!(
            format!("{e}"),
            "tls: malformed ECHConfig, invalid config_id field"
        );
    }

    #[test]
    fn valid_dns_name_matches_the_upstream_definition_including_its_gaps() {
        // uTLS 那份没有校验单个 label 的 63 字节上限 —— 这条断言就是「我们也没加」。
        let long_label = "a".repeat(70);
        assert!(
            valid_dns_name(&format!("{long_label}.com")),
            "上游没查 label 长度上限，多查一条会让「上游会用的配置我们不用」"
        );
        assert!(valid_dns_name("public.example"));
        assert!(valid_dns_name("a.b"));
        assert!(valid_dns_name("cloudflare-ech.com"));
        assert!(!valid_dns_name("single"), "只有一个 label ⇒ 不是合法名");
        assert!(!valid_dns_name("a..b"), "空 label");
        assert!(!valid_dns_name("-a.b"), "连字符在首");
        assert!(!valid_dns_name("a-.b"), "连字符在尾");
        assert!(!valid_dns_name("a_b.c"), "下划线不在字符集合里");
        assert!(!valid_dns_name(""), "空名");
        let too_long = format!("{}com", "a.".repeat(130));
        assert!(
            too_long.len() > 253,
            "这条测试的构造该超过 253：{}",
            too_long.len()
        );
        assert!(!valid_dns_name(&too_long), "整体超过 253");
    }

    #[test]
    fn mandatory_extensions_are_recognised_by_the_high_bit() {
        assert!(
            EchExtension {
                ext_type: 0xaaaa,
                data: vec![]
            }
            .is_mandatory()
        );
        assert!(
            EchExtension {
                ext_type: 0x8000,
                data: vec![]
            }
            .is_mandatory()
        );
        assert!(
            !EchExtension {
                ext_type: 0x0001,
                data: vec![]
            }
            .is_mandatory()
        );
        assert!(
            !EchExtension {
                ext_type: 0x7fff,
                data: vec![]
            }
            .is_mandatory()
        );
    }
}
