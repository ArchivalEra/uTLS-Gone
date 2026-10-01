//! 上游 `ClientHelloSpec` 的 **JSON 反序列化格式** —— `u_clienthello_json_test.go` +
//! `testdata/ClientHello-JSON-*.json` 那一族的等价物。
//!
//! # 它是什么、不是什么
//!
//! uTLS 允许把一份指纹存成 JSON 再读回来（指纹工具的实际用法），格式是**符号化**的：
//! `"GREASE"`、`"x25519"`、`"TLS 1.3"`、`"brotli"`、`"psk_dhe_ke"` —— 一张名字表，
//! 不是裸码点。本模块就是那张表加逐字段的映射，[`spec_from_str`] 是入口。
//!
//! 上游用同一份格式判了四个 golden：JSON 反解出的 spec 必须与
//! `utlsIdToSpec(preset)` 逐字段相同。我们的判据同形（`tests/utls_json_golden.rs`），
//! 并因此补上了此前缺的 `Ios(14)` 预设。
//!
//! # 与上游的两处刻意差别
//!
//! - **依赖**：JSON 解析挂在 `json` feature 后面（默认关）。指纹层的故事是
//!   「零依赖引擎、零密码学」，`serde_json` 不该因为一个可选格式进默认依赖树；
//!   CI 用 `--all-features` 跑这条判据。
//! - **格式表达不了的字段**：`session_id` / `variability`（以及 legacy_version）
//!   不在 JSON 里 —— 上游同样不存（它们来自 `ClientHelloID` 与 config）。
//!   [`spec_from_str`] 按我们的默认填并在错误信息里说明；判据只比
//!   JSON **可见**的三个字段（cipher_suites / compression_methods / extensions）。
//!
//! # 未知名字
//!
//! 任何表里没有的名字都**报错**，不静默丢弃 —— 上游的 `UnmarshalJSON` 对未知扩展
//! 也是直接返回错误。丢一条扩展就是改一条指纹。

use serde_json::Value;

use crate::hello::{
    ApplicationSettingsAlps, ClientHelloSpec, CodePoint, CompressCertificate, DelegatedCredentials,
    EcPointFormats, Extension, KeyShare, Padding, RenegotiationInfo, SessionId, SessionTicket,
    Variability,
};
use crate::values as v;

/// 反解失败的原因。未知名字一律 `Unknown`（带上下文），不静默丢弃。
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    /// JSON 本身不合法。
    Parse(String),
    /// 顶层或对象里缺某个字段 / 字段形状不对。
    Shape(String),
    /// 名字表里没有的符号（密码套件 / 组 / 算法 / 版本 / 扩展名）。
    Unknown(String),
    /// 这份 golden 声称的形状我们的模型表达不了（目前只有一种：
    /// 非 GREASE 的 key_share 带真实公钥字节 —— 预设层的 key_share 只声明组）。
    Unsupported(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Parse(m) => write!(f, "JSON 不合法：{m}"),
            Error::Shape(m) => write!(f, "字段形状不对：{m}"),
            Error::Unknown(m) => write!(
                f,
                "名字表里没有：{m}（上游加新符号时要来对表，不要放宽这条）"
            ),
            Error::Unsupported(m) => write!(f, "模型表达不了：{m}"),
        }
    }
}

impl std::error::Error for Error {}

/// 从上游 `ClientHelloSpec` 的 JSON 文本反解出一份 spec。
///
/// 格式之外的字段按 uTLS 的默认填：`legacy_version = 0x0303`、
/// `session_id = 随机 32`、`variability = 稳定序`（它们不在 JSON 里 ——
/// 上游同样不存，见模块头）。
pub fn spec_from_str(text: &str) -> Result<ClientHelloSpec, Error> {
    let d: Value = serde_json::from_str(text).map_err(|e| Error::Parse(e.to_string()))?;
    let obj = d
        .as_object()
        .ok_or_else(|| Error::Shape("顶层不是对象".into()))?;

    let cipher_suites = codepoints(field(obj, "cipher_suites")?, cipher_suite, "cipher_suites")?;
    let compression_methods = match field(obj, "compression_methods")?.as_array() {
        Some(list) => {
            let mut out = Vec::new();
            for c in list {
                let name = c
                    .as_str()
                    .ok_or_else(|| Error::Shape("compression_methods 的元素不是字符串".into()))?;
                match name {
                    "NULL" => out.push(v::COMPRESSION_NONE),
                    other => return Err(Error::Unknown(format!("压缩方法 {other}"))),
                }
            }
            out
        }
        None => return Err(Error::Shape("compression_methods 不是数组".into())),
    };

    let mut extensions = Vec::new();
    for e in field(obj, "extensions")?
        .as_array()
        .ok_or_else(|| Error::Shape("extensions 不是数组".into()))?
    {
        let e = e
            .as_object()
            .ok_or_else(|| Error::Shape("extensions 的元素不是对象".into()))?;
        extensions.push(extension(e)?);
    }

    Ok(ClientHelloSpec {
        legacy_version: v::LEGACY_VERSION,
        cipher_suites,
        compression_methods,
        extensions,
        session_id: SessionId::Random(32),
        variability: Variability::Stable,
    })
}

fn field<'a>(obj: &'a serde_json::Map<String, Value>, key: &str) -> Result<&'a Value, Error> {
    obj.get(key)
        .ok_or_else(|| Error::Shape(format!("缺字段 {key}")))
}

fn codepoints(
    arr: &Value,
    lookup: fn(&str) -> Option<u16>,
    what: &str,
) -> Result<Vec<CodePoint>, Error> {
    let list = arr
        .as_array()
        .ok_or_else(|| Error::Shape(format!("{what} 不是数组")))?;
    let mut out = Vec::new();
    for item in list {
        let name = item
            .as_str()
            .ok_or_else(|| Error::Shape(format!("{what} 的元素不是字符串")))?;
        out.push(match name {
            "GREASE" => CodePoint::Grease,
            other => CodePoint::Fixed(
                lookup(other).ok_or_else(|| Error::Unknown(format!("{what} 里的 {other}")))?,
            ),
        });
    }
    Ok(out)
}

/// 同 [`codepoints`]，但**不接受 GREASE**、产出裸 `u16`
/// （`delegated_credentials` 的 schemes 在模型里就是裸值）。
fn plain_u16s(arr: &Value, lookup: fn(&str) -> Option<u16>, what: &str) -> Result<Vec<u16>, Error> {
    let list = arr
        .as_array()
        .ok_or_else(|| Error::Shape(format!("{what} 不是数组")))?;
    let mut out = Vec::new();
    for item in list {
        let name = item
            .as_str()
            .ok_or_else(|| Error::Shape(format!("{what} 的元素不是字符串")))?;
        if name == "GREASE" {
            return Err(Error::Unsupported(format!(
                "{what} 里出现了 GREASE —— 这个位置不接受占位符"
            )));
        }
        out.push(lookup(name).ok_or_else(|| Error::Unknown(format!("{what} 里的 {name}")))?);
    }
    Ok(out)
}

fn extension(e: &serde_json::Map<String, Value>) -> Result<Extension, Error> {
    let name = e
        .get("name")
        .and_then(|n| n.as_str())
        .ok_or_else(|| Error::Shape("扩展对象缺 name".into()))?;
    Ok(match name {
        "GREASE" => Extension::Grease,
        "server_name" => Extension::ServerName,
        "extended_master_secret" => Extension::ExtendedMasterSecret,
        "renegotiation_info" => Extension::RenegotiationInfo(RenegotiationInfo {
            renegotiated_connection: Vec::new(),
        }),
        "supported_groups" => Extension::SupportedGroups(codepoints(
            field(e, "named_group_list")?,
            named_group,
            "named_group_list",
        )?),
        "ec_point_formats" => {
            let formats = string_list(field(e, "ec_point_format_list")?, "ec_point_format_list")?
                .into_iter()
                .map(|s| match s.as_str() {
                    "uncompressed" => Ok(v::POINT_FORMAT_UNCOMPRESSED),
                    other => Err(Error::Unknown(format!("ECPointFormat {other}"))),
                })
                .collect::<Result<Vec<u8>, Error>>()?;
            Extension::EcPointFormats(EcPointFormats { formats })
        }
        "session_ticket" => Extension::SessionTicket(SessionTicket { ticket: Vec::new() }),
        "application_layer_protocol_negotiation" => Extension::Alpn(
            string_list(field(e, "protocol_name_list")?, "protocol_name_list")?
                .into_iter()
                .map(String::into_bytes)
                .collect(),
        ),
        "status_request" => Extension::StatusRequest,
        "signature_algorithms" => Extension::SignatureAlgorithms(codepoints(
            field(e, "supported_signature_algorithms")?,
            signature_scheme,
            "supported_signature_algorithms",
        )?),
        "signed_certificate_timestamp" => Extension::SignedCertificateTimestamp,
        "key_share" => {
            let shares = field(e, "client_shares")?
                .as_array()
                .ok_or_else(|| Error::Shape("client_shares 不是数组".into()))?;
            let mut groups = Vec::new();
            for s in shares {
                let s = s
                    .as_object()
                    .ok_or_else(|| Error::Shape("client_shares 的元素不是对象".into()))?;
                let group = s
                    .get("group")
                    .and_then(|g| g.as_str())
                    .ok_or_else(|| Error::Shape("client_shares 的元素缺 group".into()))?;
                groups.push(match group {
                    "GREASE" => CodePoint::Grease,
                    other => CodePoint::Fixed(
                        named_group(other)
                            .ok_or_else(|| Error::Unknown(format!("key_share 组 {other}")))?,
                    ),
                });
                // 上游 golden 里只有 GREASE 那一项带 `key_exchange: [0]`（占位的一个零字节，
                // 我们的编码器本来就会为 GREASE 条目写它）；非 GREASE 组带真实公钥字节
                // 是「预设层」表达不了的东西 —— 预设只声明组，字节来自每连接的密钥交换。
                if let Some(b) = s.get("key_exchange") {
                    let bytes = b
                        .as_array()
                        .ok_or_else(|| Error::Shape("key_exchange 不是数组".into()))?;
                    let non_grease = group != "GREASE";
                    let real = bytes.iter().any(|x| x.as_u64() != Some(0));
                    if non_grease && real {
                        return Err(Error::Unsupported(format!(
                            "key_share 组 {group} 带了 {} 字节真实公钥 —— JSON 格式的这一面在预设层表达不了",
                            bytes.len()
                        )));
                    }
                }
            }
            Extension::KeyShare(KeyShare::groups(groups))
        }
        "psk_key_exchange_modes" => {
            let modes = string_list(field(e, "ke_modes")?, "ke_modes")?
                .into_iter()
                .map(|s| match s.as_str() {
                    "psk_dhe_ke" => Ok(v::PSK_MODE_DHE),
                    other => Err(Error::Unknown(format!("PSK 模式 {other}"))),
                })
                .collect::<Result<Vec<u8>, Error>>()?;
            Extension::PskKeyExchangeModes { modes }
        }
        "supported_versions" => {
            Extension::SupportedVersions(codepoints(field(e, "versions")?, version, "versions")?)
        }
        "compress_certificate" => {
            let algorithms = string_list(field(e, "algorithms")?, "algorithms")?
                .into_iter()
                .map(|s| match s.as_str() {
                    "brotli" => Ok(v::CERT_COMPRESSION_BROTLI),
                    "zlib" => Ok(v::CERT_COMPRESSION_ZLIB),
                    "zstd" => Ok(v::CERT_COMPRESSION_ZSTD),
                    other => Err(Error::Unknown(format!("证书压缩算法 {other}"))),
                })
                .collect::<Result<Vec<u16>, Error>>()?;
            Extension::CompressCertificate(CompressCertificate { algorithms })
        }
        // 上游 JSON 名字 `application_settings` 是**旧**码点（17513）；
        // 新码点（17613）在 golden 里还没出现过，来了就对表。
        "application_settings" => Extension::ApplicationSettings(ApplicationSettingsAlps {
            protocols: string_list(field(e, "supported_protocols")?, "supported_protocols")?
                .into_iter()
                .map(String::into_bytes)
                .collect(),
        }),
        "delegated_credentials" => Extension::DelegatedCredentials(DelegatedCredentials {
            // ⚠️ 这里的 schemes 是**裸 u16**（模型如此，GREASE 不进 delegated_credentials）。
            schemes: plain_u16s(
                field(e, "supported_signature_algorithms")?,
                signature_scheme,
                "delegated_credentials.supported_signature_algorithms",
            )?,
        }),
        "record_size_limit" => Extension::RecordSizeLimit {
            limit: u16::try_from(
                field(e, "record_size_limit")?
                    .as_u64()
                    .ok_or_else(|| Error::Shape("record_size_limit 不是数字".into()))?,
            )
            .map_err(|_| Error::Shape("record_size_limit 超出 u16".into()))?,
        },
        "padding" => {
            // 与上游 `UtlsPaddingExtension::UnmarshalJSON` 完全同款：`len` **缺省或 0**
            // ⇒ BoringPaddingStyle（长度在 marshal 时按整条消息算），非零 ⇒ 固定长度。
            // （iOS14 的 golden 就是 `{"name":"padding"}` —— 连 len 都没写。）
            let len = match e.get("len") {
                None => 0,
                Some(x) => x
                    .as_u64()
                    .ok_or_else(|| Error::Shape("padding.len 不是数字".into()))?,
            };
            Extension::Padding(match len {
                0 => Padding::BoringStyle,
                n => Padding::Fixed(
                    u16::try_from(n).map_err(|_| Error::Shape("padding.len 超出 u16".into()))?,
                ),
            })
        }
        other => return Err(Error::Unknown(format!("扩展 {other}"))),
    })
}

fn string_list(val: &Value, what: &str) -> Result<Vec<String>, Error> {
    val.as_array()
        .ok_or_else(|| Error::Shape(format!("{what} 不是数组")))?
        .iter()
        .map(|x| {
            x.as_str()
                .map(String::from)
                .ok_or_else(|| Error::Shape(format!("{what} 的元素不是字符串")))
        })
        .collect()
}

// ── 名字表（覆盖四份 golden 出现过的全部符号；新符号来了就在这里加一行） ──

fn cipher_suite(name: &str) -> Option<u16> {
    Some(match name {
        "TLS_AES_128_GCM_SHA256" => v::TLS_AES_128_GCM_SHA256,
        "TLS_AES_256_GCM_SHA384" => v::TLS_AES_256_GCM_SHA384,
        "TLS_CHACHA20_POLY1305_SHA256" => v::TLS_CHACHA20_POLY1305_SHA256,
        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256" => v::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" => v::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384" => v::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384" => v::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256" => {
            v::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305
        }
        "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256" => v::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
        "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA" => v::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
        "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA" => v::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
        "TLS_RSA_WITH_AES_128_GCM_SHA256" => v::TLS_RSA_WITH_AES_128_GCM_SHA256,
        "TLS_RSA_WITH_AES_256_GCM_SHA384" => v::TLS_RSA_WITH_AES_256_GCM_SHA384,
        "TLS_RSA_WITH_AES_128_CBC_SHA" => v::TLS_RSA_WITH_AES_128_CBC_SHA,
        "TLS_RSA_WITH_AES_256_CBC_SHA" => v::TLS_RSA_WITH_AES_256_CBC_SHA,
        "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA" => v::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
        "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA" => v::TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
        "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA" => v::FAKE_TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA,
        "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA" => v::TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
        "TLS_RSA_WITH_3DES_EDE_CBC_SHA" => v::TLS_RSA_WITH_3DES_EDE_CBC_SHA,
        "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256" => v::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
        "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384" => {
            v::DISABLED_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384
        }
        "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256" => v::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
        "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384" => {
            v::DISABLED_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384
        }
        "TLS_RSA_WITH_AES_128_CBC_SHA256" => v::TLS_RSA_WITH_AES_128_CBC_SHA256,
        "TLS_RSA_WITH_AES_256_CBC_SHA256" => v::DISABLED_TLS_RSA_WITH_AES_256_CBC_SHA256,
        _ => return None,
    })
}

fn named_group(name: &str) -> Option<u16> {
    Some(match name {
        "x25519" => v::X25519,
        "secp256r1" => v::CURVE_P256,
        "secp384r1" => v::CURVE_P384,
        "secp521r1" => v::CURVE_P521,
        "ffdhe2048" => v::FFDHE2048,
        "ffdhe3072" => v::FFDHE3072,
        _ => return None,
    })
}

fn signature_scheme(name: &str) -> Option<u16> {
    Some(match name {
        "ecdsa_secp256r1_sha256" => v::ECDSA_WITH_P256_AND_SHA256,
        "ecdsa_secp384r1_sha384" => v::ECDSA_WITH_P384_AND_SHA384,
        "ecdsa_secp521r1_sha512" => v::ECDSA_WITH_P521_AND_SHA512,
        "ecdsa_sha1" => v::ECDSA_WITH_SHA1,
        "rsa_pkcs1_sha1" => v::PKCS1_WITH_SHA1,
        "rsa_pkcs1_sha256" => v::PKCS1_WITH_SHA256,
        "rsa_pkcs1_sha384" => v::PKCS1_WITH_SHA384,
        "rsa_pkcs1_sha512" => v::PKCS1_WITH_SHA512,
        "rsa_pss_rsae_sha256" => v::PSS_WITH_SHA256,
        "rsa_pss_rsae_sha384" => v::PSS_WITH_SHA384,
        "rsa_pss_rsae_sha512" => v::PSS_WITH_SHA512,
        _ => return None,
    })
}

fn version(name: &str) -> Option<u16> {
    Some(match name {
        "TLS 1.0" => v::VERSION_TLS10,
        "TLS 1.1" => v::VERSION_TLS11,
        "TLS 1.2" => v::VERSION_TLS12,
        "TLS 1.3" => v::VERSION_TLS13,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_names_are_loud_not_dropped() {
        // 上游的 UnmarshalJSON 对未知扩展报错；这里验三个面都响。
        let bad_ext = r#"{"cipher_suites":[],"compression_methods":["NULL"],
            "extensions":[{"name":"no_such_extension"}]}"#;
        assert!(matches!(
            spec_from_str(bad_ext),
            Err(Error::Unknown(m)) if m.contains("no_such_extension")
        ));

        let bad_cipher = r#"{"cipher_suites":["TLSNoSuchCipher"],"compression_methods":["NULL"],"extensions":[]}"#;
        assert!(matches!(
            spec_from_str(bad_cipher),
            Err(Error::Unknown(m)) if m.contains("TLSNoSuchCipher")
        ));

        let trailing =
            r#"{"cipher_suites":[],"compression_methods":["NULL"],"extensions":[]} trailing"#;
        assert!(matches!(spec_from_str(trailing), Err(Error::Parse(_))));
    }

    #[test]
    fn padding_len_zero_means_boring_style() {
        // 上游 `UtlsPaddingExtension::UnmarshalJSON`：len 0 ⇒ BoringPaddingStyle，
        // 非 0 ⇒ 固定长度。这一条不是我们的约定，是照抄上游的语义。
        let zero = r#"{"cipher_suites":[],"compression_methods":["NULL"],
            "extensions":[{"name":"padding","len":0}]}"#;
        let spec = spec_from_str(zero).expect("合法");
        assert!(matches!(
            spec.extensions[0],
            Extension::Padding(Padding::BoringStyle)
        ));
        let fixed = r#"{"cipher_suites":[],"compression_methods":["NULL"],
            "extensions":[{"name":"padding","len":137}]}"#;
        let spec = spec_from_str(fixed).expect("合法");
        assert!(matches!(
            spec.extensions[0],
            Extension::Padding(Padding::Fixed(137))
        ));
    }
}
