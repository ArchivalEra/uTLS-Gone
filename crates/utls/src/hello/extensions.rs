//! **结构化扩展集**：把常见扩展从 `Extension::Opaque` 升级成有类型的变体。
//!
//! 为什么值得做：`Opaque` 能保证逐字节正确（它是「类型 + 原始体」），但它**不可编辑**、
//! 不可校验，而且读代码的人看不出 `vec![1, 0, 0, 0, 0]` 是 `status_request` 的哪一部分。
//! 有类型之后，spec 才真的是一份「声明」，而不只是一串字节。
//!
//! # 两条自律（这次重构全靠它们）
//!
//! 1. **每种类型只在「重新编码可证明逐字节相同」时才由反解器产出**，否则回落到 `Opaque`。
//!    所以 `body()` 与 `classify()` 必须成对写：`classify` 是 `body` 的**逆**，
//!    且只在它是逆的地方生效。见 `parse.rs` 的往返契约。
//! 2. **体内容必须与 uTLS 逐字节一致** —— 这次重构正好赶上对账刚被加强到「逐扩展比体内容」，
//!    所以任何一处体算错都会被立刻抓到（只比长度的年代，这种错是隐形的）。
//!
//! 出处：每个 `body()` 的注释都指向 Go `u_tls_extensions.go` 里对应的 `Read()`。

use super::spec::{
    ApplicationSettingsAlps, CompressCertificate, CookieExtension, DelegatedCredentials,
    EcPointFormats, Extension, PreSharedKey, PskIdentity, RenegotiationInfo, SessionTicket,
    SignatureAlgorithmsCert,
};

/// 把 `(类型, 体)` 分类成一个有类型的变体；**只有在重新编码逐字节相同时才返回 `Some`**。
///
/// 这是 `body()` 的逆。凡是有歧义、或者体里带着本模型表达不了的东西，就返回 `None`
/// 让调用方回落到 `Extension::Opaque` —— 宁可不可编辑，也不能不可靠。
pub(crate) fn classify(id: u16, body: &[u8]) -> Option<Extension> {
    use crate::values as v;
    Some(match id {
        x if x == v::EXT_STATUS_REQUEST => {
            // uTLS 的 `StatusRequestExtension`（`u_tls_extensions.go`）：恒定五字节
            // OCSP + 两个零长度字段。别的形状（带 responder id）本模型表达不了 ⇒ 回落。
            if body != [v::STATUS_TYPE_OCSP, 0, 0, 0, 0] {
                return None;
            }
            Extension::StatusRequest
        }
        x if x == v::EXT_EXTENDED_MASTER_SECRET => {
            if !body.is_empty() {
                return None;
            }
            Extension::ExtendedMasterSecret
        }
        x if x == v::EXT_RENEGOTIATION_INFO => {
            let (n, rest) = body.split_first()?;
            if usize::from(*n) != rest.len() {
                return None;
            }
            Extension::RenegotiationInfo(RenegotiationInfo {
                renegotiated_connection: rest.to_vec(),
            })
        }
        x if x == v::EXT_SESSION_TICKET => {
            // 体就是 ticket 本身，没有长度前缀 ⇒ 任意字节都能无损表达。
            Extension::SessionTicket(SessionTicket {
                ticket: body.to_vec(),
            })
        }
        x if x == v::EXT_PRE_SHARED_KEY => {
            // 体必须是**恰好**被这两个长度字段吃干净，否则退回 Opaque ——
            // 带尾巴的体重新编码时会被我们改写，那就不是逆了。
            let (ids_len_bytes, rest) = body.split_at_checked(2)?;
            let ids_len = usize::from(u16::from_be_bytes([ids_len_bytes[0], ids_len_bytes[1]]));
            let (ids, rest) = rest.split_at_checked(ids_len)?;
            let mut identities = Vec::new();
            let mut p = 0usize;
            while p < ids.len() {
                let (llen, r) = ids[p..].split_at_checked(2)?;
                let llen = usize::from(u16::from_be_bytes([llen[0], llen[1]]));
                let (label, r) = r.split_at_checked(llen)?;
                let (age, r) = r.split_at_checked(4)?;
                identities.push(PskIdentity {
                    label: label.to_vec(),
                    obfuscated_ticket_age: u32::from_be_bytes([age[0], age[1], age[2], age[3]]),
                });
                p = ids.len() - r.len();
            }
            let (bs_len_bytes, bs) = rest.split_at_checked(2)?;
            let bs_len = usize::from(u16::from_be_bytes([bs_len_bytes[0], bs_len_bytes[1]]));
            if bs.len() != bs_len {
                return None;
            }
            let mut binders = Vec::new();
            let mut q = 0usize;
            while q < bs.len() {
                let blen = bs[q] as usize;
                let b = bs.get(q + 1..q + 1 + blen)?;
                binders.push(b.to_vec());
                q += 1 + blen;
            }
            Extension::PreSharedKey(PreSharedKey {
                identities,
                binders,
            })
        }
        x if x == v::EXT_COOKIE => {
            // `u16 长度 + cookie`：长度必须**恰好**等于剩余字节数，否则退回 Opaque
            // （长度字段与实长不符的体，重新编码时会被我们改写成长度字段 —— 那就不是逆了）。
            let (len_bytes, rest) = body.split_at_checked(2)?;
            if usize::from(u16::from_be_bytes([len_bytes[0], len_bytes[1]])) != rest.len() {
                return None;
            }
            Extension::Cookie(CookieExtension {
                cookie: rest.to_vec(),
            })
        }
        x if x == v::EXT_EC_POINT_FORMATS => {
            let (n, rest) = body.split_first()?;
            if usize::from(*n) != rest.len() {
                return None;
            }
            Extension::EcPointFormats(EcPointFormats {
                formats: rest.to_vec(),
            })
        }
        x if x == v::EXT_COMPRESS_CERTIFICATE => {
            let (n, rest) = body.split_first()?;
            if usize::from(*n) != rest.len() || !rest.len().is_multiple_of(2) {
                return None;
            }
            Extension::CompressCertificate(CompressCertificate {
                algorithms: rest
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|c| u16::from_be_bytes(*c))
                    .collect(),
            })
        }
        x if x == v::EXT_APPLICATION_SETTINGS || x == v::EXT_APPLICATION_SETTINGS_NEW => {
            let protocols = parse_alps(body)?;
            let alps = ApplicationSettingsAlps { protocols };
            if x == v::EXT_APPLICATION_SETTINGS {
                Extension::ApplicationSettings(alps)
            } else {
                Extension::ApplicationSettingsNew(alps)
            }
        }
        x if x == v::EXT_SCT => {
            if !body.is_empty() {
                return None;
            }
            Extension::SignedCertificateTimestamp
        }
        x if x == v::EXT_PSK_KEY_EXCHANGE_MODES => {
            let (n, rest) = body.split_first()?;
            if usize::from(*n) != rest.len() {
                return None;
            }
            Extension::PskKeyExchangeModes {
                modes: rest.to_vec(),
            }
        }
        x if x == v::EXT_RECORD_SIZE_LIMIT => {
            let b: [u8; 2] = body.try_into().ok()?;
            Extension::RecordSizeLimit {
                limit: u16::from_be_bytes(b),
            }
        }
        x if x == v::EXT_SIGNATURE_ALGORITHMS_CERT => {
            Extension::SignatureAlgorithmsCert(SignatureAlgorithmsCert {
                schemes: u16_list(body)?,
            })
        }
        x if x == v::EXT_DELEGATED_CREDENTIALS => {
            Extension::DelegatedCredentials(DelegatedCredentials {
                schemes: u16_list(body)?,
            })
        }
        // NPN 与 ChannelID 的体在 uTLS 里**恒为空**（`Len()` 就是 4，即只有头）。
        // 所以只认空体，别的形状回落。
        x if x == v::EXT_NPN => {
            if !body.is_empty() {
                return None;
            }
            Extension::Npn
        }
        x if x == v::EXT_CHANNEL_ID => {
            if !body.is_empty() {
                return None;
            }
            Extension::ChannelId {
                old_codepoint: false,
            }
        }
        x if x == v::EXT_CHANNEL_ID_OLD => {
            if !body.is_empty() {
                return None;
            }
            Extension::ChannelId {
                old_codepoint: true,
            }
        }
        _ => return None,
    })
}

/// `u16 长度 + u16 元素` —— `signature_algorithms_cert` 与 `delegated_credentials` 的形状。
fn u16_list(body: &[u8]) -> Option<Vec<u16>> {
    let (len, rest) = body.split_at_checked(2)?;
    let n = usize::from(u16::from_be_bytes([len[0], len[1]]));
    if n != rest.len() || !n.is_multiple_of(2) {
        return None;
    }
    Some(
        rest.as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_be_bytes(*c))
            .collect(),
    )
}

/// ALPS 的体：`u16 ALPS 长度 | (u8 长度 + 协议名)*`。
fn parse_alps(body: &[u8]) -> Option<Vec<Vec<u8>>> {
    let (len, mut rest) = body.split_at_checked(2)?;
    if usize::from(u16::from_be_bytes([len[0], len[1]])) != rest.len() {
        return None;
    }
    let mut out = Vec::new();
    while let Some((n, tail)) = rest.split_first() {
        let (proto, tail) = tail.split_at_checked(usize::from(*n))?;
        out.push(proto.to_vec());
        rest = tail;
    }
    Some(out)
}

/// 把 ALPS 的协议列表编成体（编码侧，与 [`parse_alps`] 互逆）。
///
/// 出处：Go `u_tls_extensions.go` 的 `applicationSettingsExtension.Read`。
/// `["h2"]` ⇒ `00 03 02 68 32`（五字节）。
pub(crate) fn alps_body(protocols: &[Vec<u8>]) -> Vec<u8> {
    let mut inner: Vec<u8> = Vec::new();
    for p in protocols {
        inner.push(p.len() as u8);
        inner.extend_from_slice(p);
    }
    let mut b = Vec::with_capacity(2 + inner.len());
    b.extend_from_slice(&(inner.len() as u16).to_be_bytes());
    b.extend_from_slice(&inner);
    b
}

/// 把 `u16 列表` 编成体（`signature_algorithms_cert` / `delegated_credentials`）。
pub(crate) fn u16_list_body(vals: &[u16]) -> Vec<u8> {
    let mut b = Vec::with_capacity(2 + 2 * vals.len());
    b.extend_from_slice(&((2 * vals.len()) as u16).to_be_bytes());
    for v in vals {
        b.extend_from_slice(&v.to_be_bytes());
    }
    b
}
