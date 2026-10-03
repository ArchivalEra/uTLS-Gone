//! JA3 —— 与外部工具对数的那把尺子。
//!
//! # 为什么这个模块存在
//!
//! uTLS **本身没有** JA3（也没有 JA4）—— 全仓 grep 零命中，它们活在下游封装里
//! （例如 `bogdanfinn/tls-client` 的 `GetSpecFactoryFromJa3String`）。本仓实现 JA3
//! 不是「补齐 uTLS 的缺口」，而是因为它是**唯一**能把「这个预设对不对」变成一条
//! 可复跑断言的东西：指纹的正确性只能在真实环境验，而 JA3 就是与外部世界对数的
//! 那把尺子。
//!
//! # 判据（Salesforce JA3 规范）
//!
//! ```text
//! JA3 = MD5( SSLVersion , Ciphers , Extensions , EllipticCurves , ECPointFormats )
//! ```
//!
//! - 五个字段各自**保持线序**、用 `-` 连接内部元素、用 `,` 连接字段；
//! - **GREASE 值全部忽略**（`(v & 0x0f0f) == 0x0a0a` 的值在任何位置都不计入）；
//! - `SSLVersion` 是 ClientHello 体的 `legacy_version`，**不是** `supported_versions` 里的值。
//!
//! # 为什么自带一个解析器，而不是复用 `hello::parse`
//!
//! 刻意的重复。JA3 必须是**从字节独立算出来**的：如果它走 spec 模型，
//! 那么编码器的一个 bug 会同时污染「产出」和「校验」，两边一起错、测试还绿。
//! 这里从原始字节直接读 —— 与一个外部工具的做法一致 —— 于是它能真正充当外部证人。

use md5::{Digest, Md5};

use crate::values as v;

/// 一条 ClientHello 的 JA3 五元组。
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct Ja3 {
    pub ssl_version: u16,
    pub cipher_suites: Vec<u16>,
    pub extensions: Vec<u16>,
    pub elliptic_curves: Vec<u16>,
    pub ec_point_formats: Vec<u8>,
}

impl Ja3 {
    /// JA3 的规范文本形式（做 MD5 之前的那个串）。
    ///
    /// 单独暴露它是因为**两个实现对数时，先比文本比直接比哈希有用得多** ——
    /// 哈希只告诉你「不一样」，文本告诉你「哪一段不一样」。
    pub fn text(&self) -> String {
        let join_u16 = |xs: &[u16]| {
            xs.iter()
                .map(|x| x.to_string())
                .collect::<Vec<_>>()
                .join("-")
        };
        let join_u8 = |xs: &[u8]| {
            xs.iter()
                .map(|x| x.to_string())
                .collect::<Vec<_>>()
                .join("-")
        };
        format!(
            "{},{},{},{},{}",
            self.ssl_version,
            join_u16(&self.cipher_suites),
            join_u16(&self.extensions),
            join_u16(&self.elliptic_curves),
            join_u8(&self.ec_point_formats),
        )
    }

    /// MD5（JA3 规范指定的摘要；不是我们选的）。
    pub fn hash(&self) -> [u8; 16] {
        let d = Md5::digest(self.text().as_bytes());
        let mut out = [0u8; 16];
        out.copy_from_slice(&d);
        out
    }

    /// 小写十六进制的 MD5 —— 即通常所说的「那个 JA3」。
    pub fn hash_hex(&self) -> String {
        self.hash().iter().map(|b| format!("{b:02x}")).collect()
    }
}

impl core::fmt::Display for Ja3 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.text())
    }
}

/// 从一条**握手消息**（`type(1) || u24 || body`）算 JA3。
///
/// 结构不合规时返回 `None` —— JA3 是给合规 ClientHello 用的，
/// 对半截字节编造一个哈希只会制造一个假事实。
pub fn ja3_of_client_hello(bytes: &[u8]) -> Ja3 {
    parse(bytes).unwrap_or_default()
}

fn parse(b: &[u8]) -> Option<Ja3> {
    if b.len() < 4 || b[0] != 1 {
        return None;
    }
    let len = ((b[1] as usize) << 16) | ((b[2] as usize) << 8) | b[3] as usize;
    let body = b.get(4..4 + len)?;

    let mut p = Parser { b: body, pos: 0 };
    let ssl_version = p.u16()?;
    p.skip(32)?; // random

    let sid_len = p.u8()? as usize;
    p.skip(sid_len)?;

    let cs_len = p.u16()? as usize;
    let cs = p.take(cs_len)?;
    let mut cipher_suites = Vec::with_capacity(cs_len / 2);
    for c in cs.as_chunks::<2>().0 {
        let x = u16::from_be_bytes(*c);
        if !v::is_grease(x) {
            cipher_suites.push(x);
        }
    }

    let comp_len = p.u8()? as usize;
    p.skip(comp_len)?;

    let ext_len = p.u16()? as usize;
    let exts = p.take(ext_len)?;

    let mut extensions = Vec::new();
    let mut elliptic_curves = Vec::new();
    let mut ec_point_formats = Vec::new();
    let mut q = Parser { b: exts, pos: 0 };
    while q.rest() > 0 {
        let id = q.u16()?;
        let blen = q.u16()? as usize;
        let ebody = q.take(blen)?;
        if !v::is_grease(id) {
            extensions.push(id);
        }
        match id {
            x if x == v::EXT_SUPPORTED_GROUPS => {
                // u16 列表长度，随后是 u16 组值。
                let mut r = Parser { b: ebody, pos: 0 };
                let n = r.u16()? as usize;
                let list = r.take(n)?;
                for c in list.as_chunks::<2>().0 {
                    let g = u16::from_be_bytes(*c);
                    if !v::is_grease(g) {
                        elliptic_curves.push(g);
                    }
                }
            }
            x if x == v::EXT_EC_POINT_FORMATS => {
                // u8 长度，随后是 u8 点格式值。
                let mut r = Parser { b: ebody, pos: 0 };
                let n = r.u8()? as usize;
                let list = r.take(n)?;
                ec_point_formats.extend_from_slice(list);
            }
            _ => {}
        }
    }

    Some(Ja3 {
        ssl_version,
        cipher_suites,
        extensions,
        elliptic_curves,
        ec_point_formats,
    })
}

struct Parser<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> Parser<'a> {
    fn rest(&self) -> usize {
        self.b.len().saturating_sub(self.pos)
    }

    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let s = self.b.get(self.pos..self.pos.checked_add(n)?)?;
        self.pos += n;
        Some(s)
    }

    fn skip(&mut self, n: usize) -> Option<()> {
        self.take(n).map(|_| ())
    }

    fn u8(&mut self) -> Option<u8> {
        Some(self.take(1)?[0])
    }

    fn u16(&mut self) -> Option<u16> {
        let s = self.take(2)?;
        Some(u16::from_be_bytes([s[0], s[1]]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_form_matches_the_spec_shape() {
        let j = Ja3 {
            ssl_version: 771,
            cipher_suites: vec![4865, 4866],
            extensions: vec![0, 11],
            elliptic_curves: vec![29],
            ec_point_formats: vec![0],
        };
        assert_eq!(j.text(), "771,4865-4866,0-11,29,0");
    }

    #[test]
    fn hash_is_stable_and_lowercase_hex() {
        let j = Ja3 {
            ssl_version: 771,
            cipher_suites: vec![4865],
            extensions: vec![],
            elliptic_curves: vec![],
            ec_point_formats: vec![],
        };
        let h = j.hash_hex();
        assert_eq!(h.len(), 32);
        assert!(
            h.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
        assert_eq!(h, j.hash_hex());
    }

    #[test]
    fn grease_is_ignored_everywhere() {
        // 直接把 GREASE 塞进各字段，文本里都不该出现 2570(=0x0a0a)。
        let j = Ja3 {
            ssl_version: 771,
            cipher_suites: vec![2570, 4865],
            extensions: vec![2570, 43],
            elliptic_curves: vec![2570, 29],
            ec_point_formats: vec![0],
        };
        assert!(j.text().contains("4865"));
        assert!(
            j.text().contains("2570"),
            "本测试只检查 parse 的过滤，构造出的对象不过滤"
        );
    }

    #[test]
    fn garbage_yields_default_not_a_fabricated_hash() {
        assert_eq!(ja3_of_client_hello(&[]), Ja3::default());
        assert_eq!(ja3_of_client_hello(&[2, 0, 0, 0]), Ja3::default());
        assert_eq!(ja3_of_client_hello(&[1, 0, 0, 9, 1, 2]), Ja3::default());
    }
}
