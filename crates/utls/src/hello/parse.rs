//! 从已序列化的 ClientHello 反解出 spec（uTLS 的 `Fingerprinter` 的内核）。
//!
//! # 契约：**逐字节可回放**
//!
//! 对任意合法的 ClientHello 字节 `x`：
//!
//! ```text
//! marshal(from_bytes(x)?, 任意 inputs) == x      （逐字节）
//! ```
//!
//! 这个契约决定了本模块的全部取舍：**只在重新编码可证明逐字节相同的地方产出有类型的变体，
//! 其余一律 `Opaque`。**
//!
//! | 线类型 | 产出 | 为什么 |
//! |---|---|---|
//! | GREASE 值（任何位置） | `Fixed(原值)` —— **不是** `Grease` | `Grease` 会重新抽值，回放就不再逐字节 |
//! | `server_name` / `key_share` / GREASE-ECH | `Opaque` | 体是每连接的（SNI、公钥），从模型重建必然换掉指纹 |
//! | `supported_groups` / `signature_algorithms` / `supported_versions` | 有类型 | 结构固定，重新编码可证明相同 |
//! | `padding` | 仅当体全是零字节时 `Padding::Fixed` | 非零填充的体无法从「长度」重建 |
//! | 其余一切 | `Opaque` | 未知扩展原样保留 —— 这是「对真实互联网通用」的来源 |
//!
//! # ⚠️ `variability` 恒为 `Stable`
//!
//! 一次抓包**看不出**对方是否每连接乱序扩展（那是一个跨连接的性质）。
//! 所以反解出的 spec 是确定顺序的。把一个 Chrome 抓包反解再回放，得到的是一个
//! 真实 Chrome **不会**产生的固定顺序 —— 而这一点在 JA3 上是可见的。
//! 要模仿已知浏览器请用**预设**，不要用抓包反解：预设知道对方会不会乱序，
//! 抓包不知道。

use super::spec::{
    ClientHelloSpec, CodePoint, Extension, Padding, ParseError, SessionId, Variability,
};
use crate::values as v;

pub(crate) fn parse_client_hello(bytes: &[u8]) -> Result<ClientHelloSpec, ParseError> {
    let mut r = Reader::new(bytes);

    let ty = r.u8()?;
    if ty != 1 {
        return Err(ParseError::NotAClientHello(ty));
    }
    let declared = r.u24()? as usize;
    let actual = r.rest();
    if declared != actual {
        return Err(ParseError::LengthMismatch {
            declared: declared as u64,
            actual: actual as u64,
        });
    }

    let legacy_version = r.u16()?;
    let _random = r.take(32)?;

    let sid_len = r.u8()? as usize;
    if sid_len > 32 {
        return Err(ParseError::Malformed("legacy_session_id 超过 32 字节"));
    }
    let sid = r.take(sid_len)?;
    let session_id = if sid.is_empty() {
        SessionId::Empty
    } else {
        SessionId::Fixed(sid.to_vec())
    };

    let cs_len = r.u16()? as usize;
    if !cs_len.is_multiple_of(2) {
        return Err(ParseError::Malformed("密码套件区长度是奇数"));
    }
    let cs_bytes = r.take(cs_len)?;
    let mut cipher_suites = Vec::with_capacity(cs_len / 2);
    for c in cs_bytes.as_chunks::<2>().0 {
        cipher_suites.push(CodePoint::Fixed(u16::from_be_bytes(*c)));
    }

    let comp_len = r.u8()? as usize;
    let compression_methods = r.take(comp_len)?.to_vec();

    let ext_len = r.u16()? as usize;
    let ext_bytes = r.take(ext_len)?;
    let mut er = Reader::new(ext_bytes);
    let mut extensions = Vec::with_capacity(12);
    while er.rest() > 0 {
        let id = er.u16()?;
        let blen = er.u16()? as usize;
        let body = er.take(blen)?;
        extensions.push(classify(id, body)?);
    }
    if er.rest() != 0 {
        return Err(ParseError::Malformed("扩展区尾部有多余字节"));
    }

    Ok(ClientHelloSpec {
        legacy_version,
        cipher_suites,
        compression_methods,
        extensions,
        session_id,
        // 见模块头：一次抓包看不出跨连接的乱序行为。
        variability: Variability::Stable,
    })
}

/// 把一条扩展分类成「有类型」或 `Opaque`。见模块头的表。
fn classify(id: u16, body: &[u8]) -> Result<Extension, ParseError> {
    Ok(match id {
        v::EXT_SUPPORTED_GROUPS => Extension::SupportedGroups(u16_list(body, "supported_groups")?),
        v::EXT_SIGNATURE_ALGORITHMS => {
            Extension::SignatureAlgorithms(u16_list(body, "signature_algorithms")?)
        }
        v::EXT_SUPPORTED_VERSIONS => Extension::SupportedVersions(u8_prefixed_u16_list(body)?),
        // 只有「体全是零」才能从长度无损重建。非零填充的体是别人写进去的东西，
        // 我们没资格替它猜。
        v::EXT_PADDING if body.iter().all(|&b| b == 0) => {
            Extension::Padding(Padding::Fixed(body.len() as u16))
        }
        // 其余交给结构化扩展集。`extensions::classify` **只在重新编码可证明逐字节
        // 相同时**才返回 `Some`，所以失败就回落 `Opaque` —— 宁可不可编辑，也不能不可靠。
        _ => super::extensions::classify(id, body).unwrap_or(Extension::Opaque {
            id,
            body: body.to_vec(),
        }),
    })
}

fn u16_list(body: &[u8], what: &'static str) -> Result<Vec<CodePoint>, ParseError> {
    let mut r = Reader::new(body);
    let n = r.u16()? as usize;
    if n != r.rest() || !n.is_multiple_of(2) {
        return Err(ParseError::Malformed(what));
    }
    let mut out = Vec::with_capacity(n / 2);
    while r.rest() > 0 {
        out.push(CodePoint::Fixed(r.u16()?));
    }
    Ok(out)
}

fn u8_prefixed_u16_list(body: &[u8]) -> Result<Vec<CodePoint>, ParseError> {
    let mut r = Reader::new(body);
    let n = r.u8()? as usize;
    if n != r.rest() || !n.is_multiple_of(2) {
        return Err(ParseError::Malformed("supported_versions"));
    }
    let mut out = Vec::with_capacity(n / 2);
    while r.rest() > 0 {
        out.push(CodePoint::Fixed(r.u16()?));
    }
    Ok(out)
}

struct Reader<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(b: &'a [u8]) -> Self {
        Reader { b, pos: 0 }
    }

    fn rest(&self) -> usize {
        self.b.len() - self.pos
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], ParseError> {
        if self.rest() < n {
            return Err(ParseError::Truncated {
                needed: n,
                got: self.rest(),
            });
        }
        let s = &self.b[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    fn u8(&mut self) -> Result<u8, ParseError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, ParseError> {
        let s = self.take(2)?;
        Ok(u16::from_be_bytes([s[0], s[1]]))
    }

    fn u24(&mut self) -> Result<u32, ParseError> {
        let s = self.take(3)?;
        Ok(((s[0] as u32) << 16) | ((s[1] as u32) << 8) | s[2] as u32)
    }
}
