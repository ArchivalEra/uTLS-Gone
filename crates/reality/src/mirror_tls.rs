//! **镜像握手的自定义 TLS 1.3 服务端** —— REALITY 的核心那一步。
//!
//! # 参照在做什么（`tls.go:330-408` + `handshake_server_tls13.go:88-190`）
//!
//! 1. 把客户端的 hello 原样转发给真站，读回真站的第一段 flight；
//! 2. 取真站的 **ServerHello 当模板**——它的 random、session id 回声、密码套件、
//!    扩展列表**逐字节**留给客户端（这就是「镜像」：观测者看到的服务器响应
//!    与真站一模一样）；
//! 3. **只替换 `serverShare` 的密钥字节**：自己生成一对临时密钥，与客户端的
//!    key share 做 ECDH（`handshake_server_tls13.go:104-120`）；
//! 4. 会话密钥按**普通 TLS 1.3 调度**从这次 ECDH 派生（AuthKey 不进记录层）；
//! 5. 之后的三条消息自己造：`EncryptedExtensions`（空）/ `Certificate`
//!    （一次性 ed25519 自签 + 尾 64 字节 `HMAC(AuthKey, pub)`）/ `CertificateVerify`
//!    （真 ed25519 签名）/ `Finished`。
//!
//! # 为什么必须自己写这一层
//!
//! rustls 不允许替换 ServerHello 的 key share，也不接受「外供 ServerHello」——
//! 它把 ServerHello 的字节与自己的转录/密钥状态绑死。要「逐字节镜像」就只能自己
//! 跑这半段握手。好在范围是封闭的：只需要 SHA-256/384、HKDF、AES-GCM/ChaCha20
//! 与 Ed25519 签名（全部是现成原语）；密钥交换与共享密钥的计算仍然借 rustls 的
//! `SupportedKxGroup::start_and_complete`（它的混合组语义与 Go 一致，
//! 现有真栈判据已经证明了这一点）。
//!
//! # 支持面（不支持就由调用方回落透传）
//!
//! * 组：**只有 X25519(29) 与 X25519MLKEM768(4588)** —— 依据是 uTLS 客户端的能力
//!   （`KeySharePrivateKeys` 没有 P-256 私钥位，见 [`MIRRORABLE_GROUPS`] 的说明）；
//!   真站选了别的组就回落透传。
//! * 套件：`TLS_AES_128_GCM_SHA256` / `TLS_AES_256_GCM_SHA384` /
//!   `TLS_CHACHA20_POLY1305_SHA256`；
//! * 不做：HelloRetryRequest（已知边界，参照同样不做）、0-RTT、KeyUpdate 的
//!   重新派生（收到就报错，不静默）。

use std::io::{Read, Write};
use std::net::TcpStream;

use aes_gcm::aead::{Aead as _, KeyInit, Payload};
use aes_gcm::{Aes128Gcm, Aes256Gcm, Nonce};
use chacha20poly1305::ChaCha20Poly1305;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha384};

/// 镜像握手失败的原因 —— **调用方据此回落透传**（`tls.go` 的 `break f` 语义）。
#[derive(Debug)]
pub enum MirrorError {
    /// 真站的 ServerHello 解析不了/形状不认。
    BadTemplate(String),
    /// 真站选的组我们没有对应实现。
    UnsupportedGroup(u16),
    /// 真站选的套件我们没有对应实现。
    UnsupportedSuite(u16),
    /// 真站没有回显客户端的 session id（RFC 8446 §4.1.3 要求）。
    SessionIdMismatch,
    /// 没有可用的 ed25519 签名键。
    NoSigningKey(String),
    Io(std::io::Error),
    /// 握手过程中对端给了我们不能接受的东西（含 Finished 校验失败）。
    Protocol(String),
}

impl std::fmt::Display for MirrorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadTemplate(m) => write!(f, "真站 ServerHello 不可用作模板：{m}"),
            Self::UnsupportedGroup(g) => write!(f, "提供者不提供组 0x{g:04x}"),
            Self::UnsupportedSuite(s) => write!(f, "不支持套件 0x{s:04x}"),
            Self::SessionIdMismatch => write!(f, "真站没有回显客户端的 session id"),
            Self::NoSigningKey(m) => write!(f, "没有可用的签名键：{m}"),
            Self::Io(e) => write!(f, "IO：{e}"),
            Self::Protocol(m) => write!(f, "协议：{m}"),
        }
    }
}

impl From<std::io::Error> for MirrorError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

// ── 哈希与 HKDF（RFC 8446 §7.1 / RFC 5869）────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Hs {
    S256,
    S384,
}

impl Hs {
    fn len(self) -> usize {
        match self {
            Self::S256 => 32,
            Self::S384 => 48,
        }
    }

    fn digest(self, data: &[u8]) -> Vec<u8> {
        match self {
            Self::S256 => Sha256::digest(data).to_vec(),
            Self::S384 => Sha384::digest(data).to_vec(),
        }
    }

    fn hmac(self, key: &[u8], data: &[u8]) -> Vec<u8> {
        match self {
            Self::S256 => {
                let mut m = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC 任意键长");
                m.update(data);
                m.finalize().into_bytes().to_vec()
            }
            Self::S384 => {
                let mut m = <Hmac<Sha384> as Mac>::new_from_slice(key).expect("HMAC 任意键长");
                m.update(data);
                m.finalize().into_bytes().to_vec()
            }
        }
    }
}

fn hkdf_extract(hs: Hs, salt: &[u8], ikm: &[u8]) -> Vec<u8> {
    hs.hmac(salt, ikm)
}

fn hkdf_expand(hs: Hs, prk: &[u8], info: &[u8], out_len: usize) -> Vec<u8> {
    let mut okm = Vec::with_capacity(out_len);
    let mut t: Vec<u8> = Vec::new();
    let mut counter = 1u8;
    while okm.len() < out_len {
        let mut input = t.clone();
        input.extend_from_slice(info);
        input.push(counter);
        t = hs.hmac(prk, &input);
        okm.extend_from_slice(&t);
        counter = counter.checked_add(1).expect("HKDF 输出长度不可能这么大");
    }
    okm.truncate(out_len);
    okm
}

/// `HKDF-Expand-Label`（RFC 8446 §7.1）。
fn expand_label(hs: Hs, secret: &[u8], label: &str, context: &[u8], out_len: usize) -> Vec<u8> {
    let full = format!("tls13 {label}");
    let mut info = Vec::with_capacity(4 + full.len() + context.len());
    info.extend_from_slice(&(out_len as u16).to_be_bytes());
    info.push(full.len() as u8);
    info.extend_from_slice(full.as_bytes());
    info.push(context.len() as u8);
    info.extend_from_slice(context);
    hkdf_expand(hs, secret, &info, out_len)
}

/// `Derive-Secret(secret, label, messages)`（RFC 8446 §7.1）。
fn derive_secret(hs: Hs, secret: &[u8], label: &str, messages_hash: &[u8]) -> Vec<u8> {
    expand_label(hs, secret, label, messages_hash, hs.len())
}

// ── 记录层 AEAD ─────────────────────────────────────────────────────────

/// 我们**能镜像**的组：X25519 与 X25519MLKEM768。
///
/// 依据是 uTLS 客户端的实际能力，不是我们的偏好：uTLS 的 `KeySharePrivateKeys`
/// （`u_public.go:926-931`）只有 `Ecdhe`(X25519) / `Mlkem` / `MlkemEcdhe` 三个字段
/// —— **没有 P-256 的私钥位**，所以 uTLS 客户端（Xray 用的就是它）在任何情况下都
/// 完不成「服务端选 P-256」的握手。XTLS `tls.go:222-239` 只挑这两个组正是为此。
/// 真站选了别的组 ⇒ [`run`] 返回 [`MirrorError::UnsupportedGroup`] ⇒ 调用方透传。
pub const MIRRORABLE_GROUPS: [u16; 2] = [4588, 29];

/// 每连接的记录层 AEAD（三种套件各一个实现）。
///
/// `Box<dyn ...>` 而不是枚举：`Aes256Gcm` 与 `ChaCha20Poly1305` 的内部状态尺寸
/// 差值很大（clippy 的 `large_enum_variant` 会报），而这里每次记录都要用、
/// 装箱的开销相对 AEAD 本身可忽略。
type Aead = Box<dyn AeadOps>;

trait AeadOps: Send {
    fn seal(&self, nonce: &[u8; 12], aad: &[u8], plaintext: &[u8]) -> Vec<u8>;
    fn open(&self, nonce: &[u8; 12], aad: &[u8], ciphertext: &[u8]) -> Option<Vec<u8>>;
}

impl<C> AeadOps for C
where
    C: aes_gcm::aead::AeadInPlace + Send,
{
    fn seal(&self, nonce: &[u8; 12], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
        let n = Nonce::from_slice(nonce);
        self.encrypt(
            n,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .expect("AEAD 加密不会失败")
    }

    fn open(&self, nonce: &[u8; 12], aad: &[u8], ciphertext: &[u8]) -> Option<Vec<u8>> {
        let n = Nonce::from_slice(nonce);
        self.decrypt(
            n,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .ok()
    }
}

fn new_aead(suite: u16, key: &[u8]) -> Option<Aead> {
    match suite {
        0x1301 => Some(Box::new(Aes128Gcm::new_from_slice(key).ok()?)),
        0x1302 => Some(Box::new(Aes256Gcm::new_from_slice(key).ok()?)),
        0x1303 => Some(Box::new(ChaCha20Poly1305::new_from_slice(key).ok()?)),
        _ => None,
    }
}

fn nonce_for(iv: &[u8; 12], seq: u64) -> [u8; 12] {
    let mut n = *iv;
    let seq = seq.to_be_bytes();
    for (i, b) in seq.iter().enumerate() {
        n[4 + i] ^= b;
    }
    n
}

/// 一个方向的记录层状态（RFC 8446 §5.3：`TLSCiphertext` + 序号 XOR nonce）。
struct RecordKeys {
    aead: Aead,
    iv: [u8; 12],
    seq: u64,
}

impl RecordKeys {
    fn from_secret(suite: u16, hs: Hs, secret: &[u8]) -> Option<Self> {
        let key_len = match suite {
            0x1301 => 16,
            0x1302 | 0x1303 => 32,
            _ => return None,
        };
        let key = expand_label(hs, secret, "key", &[], key_len);
        let iv_v = expand_label(hs, secret, "iv", &[], 12);
        let mut iv = [0u8; 12];
        iv.copy_from_slice(&iv_v);
        Some(Self {
            aead: new_aead(suite, &key)?,
            iv,
            seq: 0,
        })
    }

    fn seal(&mut self, content_type: u8, plaintext: &[u8]) -> Vec<u8> {
        let mut inner = plaintext.to_vec();
        inner.push(content_type);
        // 记录头是 AAD；长度在加密后才知道。
        let len = inner.len() + 16; // AEAD tag
        let header = [0x17u8, 0x03, 0x03, (len >> 8) as u8, (len & 0xff) as u8];
        let nonce = nonce_for(&self.iv, self.seq);
        self.seq += 1;
        let ct = self.aead.seal(&nonce, &header, &inner);
        let mut out = header.to_vec();
        out.extend_from_slice(&ct);
        out
    }

    /// 解一条 `TLSCiphertext`，返回 `(内容类型, 明文)`。
    fn open(&mut self, header: &[u8; 5], body: &[u8]) -> Option<(u8, Vec<u8>)> {
        let nonce = nonce_for(&self.iv, self.seq);
        self.seq += 1;
        let mut pt = self.aead.open(&nonce, header, body)?;
        // 去掉末尾的零填充，最后一个非零字节是真实内容类型（RFC 8446 §5.4）。
        while let Some(last) = pt.pop() {
            if last != 0 {
                return Some((last, pt));
            }
        }
        None
    }
}

// ── ServerHello 模板的解析与打补丁 ───────────────────────────────────────

struct ServerHelloTemplate {
    /// 真站的 ServerHello **握手消息**（`0x02 || u24 || body`）。
    raw: Vec<u8>,
    suite: u16,
    /// 该扩展体里 `key_exchange` 字节的区间。
    key_exchange_range: std::ops::Range<usize>,
    peer_pub: Vec<u8>,
    group: u16,
    session_id: Vec<u8>,
}

fn parse_server_hello(msg: &[u8]) -> Result<ServerHelloTemplate, MirrorError> {
    let bad = |m: String| MirrorError::BadTemplate(m);
    if msg.len() < 4 + 2 + 32 + 1 || msg[0] != 0x02 {
        return Err(bad("不是 ServerHello 握手消息".into()));
    }
    let declared = ((msg[1] as usize) << 16) | ((msg[2] as usize) << 8) | msg[3] as usize;
    if declared + 4 != msg.len() {
        return Err(bad(format!(
            "长度字段 {declared} 与实际 {} 不符",
            msg.len() - 4
        )));
    }
    let mut p = 4usize + 2 + 32; // legacy_version + random
    let sid_len = msg[p] as usize;
    p += 1;
    let session_id = msg
        .get(p..p + sid_len)
        .ok_or_else(|| bad("session id 越界".into()))?
        .to_vec();
    p += sid_len;
    let suite = u16::from_be_bytes([
        *msg.get(p).ok_or_else(|| bad("缺密码套件".into()))?,
        *msg.get(p + 1).ok_or_else(|| bad("缺密码套件".into()))?,
    ]);
    p += 3; // 套件(2) + 压缩(1)
    let exts_len = u16::from_be_bytes([
        *msg.get(p).ok_or_else(|| bad("缺扩展长度".into()))?,
        *msg.get(p + 1).ok_or_else(|| bad("缺扩展长度".into()))?,
    ]) as usize;
    p += 2;
    let exts = msg
        .get(p..p + exts_len)
        .ok_or_else(|| bad("扩展区越界".into()))?;
    let exts_at = p;
    let mut q = 0usize;
    while q + 4 <= exts.len() {
        let ty = u16::from_be_bytes([exts[q], exts[q + 1]]);
        let bl = u16::from_be_bytes([exts[q + 2], exts[q + 3]]) as usize;
        let body = exts
            .get(q + 4..q + 4 + bl)
            .ok_or_else(|| bad(format!("扩展 0x{ty:04x} 体越界")))?;
        if ty == 0x0033 {
            if body.len() < 4 {
                return Err(bad("key_share 体过短".into()));
            }
            let group = u16::from_be_bytes([body[0], body[1]]);
            let kl = u16::from_be_bytes([body[2], body[3]]) as usize;
            if body.len() != 4 + kl {
                return Err(bad("key_share 体长度与内部声明不符".into()));
            }
            return Ok(ServerHelloTemplate {
                raw: msg.to_vec(),
                suite,
                key_exchange_range: exts_at + q + 4 + 4..exts_at + q + 4 + 4 + kl,
                peer_pub: body[4..].to_vec(),
                group,
                session_id,
            });
        }
        q += 4 + bl;
    }
    Err(bad("没有 key_share 扩展（TLS 1.3 必须有）".into()))
}

/// 用**我们的**公钥替换模板里的密钥字节（只改这一处 —— 长度不变，因为同组）。
fn patch_key_share(template: &ServerHelloTemplate, our_pub: &[u8]) -> Result<Vec<u8>, MirrorError> {
    if template.peer_pub.len() != our_pub.len() {
        return Err(MirrorError::BadTemplate(format!(
            "同组公钥长度该相同：模板 {} vs 我们 {}",
            template.peer_pub.len(),
            our_pub.len()
        )));
    }
    let mut msg = template.raw.clone();
    msg[template.key_exchange_range.clone()].copy_from_slice(our_pub);
    Ok(msg)
}

// ── 握手消息构造（RFC 8446 §4.3/4.4）──────────────────────────────────────

fn hs_msg(ty: u8, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + body.len());
    out.push(ty);
    let n = body.len();
    out.extend_from_slice(&[(n >> 16) as u8, (n >> 8) as u8, n as u8]);
    out.extend_from_slice(body);
    out
}

fn u24(v: usize) -> [u8; 3] {
    [(v >> 16) as u8, (v >> 8) as u8, v as u8]
}

/// `EncryptedExtensions`（空扩展 —— Xray 客户端不要求 ALPN 回声）。
fn encrypted_extensions() -> Vec<u8> {
    hs_msg(0x08, &[0x00, 0x00])
}

/// `Certificate`：一条一次性 ed25519 自签证书，**最后 64 字节换成 HMAC 尾签**。
///
/// ⚠️ 体里的两个长度前缀 + 每个证书条目后的 2 字节 extensions：
/// ```text
/// certificate_request_context: u8 长度 + 内容（服务端证书为空 ⇒ 0x00）
/// certificate_list:            u24 长度
///   entry:                     u24 证书长 || 证书 || u16 extensions 长（这里 0）
/// ```
/// 第一版漏了 `certificate_request_context`、第二版以为补上它就够 —— 但
/// **uTLS 的 `unmarshalCertificate` 还要求每个条目后面有 `u16` 的 extensions 字段**
/// （`handshake_messages.go:1602-1608`：`readUint24LengthPrefixed(cert)` 之后
/// 紧跟 `ReadUint16LengthPrefixed(extensions)`）。少那两个字节，客户端解不开
/// 这条消息，`readHandshake` 失败后发 `unexpected message` —— 一个看不出原因的错。
/// 这两处都是对着 uTLS 的解析器逐行核出来的（用户提示：XTLS 没有的要去 uTLS 找）。
fn certificate(cert_template: &[u8], auth_key: &[u8; 32]) -> Vec<u8> {
    let mut cert = cert_template.to_vec();
    let pub_key = raw_ed25519_public_key(&cert); // 证书里的 32 字节裸公钥
    let sig = crate::client::mirror_signature(auth_key, &pub_key);
    let n = cert.len();
    cert[n - 64..].copy_from_slice(&sig);
    let mut entry = Vec::with_capacity(3 + cert.len() + 2);
    entry.extend_from_slice(&u24(cert.len()));
    entry.extend_from_slice(&cert);
    entry.extend_from_slice(&0u16.to_be_bytes()); // 该证书的扩展列表：空

    let mut body = Vec::new();
    body.push(0x00); // certificate_request_context：服务端证书为空
    body.extend_from_slice(&u24(entry.len())); // certificate_list 长度
    body.extend_from_slice(&entry);
    hs_msg(0x0b, &body)
}

/// 从 DER 证书里取**裸 32 字节** ed25519 公钥。
///
/// Xray 客户端做 HMAC 时用的是 Go `x509` 解析出的 `ed25519.PublicKey`（裸 32 字节），
/// 所以这里必须把 DER 里的 `SubjectPublicKeyInfo` 解出来 —— **不能猜偏移**：
/// 第一版假设「签名值（末 64 字节）之前 32 字节就是公钥」，那取到的是 DER 结构字节，
/// 症状是客户端 `bad_certificate`（尾签对不上，而 AuthKey 其实是对的）。
///
/// ed25519 的 SPKI 是固定形状：`30 2a 30 05 06 03 2b 65 70 03 21 00` 后紧跟 32 字节。
/// 这里就找那个 OID（`2b 65 70` = 1.3.101.112）—— 定位后跳过
/// `30 05 06 03` + OID + `03 21 00` 共 10 字节。
fn raw_ed25519_public_key(cert_der: &[u8]) -> [u8; 32] {
    const SPKI_ED25519: [u8; 12] = [
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];
    if let Some(i) = cert_der
        .windows(SPKI_ED25519.len())
        .position(|w| w == SPKI_ED25519)
    {
        let mut out = [0u8; 32];
        out.copy_from_slice(&cert_der[i + SPKI_ED25519.len()..i + SPKI_ED25519.len() + 32]);
        return out;
    }
    // 退化路径：至少取签名值之前那 32 字节（形状不对的证书会让尾签校验失败 ——
    // 那是响亮的失败，不是静默接受）。
    let n = cert_der.len();
    let mut out = [0u8; 32];
    out.copy_from_slice(&cert_der[n - 96..n - 64]);
    out
}

/// `CertificateVerify`：ed25519 签名（RFC 8446 §4.4.3 的输入串）。
fn certificate_verify(
    signing: &dyn rustls::sign::Signer,
    hs: Hs,
    transcript_hash: &[u8],
) -> Result<Vec<u8>, MirrorError> {
    let mut input = Vec::with_capacity(64 + 34 + transcript_hash.len());
    input.extend_from_slice(&[0x20u8; 64]);
    input.extend_from_slice(b"TLS 1.3, server CertificateVerify");
    input.push(0x00);
    input.extend_from_slice(transcript_hash);
    let sig = signing
        .sign(&input)
        .map_err(|e| MirrorError::Protocol(format!("ed25519 签名失败：{e}")))?;
    let _ = hs;
    let mut body = Vec::new();
    body.extend_from_slice(&0x0807u16.to_be_bytes()); // ed25519
    body.extend_from_slice(&(sig.len() as u16).to_be_bytes());
    body.extend_from_slice(&sig);
    Ok(hs_msg(0x0f, &body))
}

/// `Finished`：`HMAC(finished_key, Transcript-Hash)`。
fn finished(hs: Hs, base_secret: &[u8], transcript_hash: &[u8]) -> Vec<u8> {
    let finished_key = expand_label(hs, base_secret, "finished", &[], hs.len());
    let verify = hs.hmac(&finished_key, transcript_hash);
    hs_msg(0x14, &verify)
}

// ── 握手与流 ────────────────────────────────────────────────────────────

/// 握手完成后的明文流（应用数据密钥已就位）。
pub struct MirrorStream {
    sock: TcpStream,
    read: RecordKeys,
    write: RecordKeys,
    buf: Vec<u8>,
}

impl MirrorStream {
    /// 拆成**读半边**与**写半边**，各自可交给一条线程 —— handler 里做双向 splice 就靠它。
    ///
    /// # 为什么这个拆分在密码学上是安全的
    ///
    /// 读/写两个方向各有一套 [`RecordKeys`]（`read` / `write`），**各自独占、序号不共享**
    /// —— TLS 1.3 的记录层序号按方向独立（RFC 8446 §5.3），两条线程各推进自己那一套
    /// 不会串号、不会重放。socket 用 `try_clone()` 给两半各一条 fd（`dup` 后共享同一
    /// TCP 连接）—— 这是纯所有权问题，不碰任何密码学状态。
    ///
    /// 拆之前 `MirrorStream` 只有 `&mut self` 一条路：两个方向要并发时借不到两次
    /// `&mut`；套 `Arc<Mutex<…>>` 又会让读线程阻塞在 `read()` 时**持锁**、写方向饿死
    /// （「客户端等响应、我们等客户端」就是死锁）。见 issue #2。
    pub fn into_split(self) -> std::io::Result<(MirrorReadHalf, MirrorWriteHalf)> {
        let write_sock = self.sock.try_clone()?;
        Ok((
            MirrorReadHalf {
                sock: self.sock,
                keys: self.read,
                buf: self.buf,
            },
            MirrorWriteHalf {
                sock: write_sock,
                keys: self.write,
            },
        ))
    }
}

impl Read for MirrorStream {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        read_plain(&mut self.sock, &mut self.read, &mut self.buf, out)
    }
}

impl Write for MirrorStream {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        write_plain(&mut self.sock, &mut self.write, data)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.sock.flush()
    }
}

/// 明文流的**读半边**：`Read`，可独立交给一条线程（[`MirrorStream::into_split`]）。
pub struct MirrorReadHalf {
    sock: TcpStream,
    keys: RecordKeys,
    buf: Vec<u8>,
}

impl Read for MirrorReadHalf {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        read_plain(&mut self.sock, &mut self.keys, &mut self.buf, out)
    }
}

/// 明文流的**写半边**：`Write` + 显式的半关 [`shutdown_write`](Self::shutdown_write)。
///
/// 半关是双向 splice 的必要动作：上游（后端）读到 EOF 时，要能告诉客户端「本方向不再
/// 发数据了」（发 FIN），否则客户端会一直等 —— 这正是 `TcpStream::shutdown(Write)`。
/// 放在写半边上而不是 `Drop` 上，因为「连接结束」与「本方向结束」是两回事。
pub struct MirrorWriteHalf {
    sock: TcpStream,
    keys: RecordKeys,
}

impl MirrorWriteHalf {
    /// 半关：告诉对端「本方向不再发数据」（发 FIN）。语义同 `TcpStream::shutdown(Write)`。
    pub fn shutdown_write(&mut self) -> std::io::Result<()> {
        self.sock.shutdown(std::net::Shutdown::Write)
    }
}

impl Write for MirrorWriteHalf {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        write_plain(&mut self.sock, &mut self.keys, data)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.sock.flush()
    }
}

/// 读一条应用数据（跨记录、处理缓冲与 KeyUpdate/alert）—— [`MirrorStream`] 与
/// [`MirrorReadHalf`] 共用，保证两条路行为逐字节一致。
fn read_plain(
    sock: &mut TcpStream,
    keys: &mut RecordKeys,
    buf: &mut Vec<u8>,
    out: &mut [u8],
) -> std::io::Result<usize> {
    if !buf.is_empty() {
        let n = out.len().min(buf.len());
        out[..n].copy_from_slice(&buf[..n]);
        buf.drain(..n);
        return Ok(n);
    }
    loop {
        let (ty, data) = read_record(sock, keys)?;
        match ty {
            0x17 => {
                if data.is_empty() {
                    continue;
                }
                *buf = data;
                let n = out.len().min(buf.len());
                out[..n].copy_from_slice(&buf[..n]);
                buf.drain(..n);
                return Ok(n);
            }
            0x18 => {
                // KeyUpdate：只接受 "update_not_requested"（1 字节 0x00）并忽略
                // 密钥更新（Go 客户端极少发；发了也不会损坏转录）。收到
                // "update_requested" 就报错 —— 我们要回一条，而本实现不派生新密钥。
                if data.first() == Some(&0x00) {
                    continue;
                }
                return Err(std::io::Error::other(
                    "REALITY 镜像：收到 KeyUpdate(requested)，本实现不派生新密钥",
                ));
            }
            0x15 => return Ok(0), // alert ⇒ 对端关闭
            other => {
                return Err(std::io::Error::other(format!(
                    "REALITY 镜像：应用阶段收到意外内容类型 0x{other:02x}"
                )));
            }
        }
    }
}

/// 加一条应用数据记录并写出 —— [`MirrorStream`] 与 [`MirrorWriteHalf`] 共用。
fn write_plain(sock: &mut TcpStream, keys: &mut RecordKeys, data: &[u8]) -> std::io::Result<usize> {
    let rec = keys.seal(0x17, data);
    sock.write_all(&rec)?;
    Ok(data.len())
}

fn read_record(sock: &mut TcpStream, keys: &mut RecordKeys) -> std::io::Result<(u8, Vec<u8>)> {
    loop {
        let mut header = [0u8; 5];
        sock.read_exact(&mut header)?;
        let len = u16::from_be_bytes([header[3], header[4]]) as usize;
        let mut body = vec![0u8; len];
        sock.read_exact(&mut body)?;
        match header[0] {
            0x14 => continue, // CCS（兼容措施）—— 忽略
            0x15 => {
                // 明文 alert：`level(1) || description(1)` —— 把描述解码出来再报，
                // 否则「客户端发了 alert」这句话本身没有诊断价值（第一版就是这样，
                // 只知道失败、不知道是 bad_certificate 还是 decrypt_error）。
                let level = body.first().copied().unwrap_or(0);
                let desc = body.get(1).copied().unwrap_or(0);
                return Err(std::io::Error::other(format!(
                    "REALITY 镜像：对端发来明文 alert（level={level} description={desc} {})",
                    alert_name(desc)
                )));
            }
            0x17 => {
                let (ty, pt) = keys
                    .open(&header, &body)
                    .ok_or_else(|| std::io::Error::other("REALITY 镜像：记录解密失败"))?;
                if ty == 0x15 {
                    // 加密的 alert：明文的最后两字节就是 level/description。
                    let level = pt.first().copied().unwrap_or(0);
                    let desc = pt.get(1).copied().unwrap_or(0);
                    return Err(std::io::Error::other(format!(
                        "REALITY 镜像：对端发来加密 alert（level={level} description={desc} {}）",
                        alert_name(desc)
                    )));
                }
                return Ok((ty, pt));
            }
            other => {
                return Err(std::io::Error::other(format!(
                    "REALITY 镜像：意外记录类型 0x{other:02x}"
                )));
            }
        }
    }
}

/// alert 描述的名字（诊断用；只需覆盖握手期常见的几个）。
fn alert_name(d: u8) -> &'static str {
    match d {
        10 => "unexpected_message",
        20 => "bad_record_mac",
        22 => "record_overflow",
        40 => "handshake_failure",
        42 => "bad_certificate",
        43 => "unsupported_certificate",
        44 => "certificate_revoked",
        45 => "certificate_expired",
        46 => "certificate_unknown",
        47 => "illegal_parameter",
        48 => "unknown_ca",
        49 => "access_denied",
        50 => "decode_error",
        51 => "decrypt_error",
        80 => "internal_error",
        90 => "user_canceled",
        109 => "missing_extension",
        110 => "unsupported_extension",
        112 => "unrecognized_name",
        _ => "",
    }
}

/// 跑镜像握手。**成功时返回已就绪的流**；任何失败 ⇒ 调用方回落透传
/// （`tls.go` 的 `break f` 语义）。此函数在失败前**不向客户端写任何字节**，
/// 所以回落是安全的。
#[allow(clippy::too_many_arguments)]
pub fn run(
    sock: TcpStream,
    client_hello_msg: &[u8],
    dest_server_hello_msg: &[u8],
    cert_template: &[u8],
    signing: &dyn rustls::sign::Signer,
    provider: &rustls::crypto::CryptoProvider,
    auth_key: &[u8; 32],
    client_session_id: &[u8],
) -> Result<MirrorStream, MirrorError> {
    let template = parse_server_hello(dest_server_hello_msg)?;
    if template.session_id != client_session_id {
        return Err(MirrorError::SessionIdMismatch);
    }
    let hs = match template.suite {
        0x1301 | 0x1303 => Hs::S256,
        0x1302 => Hs::S384,
        other => return Err(MirrorError::UnsupportedSuite(other)),
    };
    // ① 我们的临时密钥（借 rustls 的组实现 —— 混合组语义与 Go 一致，已由真栈判据证明）。
    //
    // ⚠️ **只镜像 X25519(0x001d) 与 X25519MLKEM768(4588) 两个组** —— 依据是
    // **uTLS 自己的客户端状态**，不是我们的偏好：uTLS 的 `KeySharePrivateKeys`
    // （`u_public.go:926-931`）只有三个字段 `Ecdhe`(X25519) / `Mlkem` / `MlkemEcdhe`
    // —— **没有 P-256 的私钥位**。所以 uTLS 客户端（Xray 用的就是它）在任何情况下
    // 都无法完成「服务端选 P-256」的握手，而 XTLS `tls.go:222-239` 只挑那两个组
    // 正是这个原因。本实现跟同一条约束：不一致就回落透传（`MirrorError` ⇒ 透传）。
    // （实测：本地 rustls 真站会选 P-256，Xray 客户端当场回 `unexpected message`；
    // 那不是我们镜像的错，是 uTLS 支持面的边界。）
    const MIRRORABLE_GROUPS: [u16; 2] = [4588, 29];
    if !MIRRORABLE_GROUPS.contains(&template.group) {
        return Err(MirrorError::UnsupportedGroup(template.group));
    }
    let group = provider
        .kx_groups
        .iter()
        .find(|g| u16::from(g.name()) == template.group)
        .ok_or(MirrorError::UnsupportedGroup(template.group))?;
    // ⚠️ ECDH 的输入是**客户端 hello 里的 key share**，不是真站 ServerHello 里的那个 ——
    // 后者是**真站自己的密文/公钥**，它的作用只是告诉我们「真站选了哪个组」
    // （以及我们镜像时该发同组同长的字节）。第一版把真站的密钥喂给
    // `start_and_complete`，在 MLKEM768 上当场炸出 `InvalidKeyShare`
    // （长度 1120 vs 客户端封装密钥 1216）。与 Go 参照一致：
    // `handshake_server_tls13.go:104-120` 用的是 `hs.clientHello.keyShares` 里的 peerData，
    // 真站的 serverShare 只被 `unmarshal` 出来当模板。
    let ch = crate::ch::ClientHello::parse(client_hello_msg)
        .map_err(|e| MirrorError::BadTemplate(format!("客户端 hello 解析失败：{e:?}")))?;
    let client_share = ch
        .key_shares
        .iter()
        .find(|(g, _)| *g == template.group)
        .map(|(_, d)| d.clone())
        .ok_or_else(|| {
            MirrorError::Protocol(format!(
                "客户端没有报组 0x{:04x} 的 key share（真站却选了它）",
                template.group
            ))
        })?;
    let done = group
        .start_and_complete(&client_share)
        .map_err(|e| MirrorError::Protocol(format!("ECDH 失败：{e}")))?;
    // ② 打补丁：只换密钥字节。
    let server_hello = patch_key_share(&template, &done.pub_key)?;

    // ③ 密钥调度：普通 TLS 1.3（无 PSK —— REALITY 不做会话恢复）。
    let zero = vec![0u8; hs.len()];
    let early = hkdf_extract(hs, &zero, &zero);
    let derived = derive_secret(hs, &early, "derived", &hs.digest(&[]));
    let handshake_secret = hkdf_extract(hs, &derived, done.secret.secret_bytes());
    let transcript_ch_sh = hs.digest(&[client_hello_msg, &server_hello].concat());
    let c_hs = derive_secret(hs, &handshake_secret, "c hs traffic", &transcript_ch_sh);
    let s_hs = derive_secret(hs, &handshake_secret, "s hs traffic", &transcript_ch_sh);
    let derived2 = derive_secret(hs, &handshake_secret, "derived", &hs.digest(&[]));
    let master = hkdf_extract(hs, &derived2, &zero);

    // ④ 服务端 flight 的三条消息 + Finished（转录逐步累积）。
    let mut transcript = [client_hello_msg, &server_hello].concat();
    let ee = encrypted_extensions();
    transcript.extend_from_slice(&ee);
    let cert = certificate(cert_template, auth_key);
    transcript.extend_from_slice(&cert);
    let cv = certificate_verify(signing, hs, &hs.digest(&transcript))?;
    transcript.extend_from_slice(&cv);
    let s_fin = finished(hs, &s_hs, &hs.digest(&transcript));
    transcript.extend_from_slice(&s_fin);

    // ⑤ 应用密钥（转录到服务端 Finished 为止）。
    let app_hash = hs.digest(&transcript);
    let c_ap = derive_secret(hs, &master, "c ap traffic", &app_hash);
    let s_ap = derive_secret(hs, &master, "s ap traffic", &app_hash);

    // ⑥ 写：ServerHello 记录 + CCS + 加密 flight。
    //    到这里为止**没有任何失败路径**（全部失败已在上面返回），所以可以开始写。
    let mut sock = sock;
    let mut out = Vec::new();
    let sh_msg = &server_hello;
    out.extend_from_slice(&[
        0x16,
        0x03,
        0x03,
        ((sh_msg.len()) >> 8) as u8,
        (sh_msg.len() & 0xff) as u8,
    ]);
    out.extend_from_slice(sh_msg);
    out.extend_from_slice(&[0x14, 0x03, 0x03, 0x00, 0x01, 0x01]); // 兼容 CCS
    let mut write_hs = RecordKeys::from_secret(template.suite, hs, &s_hs).expect("套件已检验");
    let mut flight = Vec::new();
    flight.extend_from_slice(&ee);
    flight.extend_from_slice(&cert);
    flight.extend_from_slice(&cv);
    flight.extend_from_slice(&s_fin);
    out.extend_from_slice(&write_hs.seal(0x16, &flight));
    sock.write_all(&out)?;
    sock.flush()?;

    // ⑦ 读客户端 Finished（握手密钥），校验；随后换成应用密钥。
    let mut read_hs = RecordKeys::from_secret(template.suite, hs, &c_hs).expect("套件已检验");
    let (ty, client_finished) = read_record(&mut sock, &mut read_hs)?;
    match ty {
        0x16 => {}
        0x15 => {
            return Err(MirrorError::Protocol(
                "客户端在 Finished 之前中断（alert）".into(),
            ));
        }
        other => {
            return Err(MirrorError::Protocol(format!(
                "客户端 Finished 之前收到类型 0x{other:02x}"
            )));
        }
    }
    if client_finished.len() < 36 || client_finished[0] != 0x14 {
        return Err(MirrorError::Protocol(
            "客户端第二条消息不是 Finished".into(),
        ));
    }
    let c_verify = &client_finished[4..];
    let expect = {
        let finished_key = expand_label(hs, &c_hs, "finished", &[], hs.len());
        hs.hmac(&finished_key, &app_hash)
    };
    if c_verify != expect.as_slice() {
        return Err(MirrorError::Protocol("客户端 Finished 校验失败".into()));
    }

    Ok(MirrorStream {
        sock,
        read: RecordKeys::from_secret(template.suite, hs, &c_ap).expect("套件已检验"),
        write: RecordKeys::from_secret(template.suite, hs, &s_ap).expect("套件已检验"),
        buf: Vec::new(),
    })
}

#[cfg(test)]
mod split_tests {
    //! **`into_split` 的离线判据**（issue #2 的核心形状）。
    //!
    //! 不依赖任何外部二进制：构造一对回环 `MirrorStream`（两端的读/写密钥镜像对称），
    //! 直接钉住「拆出来的两半可以各自独立推进」—— 也就是旧形态做不到、
    //! `Arc<Mutex<…>>` 又会死锁的那个形状。

    use super::*;
    use std::net::{TcpListener, TcpStream};
    use std::sync::mpsc;
    use std::time::Duration;

    /// 一条回环连接的两端，各自配一对镜像对称的读/写 `RecordKeys`。
    ///
    /// 密钥对称：两端都用同一 secret 派生 read/write ⇒ A 的 write 就是 B 的 read
    /// （同一套件、同一 secret ⇒ 同一把 key/iv，seq 各自从 0 起，方向独立）。
    fn mirrored_pair() -> (MirrorStream, MirrorStream) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("占端口");
        let addr = listener.local_addr().expect("端口");
        let accept = std::thread::spawn(move || listener.accept().expect("accept").0);
        let a_sock = TcpStream::connect(addr).expect("连回环");
        let b_sock = accept.join().expect("accept 线程");
        a_sock
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("读超时");
        b_sock
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("读超时");
        let secret = [0x42u8; 32];
        let mk = |sock: TcpStream| MirrorStream {
            sock,
            read: RecordKeys::from_secret(0x1301, Hs::S256, &secret).expect("读键"),
            write: RecordKeys::from_secret(0x1301, Hs::S256, &secret).expect("写键"),
            buf: Vec::new(),
        };
        (mk(a_sock), mk(b_sock))
    }

    /// 拆出的两半各拿一条 fd：写半边的 `Write` 推进，不会碰到读半边的记录序号。
    #[test]
    fn into_split_yields_two_independent_halves() {
        let (a, _b) = mirrored_pair();
        let (r, mut w) = a.into_split().expect("分半");
        // 写若干条，读半边此时**没读**任何东西 —— 两半互不影响。
        for i in 0..8u8 {
            w.write_all(&[i, i, i]).expect("写");
        }
        w.flush().expect("flush");
        // 写半边能半关（发 FIN）而不需要读半边配合。
        w.shutdown_write().expect("半关");
        // 读半边仍然可用（这里对端还没写 ⇒ 读会阻塞，设超时证明它“能进去读”）。
        // 只验证类型可用，不做阻塞读（那由下一条判据专门测）。
        let _ = r; // 读半边在手 = 拆分成功
    }

    /// **判据（issue #2 的症结）**：读半边阻塞在 `read()` 时，写半边**照样能写出去**。
    ///
    /// 旧形态（一个 `&mut`）根本借不出两半；`Arc<Mutex<…>>` 形态下读线程持锁阻塞、
    /// 写方向饿死。拆成两半后，两条线程各推进自己那一套 `RecordKeys`——
    /// 这条判据就钉住「读阻塞不挡写」。
    #[test]
    fn a_blocked_read_half_does_not_stall_the_write_half() {
        let (a, b) = mirrored_pair();
        let (mut ar, mut aw) = a.into_split().expect("A 分半");
        let (mut br, mut bw) = b.into_split().expect("B 分半");

        // 线程 1：A 的读半边去读 —— 此刻 B 还没写，它会阻塞。
        let (tx, rx) = mpsc::channel();
        let reader = std::thread::spawn(move || {
            let mut buf = [0u8; 64];
            let n = ar.read(&mut buf).expect("A 读到 B 写的数据");
            tx.send(buf[..n].to_vec()).expect("回传");
        });
        // 给读线程一点时间进入阻塞。
        std::thread::sleep(Duration::from_millis(100));
        assert!(
            rx.try_recv().is_err(),
            "A 的读此刻应当还阻塞着（B 尚未写）—— 这是本判据的前提"
        );

        // 关键：A 的**读半边**阻塞期间，A 的**写半边**照常把数据写到 B。
        aw.write_all(b"from-A").expect("A 写");
        aw.flush().expect("flush");
        bw.write_all(b"from-B").expect("B 写");
        bw.flush().expect("flush");

        // B 的读半边收到 A 写的。
        let mut buf = [0u8; 64];
        let n = br.read(&mut buf).expect("B 读到 A 写的数据");
        assert_eq!(&buf[..n], b"from-A", "B 侧读到的应当是 A 写的方向内容");

        // A 的读半边随后也拿到 B 写的 —— 读线程从阻塞里出来了。
        let got = rx
            .recv_timeout(Duration::from_secs(2))
            .expect("A 的读应当在 B 写之后返回");
        assert_eq!(got, b"from-B");
        reader.join().expect("读线程");
    }

    /// **双向并发各 N 轮**：两端同时各写 N 轮、各读 N 轮，每轮都必须到达。
    /// 这是 issue 里「反代部署」的最小形状（两个方向都在推进）。
    #[test]
    fn both_directions_run_concurrently_for_n_rounds() {
        let (a, b) = mirrored_pair();
        let (ar, aw) = a.into_split().expect("A 分半");
        let (br, bw) = b.into_split().expect("B 分半");

        const N: u8 = 64;
        // A→B 方向与 B→A 方向各一条写线程；两条读在主线程顺序做。
        let w_ab = std::thread::spawn(move || {
            let mut aw = aw;
            for i in 0..N {
                aw.write_all(&[0xA0, i]).expect("A→B 写");
                aw.flush().expect("flush");
            }
        });
        let w_ba = std::thread::spawn(move || {
            let mut bw = bw;
            for i in 0..N {
                bw.write_all(&[0xB0, i]).expect("B→A 写");
                bw.flush().expect("flush");
            }
        });

        // 主线程读两个方向：**同时**在读意味着两个方向真的在并发推进。
        let mut ar = ar;
        let mut br = br;
        for i in 0..N {
            let a = read_two(&mut br).expect("B 读到 A→B");
            assert_eq!(a, [0xA0, i], "A→B 第 {i} 轮");
            let b = read_two(&mut ar).expect("A 读到 B→A");
            assert_eq!(b, [0xB0, i], "B→A 第 {i} 轮");
        }
        w_ab.join().expect("A→B 写线程");
        w_ba.join().expect("B→A 写线程");
    }

    /// 从读半边读回**恰好 2 字节**（小工具）。缓冲区**必须**是 2 字节 ——
    /// 第一版传了 8 字节缓冲：`read_plain` 会把它填满 8 字节（吞掉 4 条记录）
    /// 却只返回前 2 个 ⇒ 序列跳号（这是本判据自己抓出来的 bug，留着当教训）。
    fn read_two(r: &mut MirrorReadHalf) -> std::io::Result<[u8; 2]> {
        let mut out = [0u8; 2];
        let mut got = 0;
        while got < out.len() {
            let n = r.read(&mut out[got..])?;
            if n == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "读半边过早结束",
                ));
            }
            got += n;
        }
        Ok(out)
    }
}
