//! 一台**本地** TLS 1.3 服务端（rustls），给引擎的联网类测试用。
//!
//! # 为什么需要它
//!
//! 之前只有两条「真握手」的判据，都不够用：
//!
//! - 打 `tls.browserleaks.com`：能证明「字节真的上线了、服务器所见与我们一致」，
//!   但**服务器不可控** —— 没法让它要求特定组（逼出 HelloRetryRequest），
//!   也没法让它发 session ticket（验 resumption）；
//! - 手写的假服务端（`hello_retry_e2e.rs`）：可控，但**握手完不成**，
//!   所以它只能证「第二飞发出去了」，证不了「这条连接真的完成了、真的复用了会话」。
//!
//! 这台把两个缺口一起补上：完全离线的 loopback 服务端，会话可被断言
//! （`handshake_kind() == Resumed` 是**服务端**说的，不是我们自报的）。
//!
//! # 凭据
//!
//! 证书与私钥是**生成好放进仓库**的（`tests/fixtures/server-cert.der` /
//! `server-key.pk8.der`，CN=localhost，SAN 含 `localhost`/`example.com`/`127.0.0.1`，
//! 有效期到 2126）。复现命令记在 `fixtures/README.md` —— 它是测试凭据，不是秘密，
//! 但也**只**用于本地测试：私钥在仓库里，任何真实用途都必须换新的。
#![allow(dead_code)] // 各测试文件各自引用这个模块，用不到的不该报警告。

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::server::{ServerConfig, ServerConnection};
use rustls::{ClientConfig, SignatureScheme};

pub const CERT_DER: &[u8] = include_bytes!("../fixtures/server-cert.der");
pub const KEY_PKCS8_DER: &[u8] = include_bytes!("../fixtures/server-key.pk8.der");

fn cert() -> CertificateDer<'static> {
    CertificateDer::from(CERT_DER.to_vec())
}

fn key() -> PrivateKeyDer<'static> {
    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(KEY_PKCS8_DER.to_vec()))
}

/// 服务端配置。`tickets` 为真时开 session ticket（TLS 1.3 的 resumption 必需）。
///
/// `only_groups` 用来**逼出 HelloRetryRequest**：服务端只认这些组时，只要客户端的
/// `key_share` 里没有它，服务端就会回 HRR 要求它（这是 RFC 8446 §4.1.4 的正常行为，
/// 不是错误注入）。
pub fn server_config(
    tickets: bool,
    only_groups: Option<Vec<rustls::NamedGroup>>,
) -> Arc<ServerConfig> {
    let provider = match only_groups {
        None => Arc::new(rustls::crypto::aws_lc_rs::default_provider()),
        Some(groups) => {
            let mut p = rustls::crypto::aws_lc_rs::default_provider();
            p.kx_groups.retain(|g| groups.contains(&g.name()));
            Arc::new(p)
        }
    };

    let mut config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3 可用")
        .with_no_client_auth()
        .with_single_cert(vec![cert()], key())
        .expect("证书与私钥配套");
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    if tickets {
        config.ticketer = rustls::crypto::aws_lc_rs::Ticketer::new().expect("ticketer");
        config.send_tls13_tickets = 2;
    }
    Arc::new(config)
}

/// 客户端配置：信任仓库里那份自签证书，其余按 `config` 的意图。
///
/// 这里**不复用** `utls_engine::client_config`（它锚在 `webpki-roots` 上）：
/// 本地服务端用的是自签证书，锚必须换成它，否则握手会死在验签上 ——
/// 而那不是本条测试要证的事。
pub fn client_config_with_roots(
    fingerprint: utls_engine::FingerprintClient,
    alpn: Vec<Vec<u8>>,
) -> ClientConfig {
    client_config_with_roots_and_store(fingerprint, alpn, None)
}

/// 同上，但**完全跳过证书链校验**（`AcceptAnySignature`）。
///
/// 为什么默认要跳过：这份自签证书是 `openssl req -x509` 生成的，它带 `CA:TRUE`，
/// 而 webpki 见到「CA 证书当叶子用」会报 `CaUsedAsEndEntity`。实测症状是
/// **握手在收到服务端 flight 之后才失败** —— 于是客户端永远读不到
/// `NewSessionTicket`，会话存储是空的，复用测试会以「服务端说 Full」的形式失败，
/// 看起来像 PSK 接线错了（踩过）。把证书换成正牌 EE 也能绕过，但那是**测试凭据的
/// 形状问题，不是被验的机制**：这些测试要证的是 HRR / PSK 的接线，不是 PKI。
///
/// 用 root store 的那条路仍然保留（`client_config_with_roots`），需要验证书链时用它。
///
/// 同上，外加一个**跨连接共享**的会话存储 —— 复用的前提。
///
/// # ⚠️ 复用的真正前提是**验签器指针相同**，不是「共用一个 store」
///
/// rustls 用 `Weak::ptr_eq` 比较会话里存的验签器与当前 config 的验签器
/// （`persist.rs::compatible_config`）：**指针不同就静默拒绝复用**，
/// 而那张票已经被 `take_tls13_ticket` 拿走了（票没了、也没复用）。
/// 所以「每条连接新建一个 config」的写法**永远复用不了**，症状是服务端说 `Full` ——
/// 本仓实测踩到，查了很久（看起来像 PSK 接线错了）。
///
/// 结论：**两条连接必须共用一个 `Arc<ClientConfig>`**。需要不同 spec 时用
/// [`shared_verifier`] 把同一个验签器对象注入不同的 config。
pub fn client_config_with_roots_and_store(
    fingerprint: utls_engine::FingerprintClient,
    alpn: Vec<Vec<u8>>,
    store: Option<Arc<dyn rustls::client::ClientSessionStore>>,
) -> ClientConfig {
    let mut config = ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .expect("TLS 1.3 可用")
    .dangerous()
    .with_custom_certificate_verifier(Arc::new(AcceptAnySignature))
    .with_no_client_auth();
    config.alpn_protocols = alpn;
    if let Some(store) = store {
        config.resumption = rustls::client::Resumption::store(store);
    }
    config.fork_client_hello = Some(Arc::new(fingerprint));
    config
}

/// 一个**自己记账**的会话存储（测试替身）。
///
/// 为什么不用 rustls 的 `ClientSessionMemoryCache`：会话存储的失败是**静默**的 ——
/// 实测踩到「客户端收到 2 张 ticket，库里却是空的，且没有任何错误」，于是复用测试
/// 以「服务端说 Full」的形式失败，看起来像 PSK 接线错了。这个替身把
/// insert/take 都记下来，断言就能落在**存储这一层**上。
///
/// 它只实现复用要用的那两条（TLS 1.3 ticket）；TLS 1.2 与 kx_hint 一律空。
#[derive(Debug, Default)]
pub struct RecordingStore {
    tickets: Mutex<Vec<rustls::client::Tls13ClientSessionValue>>,
    pub inserts: Mutex<usize>,
    pub takes: Mutex<Vec<bool>>,
}

impl RecordingStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// 库里还有票吗。
    pub fn len(&self) -> usize {
        self.tickets.lock().expect("锁").len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn insert_count(&self) -> usize {
        *self.inserts.lock().expect("锁")
    }
}

impl rustls::client::ClientSessionStore for RecordingStore {
    fn set_kx_hint(&self, _: rustls::pki_types::ServerName<'static>, _: rustls::NamedGroup) {}
    fn kx_hint(&self, _: &rustls::pki_types::ServerName<'_>) -> Option<rustls::NamedGroup> {
        None
    }
    fn set_tls12_session(
        &self,
        _: rustls::pki_types::ServerName<'static>,
        _: rustls::client::Tls12ClientSessionValue,
    ) {
    }
    fn tls12_session(
        &self,
        _: &rustls::pki_types::ServerName<'_>,
    ) -> Option<rustls::client::Tls12ClientSessionValue> {
        None
    }
    fn remove_tls12_session(&self, _: &rustls::pki_types::ServerName<'_>) {}
    fn insert_tls13_ticket(
        &self,
        _: rustls::pki_types::ServerName<'static>,
        value: rustls::client::Tls13ClientSessionValue,
    ) {
        *self.inserts.lock().expect("锁") += 1;
        self.tickets.lock().expect("锁").push(value);
    }
    fn take_tls13_ticket(
        &self,
        _: &rustls::pki_types::ServerName<'_>,
    ) -> Option<rustls::client::Tls13ClientSessionValue> {
        let got = self.tickets.lock().expect("锁").pop();
        self.takes.lock().expect("锁").push(got.is_some());
        got
    }
}

/// 把一条客户端连接跑到「握手完成 **且** 会话票据读完」。
///
/// ⚠️ 为什么不能「握手一完成就停」：TLS 1.3 的 `NewSessionTicket` 是**握手之后**
/// 才发的，而客户端只在处理那条消息时才会把会话存进 `ClientSessionStore`。
/// 于是「握手完成即 break」的写法会让存储永远是空的 —— 复用测试会以
/// 「服务端说 Full」的形式失败，看起来像 PSK 接线错了（踩过）。
///
/// 读超时是必需的：握手完成后服务端可能暂时没有数据可发，而 socket 是阻塞的 ——
/// 没有超时就会一直等下去（挂测试）。超时在握手阶段是错误（`?` 传出去），
/// 在握手之后的收票据阶段是**预期**（忽略）。
pub fn drive_client(
    conn: &mut rustls::ClientConnection,
    sock: &mut std::net::TcpStream,
) -> Result<(), std::io::Error> {
    sock.set_read_timeout(Some(std::time::Duration::from_millis(500)))
        .expect("设读超时");
    while conn.is_handshaking() {
        // `complete_io` 的 io 错误在握手阶段是**真错误**（超时/连接断），传出去。
        conn.complete_io(sock)
            .map_err(|e| std::io::Error::other(e.to_string()))?;
    }
    // 收 NewSessionTicket（最多两轮，超时即停）。
    // 读超时是预期的（服务端可能已经写完、暂时没数据）；**其它**错误必须说出来 ——
    // 静默吞掉会让「票据收到了但没存进 store」这种失败变得无从查起（踩过）。
    for _ in 0..2 {
        match conn.complete_io(sock) {
            Ok(_) => {}
            Err(e) if is_timeout(&e) => break,
            Err(e) => {
                eprintln!("（握手已完成，收票据时出错）{e}");
                break;
            }
        }
    }
    Ok(())
}

/// 读超时在 rustls 里被包成 `Error::Io`（或直接是 io 错误）—— 只有超时才该被静默。
fn is_timeout<E: std::fmt::Display>(e: &E) -> bool {
    let text = e.to_string();
    text.contains("timed out") || text.contains("WouldBlock") || text.contains("os error 11")
}

/// 一次服务端会话的结果 —— 断言要用的全部证据。
#[derive(Debug, Clone, Default)]
pub struct Served {
    /// **服务端自己**判断的握手种类：`Resumed` 才是真的复用了会话。
    /// （客户端自报「我复用了」不算证据 —— 那可能只是它把 PSK 发出去了、服务端没认。）
    pub resumed: bool,
    /// 服务端判断的握手种类。`FullWithHelloRetryRequest` 就是「真的回了一次 HRR」——
    /// 这个信号比「我们自己数了几条 ClientHello」强，因为它是**对端**说的。
    pub handshake_kind: Option<rustls::HandshakeKind>,
    pub version: Option<rustls::ProtocolVersion>,
    pub alpn: Option<Vec<u8>>,
    /// 收到的**全部** ClientHello（逐字节，含 5 字节记录头），按到达顺序。
    ///
    /// 为什么是复数：走 HRR 的连接有**两条** ClientHello，而「第二条到底发了什么」
    /// 正是 HRR 相关判据要验的东西（第一条只说了一半）。只留第一条会让
    /// 「第二飞的 binder 重算了吗」这类断言无从下手 —— 实测踩到过。
    pub client_hellos: Vec<Vec<u8>>,
    /// 第一条（等价于 `client_hellos[0]`，保留它让常见断言短一点）。
    pub client_hello: Vec<u8>,
}

/// 把服务端跑起来，接受 `n` 条连接，返回监听地址与「收结果的句柄」。
///
/// 客户端连 `addr`；`n` 条都结束后 `join()` 得到每条连接的结果。
pub fn spawn_server(
    config: Arc<ServerConfig>,
    n: usize,
) -> (std::net::SocketAddr, thread::JoinHandle<Vec<Served>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("绑定回环");
    let addr = listener.local_addr().expect("取地址");
    let handle = thread::spawn(move || {
        let mut out = Vec::new();
        for _ in 0..n {
            let (sock, _) = listener.accept().expect("accept");
            // 读超时：握手失败（例如客户端因 ECH 被拒而中止）时，握手之后那一轮
            // `complete_io` 会一直等一个永远不会来的字节，`join()` 于是挂住整条测试。
            // loopback 上 2 秒足够任何正常握手用它。
            sock.set_read_timeout(Some(std::time::Duration::from_secs(2)))
                .expect("设读超时");
            let mut tee = Tee::new(sock);
            let mut conn = ServerConnection::new(config.clone()).expect("建服务端连接");
            // 握手；完事后再来一轮，把 NewSessionTicket 刷出去（TLS 1.3 的 ticket
            // 是在握手之后发的，`is_handshaking()` 已经是 false 了）。
            while conn.is_handshaking() {
                if conn.complete_io(&mut tee).is_err() {
                    break;
                }
            }
            let _ = conn.complete_io(&mut tee);
            let hellos = tee.client_hellos();
            out.push(Served {
                resumed: conn.handshake_kind() == Some(rustls::HandshakeKind::Resumed),
                handshake_kind: conn.handshake_kind(),
                version: conn.protocol_version(),
                alpn: conn.alpn_protocol().map(|p| p.to_vec()),
                client_hello: hellos.first().cloned().unwrap_or_default(),
                client_hellos: hellos,
            });
        }
        out
    });
    (addr, handle)
}

/// 一个把客户端发来的 **ClientHello 记录**全部记下来的透明包装。
///
/// 为什么要它：rustls 的服务端不暴露收到的原始字节，而「我们发出去的到底是不是
/// 我们以为的那条」是本项目所有对账的基础。`read` 可能分批返回，所以要按记录头里的
/// 长度**攒满**再记，而不是拿第一次 `read` 的片段当一条记录（踩过：在 517 字节的
/// hello 上偶尔只拿到几十字节）。CCS 之类的非握手记录直接跳过。
struct Tee {
    inner: TcpStream,
    pending: Vec<u8>,
    hellos: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl Tee {
    fn new(inner: TcpStream) -> Self {
        Tee {
            inner,
            pending: Vec::new(),
            hellos: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn client_hellos(&self) -> Vec<Vec<u8>> {
        self.hellos.lock().expect("锁").clone()
    }

    /// 把攒下的字节里能切出的完整记录都处理掉。
    fn drain(&mut self) {
        loop {
            if self.pending.len() < 5 {
                return;
            }
            let len = u16::from_be_bytes([self.pending[3], self.pending[4]]) as usize;
            if self.pending.len() < 5 + len {
                return;
            }
            let record: Vec<u8> = self.pending.drain(..5 + len).collect();
            // 握手记录（0x16）且握手类型是 ClientHello（1）才是我们要的。
            if record[0] == 0x16 && record.get(5) == Some(&1) {
                self.hellos.lock().expect("锁").push(record);
            }
        }
    }
}

impl Read for Tee {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        if n == 0 {
            return Ok(0);
        }
        self.pending.extend_from_slice(&buf[..n]);
        self.drain();
        Ok(n)
    }
}

impl Write for Tee {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.inner.write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

/// 同一个验签器对象，用来在**多个 config** 之间共享（见上面那段说明）。
pub fn shared_verifier() -> Arc<AcceptAnySignature> {
    Arc::new(AcceptAnySignature)
}

/// 同上，但注入一个**外面给的**验签器 —— 想用两个不同 config 复用会话时，
/// 必须把同一个验签器 Arc 传给两边。
pub fn client_config_with_verifier(
    fingerprint: utls_engine::FingerprintClient,
    alpn: Vec<Vec<u8>>,
    verifier: Arc<AcceptAnySignature>,
    store: Option<Arc<dyn rustls::client::ClientSessionStore>>,
) -> ClientConfig {
    let mut config = ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .expect("TLS 1.3 可用")
    .dangerous()
    .with_custom_certificate_verifier(verifier)
    .with_no_client_auth();
    config.alpn_protocols = alpn;
    if let Some(store) = store {
        config.resumption = rustls::client::Resumption::store(store);
    }
    config.fork_client_hello = Some(Arc::new(fingerprint));
    config
}

/// 客户端侧「什么证书都收」的验签器：自签证书 + 本地回环，测试里够用。
///
/// 用它而不是 `client_config_with_roots` 的场合：只关心「握手能不能谈成」而不关心
/// 证书链时。**不要**在真实场景用它。
#[derive(Debug)]
pub struct AcceptAnySignature;

impl rustls::client::danger::ServerCertVerifier for AcceptAnySignature {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
        ]
    }
}

// ── ECH 测试素材 ────────────────────────────────────────────────────────────

/// X25519 + HKDF-SHA256 + AES-128-GCM 的 HPKE 实例（ECH 里最常见的那套）。
pub fn ech_hpke_suite() -> &'static dyn rustls::crypto::hpke::Hpke {
    rustls::crypto::aws_lc_rs::hpke::ALL_SUPPORTED_SUITES
        .iter()
        .copied()
        .find(|s| {
            u16::from(s.suite().kem) == 0x0020
                && u16::from(s.suite().sym.kdf_id) == 0x0001
                && u16::from(s.suite().sym.aead_id) == 0x0001
        })
        .expect("这套 HPKE 该在支持列表里")
}

/// 拼一份线上格式的 `ECHConfigList`（公钥外面给，便于测试里自己生成密钥对）。
pub fn ech_config_list(public_key: &[u8], config_id: u8, extensions: &[(u16, &[u8])]) -> Vec<u8> {
    let mut exts = Vec::new();
    for (t, data) in extensions {
        exts.extend_from_slice(&t.to_be_bytes());
        exts.extend_from_slice(&(data.len() as u16).to_be_bytes());
        exts.extend_from_slice(data);
    }
    let mut body = Vec::new();
    body.push(config_id);
    body.extend_from_slice(&0x0020u16.to_be_bytes());
    body.extend_from_slice(&(public_key.len() as u16).to_be_bytes());
    body.extend_from_slice(public_key);
    body.extend_from_slice(&4u16.to_be_bytes());
    body.extend_from_slice(&0x0001u16.to_be_bytes());
    body.extend_from_slice(&0x0001u16.to_be_bytes());
    body.push(0);
    let name = b"public.example";
    body.push(name.len() as u8);
    body.extend_from_slice(name);
    body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    body.extend_from_slice(&exts);

    let mut config = Vec::new();
    config.extend_from_slice(&0xfe0du16.to_be_bytes());
    config.extend_from_slice(&(body.len() as u16).to_be_bytes());
    config.extend_from_slice(&body);

    let mut list = Vec::new();
    list.extend_from_slice(&(config.len() as u16).to_be_bytes());
    list.extend_from_slice(&config);
    list
}
