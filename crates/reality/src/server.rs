//! **镜像服务端（可连的真实现）** —— XTLS/REALITY `tls.go` 整段的 Rust 等价物。
//!
//! # 每连接做什么（对照 `tls.go:200-430`）
//!
//! 1. 读客户端的 ClientHello（可能跨多条记录，见 [`read_first_hello`]）；
//! 2. 鉴权（[`crate::ch::decide`]，`tls.go:213-275`）；
//! 3. **无论鉴权与否都拨真站并把 hello 原样转过去**（`tls.go:172` 的 dial + 转发）
//!    —— 这是抗探测的核心：真站看到的是一次正常访问；
//! 4. 鉴权通过 ⇒ 用 rustls 完成**我们自己的** TLS 1.3 握手，证书是
//!    **一次性自签 ed25519 + HMAC(AuthKey, pub) 尾签**（`handshake_server_tls13.go:143-160`）
//!    —— 客户端据此认出「这是 REALITY 服务端」；
//!    之后明文交给调用方的 [`Handler`]（上层协议，如 VLESS）；
//! 5. 未鉴权 ⇒ 双向原样透传（`tls.go:410-425`）：客户端拿到与直连真站**逐字节相同**
//!    的握手与证书。
//!
//! # 与参照的一处**架构性差异**（如实记在这里，也记进 `questions/11`）
//!
//! 参照实现会拿**真站的 ServerHello 当模板**，只替换 `serverShare` 的密钥字节
//! （`handshake_server_tls13.go:104-120`）—— 它自己就是 TLS 栈，改起来自然。
//! 本实现跑在 rustls 上、**不 fork 服务端**，所以 ServerHello 由 rustls 生成：
//! 密码学上完全合法（客户端只验转录与证书尾签，看不到真站的 ServerHello），
//! 但**「ServerHello 与真站同形」这一层保真没有做**。要做需要给 fork 加一条
//! 服务端侧的 ClientHello/ServerHello 缝（与客户端侧的 (a) 对偶），那是一件
//! 单独立项的活 —— 记为已知差异，不假装。
//!
//! # 证书为什么可以「签名是 HMAC」
//!
//! 客户端（Xray `reality.go:109-128`）**不做**常规链验证：它取
//! `cert.PublicKey` 与 `cert.Signature`，比较 `HMAC-SHA512(AuthKey, pub) == sig`。
//! 所以服务端每连接现盖一个尾签即可 —— 而 ed25519 的 `CertificateVerify` 仍由
//! 真私钥签（证明我们持有证书对应的私钥）。两条一起，客户端才认。

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;

use crate::ch::{ClientHello as ParsedHello, RealityConfig, decide};
use crate::client::mirror_signature;
use crate::mirror::{DestRecord, split_dest_flight};
use crate::{Decision, FallbackReason};

/// 明文流的形状（鉴权成功后的上层协议）。
pub trait PlaintextStream: Read + Write + Send {}
impl<T: Read + Write + Send> PlaintextStream for T {}

/// 鉴权成功的连接信息（交给 [`Handler`]）。
#[derive(Debug, Clone)]
pub struct AuthInfo {
    pub peer: SocketAddr,
    pub server_name: Option<String>,
    pub short_id: [u8; 8],
    pub client_ver: [u8; 4],
    pub client_time: u32,
}

/// 上层协议处理器（Xray 里那是 VLESS 服务端；本 crate 只做传输，交给调用方）。
pub type Handler = Arc<dyn Fn(Box<dyn PlaintextStream>, AuthInfo) + Send + Sync>;

/// 服务端配置。
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// 鉴权参数（`tls.go` 的 `Config` 里与判定相关的那几个）。
    pub reality: RealityConfig,
    /// 真站地址（`Config.Dest` + SNI 决定的名字；测试里是本地装置）。
    pub dest: SocketAddr,
    /// ed25519 自签证书模板（DER；每连接只改**最后 64 字节**为 HMAC 尾签）。
    pub cert_template: Vec<u8>,
    /// 证书对应的 ed25519 私钥（PKCS#8 DER）—— 签 `CertificateVerify` 用。
    pub signing_key: Vec<u8>,
}

/// 服务器的运行统计 —— 判据的取证面。
#[derive(Debug, Default)]
pub struct Stats {
    pub connections: AtomicUsize,
    pub authenticated: AtomicUsize,
    pub fallback: AtomicUsize,
    /// 真站 flight 形状不合的次数（会原样透传）。
    pub dest_flight_malformed: AtomicUsize,
}

/// 一台 REALITY 服务端。
pub struct Server {
    config: ServerConfig,
    handler: Handler,
    stats: Arc<Stats>,
}

impl Server {
    pub fn new(config: ServerConfig, handler: Handler) -> Self {
        Self {
            config,
            handler,
            stats: Arc::new(Stats::default()),
        }
    }

    pub fn stats(&self) -> Arc<Stats> {
        Arc::clone(&self.stats)
    }

    /// 在 `addr` 上服务，直到进程结束（每连接一个线程 —— 判据用，不追性能）。
    pub fn serve(self: Arc<Self>, addr: SocketAddr) -> std::io::Result<()> {
        let listener = TcpListener::bind(addr)?;
        self.serve_on(listener)
    }

    /// 用调用方给的 listener 服务（测试要先知道端口）。
    pub fn serve_on(self: Arc<Self>, listener: TcpListener) -> std::io::Result<()> {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            let me = Arc::clone(&self);
            std::thread::spawn(move || {
                let _ = me.serve_connection(stream);
            });
        }
        Ok(())
    }

    /// 一条连接的全过程（`tls.go` 的 per-connection 逻辑）。
    fn serve_connection(&self, mut client: TcpStream) -> std::io::Result<()> {
        self.stats.connections.fetch_add(1, Ordering::SeqCst);
        // ① 读第一条 ClientHello（可能跨记录）。
        let (hello_record, handshake_msg) = read_first_hello(&mut client)?;
        let hello = match ParsedHello::parse(&handshake_msg) {
            Ok(h) => h,
            Err(_) => {
                // 连 ClientHello 都解析不了 ⇒ 当作未鉴权：原样透传给真站。
                self.stats.fallback.fetch_add(1, Ordering::SeqCst);
                return self.raw_proxy(client, hello_record, None);
            }
        };
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let decision = decide(&hello, &self.config.reality, now);

        // ② 无论哪条路都先拨真站、把 hello 原样转过去（抗探测）。
        //    ⚠️ 顺序与参照一致：`tls.go:172` 的 dial 在鉴权之后、握手之前。
        let mut dest = TcpStream::connect(self.config.dest)?;
        dest.write_all(&hello_record)?;
        dest.flush()?;

        match decision {
            Decision::Authenticated {
                auth_key,
                short_id,
                client_ver,
                client_time,
                ..
            } => {
                self.stats.authenticated.fetch_add(1, Ordering::SeqCst);
                // ③ 读真站的 first flight（形状校验；见模块头的架构性差异）。
                let dest_flight = read_some(&mut dest, 16 * 1024)?;
                if let Some(DestRecord::Malformed(_)) = split_dest_flight(&dest_flight)
                    .iter()
                    .find(|r| matches!(r, DestRecord::Malformed(_)))
                {
                    self.stats
                        .dest_flight_malformed
                        .fetch_add(1, Ordering::SeqCst);
                }
                // ④ 我们自己的 TLS 1.3 握手（证书现盖 HMAC 尾签）。
                let tls_config = self.per_connection_tls_config(&auth_key)?;
                let mut conn = rustls::ServerConnection::new(tls_config)
                    .map_err(|e| std::io::Error::other(format!("rustls 服务端建连接失败：{e}")))?;
                // 把已经读掉的 hello 记录重新喂进去。
                conn.read_tls(&mut hello_record.as_slice())?;
                conn.process_new_packets()
                    .map_err(|e| std::io::Error::other(format!("处理 hello 失败：{e}")))?;
                // 继续握手直到完成（后续字节从 socket 读）。
                while conn.is_handshaking() {
                    conn.complete_io(&mut client)?;
                }
                // ⑤ 明文交给上层。
                let info = AuthInfo {
                    peer: client
                        .peer_addr()
                        .unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap()),
                    server_name: hello.server_name.clone(),
                    short_id,
                    client_ver,
                    client_time,
                };
                let stream = rustls_stream(conn, client);
                (self.handler)(Box::new(stream), info);
                Ok(())
            }
            Decision::Fallback { reason } => {
                self.stats.fallback.fetch_add(1, Ordering::SeqCst);
                self.raw_proxy(client, Vec::new(), Some((dest, hello_record.len(), reason)))
            }
        }
    }

    /// 每连接的 rustls 配置：证书解析器按连接盖 HMAC 尾签。
    fn per_connection_tls_config(
        &self,
        auth_key: &[u8; 32],
    ) -> std::io::Result<Arc<rustls::ServerConfig>> {
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.config.signing_key.clone()));
        let signing = provider
            .key_provider
            .load_private_key(key)
            .map_err(|e| std::io::Error::other(format!("加载 ed25519 私钥失败：{e}")))?;
        let resolver = RealityCertResolver {
            template: self.config.cert_template.clone(),
            auth_key: *auth_key,
            signing,
        };
        let mut config = rustls::ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|e| std::io::Error::other(e.to_string()))?
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(resolver));
        // FORK(utls-rs) (j)：REALITY 的证书是 ed25519 + HMAC 尾签，而浏览器指纹
        // （Chrome 131/133）不报 Ed25519 —— Go 参照把 sigAlg 写死
        // （`handshake_server_tls13.go:165`）。这里打开同一条硬编码。
        config.fork_use_certificate_signature_scheme = true;
        // Xray 的 reality 客户端在 raw TCP 上可能不带 ALPN；带上也无害。
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        Ok(Arc::new(config))
    }

    /// 未鉴权（或 ClientHello 畸形）：把已读的字节转发给真站后双向原样透传。
    ///
    /// `pending` 是「还没写给真站的字节」：畸形路径给了整条 hello，鉴权路径给了
    /// 已经转发过的空串（真站连接已建好、hello 已发）。
    fn raw_proxy(
        &self,
        mut client: TcpStream,
        pending: Vec<u8>,
        established: Option<(TcpStream, usize, FallbackReason)>,
    ) -> std::io::Result<()> {
        let mut dest = match established {
            Some((d, _, _)) => d,
            None => {
                let mut d = TcpStream::connect(self.config.dest)?;
                d.write_all(&pending)?;
                d.flush()?;
                d
            }
        };
        let mut c2 = client.try_clone()?;
        let mut d2 = dest.try_clone()?;
        let up = std::thread::spawn(move || {
            let _ = std::io::copy(&mut client, &mut dest);
            let _ = dest.shutdown(std::net::Shutdown::Write);
        });
        let _ = std::io::copy(&mut d2, &mut c2);
        let _ = c2.shutdown(std::net::Shutdown::Write);
        let _ = up.join();
        Ok(())
    }
}

/// 每连接现盖尾签的证书解析器（`handshake_server_tls13.go:143-160` 的等价物）。
#[derive(Debug)]
struct RealityCertResolver {
    /// 证书 DER 模板：每连接复制一份，把**最后 64 字节**换成 HMAC 尾签。
    template: Vec<u8>,
    auth_key: [u8; 32],
    signing: Arc<dyn rustls::sign::SigningKey>,
}

impl ResolvesServerCert for RealityCertResolver {
    fn resolve(&self, _hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let pubkey = self.signing.public_key()?;
        // ⚠️ HMAC 的输入是**裸 ed25519 公钥（32 字节）**，不是 SPKI/DER 包装。
        // 客户端（Xray `reality.go:111`）做的是 `h.Write(pub)`，`pub` 来自
        // `certs[0].PublicKey.(ed25519.PublicKey)` —— 那是 Go 解析出的**原始**公钥。
        // 第一版传的是 rustls 的 `SubjectPublicKeyInfoDer`（44 字节），于是
        // AuthKey 两侧明明相同（实测打印过），HMAC 却对不上 ⇒ 客户端 BadCertificate。
        // SPKI 里 ed25519 公钥固定在最后 32 字节（`03 21 00 <32 字节>`）。
        let spki = pubkey.as_ref();
        let raw_pub = spki
            .get(spki.len().saturating_sub(32)..)
            .filter(|_| spki.len() >= 32)?;
        let mut der = self.template.clone();
        let sig = mirror_signature(&self.auth_key, raw_pub);
        let n = der.len();
        der[n - 64..].copy_from_slice(&sig);
        Some(Arc::new(CertifiedKey::new(
            vec![CertificateDer::from(der)],
            Arc::clone(&self.signing),
        )))
    }
}

/// rustls 连接 + TcpStream 的组合流（明文读写走 rustls，字节走 socket）。
struct TlsStream {
    conn: rustls::ServerConnection,
    sock: TcpStream,
}

impl Read for TlsStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            if self.conn.wants_read() {
                let (rd, _) = self.conn.complete_io(&mut self.sock)?;
                if rd == 0 {
                    return Ok(0);
                }
            }
            match self.conn.reader().read(buf) {
                Ok(n) => return Ok(n),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                Err(e) => return Err(e),
            }
        }
    }
}

impl Write for TlsStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let n = self.conn.writer().write(buf)?;
        self.conn.complete_io(&mut self.sock)?;
        Ok(n)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.conn.complete_io(&mut self.sock)?;
        Ok(())
    }
}

fn rustls_stream(conn: rustls::ServerConnection, sock: TcpStream) -> TlsStream {
    TlsStream { conn, sock }
}

/// 读第一条 ClientHello：可能跨记录（`tls.go:213` 的 `readClientHello`）。
///
/// 返回 `(第一条记录的全部字节, 握手消息字节)` —— 记录字节要原样转发给真站
/// （那是「真站看到一次正常访问」的载体），握手消息给鉴权解析。
pub fn read_first_hello(sock: &mut TcpStream) -> std::io::Result<(Vec<u8>, Vec<u8>)> {
    let mut record = vec![0u8; 5];
    sock.read_exact(&mut record)?;
    if record[0] != 0x16 {
        return Err(std::io::Error::other(format!(
            "第一条记录不是握手（type=0x{:02x}）",
            record[0]
        )));
    }
    let declared = u16::from_be_bytes([record[3], record[4]]) as usize;
    let mut body = vec![0u8; declared];
    sock.read_exact(&mut body)?;
    // 若握手消息跨记录，继续读后续记录（每条都带 5 字节头）。
    let hs_len = {
        if body.len() < 4 {
            return Err(std::io::Error::other("记录太短，不像 ClientHello"));
        }
        ((body[1] as usize) << 16) | ((body[2] as usize) << 8) | body[3] as usize
    };
    while body.len() < 4 + hs_len {
        let mut next = vec![0u8; 5];
        sock.read_exact(&mut next)?;
        if next[0] != 0x16 {
            return Err(std::io::Error::other("ClientHello 中途出现非握手记录"));
        }
        let n = u16::from_be_bytes([next[3], next[4]]) as usize;
        let mut more = vec![0u8; n];
        sock.read_exact(&mut more)?;
        record.extend_from_slice(&next);
        body.extend_from_slice(&more);
    }
    let hs = body[..4 + hs_len].to_vec();
    record.extend_from_slice(&body);
    Ok((record, hs))
}

/// 读一段（最多 `max` 字节；loopback 上一条 flight 通常一次读完）。
fn read_some(sock: &mut TcpStream, max: usize) -> std::io::Result<Vec<u8>> {
    sock.set_read_timeout(Some(std::time::Duration::from_millis(500)))?;
    let mut buf = vec![0u8; max];
    match sock.read(&mut buf) {
        Ok(n) => {
            buf.truncate(n);
            Ok(buf)
        }
        Err(e)
            if e.kind() == std::io::ErrorKind::WouldBlock
                || e.kind() == std::io::ErrorKind::TimedOut =>
        {
            Ok(Vec::new())
        }
        Err(e) => Err(e),
    }
}
