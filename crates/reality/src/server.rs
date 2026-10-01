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

use crate::ch::{ClientHello as ParsedHello, RealityConfig, decide};
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
    /// 用**镜像握手**（真站 ServerHello 当模板）完成的连接数。
    pub mirrored: AtomicUsize,
    /// 鉴权通过但镜像失败、回落到透传的次数。
    pub mirror_failed: AtomicUsize,
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
                // ③ 读真站的 **ServerHello**（镜像的模板）。
                //    参照 `tls.go:330-360` 逐记录读、逐记录校验形状；我们只需要
                //    ServerHello 那一条来当模板，其余留给透传路径。
                let dest_sh = match read_one_handshake_record(&mut dest) {
                    Ok(msg) => msg,
                    Err(_) => {
                        self.stats
                            .dest_flight_malformed
                            .fetch_add(1, Ordering::SeqCst);
                        // 读不到模板 ⇒ 回落透传（参照的 `break f` + 直接把已读字节转给客户端）。
                        return self.raw_proxy(
                            client,
                            Vec::new(),
                            Some((
                                dest,
                                hello_record.len(),
                                FallbackReason::KeyShareShape(String::from(
                                    "真站没有回 ServerHello",
                                )),
                            )),
                        );
                    }
                };
                // ④ **镜像握手**：真站的 ServerHello 逐字节当模板，只替换密钥字节。
                //    这是 REALITY 的核心一步（`handshake_server_tls13.go:104-120`）。
                let signing = match self.signing_signer() {
                    Ok(s) => s,
                    Err(e) => {
                        return Err(std::io::Error::other(e));
                    }
                };
                let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
                let client_sid = hello.session_id.to_vec();
                match crate::mirror_tls::run(
                    client.try_clone()?,
                    &handshake_msg,
                    &dest_sh,
                    &self.config.cert_template,
                    &*signing,
                    &provider,
                    &auth_key,
                    &client_sid,
                ) {
                    Ok(stream) => {
                        self.stats.mirrored.fetch_add(1, Ordering::SeqCst);
                        let info = AuthInfo {
                            peer: client
                                .peer_addr()
                                .unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap()),
                            server_name: hello.server_name.clone(),
                            short_id,
                            client_ver,
                            client_time,
                        };
                        (self.handler)(Box::new(stream), info);
                        Ok(())
                    }
                    Err(e) => {
                        // 镜像失败 ⇒ **回落透传**（参照的行为：认证过了但真站 flow
                        // 用不上时，把客户端当普通访问处理）。镜像在失败前不写任何
                        // 字节，所以这里安全。
                        //
                        // ⚠️ 计数口径：`fallback` 是「这条连接最终走了原样透传」的
                        // **总数**，所以这里与 `Decision::Fallback` 分支都要自增 ——
                        // 只记「鉴权失败导致的透传」会让这个数不等于透传连接数
                        // （实测：P-256 那条判据断言 fallback==1 而实际 0）。
                        // `mirror_failed` 是它的**子集**（其中多少次是镜像失败引起）。
                        self.stats.mirror_failed.fetch_add(1, Ordering::SeqCst);
                        self.stats.fallback.fetch_add(1, Ordering::SeqCst);
                        if std::env::var_os("REALITY_DBG").is_some() {
                            eprintln!("[srv] 镜像失败（回落透传）：{e}");
                        }
                        self.raw_proxy(
                            client,
                            Vec::new(),
                            Some((
                                dest,
                                hello_record.len(),
                                FallbackReason::KeyShareShape(format!("镜像回落：{e}")),
                            )),
                        )
                    }
                }
            }

            Decision::Fallback { reason } => {
                self.stats.fallback.fetch_add(1, Ordering::SeqCst);
                self.raw_proxy(client, Vec::new(), Some((dest, hello_record.len(), reason)))
            }
        }
    }

    /// 每连接的 ed25519 签名键（`CertificateVerify` 用它签）。
    ///
    /// 与证书模板同一对密钥 —— 证书证明身份，`CertificateVerify` 证明我们持有私钥。
    fn signing_signer(&self) -> Result<Box<dyn rustls::sign::Signer>, String> {
        let provider = rustls::crypto::aws_lc_rs::default_provider();
        let key = rustls::pki_types::PrivateKeyDer::Pkcs8(
            rustls::pki_types::PrivatePkcs8KeyDer::from(self.config.signing_key.clone()),
        );
        let signing = provider
            .key_provider
            .load_private_key(key)
            .map_err(|e| format!("加载 ed25519 私钥失败：{e}"))?;
        signing
            .choose_scheme(&[rustls::SignatureScheme::ED25519])
            .ok_or_else(|| String::from("签名键不支持 Ed25519"))
    }

    /// 未鉴权（或镜像失败）：把已读的字节转发给真站后双向原样透传。
    ///
    /// `established` 为 `Some((dest, ...))` 表示真站连接**已经建好**（hello 已转发）；
    /// `None` 时用 `pending` 里的字节现建一条。两个方向的字节都**原样**走 ——
    /// 客户端因此拿到与直连真站逐字节相同的握手（判据在 real_stack.rs）。
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

/// 从**真站连接**上读一条握手记录，返回**握手消息**（`type || u24 || body`）。
///
/// 参照 `tls.go:330-360` 逐记录读并校验形状；镜像只需要第一条（ServerHello）。
/// 跳过 CCS（那可能在 ServerHello 之前出现？不会 —— 顺序是 SH → CCS，但保守处理）。
fn read_one_handshake_record(sock: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    sock.set_read_timeout(Some(std::time::Duration::from_secs(10)))?;
    loop {
        let mut header = [0u8; 5];
        sock.read_exact(&mut header)?;
        let len = u16::from_be_bytes([header[3], header[4]]) as usize;
        let mut body = vec![0u8; len];
        sock.read_exact(&mut body)?;
        match header[0] {
            0x16 => return Ok(body),
            0x14 => continue, // CCS：跳过（真站在 ServerHello 之后才发，保守起见仍处理）
            other => {
                return Err(std::io::Error::other(format!(
                    "真站第一条不是握手记录（type=0x{other:02x}）"
                )));
            }
        }
    }
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
