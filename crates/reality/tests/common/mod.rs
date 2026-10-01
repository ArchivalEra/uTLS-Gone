//! **本地真站（dest）装置**：一台真实的 rustls TLS 1.3 服务端，用来当 REALITY
//! 镜像的「真站」——把客户端给的 hello 喂给它，抓回它回的第一段 flight。
//!
//! # 为什么需要它
//!
//! 镜像服务端的判据要有**真站的实际字节**：`tls.go:330-360` 那张形状校验表
//! （ServerHello → CCS → 应用数据）只有在真站真的这样回时才有意义。
//! 本地 rustls 服务端就是那个「真站」——完全离线、可控（能只看 P-256）、
//! 且**它的证书链是真的**（`fixtures/server-cert.der`，与 utls-engine 共用同一份
//! 测试凭据；那是测试凭据不是秘密，见 utls-engine 的 fixtures/README）。
#![allow(dead_code)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::{ServerConfig, ServerConnection};

pub const CERT_DER: &[u8] = include_bytes!("../fixtures/server-cert.der");
pub const KEY_PKCS8_DER: &[u8] = include_bytes!("../fixtures/server-key.pk8.der");

/// 服务端配置；`only_groups = Some(..)` 时把提供者的 kx_groups 滤成只认那些组
///（P-256-only 判据用）。
pub fn server_config(only_groups: Option<Vec<rustls::NamedGroup>>) -> Arc<ServerConfig> {
    let provider = match only_groups {
        None => Arc::new(rustls::crypto::aws_lc_rs::default_provider()),
        Some(groups) => {
            let mut p = rustls::crypto::aws_lc_rs::default_provider();
            p.kx_groups.retain(|g| groups.contains(&g.name()));
            Arc::new(p)
        }
    };
    Arc::new(
        ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .expect("TLS 1.3 可用")
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(CERT_DER.to_vec())],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(KEY_PKCS8_DER.to_vec())),
            )
            .expect("证书与私钥配套"),
    )
}

/// 把 `client_hello`（**完整的 ClientHello 握手消息**，不带记录头）当原始记录体
/// 喂给本地真站，抓回它回复的**全部字节**（ServerHello 记录 + CCS + 加密 flight）。
///
/// 实现：手写记录头（`0x16 0x03 0x01` + u16 长度）包住 hello —— 真实客户端的
/// 第一飞就是 b 这个样子；然后一直读到服务端把首 flight 写完。
pub fn run_tls13_server_and_capture_flight(
    config: Arc<ServerConfig>,
    client_hello: Vec<u8>,
) -> Vec<u8> {
    let listener = TcpListener::bind("127.0.0.1:0").expect("占端口");
    let addr = listener.local_addr().expect("端口");
    let handle = thread::spawn(move || {
        let (mut sock, _) = listener.accept().expect("accept");
        sock.set_read_timeout(Some(Duration::from_secs(5)))
            .expect("读超时");
        let mut conn = ServerConnection::new(config).expect("建服务端连接");
        // 把 hello 包成一条记录（真实客户端的第一飞就是这个形状）。
        let mut record = vec![0x16, 0x03, 0x01];
        record.extend_from_slice(&(client_hello.len() as u16).to_be_bytes());
        record.extend_from_slice(&client_hello);
        conn.read_tls(&mut record.as_slice()).expect("喂 hello");
        conn.process_new_packets().expect("处理 hello");
        // 服务端此刻会把首 flight 排进待发缓冲；取出来写回 socket。
        let mut out = Vec::new();
        while conn.wants_write() {
            let mut chunk = Vec::new();
            let n = conn.write_tls(&mut chunk).expect("取待发字节");
            if n == 0 {
                break;
            }
            out.extend_from_slice(&chunk);
        }
        sock.write_all(&out).expect("写 flight");
        sock.flush().expect("flush");
        out
    });
    // 客户端：连上去、读走 flight（读不到 EOF 也没关系 —— 收到一段就够分类）。
    let mut sock = TcpStream::connect(addr).expect("连回环");
    sock.set_read_timeout(Some(Duration::from_millis(500)))
        .expect("读超时");
    let mut sink = Vec::new();
    let mut buf = [0u8; 4096];
    while let Ok(n) = sock.read(&mut buf) {
        if n == 0 {
            break;
        }
        sink.extend_from_slice(&buf[..n]);
    }
    let out = handle.join().expect("真站线程");
    assert_eq!(
        sink, out,
        "客户端收到的 flight 必须与服务端写出的逐字节相同（装置自检）"
    );
    out
}

/// 真站（rustls 服务端）的配置：用 vendored rustls 的测试证书。
///
/// ⚠️ 组偏好要与**真实真站的处境**一致：rustls 默认顺序是
/// X25519 → P-256 → P-384 → MLKEM768，于是它会选 **P-256** —— 而 uTLS 客户端
/// （`KeySharePrivateKeys` 只有 `Ecdhe`(X25519)/`Mlkem`/`MlkemEcdhe` 三个字段，
/// `u_public.go:926-931`）**完不成** P-256 的握手。真实大站（Cloudflare/Google）
/// 都优先 X25519MLKEM768，参照的镜像正是为那种真站写的。所以这里把顺序调成
/// MLKEM768 → X25519 → 其余 —— 与 rustls 的 `prefer-post-quantum` 偏好一致
/// （那个 feature 就是给「模仿真实互联网」用的）。
pub fn dest_server_config() -> Arc<ServerConfig> {
    dest_server_config_with_groups(None)
}

/// 同上，可限制 kx_groups（P-256-only 判据用）。
pub fn dest_server_config_with_groups(
    only_groups: Option<Vec<rustls::NamedGroup>>,
) -> Arc<ServerConfig> {
    let mut p = rustls::crypto::aws_lc_rs::default_provider();
    p.kx_groups.sort_by_key(|g| match u16::from(g.name()) {
        4588 => 0, // X25519MLKEM768 最前
        29 => 1,   // 次选 X25519
        _ => 2,
    });
    if let Some(groups) = only_groups {
        p.kx_groups.retain(|g| groups.contains(&g.name()));
    }
    let provider = Arc::new(p);
    Arc::new(
        ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .expect("TLS 1.3")
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(CERT_DER.to_vec())],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(KEY_PKCS8_DER.to_vec())),
            )
            .expect("证书与私钥配套"),
    )
}

/// 一个跳过证书验证的 rustls 客户端（**判据只看证书字节**，不看链）：
/// 连上去、完成握手、把服务端给的证书 DER 取回来。
pub fn tls_client_handshake_and_peer_cert(addr: impl ToSocketAddrs) -> std::io::Result<Vec<u8>> {
    #[derive(Debug)]
    struct Skip;
    impl rustls::client::danger::ServerCertVerifier for Skip {
        fn verify_server_cert(
            &self,
            _end_entity: &rustls::pki_types::CertificateDer<'_>,
            _intermediates: &[rustls::pki_types::CertificateDer<'_>],
            _server_name: &rustls::pki_types::ServerName<'_>,
            _ocsp: &[u8],
            _now: rustls::pki_types::UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &rustls::pki_types::CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }
        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &rustls::pki_types::CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }
        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            vec![
                rustls::SignatureScheme::ED25519,
                rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
                rustls::SignatureScheme::RSA_PSS_SHA256,
            ]
        }
    }
    let cfg = Arc::new(
        rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(Skip))
        .with_no_client_auth(),
    );
    let mut sock = TcpStream::connect(addr)?;
    sock.set_read_timeout(Some(Duration::from_secs(5)))?;
    let name = rustls::pki_types::ServerName::try_from("localhost").expect("名字");
    let mut conn = rustls::ClientConnection::new(cfg, name).expect("建客户端");
    while conn.is_handshaking() {
        conn.complete_io(&mut sock)?;
    }
    let certs = conn
        .peer_certificates()
        .ok_or_else(|| std::io::Error::other("服务端没给证书"))?;
    Ok(certs[0].as_ref().to_vec())
}
