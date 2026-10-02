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

// ── 带 REALITY 封装的 rustls 客户端（判据装置，issue #3）────────────────────
//
// 本仓的客户端半边是**注入式**的：REALITY 鉴权要的那把 X25519 私钥由调用方自己
// 持有（[`reality::client::seal_hello`] 的入参），TLS 侧其余组的交换由提供者现起
// （pub 进 hello、complete 留给 rustls）—— 与 `crates/utls-engine` 的
// `ExternalKeyExchange`（fork 能力 (e)）同一形状。
//
// 为什么判据客户端要自建而不能用 Xray：uTLS 的 `KeySharePrivateKeys` 没有 P-256
// 私钥位，Xray 客户端完不成「服务端选 P-256」—— 这正是 issue #3 之前 P-256-only
// dest 必落透传的原因。本装置证明的恰是反命题：**注入式客户端**带 P-256 share 时，
// 镜像路径端到端可用（鉴权 → 镜像 → 双向往返）。

use std::sync::Mutex as StdMutex;
use std::sync::atomic::{AtomicBool, Ordering};

use rustls::DigitallySignedStruct;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::{ClientHelloPlan, ExternalKeyExchange, PlanRequest, SuppliesClientHello};
use rustls::crypto::{ActiveKeyExchange, CryptoProvider, SupportedKxGroup};

/// 调用方持有的 X25519 交换（REALITY 鉴权钥匙）：complete 就是裸 X25519。
#[derive(Debug)]
struct HeldX25519 {
    group: u16,
    pub_key: Vec<u8>,
    private: [u8; 32],
    /// complete() 被调过的探针 —— 判据用它证明「TLS 握手用的是哪个组」。
    consumed: Arc<AtomicBool>,
}

impl ExternalKeyExchange for HeldX25519 {
    fn group(&self) -> u16 {
        self.group
    }
    fn pub_key(&self) -> Vec<u8> {
        self.pub_key.clone()
    }
    fn complete(&self, peer_pub_key: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        self.consumed.store(true, Ordering::SeqCst);
        let peer: [u8; 32] = peer_pub_key
            .try_into()
            .map_err(|_| rustls::Error::General("X25519 对端公钥该是 32 字节".into()))?;
        let secret = x25519_dalek::StaticSecret::from(self.private)
            .diffie_hellman(&x25519_dalek::PublicKey::from(peer));
        Ok(secret.as_bytes().to_vec())
    }
}

/// 提供者持有的交换（P-256 / P-384 / MLKEM768……）：pub 进指纹，complete 委托 rustls。
struct HeldProviderKx {
    group: u16,
    pub_key: Vec<u8>,
    inner: StdMutex<Option<Box<dyn ActiveKeyExchange>>>,
    consumed: Arc<AtomicBool>,
}

impl std::fmt::Debug for HeldProviderKx {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HeldProviderKx")
            .field("group", &format_args!("0x{:04x}", self.group))
            .field("pub_key_len", &self.pub_key.len())
            .finish()
    }
}

impl ExternalKeyExchange for HeldProviderKx {
    fn group(&self) -> u16 {
        self.group
    }
    fn pub_key(&self) -> Vec<u8> {
        self.pub_key.clone()
    }
    fn complete(&self, peer_pub_key: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        self.consumed.store(true, Ordering::SeqCst);
        let kx = self
            .inner
            .lock()
            .map_err(|_| rustls::Error::General("密钥交换的锁中毒".into()))?
            .take()
            .ok_or_else(|| rustls::Error::General("这把交换已经被用过了".into()))?;
        Ok(kx.complete(peer_pub_key)?.secret_bytes().to_vec())
    }
}

/// 从 DER 证书里取裸 32 字节 ed25519 公钥（SPKI 形状定位 —— 与
/// `mirror_tls::raw_ed25519_public_key` 同一算法；那是私有函数，判据侧自持一份）。
fn spki_ed25519_public_key(cert_der: &[u8]) -> [u8; 32] {
    const SPKI_ED25519: [u8; 12] = [
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];
    let i = cert_der
        .windows(SPKI_ED25519.len())
        .position(|w| w == SPKI_ED25519)
        .expect("ed25519 的 SPKI 固定形状必在（镜像证书就是自签 ed25519）");
    let mut out = [0u8; 32];
    out.copy_from_slice(&cert_der[i + SPKI_ED25519.len()..i + SPKI_ED25519.len() + 32]);
    out
}

/// 判据客户端的证书校验器：**不做** x509 链验证（自签 ed25519 本来就没有链），
/// 做的是 Xray `VerifyPeerCertificate` 的那件事 ——
/// `HMAC-SHA512(AuthKey, cert.PublicKey) == cert.Signature`。
/// 对上 ⇒ 这是 REALITY 服务端（不是透传回来的真站）；对不上 ⇒ 判据当场红。
#[derive(Debug)]
struct RealityCertVerifier {
    auth_key: Arc<StdMutex<Option<[u8; 32]>>>,
}

impl ServerCertVerifier for RealityCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let auth_key = self
            .auth_key
            .lock()
            .expect("AuthKey 槽的锁")
            .expect("plan() 已算出 AuthKey（封包发生在证书校验之前）");
        let der = end_entity.as_ref();
        let pubkey = spki_ed25519_public_key(der);
        let sig = &der[der.len() - 64..];
        assert_eq!(
            reality::client::verify_mirror_signature(&auth_key, &pubkey, sig),
            reality::PeerVerdict::RealityServer,
            "镜像证书的尾签该是 REALITY 的 HMAC —— 对不上说明我们拿到的是真站证书\
             （透传），而不是镜像路径"
        );
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA256,
        ]
    }
}

/// 「交换被消费」探针表：`(组, complete 是否发生过)` —— 判据从这里读
/// 「真站选中的是哪个组」。
pub type ExchangeProbes = Arc<StdMutex<Vec<(u16, Arc<AtomicBool>)>>>;

/// 判据客户端（[`SuppliesClientHello`] 的实现）：Firefox-148 指纹 + REALITY 封装。
///
/// `plan()` 每连接一次：按 spec 的 `key_share` 组各起一把真交换 —— X25519 用
/// **调用方持有的**私钥（它同时是 REALITY 的鉴权钥匙：服务端拿 hello 里那把
/// X25519 公钥 × 静态私钥派生 AuthKey，客户端拿同一把私钥 × 服务端静态公钥），
/// 其余组由提供者现起。序列化之后、上发之前做 REALITY 封装（sessionId 的 32 字节
/// 回填密文）—— 与 Xray `UClient` 的 `BuildHandshakeState` 之后 `Seal` 回填同序。
pub struct RealityTestClient {
    spec: utls::hello::ClientHelloSpec,
    sni: String,
    x25519_priv: [u8; 32],
    reality_cfg: reality::client::ClientConfig,
    now: u64,
    provider: Arc<CryptoProvider>,
    /// plan() 算出的 AuthKey —— 证书校验器从这里拿（封包先于校验，必有值）。
    auth_key: Arc<StdMutex<Option<[u8; 32]>>>,
    /// 每次 plan() 登记的探针，见 [`ExchangeProbes`]。
    pub exchange_state: ExchangeProbes,
}

impl std::fmt::Debug for RealityTestClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RealityTestClient")
            .field("sni", &self.sni)
            .field("spec", &self.spec)
            .finish_non_exhaustive()
    }
}

impl RealityTestClient {
    pub fn new(
        spec: utls::hello::ClientHelloSpec,
        sni: &str,
        x25519_priv: [u8; 32],
        server_static_pub: [u8; 32],
        short_id: [u8; 8],
        now: u64,
    ) -> Arc<Self> {
        Arc::new(Self {
            spec,
            sni: sni.to_string(),
            x25519_priv,
            reality_cfg: reality::client::ClientConfig {
                public_key: server_static_pub,
                short_id,
                client_ver: [1, 8, 13, 0],
                fallback_to_webpki: true,
            },
            now,
            provider: Arc::new(rustls::crypto::aws_lc_rs::default_provider()),
            auth_key: Arc::new(StdMutex::new(None)),
            exchange_state: Arc::new(StdMutex::new(Vec::new())),
        })
    }

    /// 判据用的 AuthKey（plan() 之后才有值）。
    pub fn auth_key(&self) -> [u8; 32] {
        self.auth_key
            .lock()
            .expect("AuthKey 槽的锁")
            .expect("plan() 已跑（连接已发起）")
    }

    /// 某组的交换是否在握手里被消费过（= 服务端选中了它）。
    pub fn exchange_consumed(&self, group: u16) -> bool {
        self.exchange_state
            .lock()
            .expect("探针槽的锁")
            .iter()
            .find(|(g, _)| *g == group)
            .map(|(_, f)| f.load(Ordering::SeqCst))
            .unwrap_or(false)
    }
}

impl SuppliesClientHello for RealityTestClient {
    fn plan(&self, _request: &PlanRequest) -> Result<ClientHelloPlan, rustls::Error> {
        use utls::hello::{HandshakeInputs, SessionId};
        // 可复现判据：固定种子（random/SNI/时刻由调用方定）。
        let mut spec = self.spec.clone();
        spec.session_id = SessionId::Fixed(vec![0u8; 32]); // REALITY 回填的目标区
        let mut inputs = HandshakeInputs::deterministic([0x77; 32]);
        inputs.sni = Some(self.sni.clone());

        // 每把 key share 一把真交换（fork 的契约：hello 里写的组要拿得出交换，
        // 服务端选中谁就用谁 —— 这正是 issue #3 要的能力面）。
        let mut key_exchange = Vec::new();
        let mut exchanges: Vec<Arc<dyn ExternalKeyExchange>> = Vec::new();
        let mut probes = self.exchange_state.lock().expect("探针槽的锁");
        probes.clear();
        for g in spec.key_share_groups() {
            let consumed = Arc::new(AtomicBool::new(false));
            probes.push((g, Arc::clone(&consumed)));
            if g == utls::values::X25519 {
                // 调用方持有：REALITY 鉴权钥匙（公钥进 hello，私钥留在客户端手里）。
                let secret = x25519_dalek::StaticSecret::from(self.x25519_priv);
                let pubkey = *x25519_dalek::PublicKey::from(&secret).as_bytes();
                key_exchange.push((g, pubkey.to_vec()));
                exchanges.push(Arc::new(HeldX25519 {
                    group: g,
                    pub_key: pubkey.to_vec(),
                    private: self.x25519_priv,
                    consumed,
                }));
            } else {
                // 提供者持有：pub 进指纹，complete 由 rustls 在收到 serverShare 后调。
                let skxg: &dyn SupportedKxGroup = *self
                    .provider
                    .kx_groups
                    .iter()
                    .find(|k| u16::from(k.name()) == g)
                    .ok_or_else(|| {
                        rustls::Error::General(format!(
                            "判据客户端：提供者没有组 0x{g:04x} 的实现，这把 share 发不出去"
                        ))
                    })?;
                let kx = skxg.start()?;
                let pubkey = kx.pub_key().to_vec();
                key_exchange.push((g, pubkey.clone()));
                exchanges.push(Arc::new(HeldProviderKx {
                    group: g,
                    pub_key: pubkey,
                    inner: StdMutex::new(Some(kx)),
                    consumed,
                }));
            }
        }
        inputs.key_exchange = key_exchange;

        // 序列化 → REALITY 封装（只改 sessionId 的 32 字节）。
        let raw = spec
            .marshal(&inputs)
            .map_err(|e| rustls::Error::General(format!("指纹层产出 hello 失败：{e}")))?
            .into_bytes();
        let sealed =
            reality::client::seal_hello(&raw, &self.x25519_priv, &self.reality_cfg, self.now)
                .map_err(|e| rustls::Error::General(format!("REALITY 封装失败：{e}")))?;
        *self.auth_key.lock().expect("AuthKey 槽的锁") = Some(sealed.auth_key);

        // hello 里出现过的扩展类型全集（fork 的「服务器回了没提供的扩展」检查要它；
        // 封装不改扩展，从封好的字节里读即可）。
        Ok(ClientHelloPlan {
            client_hello: Some(sealed.hello),
            sent_extensions: Some(extension_types(&raw)),
            key_exchanges: exchanges,
            psk_binder: None,
            ech: None,
            // 以下三项只影响引擎自建的 hello（这里外供了字节）—— 按默认意图填。
            stable_extension_order: false,
            extra_cipher_suites: Vec::new(),
            suppress_renegotiation_scsv: true,
        })
    }
}

/// 从握手消息里读出全部扩展类型（与引擎的 `extension_types_of` 同一算法）。
fn extension_types(hello: &[u8]) -> Vec<u16> {
    let len = ((hello[1] as usize) << 16) | ((hello[2] as usize) << 8) | hello[3] as usize;
    let body = &hello[4..4 + len];
    let mut p = 2 + 32;
    p += 1 + body[p] as usize;
    let cs = u16::from_be_bytes([body[p], body[p + 1]]) as usize;
    p += 2 + cs;
    p += 1 + body[p] as usize;
    let exts = u16::from_be_bytes([body[p], body[p + 1]]) as usize;
    p += 2;
    let region = &body[p..p + exts];
    let mut out = Vec::new();
    let mut q = 0usize;
    while q + 4 <= region.len() {
        out.push(u16::from_be_bytes([region[q], region[q + 1]]));
        let bl = u16::from_be_bytes([region[q + 2], region[q + 3]]) as usize;
        q += 4 + bl;
    }
    out
}

/// 判据客户端的 TLS 流（rustls 连接 + 底层 socket）。
pub type RealityTlsStream = rustls::StreamOwned<rustls::ClientConnection, TcpStream>;

/// 连上 REALITY 服务端并跑完镜像握手，返回可读写的 TLS 流与客户端装置。
///
/// 这就是 issue #3 判据的客户端面：指纹 hello + REALITY 封装 + 调用方持钥的
/// X25519 + 提供者持有的其余组。握手若成了，证书校验器已经验过 REALITY 尾签。
pub fn connect_reality_client(
    addr: std::net::SocketAddr,
    spec: utls::hello::ClientHelloSpec,
    sni: &str,
    x25519_priv: [u8; 32],
    server_static_pub: [u8; 32],
    short_id: [u8; 8],
    now: u64,
) -> std::io::Result<(RealityTlsStream, Arc<RealityTestClient>)> {
    let client = RealityTestClient::new(spec, sni, x25519_priv, server_static_pub, short_id, now);
    let verifier = RealityCertVerifier {
        auth_key: Arc::clone(&client.auth_key),
    };
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .expect("TLS 1.3")
    .dangerous()
    .with_custom_certificate_verifier(Arc::new(verifier))
    .with_no_client_auth();
    config.fork_client_hello = Some(Arc::clone(&client) as Arc<dyn SuppliesClientHello>);

    let name = rustls::pki_types::ServerName::try_from(sni.to_string()).expect("SNI 名字合法");
    let conn = rustls::ClientConnection::new(Arc::new(config), name).expect("建客户端连接");
    let tcp = TcpStream::connect(addr)?;
    tcp.set_read_timeout(Some(Duration::from_secs(10)))?;
    let mut stream = rustls::StreamOwned::new(conn, tcp);
    // 显式跑完握手 —— complete_io 只驱动握手，不吞应用数据。
    while stream.conn.is_handshaking() {
        stream
            .conn
            .complete_io(&mut stream.sock)
            .map_err(|e| std::io::Error::other(format!("镜像握手没谈成：{e}")))?;
    }
    Ok((stream, client))
}
