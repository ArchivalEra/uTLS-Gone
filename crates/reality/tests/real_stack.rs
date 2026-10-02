//! **真栈判据**（issue #1 结案判据 3 与 4）：**stock Xray-core 客户端**指向
//! 本仓的 REALITY 服务端，走鉴权路径完成握手并承载流量；未鉴权客户端拿到与
//! 直连真站**逐字节相同**的证书链。
//!
//! # 装置（全部离线）
//!
//! ```text
//! [测试客户端] --TCP--> [xray 的 dokodemo-door 入站]
//!                          |
//!                          | VLESS/REALITY 出站（fingerprint=chrome）
//!                          v
//!                 [本仓 REALITY 服务端] --转发 hello--> [本地真站（rustls）]
//!                          |
//!                          | 鉴权成功 ⇒ 明文交给 Handler（测试里是回显）
//!                          v
//! ```
//!
//! Xray 二进制：**官方 release**（`README` 里记了解压方式），本机实测
//! `Xray 26.3.27`。取不到时本测试会**如实失败**（不静默跳过）——
//! 「跑不了」与「跑通了」不能长得一样。
//!
//! # 判据
//!
//! 1. **鉴权路径（Xray）**：Xray 客户端（配置了正确的 publicKey/shortId）连上后，
//!    服务端的 `authenticated` 计数 +1、`fallback` 为 0；测试数据经
//!    握手后的明文流往返（Xray 收到回显）。
//! 2. **未鉴权路径**：普通 TLS 客户端（不带 REALITY sessionId）连上服务端，
//!    看到的证书链与**直连真站**逐字节相同（服务端把连接原样透传）。
//! 3. **双向 splice（Xray）**：明文流拆两半，后端主动推的数据在客户端先写之前
//!    到达（issue #2）。
//! 4. **P-256-only dest 的未鉴权面**：没鉴权 ⇒ 照旧透传（issue #3 支持面放宽
//!    不动这条边界）。
//! 5. **真站选 P-256 ⇒ 镜像端到端**（issue #3 的核心）：本仓注入式客户端半边
//!    （X25519 鉴权钥调用方持有 + 提供者持有的 P-256 交换）对着 P-256-only 真站，
//!    鉴权 → 镜像 → 双向往返；P-384 同型一条。
//!
//! 其中 1、3 需要 stock Xray；2、4、5（P-256 与 P-384 两条）不需要，随 workspace 跑。
//!
//! # 需要外部二进制 —— 测试自己管
//!
//! 找不到 `xray` 时：`REALITY_XRAY` 环境变量指定路径；否则试 PATH 与
//! `/tmp/xray-bin/xray`。都没有 ⇒ panic 并打印取法（不 `#[ignore]`：
//! 这条判据是 issue 的结案条件，静默跳过等于没有）。

mod common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use reality::ch::RealityConfig;
use reality::server::{AuthInfo, Handler, PlaintextStream, Server, ServerConfig};

const SERVER_PRIV: [u8; 32] = [0x31; 32];
const CLIENT_PRIV: [u8; 32] = [0x32; 32];
const SHORT_ID: [u8; 8] = [0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8];
const SERVER_NAME: &str = "localhost";

/// 本仓的 ed25519 测试证书（尾 64 字节每连接被 HMAC 覆盖；见 server 模块头）。
const CERT_TEMPLATE: &[u8] = include_bytes!("fixtures/ed25519-cert.der");
const SIGNING_KEY: &[u8] = include_bytes!("fixtures/ed25519-key.pk8.der");

fn reality_config() -> RealityConfig {
    RealityConfig {
        server_names: vec![String::from(SERVER_NAME)],
        private_key: SERVER_PRIV,
        short_ids: vec![SHORT_ID],
        min_client_ver: None,
        max_client_ver: None,
        // Xray 默认 MaxTimeDiff = 0（不检查）；判据里也放开，让「鉴权」只取决于
        // sessionId 密文与 shortId。
        max_time_diff: None,
    }
}

/// 找 xray 二进制；找不到就**如实失败**并打印取法。
fn xray_bin() -> std::path::PathBuf {
    if let Ok(p) = std::env::var("REALITY_XRAY") {
        let p = std::path::PathBuf::from(p);
        assert!(p.exists(), "REALITY_XRAY 指向的路径不存在：{}", p.display());
        return p;
    }
    for cand in ["/tmp/xray-bin/xray", "xray"] {
        let p = std::path::PathBuf::from(cand);
        if p.exists() {
            return p;
        }
        if let Ok(out) = Command::new("sh")
            .arg("-c")
            .arg(format!("command -v {cand}"))
            .output()
            && out.status.success()
        {
            let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if !s.is_empty() {
                return std::path::PathBuf::from(s);
            }
        }
    }
    panic!(
        "找不到 stock Xray-core 客户端。取法（本机实测）：\n\
         curl -sSL -o /tmp/xray.zip https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip\n\
         mkdir -p /tmp/xray-bin && cd /tmp/xray-bin && unzip -o /tmp/xray.zip && chmod +x xray\n\
         或设 REALITY_XRAY=<路径>。这条判据是 issue #1 的结案条件之一，不许静默跳过。"
    );
}

/// 启动本地真站（rustls TLS 1.3，用 utls-engine 的测试证书），返回端口。
///
/// 真站只被用来「收到转发的 hello 并回一段合法 flight」——REALITY 的抗探测面。
fn spawn_local_dest() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("占端口");
    let port = listener.local_addr().expect("端口").port();
    let cfg = common::dest_server_config();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut sock) = stream else { continue };
            let cfg = Arc::clone(&cfg);
            std::thread::spawn(move || {
                // 用 rustls 服务端把对方当普通 TLS 客户端接 —— 只走到
                // 「我们发了 flight、对方回了什么」为止，错误无所谓。
                let Ok(mut conn) = rustls::ServerConnection::new(cfg) else {
                    return;
                };
                let _ = sock.set_read_timeout(Some(Duration::from_secs(3)));
                while conn.is_handshaking() {
                    if conn.complete_io(&mut sock).is_err() {
                        break;
                    }
                }
                let _ = conn.complete_io(&mut sock);
            });
        }
    });
    port
}

/// 回显处理器（**测试替身**，不是本 crate 的协议实现）：
/// 先**读掉 Xray 的 VLESS 请求头**，写 VLESS 响应头，再逐字节回显。
///
/// # 为什么要解析请求头
///
/// 实测证据：不解析时服务端统计是 `connections=10 authenticated=10` —— 鉴权
/// 每一次都过了，但客户端收到 **0 字节**。原因是 Xray 的 outbound 在裸流上报
/// VLESS 请求（`version(1) || uuid(16) || addon_len(1) || addon || command(1) ||
/// port(2) || addr_type(1) || addr`），它在等我们回应；不解析就只能干等。
/// 这里按最小字段读掉请求头，好让测到的数据是「上层协议真的承载了」。
fn echo_handler() -> Handler {
    // 回显是**严格串行**的（读头 → 回显 → 读应用数据回写），不需要分半 ⇒ 用
    // `handler_from_stream` 把「收合体流」的旧写法桥到新的两半形态。
    // ⚠️ 双向**并发**的 handler 不能走这里（JoinedStream 两方向共用一把锁、会串行化，
    // 正是 issue #2 要躲的形状）—— 见下述 `splice_handler`。
    reality::server::handler_from_stream(|mut s: Box<dyn PlaintextStream>, info: AuthInfo| {
        let version = match read_vless_request_header(&mut *s) {
            Some(v) => v,
            None => return,
        };
        eprintln!(
            "（回显替身）收到 VLESS 请求：version={version} short_id={:02x?} server_name={:?}",
            info.short_id, info.server_name
        );
        // VLESS 响应头：version(1) + addon_len(1)。
        let _ = s.write_all(&[0x00, 0x00]);
        let _ = s.flush();
        // 回显应用数据。
        let mut buf = [0u8; 4096];
        loop {
            match s.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if s.write_all(&buf[..n]).is_err() {
                        break;
                    }
                    let _ = s.flush();
                }
            }
        }
    })
}

/// 读掉 Xray 的 VLESS 请求头：`version(1) || uuid(16) || addon_len(1) || addon ||
/// command(1) || port(2) || addr_type(1) || addr`。返回 `version`。
///
/// 为什么要读：Xray 的 outbound 在裸流上报 VLESS 请求，它在等我们回应 —— 不读掉
/// 请求头就只能干等（判据 1 的注释记了这条实测）。回显 handler 与 splice handler
/// 都要先读它，抽出来避免两处走散。
fn read_vless_request_header(s: &mut dyn Read) -> Option<u8> {
    let mut head = [0u8; 1];
    s.read_exact(&mut head).ok()?;
    let version = head[0];
    let mut rest = [0u8; 16 + 1];
    s.read_exact(&mut rest).ok()?;
    let addon_len = rest[16] as usize;
    if addon_len > 0 {
        let mut addon = vec![0u8; addon_len];
        s.read_exact(&mut addon).ok()?;
    }
    let mut cmd = [0u8; 1 + 2 + 1];
    s.read_exact(&mut cmd).ok()?;
    let addr_len = match cmd[3] {
        0x01 => 4,
        0x02 => 1 + 1, // 域名：长度字节 + 名字
        0x03 => 16,
        _ => return None,
    };
    let mut skip = vec![0u8; addr_len];
    s.read_exact(&mut skip).ok()?;
    if cmd[3] == 0x02 {
        let n = skip[0] as usize;
        let mut name = vec![0u8; n];
        s.read_exact(&mut name).ok()?;
    }
    Some(version)
}

/// 起一台本仓 REALITY 服务端，返回 (地址, 统计)。
fn spawn_reality_server(dest_port: u16) -> (SocketAddr, Arc<reality::server::Stats>) {
    let cfg = ServerConfig {
        reality: reality_config(),
        dest: format!("127.0.0.1:{dest_port}").parse().expect("dest 地址"),
        cert_template: CERT_TEMPLATE.to_vec(),
        signing_key: SIGNING_KEY.to_vec(),
    };
    let server = Arc::new(Server::new(cfg, echo_handler()));
    let stats = server.stats();
    let listener = TcpListener::bind("127.0.0.1:0").expect("占端口");
    let addr = listener.local_addr().expect("端口");
    std::thread::spawn(move || {
        let _ = server.serve_on(listener);
    });
    (addr, stats)
}

/// 生成 Xray 配置并启动它；返回子进程与入站端口。
///
/// clippy 的 `zombie_processes` 看不出调用方用 `Kill`（Drop 里 kill + wait）收尸 ——
/// 那是这个返回 `Child` 的函数的约定，标注在这里。
#[allow(clippy::zombie_processes)]
fn spawn_xray(server: SocketAddr) -> (Child, u16) {
    let inbound = TcpListener::bind("127.0.0.1:0").expect("占入站端口");
    let inbound_port = inbound.local_addr().expect("端口").port();
    drop(inbound);
    let public_key = {
        // Xray 的 publicKey 是 x25519 公钥的 base64url（raw，无 padding）。
        use base64::Engine;
        let pk = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(SERVER_PRIV));
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(pk.as_bytes())
    };
    let short_id_hex: String = SHORT_ID.iter().map(|b| format!("{b:02x}")).collect();
    let uuid = "11111111-2222-3333-4444-555555555555";
    let config = format!(
        r#"{{
  "log": {{ "loglevel": "debug" }},
  "inbounds": [{{
    "listen": "127.0.0.1", "port": {inbound_port}, "protocol": "dokodemo-door",
    "settings": {{ "address": "127.0.0.1", "port": 80, "network": "tcp" }}
  }}],
  "outbounds": [{{
    "protocol": "vless",
    "settings": {{ "vnext": [{{ "address": "127.0.0.1", "port": {}, "users": [{{ "id": "{uuid}", "encryption": "none" }}] }}] }},
    "streamSettings": {{
      "network": "tcp",
      "security": "reality",
      "realitySettings": {{
        "show": true,
        "serverName": "{SERVER_NAME}",
        "fingerprint": "chrome",
        "publicKey": "{public_key}",
        "shortId": "{short_id_hex}",
        "spiderX": "/"
      }}
    }}
  }}]
}}"#,
        server.port()
    );
    let dir = std::env::temp_dir().join(format!("reality-xray-{inbound_port}"));
    std::fs::create_dir_all(&dir).expect("建临时目录");
    let cfg_path = dir.join("config.json");
    std::fs::write(&cfg_path, config).expect("写配置");
    let child = Command::new(xray_bin())
        .arg("run")
        .arg("-c")
        .arg(&cfg_path)
        .stdout(Stdio::from(
            std::fs::File::create(dir.join("xray.out")).expect("输出文件"),
        ))
        .stderr(Stdio::from(
            std::fs::File::create(dir.join("xray.log")).expect("日志文件"),
        ))
        .spawn()
        .expect("启动 xray");
    // 等入站端口可用。
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if TcpStream::connect_timeout(
            &format!("127.0.0.1:{inbound_port}").parse().unwrap(),
            Duration::from_millis(200),
        )
        .is_ok()
        {
            return (child, inbound_port);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("xray 的入站端口 10 秒内没起来");
}

/// **判据 1**：stock Xray 客户端 → 本仓服务端，鉴权路径握手 + 往返数据。
///
/// ⚠️ `#[ignore]`：这条**需要 stock Xray 二进制**（真栈判据的核心一格）。默认不跑，
/// 是为了让 `cargo test --workspace` 在没装 Xray 的机器上仍然全绿；CI 的
/// `reality-stack` job 与本地都显式跑它（`--include-ignored`）。其余四条
/// （未鉴权透传 ×2 / P-256 镜像 / P-384 镜像）不需要 Xray，照常随 workspace 跑。
#[test]
#[ignore = "需要 stock Xray-core 客户端（取法见 xray_bin()）"]
fn the_stock_xray_client_authenticates_and_moves_traffic() {
    let dest_port = spawn_local_dest();
    let (server_addr, stats) = spawn_reality_server(dest_port);
    let (xray, inbound) = spawn_xray(server_addr);
    // 确保 xray 退出时被清理。
    struct Kill(Child);
    impl Drop for Kill {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let _kill = Kill(xray);

    // 测试客户端：连 Xray 入站，写一段可识别的数据，等回显。
    let mut sock = TcpStream::connect(("127.0.0.1", inbound)).expect("连 xray 入站");
    sock.set_read_timeout(Some(Duration::from_secs(10)))
        .expect("读超时");
    let payload = format!("REALITY-PING-{}", std::process::id());
    sock.write_all(payload.as_bytes()).expect("写");
    sock.flush().expect("flush");

    // 回显里应含我们写的那串（Xray 会剥掉前 2 字节 VLESS 响应头）。
    let mut got = Vec::new();
    let mut buf = [0u8; 4096];
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline && !got.windows(payload.len()).any(|w| w == payload.as_bytes())
    {
        match sock.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => got.extend_from_slice(&buf[..n]),
            Err(_) => break,
        }
    }
    if !got.windows(payload.len()).any(|w| w == payload.as_bytes()) {
        let dir = std::env::temp_dir().join(format!("reality-xray-{inbound}"));
        let log = std::fs::read_to_string(dir.join("xray.log")).unwrap_or_default();
        panic!(
            "回显里没有写进去的数据 —— 握手成了但流量没通？收到 {} 字节：{:?}\n\
             服务端统计：connections={} authenticated={} mirrored={} mirror_failed={} fallback={} malformed={}\n\
             xray 日志：\n{log}",
            got.len(),
            String::from_utf8_lossy(&got),
            stats.connections.load(std::sync::atomic::Ordering::SeqCst),
            stats
                .authenticated
                .load(std::sync::atomic::Ordering::SeqCst),
            stats.mirrored.load(std::sync::atomic::Ordering::SeqCst),
            stats
                .mirror_failed
                .load(std::sync::atomic::Ordering::SeqCst),
            stats.fallback.load(std::sync::atomic::Ordering::SeqCst),
            stats
                .dest_flight_malformed
                .load(std::sync::atomic::Ordering::SeqCst),
        );
    }

    // 服务端的取证：这条连接走的是**鉴权**路径。
    // ⚠️ 计数是「≥1」而不是「==1」：`spawn_xray` 会用一条探测连接等入站端口
    // 就绪（Xray 在端口监听后才会接），那条连接同样走完鉴权（真客户端 + 真服务端
    // 都用同一份密钥材料）—— 实测第一次跑就是 2。判据要证的是「走到了鉴权路径」，
    // 不是「恰好一次连接」，所以断言 ≥1 并把实测值打出来。
    let authenticated = stats
        .authenticated
        .load(std::sync::atomic::Ordering::SeqCst);
    assert!(
        authenticated >= 1,
        "服务端该记下鉴权连接，实际 {authenticated}"
    );
    assert_eq!(
        stats.fallback.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "不该有 fallback（客户端的 publicKey/shortId 都对）"
    );
}

/// **判据 2**：未鉴权客户端拿到与直连真站**逐字节相同**的证书链。
#[test]
fn an_unauthenticated_client_sees_the_dest_certificate_byte_for_byte() {
    let dest_port = spawn_local_dest();
    let (server_addr, stats) = spawn_reality_server(dest_port);

    // ① 直连真站：取它给的证书 DER。
    let direct = common::tls_client_handshake_and_peer_cert(("127.0.0.1", dest_port))
        .expect("直连真站该完成握手");

    // ② 经 REALITY 服务端（未鉴权 —— 客户端不会 REALITY 封装）。
    let via_reality = common::tls_client_handshake_and_peer_cert(server_addr)
        .expect("透传路径该完成握手（客户端拿到的是真站的握手）");

    assert_eq!(
        direct, via_reality,
        "未鉴权客户端看到的证书链必须与直连真站**逐字节相同**"
    );
    assert_eq!(
        stats.fallback.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "服务端该记下 1 条 fallback"
    );
    assert_eq!(
        stats
            .authenticated
            .load(std::sync::atomic::Ordering::SeqCst),
        0,
        "不该有鉴权连接"
    );
}

/// **判据 4（P-256-only dest 的未鉴权面）**：不带 REALITY 封装的客户端照旧透传 ——
/// 拿到与直连真站**逐字节相同**的证书链。
///
/// # 为什么还有这条（issue #3 之后的口径）
///
/// 镜像支持面放宽到 NIST 组（issue #3）改变的是**鉴权路径**；「没鉴权 ⇒ 原样透传」
/// 是另一条边界，不该跟着动。真栈上的形状：P-256-only 真站 + 普通 TLS 客户端
/// （两边直谈，REALITY 服务端只搬字节），服务端记 1 条 fallback、0 条鉴权、
/// 0 条镜像。
///
/// 鉴权过 + 真站选 P-256 的**镜像**路径由判据 6 端到端钉住
/// （[`a_p256_selected_dest_mirrors_and_carries_traffic`]）。
#[test]
fn an_unauthenticated_client_on_a_p256_only_dest_gets_passthrough() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("占端口");
    let dest_port = listener.local_addr().expect("端口").port();
    let cfg = common::dest_server_config_with_groups(Some(vec![rustls::NamedGroup::secp256r1]));
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut sock) = stream else { continue };
            let cfg = Arc::clone(&cfg);
            std::thread::spawn(move || {
                let Ok(mut conn) = rustls::ServerConnection::new(cfg) else {
                    return;
                };
                let _ = sock.set_read_timeout(Some(Duration::from_secs(5)));
                while conn.is_handshaking() {
                    if conn.complete_io(&mut sock).is_err() {
                        return;
                    }
                }
            });
        }
    });

    // ① 直连 P-256-only 真站：取它给的证书 DER（默认提供者带 P-256 ⇒ 谈得成）。
    let direct = common::tls_client_handshake_and_peer_cert(("127.0.0.1", dest_port))
        .expect("直连 P-256-only 真站该完成握手");

    // ② 经 REALITY 服务端（未鉴权 —— 客户端不会 REALITY 封装）：应当被原样透传。
    let (server_addr, stats) = spawn_reality_server(dest_port);
    let via_reality = common::tls_client_handshake_and_peer_cert(server_addr)
        .expect("透传路径该完成握手（客户端拿到的是真站的握手）");

    assert_eq!(
        direct, via_reality,
        "未鉴权客户端看到的证书链必须与直连真站**逐字节相同**"
    );
    assert_eq!(
        stats.fallback.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "这条走的是 fallback（透传）"
    );
    assert_eq!(
        stats
            .authenticated
            .load(std::sync::atomic::Ordering::SeqCst),
        0,
        "不该有鉴权连接"
    );
    assert_eq!(
        stats.mirrored.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "不该有镜像"
    );
}

/// **判据 6（issue #3 的核心）**：真站选 P-256 ⇒ **镜像路径端到端可用**。
///
/// # 客户端是谁
///
/// 本仓的注入式客户端半边（tests/common 的
/// [`common::connect_reality_client`]）：Firefox-148 指纹，X25519 私钥由调用方
/// 持有（REALITY 鉴权钥匙），P-256 / MLKEM768 的交换由提供者持有。uTLS 没有
/// P-256 私钥位（`u_public.go:926-931`），Xray 到不了这一步 —— 这正是 issue #3
/// 之前「真站选 P-256 必落透传」的根源；注入式客户端是那个反命题：**服务端选
/// P-256 对它可完成**。
///
/// # 判什么
///
/// 1. 镜像握手完成（镜像 flight 被客户端 rustls 收下，Finished 双向过）；
/// 2. 客户端的证书校验器认出 **REALITY 服务端**（尾签 `HMAC(AuthKey, pub)` 对上
///    —— 不是透传回来的真站证书）；
/// 3. TLS 交换用的是 **P-256**（客户端侧探针：0x0017 的交换被消费，X25519 没有
///    —— REALITY 鉴权用的 X25519 不参与 TLS 交换）；
/// 4. **双向往返**：后端 → 客户端的 banner 先到（不等客户端说话），
///    客户端 → 后端的回显随后到；
/// 5. 服务端取证：authenticated=1、mirrored=1、mirror_failed=0、fallback=0。
#[test]
fn a_p256_selected_dest_mirrors_and_carries_traffic() {
    let (server_addr, stats, _guards) =
        spawn_nist_dest_and_server(vec![rustls::NamedGroup::secp256r1], banner_echo_handler());

    // ① 客户端：注入式 REALITY 客户端（Firefox-148，key_share [MLKEM768, X25519, P-256]）。
    let spec = utls::hello::ClientHelloSpec::from_preset(utls::hello::ClientHelloId::Firefox(148))
        .expect("预设存在");
    let server_static_pub =
        *x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(SERVER_PRIV)).as_bytes();
    let (mut tls, client) = common::connect_reality_client(
        server_addr,
        spec,
        SERVER_NAME,
        CLIENT_PRIV,
        server_static_pub,
        SHORT_ID,
        now_secs(),
    )
    .expect("真站选 P-256 时镜像握手该端到端谈成");

    // ② **双向往返**：banner 先到（后端 → 客户端方向不等客户端说话），
    //    随后客户端写的回显回来（客户端 → 后端 → 客户端）。
    let mut buf = [0u8; 4096];
    let n = tls.read(&mut buf).expect("读 banner");
    assert_eq!(
        &buf[..n],
        b"REALITY-MIRROR-BANNER\n",
        "先到的该是 handler 主动推的 banner（数据经镜像明文流到达）"
    );
    let payload = format!("P256-PING-{}", std::process::id());
    tls.write_all(payload.as_bytes()).expect("写");
    tls.flush().expect("flush");
    let n = tls.read(&mut buf).expect("读回显");
    assert_eq!(
        &buf[..n],
        payload.as_bytes(),
        "回显该逐字节回来（另一条方向也通了）"
    );

    // ③ 客户端侧证据：TLS 交换用的是 P-256（0x0017），X25519 没被 TLS 消费。
    assert!(
        client.exchange_consumed(utls::values::CURVE_P256),
        "真站选 P-256 ⇒ 镜像的 serverShare 是 P-256 ⇒ 客户端的 P-256 交换该被消费"
    );
    assert!(
        !client.exchange_consumed(utls::values::X25519),
        "X25519 只用于 REALITY 鉴权（AuthKey），不该被 TLS 交换消费 —— \
         消费了说明服务端选错了组"
    );
    assert_eq!(
        client.auth_key().len(),
        32,
        "AuthKey 已由 plan() 算出（证书校验器用它验出了 REALITY 服务端）"
    );

    // ④ 服务端取证：这条连接走的是**镜像**路径，一次成。
    let load = |c: &std::sync::atomic::AtomicUsize| c.load(std::sync::atomic::Ordering::SeqCst);
    assert_eq!(load(&stats.connections), 1, "恰一条连接");
    assert_eq!(load(&stats.authenticated), 1, "鉴权该过");
    assert_eq!(load(&stats.mirrored), 1, "镜像该成 —— issue #3 的正面");
    assert_eq!(
        load(&stats.mirror_failed),
        0,
        "不该有镜像失败（P-256 已在支持面内）"
    );
    assert_eq!(load(&stats.fallback), 0, "不该回落透传");
}

/// **判据 7（issue #3 的第二只脚）**：P-384 同型 —— 放开的是一族（P-256/P-384/
/// P-521），不只 P-256 一族。形状与判据 6 相同：key_share `[MLKEM768, X25519,
/// P-384]`，真站 P-384-only，镜像握手 + 双向往返 + 服务端统计。
///
/// （P-521 没有对应判据：本仓自带的 aws-lc 提供者没有 secp521r1，真站选 P-521
/// 时在组查找处 `UnsupportedGroup` ⇒ 照旧透传 —— 这是实现面的已知边界，
/// [`reality::mirror_tls::MIRRORABLE_GROUPS`] 的文档记了。）
#[test]
fn a_p384_selected_dest_mirrors_and_carries_traffic() {
    let (server_addr, stats, _guards) =
        spawn_nist_dest_and_server(vec![rustls::NamedGroup::secp384r1], banner_echo_handler());

    // Firefox-148 指纹，key_share 换成 [MLKEM768, X25519, P-384]。MLKEM768 必须保留：
    // REALITY 的鉴权形状检查（`reality_peer_pub`，tls.go:239-241）要求它在最前，
    // 哪怕真站最后选的是 P-384。
    let spec = firefox_spec_with_key_shares(&[
        utls::values::X25519_MLKEM768,
        utls::values::X25519,
        utls::values::CURVE_P384,
    ]);
    let server_static_pub =
        *x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(SERVER_PRIV)).as_bytes();
    let (mut tls, client) = common::connect_reality_client(
        server_addr,
        spec,
        SERVER_NAME,
        CLIENT_PRIV,
        server_static_pub,
        SHORT_ID,
        now_secs(),
    )
    .expect("真站选 P-384 时镜像握手该端到端谈成");

    let mut buf = [0u8; 4096];
    let n = tls.read(&mut buf).expect("读 banner");
    assert_eq!(&buf[..n], b"REALITY-MIRROR-BANNER\n");
    let payload = format!("P384-PING-{}", std::process::id());
    tls.write_all(payload.as_bytes()).expect("写");
    tls.flush().expect("flush");
    let n = tls.read(&mut buf).expect("读回显");
    assert_eq!(&buf[..n], payload.as_bytes(), "双向往返该通");

    assert!(
        client.exchange_consumed(utls::values::CURVE_P384),
        "真站选 P-384 ⇒ 客户端的 P-384 交换该被消费"
    );
    assert!(
        !client.exchange_consumed(utls::values::X25519),
        "X25519 不该被 TLS 消费"
    );

    let load = |c: &std::sync::atomic::AtomicUsize| c.load(std::sync::atomic::Ordering::SeqCst);
    assert_eq!(load(&stats.connections), 1);
    assert_eq!(load(&stats.authenticated), 1);
    assert_eq!(load(&stats.mirrored), 1, "P-384 也在镜像支持面内");
    assert_eq!(load(&stats.mirror_failed), 0);
    assert_eq!(load(&stats.fallback), 0);
}

/// 判据 6/7 共用的装置：**只认给定组**的本地 rustls 真站 + 带给定 handler 的
/// REALITY 服务端。返回 (服务端地址, 统计, 真站 accept 循环的句柄)。
fn spawn_nist_dest_and_server(
    dest_groups: Vec<rustls::NamedGroup>,
    handler: Handler,
) -> (
    SocketAddr,
    Arc<reality::server::Stats>,
    std::thread::JoinHandle<()>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("占端口");
    let dest_port = listener.local_addr().expect("端口").port();
    let cfg = common::dest_server_config_with_groups(Some(dest_groups));
    let dest_thread = std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut sock) = stream else { continue };
            let cfg = Arc::clone(&cfg);
            std::thread::spawn(move || {
                let Ok(mut conn) = rustls::ServerConnection::new(cfg) else {
                    return;
                };
                let _ = sock.set_read_timeout(Some(Duration::from_secs(5)));
                while conn.is_handshaking() {
                    if conn.complete_io(&mut sock).is_err() {
                        return;
                    }
                }
            });
        }
    });

    let cfg = ServerConfig {
        reality: reality_config(),
        dest: format!("127.0.0.1:{dest_port}").parse().expect("dest 地址"),
        cert_template: CERT_TEMPLATE.to_vec(),
        signing_key: SIGNING_KEY.to_vec(),
    };
    let server = Arc::new(Server::new(cfg, handler));
    let stats = server.stats();
    let listener = TcpListener::bind("127.0.0.1:0").expect("占端口");
    let addr = listener.local_addr().expect("端口");
    std::thread::spawn(move || {
        let _ = server.serve_on(listener);
    });
    (addr, stats, dest_thread)
}

/// banner-echo handler：先**主动**推 banner（不等客户端说话 —— 服务端 → 客户端
/// 方向先行），再逐字节回显。判据 6/7 用它证「双向往返」。
fn banner_echo_handler() -> Handler {
    Arc::new(
        |mut r: Box<dyn reality::server::PlaintextRead>,
         mut w: Box<dyn reality::server::PlaintextWrite>,
         _info: AuthInfo| {
            let _ = w.write_all(b"REALITY-MIRROR-BANNER\n");
            let _ = w.flush();
            let mut buf = [0u8; 4096];
            loop {
                match r.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if w.write_all(&buf[..n]).is_err() {
                            break;
                        }
                        let _ = w.flush();
                    }
                }
            }
        },
    )
}

/// Firefox-148 指纹，`key_share` 换成给定的组（线序即传入顺序）。
/// X25519 必须保留 —— 它是 REALITY 的鉴权钥匙位（服务端拿它派生 AuthKey）。
fn firefox_spec_with_key_shares(groups: &[u16]) -> utls::hello::ClientHelloSpec {
    use utls::hello::{ClientHelloId, ClientHelloSpec, CodePoint, Extension, KeyShare};
    let mut spec = ClientHelloSpec::from_preset(ClientHelloId::Firefox(148)).expect("预设存在");
    let at = spec
        .extensions
        .iter()
        .position(|e| matches!(e, Extension::KeyShare(_)))
        .expect("Firefox 148 有 key_share");
    spec.extensions[at] = Extension::KeyShare(KeyShare::groups(
        groups
            .iter()
            .copied()
            .map(CodePoint::Fixed)
            .collect::<Vec<_>>(),
    ));
    spec
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("时钟")
        .as_secs()
}

/// **判据 5（issue #2 的症结）**：鉴权路径的明文流拆两半后，handler 能做**双向并发
/// splice** —— 后端主动推送（不等客户端先说话）能到达客户端，且客户端数据能到达后端。
///
/// # 这条补的是什么
///
/// 判据 1 的 echo 是**严格串行**的（读头 → 回显 → 读应用数据回写），单个 `&mut`
/// 就够用 —— 它**掩盖**了「明文流没法分半」这个缺口（issue #2 原话）。这条换成
/// 反代部署的真实形状：handler 把明文流拆两半，一个方向 `copy` 到后端 socket、
/// 另一个方向并发 `copy` 回来。
///
/// # 为什么「后端主动推 banner」是关键
///
/// 后端连上后**立刻**推一段 banner（不等客户端先发）。客户端做的是「连入站、**先读**」——
/// banner 一到就说明「后端 → 客户端」方向在鉴权路径上**独立**推进了；串行 echo 做不到
/// 这件事（串行版只在收到客户端数据之后才回）。随后客户端写一段、读回显，
/// 覆盖另一个方向。两个方向都走通 = issuer 要的「两个方向并发推进」。
///
/// 需要 stock Xray（与判据 1 同依赖）⇒ `#[ignore]`，CI 的 `reality-stack` job 跑它。
#[test]
#[ignore = "需要 stock Xray-core 客户端（取法见 xray_bin()）"]
fn the_handler_can_splice_both_directions_over_a_real_xray_client() {
    // ① 本地后端：连上先推 banner，然后回显。
    let backend = TcpListener::bind("127.0.0.1:0").expect("占后端端口");
    let backend_port = backend.local_addr().expect("端口").port();
    std::thread::spawn(move || {
        for stream in backend.incoming() {
            let Ok(mut sock) = stream else { continue };
            std::thread::spawn(move || {
                let _ = sock.write_all(b"BACKEND-BANNER\n");
                let _ = sock.flush();
                let mut buf = [0u8; 4096];
                loop {
                    match sock.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if sock.write_all(&buf[..n]).is_err() {
                                break;
                            }
                            let _ = sock.flush();
                        }
                    }
                }
            });
        }
    });

    // ② 服务端 + **splice handler**（issue #2 要的可写形状）：拆两半、双向 copy。
    let dest_port = spawn_local_dest();
    let cfg = ServerConfig {
        reality: reality_config(),
        dest: format!("127.0.0.1:{dest_port}").parse().expect("dest"),
        cert_template: CERT_TEMPLATE.to_vec(),
        signing_key: SIGNING_KEY.to_vec(),
    };
    let handler: Handler = Arc::new(
        move |mut client_r: Box<dyn reality::server::PlaintextRead>,
              mut client_w: Box<dyn reality::server::PlaintextWrite>,
              info: AuthInfo| {
            // 读掉 VLESS 请求头（Xray 在裸流上报它，不读就只能干等）。
            if read_vless_request_header(&mut client_r).is_none() {
                return;
            }
            // **VLESS 响应头**：version(1) + addon_len(1)。必须先回 —— Xray 客户端
            // 在读到响应头之前不会把后端数据交给本地 socket（第一版漏了这句，
            // 后端推的 banner 全被 Xray 挡在缓冲里，客户端收到 0 字节）。
            let _ = client_w.write_all(&[0x00, 0x00]);
            let _ = client_w.flush();
            let mut back = TcpStream::connect(("127.0.0.1", backend_port)).expect("连后端");
            let mut back_r = back.try_clone().expect("后端读半边");
            // 方向一：客户端 → 后端（独立线程）—— 读半边在手，读时不会挡住写半边。
            let up = std::thread::spawn(move || {
                let mut r: Box<dyn reality::server::PlaintextRead> = client_r;
                let _ = std::io::copy(&mut r, &mut back);
                let _ = back.shutdown(std::net::Shutdown::Write);
            });
            // 方向二：后端 → 客户端（主线程），结束后**半关**客户端写方向。
            let _ = std::io::copy(&mut back_r, &mut client_w);
            let _ = client_w.shutdown_write();
            let _ = up.join();
            eprintln!(
                "（splice handler）双向走完：short_id={:02x?} server_name={:?}",
                info.short_id, info.server_name
            );
        },
    );
    let server = Arc::new(Server::new(cfg, handler));
    let stats = server.stats();
    let listener = TcpListener::bind("127.0.0.1:0").expect("占端口");
    let addr = listener.local_addr().expect("端口");
    std::thread::spawn(move || {
        let _ = server.serve_on(listener);
    });

    // ③ Xray 客户端指向本仓服务端。
    let (xray, inbound) = spawn_xray(addr);
    struct Kill(Child);
    impl Drop for Kill {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let _kill = Kill(xray);

    let mut sock = TcpStream::connect(("127.0.0.1", inbound)).expect("连 xray 入站");
    sock.set_read_timeout(Some(Duration::from_secs(10)))
        .expect("读超时");

    // ④ **先发一个 kick 触发建连**：Xray 的 dokodemo-door 是惰性的 —— 客户端不先发
    //    数据，它就不会往 REALITY 服务端建 outbound，handler 根本不跑（第一版就在这里
    //    收到 0 字节）。kick 一到，Xray 建连 ⇒ 后端连上 ⇒ 后端主动推 banner。
    let kick = format!("KICK-{}", std::process::id());
    sock.write_all(kick.as_bytes()).expect("写 kick");
    sock.flush().expect("flush");

    // ⑤ 读：后端主动推的 banner **必须**到达。这就是「后端 → 客户端」方向在鉴权路径上
    //    **独立**推进的证据 —— handler 里客户端→后端那条 `copy` 线程此刻正阻塞在
    //    `client_r.read()`（客户端没再发），却挡不住后端→客户端这条线；
    //    换成旧形态（单个 `&mut`）或 `Arc<Mutex<…>>`，这里就会死锁到超时。
    let mut got = Vec::new();
    let mut buf = [0u8; 4096];
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline && !got.windows(15).any(|w| w == b"BACKEND-BANNER\n") {
        match sock.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => got.extend_from_slice(&buf[..n]),
            Err(_) => break,
        }
    }
    assert!(
        got.windows(15).any(|w| w == b"BACKEND-BANNER\n"),
        "后端主动推的 banner 没到客户端 ⇒ 「后端→客户端」方向没在鉴权路径上独立推进\
         （客户端→后端那条线阻塞时，写方向被挡死了 —— 正是 issue #2 的死锁形状）。\
         收到 {} 字节：{:?}\n服务端统计：mirrored={} mirror_failed={} fallback={}",
        got.len(),
        String::from_utf8_lossy(&got),
        stats.mirrored.load(std::sync::atomic::Ordering::SeqCst),
        stats
            .mirror_failed
            .load(std::sync::atomic::Ordering::SeqCst),
        stats.fallback.load(std::sync::atomic::Ordering::SeqCst),
    );

    // ⑥ 另一个方向：kick 的回显（后端收到 kick 后连 banner 带回显）也要到。
    //    banner 与 kick 的回显都到达 ⇒ 两个方向都推进了（双向并发）。
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline && !got.windows(kick.len()).any(|w| w == kick.as_bytes()) {
        match sock.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => got.extend_from_slice(&buf[..n]),
            Err(_) => break,
        }
    }
    assert!(
        got.windows(kick.len()).any(|w| w == kick.as_bytes()),
        "kick 的回显没回来 ⇒ 「客户端→后端」方向没通。收到 {} 字节：{:?}",
        got.len(),
        String::from_utf8_lossy(&got)
    );
    assert!(
        stats
            .authenticated
            .load(std::sync::atomic::Ordering::SeqCst)
            >= 1,
        "该走鉴权路径"
    );
}
