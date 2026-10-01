//! **离线 ECH 判据（服务端那一半）**：让**我们的客户端**与 **uTLS 自己的 ECH 服务端**握手。
//!
//! # 为什么需要这一格
//!
//! ECH 的「接受」需要两台机器：一台会确认的服务器与一个会核对的客户端。
//! 公网端点（`crypto.cloudflare.com` / `defo.ie`）会漂：配置轮换、多后端、行为随版本变
//! （`questions/10` 里那条时好时坏的记录就是这么来的），于是「红了」这件事本身没法定位。
//!
//! uTLS 里**带着**一台能用的 ECH 服务端（`processECHClientHello`，`TestECH` 就是自问自答），
//! 所以判据可以搬回本机：Go 侧起一台监听回环的 uTLS 服务端，我们这边用真的客户端去连，
//! 断言 `ech_status == Accepted` —— 客户端那半边（接受确认的算法、内层转录、密钥调度）
//! 也就一起进了判据，而那正是 `Rejected + cannot decrypt peer's message` 的形状。
//!
//! # 依赖（缺了会**响亮失败**，不静默跳过）
//!
//! - `go`（本机在 `~/.local/go/bin`）；
//! - uTLS 的源码树（默认 `/tmp/utls-ref/utls-master`，可用 `UTLS_REF_DIR` 覆盖）。
//!
//! 与 `end_to_end` / `ech_e2e` 那两组「要真网络」的测试一样，这条默认不跑：
//!
//! ```bash
//! cargo test -p utls-engine --test ech_utls_server -- --ignored --nocapture
//! ```
//!
//! # 它判什么、不判什么
//!
//! 判：**我们的 ECH 提议 + 我们的接受判定** 能通过与参照实现同源的服务器。
//! 不判：公网端点（那要 egress，见 `ech_e2e.rs`）。两者是**互补**的：
//! 这里失败 ⇒ 我们的实现错了；这里通过而公网失败 ⇒ 端点的行为与参照实现不同，
//! 那件事该记在 `questions/` 里、并带着「与参照实现不同」这个前提去谈，而不是当成我们的 bug。

mod common;

use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::sync::Arc;

use rustls::client::EchStatus;
use rustls::pki_types::ServerName;
use rustls::ClientConnection;
use utls::hello::{ClientHelloId, ClientHelloSpec};
use utls_engine::FingerprintClient;

/// uTLS 源码树的位置（探针文件要复制进去跑）。
fn utls_ref_dir() -> std::path::PathBuf {
    std::path::PathBuf::from(
        std::env::var("UTLS_REF_DIR").unwrap_or_else(|_| "/tmp/utls-ref/utls-master".into()),
    )
}

/// 真名（内层 SNI）与公开名（外层 SNI / 证书 / 配置里的 `public_name`）。
const INNER_NAME: &str = "secret.example";
const PUBLIC_NAME: &str = "public.example";

/// 起一台 uTLS 的 ECH 服务端（Go 侧探针），把我们的客户端连上去。
///
/// 返回 `(服务端的 ECHAccepted, 服务端看到的 SNI, 客户端拿到的 ALPN, 客户端的 ech_status)`。
#[test]
#[ignore = "要有 go 与 uTLS 源码树（默认 /tmp/utls-ref/utls-master）：它跑 uTLS 自己的 ECH 服务端"]
fn our_client_completes_ech_against_the_utls_server() {
    let ref_dir = utls_ref_dir();
    if !ref_dir.join("ech.go").exists() {
        panic!(
            "找不到 uTLS 源码树（{}）。这份探针要靠**它自己的**服务端做判据；\
             设 UTLS_REF_DIR 指向解包后的 utls-master，或把它放到默认位置。",
            ref_dir.display()
        );
    }
    // 探针入库在 `crates/utls/tests/fixtures/gen-reference/`，跑之前复制进树里
    // （与 `ech_inner_probe_test.go` 等几个探针同一套用法）。
    let probe = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../utls/tests/fixtures/gen-reference/probes/ech_server_live_test.go");
    std::fs::copy(&probe, ref_dir.join("ech_server_live_test.go"))
        .unwrap_or_else(|e| panic!("复制探针到 {} 失败：{e}", ref_dir.display()));

    // 服务器要用的 ECH 密钥对：**我们生成**（因为配置与密封都在我们这边），
    // 私钥交给服务端 —— 这样「客户端封给谁」与「服务器用哪把钥解」是同一对。
    let suite = common::ech_hpke_suite();
    let (public_key, private_key) = suite.generate_key_pair().expect("生成 ECH 密钥");
    let config_list = common::ech_config_list(&public_key.0, 0x44, &[]);

    let mut child = Command::new("go")
        .args([
            "test",
            "-run",
            "TestProbeECHServerLive",
            "-v",
            "-timeout",
            "120s",
            "-live-config-hex",
            &hex(&config_list[2..]),
            "-live-priv-hex",
            &hex(private_key.secret_bytes()),
            "-live-host",
            PUBLIC_NAME,
        ])
        .current_dir(&ref_dir)
        .env("GOPROXY", "https://goproxy.cn,direct")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("跑不动 go（需要它在 PATH 里）");

    let stdout = child.stdout.take().expect("拿到 stdout");
    let mut lines = BufReader::new(stdout).lines();
    // 等握手信号那一行（`go test` 在 -v 下会立刻透出来；编译可能要几秒）。
    let addr = loop {
        match lines.next() {
            Some(Ok(l)) => {
                if let Some(a) = l.strip_prefix("PROBE listen=") {
                    break a.trim().to_string();
                }
            }
            other => panic!("没等到监听地址就退出了：{other:?}"),
        }
    };

    // ── 我们这边：真客户端 ──
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let client = FingerprintClient::new(
        ClientHelloSpec::from_preset(ClientHelloId::Chrome(70)).expect("预设"),
        provider,
    )
    // 内层放真名、外层放公开名 —— 这正是 ECH 的意义（SNI 不进明文）。
    .with_sni(INNER_NAME)
    .with_alpn(vec![b"h2".to_vec(), b"http/1.1".to_vec()])
    .with_ech(config_list);
    let config = Arc::new(common::client_config_with_verifier(
        client,
        vec![b"h2".to_vec(), b"http/1.1".to_vec()],
        common::shared_verifier(),
        None,
    ));
    let conn = ClientConnection::new(config, ServerName::try_from(PUBLIC_NAME).unwrap())
        .expect("建连接");
    let sock = std::net::TcpStream::connect(&addr).expect("连服务端");
    let mut stream = rustls::StreamOwned::new(conn, sock.try_clone().expect("克隆套接字"));
    // 握手循环自己写：`drive_client` 会吞掉「握手失败」之外的信息，而这里失败时要看状态。
    stream.sock.set_read_timeout(Some(std::time::Duration::from_secs(10))).ok();
    let mut result = Ok(());
    while stream.conn.is_handshaking() {
        if let Err(e) = stream.conn.complete_io(&mut stream.sock) {
            result = Err(e.to_string());
            break;
        }
    }
    let status = stream.conn.ech_status();
    let alpn = stream.conn.alpn_protocol().map(|p| String::from_utf8_lossy(p).to_string());

    // ── 服务端那一半：读它的结论 ──
    let mut server_line = String::new();
    for l in lines {
        let l = l.expect("读服务端输出");
        eprintln!("{l}");
        if l.starts_with("PROBE live ech_accepted=") {
            server_line = l;
            break;
        }
    }
    let _ = child.kill();
    let _ = child.wait();
    let _ = sock.shutdown(std::net::Shutdown::Both);

    assert!(
        matches!(result, Ok(())),
        "握手没走完（客户端侧）：{}；ech_status = {status:?}",
        result.unwrap_err()
    );
    let server_accepted = server_line.contains("ech_accepted=true");
    let server_sni = server_line
        .split("server_name=\"")
        .nth(1)
        .map(|s| s.split('"').next().unwrap_or("").to_string())
        .unwrap_or_default();
    // 判据一（服务器那一半）：它说接受了，而且它看到的是**内层**的真名。
    assert!(server_accepted, "uTLS 的服务端没有接受我们的 ECH 提议：{server_line}");
    assert_eq!(
        server_sni, INNER_NAME,
        "服务端认证的名字该是内层那个真名（ECH 要保护的就是它）：{server_line}"
    );
    // 判据二（客户端那一半）：我们也判定为「接受」。
    assert_eq!(
        status,
        EchStatus::Accepted,
        "服务端接受了 ECH，而我们这边判成了 {status:?} —— \
         这正是在公网端点上看到的形状（`Rejected` + 解不开对端消息）"
    );
    assert_eq!(alpn.as_deref(), Some("h2"), "ALPN 该在 ECH 内层里协商出 h2");
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
