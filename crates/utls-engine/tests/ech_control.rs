use rustls::client::{EchConfig, EchMode};
use rustls::crypto::aws_lc_rs::hpke::ALL_SUPPORTED_SUITES;
use rustls::pki_types::{EchConfigListBytes, ServerName};
use rustls::{ClientConfig, ClientConnection, StreamOwned};
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};

fn fetch(host: &str) -> Vec<u8> {
    let out = std::process::Command::new("dig")
        .args(["+short", "-t", "TYPE65", host, "@1.1.1.1"])
        .output()
        .expect("dig");
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    let ech = text
        .split_whitespace()
        .find_map(|t| t.strip_prefix("ech="))
        .expect("ech=");
    let mut v = Vec::new();
    let mut acc = 0u32;
    let mut bits = 0u32;
    for c in ech.bytes() {
        let d = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'-' | b'+' => 62,
            b'_' | b'/' => 63,
            b'=' => break,
            _ => panic!(),
        };
        acc = (acc << 6) | u32::from(d);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            v.push((acc >> bits) as u8);
        }
    }
    v
}

#[test]
#[ignore]
fn control() {
    let host = std::env::var("ECH_HOST").unwrap_or_else(|_| "crypto.cloudflare.com".into());
    let list = fetch(&host);
    eprintln!("配置 {} 字节", list.len());
    let ech =
        EchConfig::new(EchConfigListBytes::from(&list[..]), ALL_SUPPORTED_SUITES).expect("配置");
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    // 注意顺序：`with_ech` 在 `WantsVersions` 上（它会自己定版本）。
    // `ClientConfig::builder()` 直接给到 `WantsVerifier`，而 `with_ech` 在 `WantsVersions` 上
    // —— 所以要显式走 `builder_with_provider`。
    let mut config = ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_ech(EchMode::Enable(ech))
    .expect("ECH 构建器")
    .with_root_certificates(roots)
    .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let cfg = Arc::new(config);
    let name = ServerName::try_from(host.clone()).unwrap();
    let conn = ClientConnection::new(cfg, name).expect("连接");
    let tcp = std::net::TcpStream::connect(format!("{host}:443")).expect("tcp");
    tcp.set_read_timeout(Some(std::time::Duration::from_secs(10)))
        .ok();
    // 记下 rustls 实际发出去的那条 ClientHello —— 那是「能通的对岸」，与我们的比就有方向了。
    let seen = Arc::new(Mutex::new(Vec::new()));
    let mut s = StreamOwned::new(
        conn,
        Tee {
            inner: tcp,
            seen: seen.clone(),
        },
    );
    loop {
        match s.conn.complete_io(&mut s.sock) {
            Ok(_) => {
                if !s.conn.is_handshaking() {
                    break;
                }
            }
            Err(e) => {
                eprintln!("rustls 自己的 ECH 客户端: 握手失败 = {e}");
                eprintln!("ech_status = {:?}", s.conn.ech_status());
                return;
            }
        }
    }
    eprintln!(
        "✅ rustls 自己的 ECH 客户端: 握手完成, ech_status = {:?}",
        s.conn.ech_status()
    );
    let hello = seen.lock().unwrap().clone();
    report_outer(hello, "rustls");
}

/// 从一条外层 ClientHello 里读出 ECH 扩展的关键数字（**公开可读**：外层是明文）。
fn report_outer(rec: Vec<u8>, who: &str) {
    if rec.len() < 10 {
        eprintln!("{who}: 没抓到 ClientHello");
        return;
    }
    let msg = &rec[5..];
    let len = ((msg[1] as usize) << 16) | ((msg[2] as usize) << 8) | msg[3] as usize;
    let body = &msg[4..4 + len];
    let mut p = 2 + 32;
    p += 1 + body[p] as usize;
    let cs = u16::from_be_bytes([body[p], body[p + 1]]) as usize;
    p += 2 + cs;
    p += 1 + body[p] as usize;
    let n = u16::from_be_bytes([body[p], body[p + 1]]) as usize;
    p += 2;
    let region = &body[p..p + n];
    let mut q = 0usize;
    let mut types = Vec::new();
    while q + 4 <= region.len() {
        let ty = u16::from_be_bytes([region[q], region[q + 1]]);
        let bl = u16::from_be_bytes([region[q + 2], region[q + 3]]) as usize;
        types.push(ty);
        if ty == 0xfe0d {
            let e = &region[q + 4..q + 4 + bl];
            let mut r = 1usize; // type byte
            let kdf = u16::from_be_bytes([e[r], e[r + 1]]);
            r += 2;
            let aead = u16::from_be_bytes([e[r], e[r + 1]]);
            r += 2;
            let cid = e[r];
            r += 1;
            let encl = u16::from_be_bytes([e[r], e[r + 1]]) as usize;
            r += 2 + encl;
            let pl = u16::from_be_bytes([e[r], e[r + 1]]) as usize;
            eprintln!(
                "{who}: 外层 ECH: type={} kdf=0x{kdf:04x} aead=0x{aead:04x} config_id=0x{cid:02x} \
                 enc_len={encl} **payload_len={pl}** (⇒ 内层明文 {} 字节)",
                e[0],
                pl - 16
            );
        }
        q += 4 + bl;
    }
    eprintln!(
        "{who}: 外层扩展类型序列 = {types:?} (共 {} 条)",
        types.len()
    );
    let _ = types;
}

/// 只记录客户端→服务端方向的字节（到第一条完整记录为止）。
struct Tee {
    inner: std::net::TcpStream,
    seen: Arc<Mutex<Vec<u8>>>,
}

impl Read for Tee {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.inner.read(buf)
    }
}
impl Write for Tee {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let n = self.inner.write(buf)?;
        let mut seen = self.seen.lock().unwrap();
        seen.extend_from_slice(&buf[..n]);
        Ok(n)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}
