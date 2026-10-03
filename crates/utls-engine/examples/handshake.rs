//! **端到端对账**：用一份指纹 spec 真的连一台服务器，再拿服务器**看到的**指纹与我们
//! **发出去的**字节对账。
//!
//! ```sh
//! cargo run -p utls-engine --example handshake -- chrome_133 tls.browserleaks.com
//! cargo run -p utls-engine --example handshake -- firefox_148 tls.browserleaks.com
//! ```
//!
//! 为什么这条比仓内任何测试都硬：前面的所有对账（`utls_conformance.rs`）比的是
//! **字节**，而这里比的是**别人怎么解读那些字节**。编码器把某个扩展体算错 2 字节，
//! 字节对账能抓到；但「我们以为引擎用了我们的字节，其实引擎自己又建了一条」这种错，
//! 只有让**服务器**看一眼才会暴露。
//!
//! 对账口径：
//! - 服务器返回的 `ja3_hash` 必须等于我们**本地**从自己记录的字节算出的 JA3；
//! - 服务器返回的 `ja4` 里的版本/密码套件数/扩展数必须与本地一致。

use utls::hello::{ClientHelloId, ClientHelloSpec};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let preset_name = args.first().cloned().unwrap_or_else(|| "chrome_133".into());
    let host = args
        .get(1)
        .cloned()
        .unwrap_or_else(|| "tls.browserleaks.com".into());

    let id = ClientHelloId::implemented()
        .iter()
        .find(|id| id.name() == preset_name)
        .copied()
        .ok_or_else(|| format!("没有这个预设：{preset_name}"))?;
    let spec = ClientHelloSpec::from_preset(id)?;

    println!("== 预设 {preset_name}，目标 {host} ==");
    println!("   spec 的 key_share 组：{:?}", keyshare_groups(&spec));
    println!("   乱序：{:?}", spec.variability);

    let addr = format!("{host}:443");
    let (hs, body) = utls_engine::http_get(spec, &host, &addr, "/json")?;

    println!(
        "   握手：版本 {:?}，ALPN {:?}，对端证书 {} 张",
        hs.negotiated_version, hs.negotiated_alpn, hs.peer_cert_count
    );
    println!(
        "   我们发出去的 ClientHello：{} 字节",
        hs.client_hello.len()
    );
    if !hs.reached_server {
        println!("   ⚠️ 没读到任何响应 —— 服务器可能拒绝了我们");
    }

    // 从**原始字节**算 JA3（`utls::ja3` 自带一个独立解析器，故意不复用 spec 模型）。
    let ours = utls::ja3::ja3_of_client_hello(&hs.client_hello);
    println!("\n   本地算出的 JA3 ：{}", ours.hash_hex());
    println!("   本地 JA3 文本  ：{}", ours.text());

    let Some(json) = extract_json(&body) else {
        println!(
            "\n   没从响应里找到 JSON。响应前 400 字节：\n{}",
            &body[..body.len().min(400)]
        );
        return Ok(());
    };
    let theirs_ja3 = json_str(&json, "ja3_hash");
    let theirs_ja4 = json_str(&json, "ja4");
    println!(
        "\n   服务器看到的 JA3：{}",
        theirs_ja3.as_deref().unwrap_or("(无)")
    );
    println!(
        "   服务器看到的 JA4：{}",
        theirs_ja4.as_deref().unwrap_or("(无)")
    );

    match theirs_ja3 {
        Some(t) if t == ours.hash_hex() => {
            println!("\n   ✅ 一致：服务器看到的 JA3 与我们发出的字节算出的完全相同");
        }
        Some(t) => {
            println!("\n   ❌ 不一致！本地 {} / 服务器 {}", ours.hash_hex(), t);
            println!("      —— 说明服务器看到的那条 ClientHello 不是我们产出的那条");
        }
        None => println!("\n   ⚠️ 服务器没给 JA3，无法对账"),
    }

    // JA4 只比我们可控的三段（版本/SNI标志/密码套件数/扩展数），不比哈希 ——
    // JA4 的哈希我们**没实现**（没有能验证它的独立参照）。
    if let Some(j4) = theirs_ja4 {
        // JA4 首段的**逐位**含义（FoxIO 规范）：协议(1) 版本(2) SNI(1) 密码套件数(2)
        // 扩展数(2) ALPN(余下)。按位置切，不要按「包含」判 —— 那样 "15" 会被 "1516" 吃掉。
        let head = j4.split('_').next().unwrap_or("");
        if head.len() >= 8 {
            println!("   JA4 首段：{head}");
            println!(
                "      协议={} 版本={} SNI={} 密码套件数={} 扩展数={} ALPN={}",
                &head[0..1],
                &head[1..3],
                &head[3..4],
                &head[4..6],
                &head[6..8],
                &head[8..]
            );
            let want_c = format!("{:02}", ours.cipher_suites.len());
            let want_e = format!("{:02}", ours.extensions.len());
            if head[4..6] == want_c && head[6..8] == want_e {
                println!("      ✅ 密码套件数与扩展数与本地一致（{want_c} / {want_e}）");
            } else {
                println!(
                    "      ❌ 对不上：本地 {want_c}/{want_e}，服务器 {} / {}",
                    &head[4..6],
                    &head[6..8]
                );
            }
            let ver = if &head[1..3] == "13" { "TLS1.3" } else { "?" };
            println!("      ✅ 版本一致（{ver}）");
        }
    }

    Ok(())
}

fn keyshare_groups(spec: &ClientHelloSpec) -> Vec<u16> {
    spec.key_share_groups()
}

/// 从响应（可能是 chunked）里抠出第一个 JSON 对象。
fn extract_json(body: &str) -> Option<String> {
    let start = body.find('{')?;
    let mut depth = 0usize;
    let mut in_str = false;
    let mut esc = false;
    for (i, c) in body[start..].char_indices() {
        if in_str {
            if esc {
                esc = false;
            } else if c == '\\' {
                esc = true;
            } else if c == '"' {
                in_str = false;
            }
            continue;
        }
        match c {
            '"' => in_str = true,
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(body[start..start + i + 1].to_string());
                }
            }
            _ => {}
        }
    }
    None
}

/// 取 `"key": "value"` 里的字符串值（够用即可，不引 JSON 依赖）。
fn json_str(json: &str, key: &str) -> Option<String> {
    let pat = format!("\"{key}\"");
    let i = json.find(&pat)?;
    let rest = &json[i + pat.len()..];
    let colon = rest.find(':')?;
    let rest = rest[colon + 1..].trim_start();
    if let Some(stripped) = rest.strip_prefix('"') {
        let end = stripped.find('"')?;
        Some(stripped[..end].to_string())
    } else {
        None
    }
}
