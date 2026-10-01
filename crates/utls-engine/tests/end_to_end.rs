//! **端到端对账**：真的连一台服务器，再拿它**看到的**指纹与我们的断言对账。
//!
//! 默认不跑（要联网）：
//!
//! ```sh
//! cargo test -p utls-engine --test end_to_end -- --ignored --nocapture
//! ```
//!
//! # 为什么这条断言的形状是这样
//!
//! 前面的所有对账都比**字节**（`utls_conformance.rs` 比的是我们产出 vs 参照实现产出）。
//! 编码器把某个扩展体算错，字节对账能抓到；但「我们以为引擎用了我们的字节，
//! 其实引擎自己另建了一条」这种错，字节对账**看不见** —— 只有让服务器看一眼才会暴露。
//! 所以这里断言的是：**服务器观察到的 JA3 == 我们从自己记录的发出去的字节算出的 JA3**。
//!
//! 再加一条更强的：对 `Stable` 预设，那两者还必须等于**台账里的黄金事实**
//! （`fp_<预设>_ja3_md5`，由 `examples/reflect-facts.rs` 离线产出）。
//! 于是三方一致：离线黄金值 = 我们发出去的字节 = 外部观察者看到的。

use utls::hello::{ClientHelloId, ClientHelloSpec};

fn preset(name: &str) -> ClientHelloSpec {
    let id = ClientHelloId::implemented()
        .iter()
        .find(|id| id.name() == name)
        .copied()
        .unwrap_or_else(|| panic!("没有这个预设：{name}"));
    ClientHelloSpec::from_preset(id).unwrap()
}

/// 读根仓库 `FACTS.json` 里那条黄金事实（离线产出）。读不到就返回 `None` —— 不编值。
fn ledger_ja3(preset_name: &str) -> Option<String> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../FACTS.json");
    let text = std::fs::read_to_string(path).ok()?;
    let needle = format!("\"fp_{preset_name}_ja3_md5\"");
    let i = text.find(&needle)?;
    let rest = &text[i..];
    let j = rest.find("\"value\"")?;
    let rest = &rest[j..];
    let k = rest.find(':')?;
    let rest = rest[k + 1..].trim_start();
    let rest = rest.strip_prefix('"')?;
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

fn check(name: &str) {
    let spec = preset(name);
    let stable = spec.variability == utls::hello::Variability::Stable;

    // ⚠️ **重试只覆盖传输层失败**（连不上、读超时），**绝不覆盖断言**。
    // 两者的区别是本质的：「连不上」是外界的抖动，「指纹不一致」是我们的缺陷 ——
    // 后者一旦被重试掩盖，这条测试就变成了一个会自己变绿的装饰。
    // 实测踩到过：两个测试并发连同一台主机时，其中一个会超时。
    let mut last_err = String::new();
    let (hs, body) = 'attempt: {
        for attempt in 1..=3 {
            match utls_engine::http_get(
                spec.clone(),
                "tls.browserleaks.com",
                "tls.browserleaks.com:443",
                "/json",
            ) {
                Ok(v) => break 'attempt v,
                Err(e) => {
                    last_err = format!("{e}");
                    eprintln!("{name}: 第 {attempt} 次连接失败（传输层）：{e}");
                    std::thread::sleep(std::time::Duration::from_secs(2 * attempt));
                }
            }
        }
        panic!("{name}: 连了 3 次都没连上，最后一次：{last_err}");
    };

    let ours = utls::ja3::ja3_of_client_hello(&hs.client_hello);
    println!("{name}: 发出 {} 字节，JA3 {}", hs.client_hello.len(), ours.hash_hex());
    assert!(hs.reached_server, "{name}: 没读到任何响应");

    // 从 JSON 里抠 ja3_hash（不引 JSON 依赖，够用即可）。
    let json = body
        .split_once('{')
        .and_then(|(_, rest)| rest.find("\"ja3_hash\"").map(|i| (i, rest)))
        .map(|(i, rest)| &rest[i..])
        .unwrap_or_else(|| panic!("{name}: 响应里没有 ja3_hash。前 300 字节：\n{}", &body[..body.len().min(300)]));
    let theirs = json
        .split('"')
        .nth(3)
        .unwrap_or_else(|| panic!("{name}: ja3_hash 解析失败"))
        .to_string();

    assert_eq!(
        theirs,
        ours.hash_hex(),
        "{name}: 服务器看到的 JA3 与我们发出的字节不符 —— \
         说明引擎没有原样使用我们产出的 ClientHello"
    );

    if stable {
        if let Some(golden) = ledger_ja3(name) {
            assert_eq!(
                ours.hash_hex(),
                golden,
                "{name}: 与台账里的黄金事实不符 —— 离线产出与真实连接走样了"
            );
            println!("{name}: ✅ 三方一致（离线黄金 = 发出的字节 = 服务器所见）");
        } else {
            println!("{name}: ✅ 服务器所见 == 本地；台账读不到，跳过黄金值这一半");
        }
    } else {
        println!("{name}: ✅ 服务器所见 == 本地（乱序预设，JA3 每次不同，符合预期）");
    }
}

#[test]
#[ignore = "要联网；`cargo test -p utls-engine --test end_to_end -- --ignored`"]
fn stable_preset_matches_the_server_and_the_ledger() {
    check("firefox_148");
}

#[test]
#[ignore = "要联网；`cargo test -p utls-engine --test end_to_end -- --ignored`"]
fn shuffled_preset_matches_the_server() {
    // 乱序预设的 JA3 每次不同，但**服务器看到的必须等于本地算出的那一个**。
    check("chrome_133");
}

/// 走 **uTLS 形状的 API**（`apply_preset_by_id` → `set_sni` → `connect` → `http_get`）
/// 再对一次账 —— 否则新 API 只在离线被测到，没人知道它接得上真实握手。
#[test]
#[ignore = "要联网；`cargo test -p utls-engine --test end_to_end -- --ignored`"]
fn uclient_api_reaches_the_server_and_matches() {
    use utls_engine::UClient;

    // 传输层重试，同 `check`；断言不重试。
    let mut last = String::new();
    for attempt in 1..=3 {
        let built = UClient::new()
            .apply_preset_by_id(utls::hello::ClientHelloId::Chrome(133))
            .unwrap()
            .set_sni("tls.browserleaks.com")
            .set_alpn(vec![b"http/1.1".to_vec()])
            .connect("tls.browserleaks.com", "tls.browserleaks.com:443");
        match built {
            Ok((mut conn, hello)) => {
                let body = conn.http_get("tls.browserleaks.com", "/json").unwrap_or_default();
                assert!(!body.is_empty(), "没读到响应");

                let ours = utls::ja3::ja3_of_client_hello(&hello);
                let json = body
                    .split_once('{')
                    .and_then(|(_, rest)| rest.find("\"ja3_hash\"").map(|i| (i, rest)))
                    .map(|(i, rest)| &rest[i..])
                    .expect("响应里没有 ja3_hash");
                let theirs = json.split('"').nth(3).expect("ja3_hash 解析失败").to_string();
                assert_eq!(
                    theirs,
                    ours.hash_hex(),
                    "走 UClient::apply_preset_by_id 的连接，服务器所见与本地不符"
                );
                println!(
                    "UClient::apply_preset_by_id(Chrome 133)：TLS {:?}，发出 {} 字节，JA3 {} ✅",
                    conn.negotiated_version(),
                    hello.len(),
                    ours.hash_hex()
                );
                return;
            }
            Err(e) => {
                last = format!("{e}");
                eprintln!("第 {attempt} 次连接失败（传输层）：{e}");
                std::thread::sleep(std::time::Duration::from_secs(2 * attempt));
            }
        }
    }
    panic!("连了 3 次都没连上，最后一次：{last}");
}
