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
//! 再加一条更强的：对 `Stable` 预设，那两者还必须等于**内联的黄金值**
//! （`fp_<预设>_ja3_md5`，判据文件里自持）。
//! 于是三方一致：内联黄金值 = 我们发出去的字节 = 外部观察者看到的。

use utls::hello::{ClientHelloId, ClientHelloSpec};

fn preset(name: &str) -> ClientHelloSpec {
    let id = ClientHelloId::implemented()
        .iter()
        .find(|id| id.name() == name)
        .copied()
        .unwrap_or_else(|| panic!("没有这个预设：{name}"));
    ClientHelloSpec::from_preset(id).unwrap()
}

/// 黄金 JA3 MD5（判据文件内联自持 —— 判据自己当权威）。
fn golden_ja3(preset_name: &str) -> Option<String> {
    let md5 = match preset_name {
        "360_11" => "2b3a40903395f08c297cd63b9734cb75",
        "360_7" => "c405bbbe31c0e53ac4c8448355b2af5b",
        "android_11" => "6c0f0a346dcd84cb4b97a0d9382c53fd",
        "chrome_100" => "cd08e31494f9531f560d64c695473da9",
        "chrome_100_psk" => "e1d8b04eeb8ef3954ec4f49267a783ef",
        "chrome_102" => "cd08e31494f9531f560d64c695473da9",
        "chrome_106" => "def317a12dc7ed05a1b27f43af514602",
        "chrome_112_psk" => "3f9ed491ea677a123655db3560fe9dc5",
        "chrome_114_psk" => "6d720efbfea20c5396c1e146b3686ae4",
        "chrome_115_pq" => "0e56ea8d7576172d3325596634e6c05f",
        "chrome_115_psk" => "8813703eeb522d2179bea34fb7b29c05",
        "chrome_120" => "4e9f1c0a7ee4ceec80faed41334e1dcf",
        "chrome_120_pq" => "c99b8581a3e59b0bae7aef14a6e5e3bf",
        "chrome_131" => "8e494a6419f08a68d438dc930b4f951b",
        "chrome_133" => "41a1630b19c58de694b977cc0d783dd7",
        "chrome_58" => "94c485bca29d5392be53f2b8cf7f4304",
        "chrome_62" => "94c485bca29d5392be53f2b8cf7f4304",
        "chrome_70" => "6a958df291c3f2ee216e80434750d4e1",
        "chrome_72" => "66918128f1b9b03303d77c6f2eefd128",
        "chrome_83" => "b32309a26951912be7dba376398abc3b",
        "chrome_87" => "b32309a26951912be7dba376398abc3b",
        "chrome_96" => "cd08e31494f9531f560d64c695473da9",
        "edge_106" => "cd08e31494f9531f560d64c695473da9",
        "edge_85" => "b32309a26951912be7dba376398abc3b",
        "firefox_102" => "579ccef312d18482fc42e2b822ca2430",
        "firefox_105" => "579ccef312d18482fc42e2b822ca2430",
        "firefox_120" => "b5001237acdf006056b409cc433726b0",
        "firefox_148" => "7704a11cf87dfcf33080b90ce11d5527",
        "firefox_55" => "0ffee3ba8e615ad22535e7f771690a28",
        "firefox_56" => "0ffee3ba8e615ad22535e7f771690a28",
        "firefox_63" => "b20b44b18b853ef29ab773e921b03422",
        "firefox_65" => "b20b44b18b853ef29ab773e921b03422",
        "firefox_99" => "6b5e0cfe988c723ee71faf54f8460684",
        "ios_11" => "a69708a64f853c3bcc214c2c5faf84f3",
        "ios_12" => "5c118da645babe52f060d0754256a73c",
        "ios_13" => "6fa3244afc6bb6f9fad207b6b52af26b",
        "ios_14" => "656b9a2f4de6ed4909e157482860ab3d",
        "qq_11" => "cd08e31494f9531f560d64c695473da9",
        "safari_16" => "773906b0efdefa24a7f2b8eb6985bf37",
        "safari_26" => "ecdf4f49dd59effc439639da29186671",
        _ => return None,
    };
    Some(md5.to_string())
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
    println!(
        "{name}: 发出 {} 字节，JA3 {}",
        hs.client_hello.len(),
        ours.hash_hex()
    );
    assert!(hs.reached_server, "{name}: 没读到任何响应");

    // 从 JSON 里抠 ja3_hash（不引 JSON 依赖，够用即可）。
    let json = body
        .split_once('{')
        .and_then(|(_, rest)| rest.find("\"ja3_hash\"").map(|i| (i, rest)))
        .map(|(i, rest)| &rest[i..])
        .unwrap_or_else(|| {
            panic!(
                "{name}: 响应里没有 ja3_hash。前 300 字节：\n{}",
                &body[..body.len().min(300)]
            )
        });
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
        if let Some(golden) = golden_ja3(name) {
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
                let body = conn
                    .http_get("tls.browserleaks.com", "/json")
                    .unwrap_or_default();
                assert!(!body.is_empty(), "没读到响应");

                let ours = utls::ja3::ja3_of_client_hello(&hello);
                let json = body
                    .split_once('{')
                    .and_then(|(_, rest)| rest.find("\"ja3_hash\"").map(|i| (i, rest)))
                    .map(|(i, rest)| &rest[i..])
                    .expect("响应里没有 ja3_hash");
                let theirs = json
                    .split('"')
                    .nth(3)
                    .expect("ja3_hash 解析失败")
                    .to_string();
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
