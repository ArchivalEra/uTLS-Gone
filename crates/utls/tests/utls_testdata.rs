//! **uTLS 自带 `testdata/` 抓包夹具对账** —— 拿上游自己的记录判我们。
//!
//! 与 `utls_conformance.rs` 的区别在于**谁是权威**：那边是「我写的 Go 参照生成器」，
//! 这边是**uTLS 仓库里 `testdata/` 下的录音**，是 uTLS 自己认下的标准答案。
//! 两者覆盖的错误面不同，所以两条都要有。
//!
//! # 权威是谁、为什么它比参照生成器强
//!
//! 参照生成器（`fixtures/gen-reference/`）是我写的：它**调用** uTLS 的公开 API 产出
//! 指纹。所以它能抓「我们抄错了预设」，但抓不到「生成器自己只调了一半 API」。
//! 而 `testdata/` 里的夹具是 uTLS 的**测试套件**自己产出的录音（跑
//! `TestUTLSHandshakeClient*` 时由 `recordingConn` 写下），覆盖的是**完整连接路径**
//! —— 包括 `ApplyConfig` / `SetTLSVers` / `SetClientRandom` / `RemoveSNIExtension`
//! 这些只有走一遍握手才会经过的步骤。本仓那条 SNI 的真 bug 就是这么抓到的。
//!
//! # 夹具的来源与格式
//!
//! 见 `fixtures/utls-testdata/README.md`。格式是 Go 的文本十六进制转储，
//! **每行两组 8 字节**（只读前一组会丢掉一半字节 —— 踩过）。
//!
//! # 对账口径
//!
//! 拿夹具的 `Flow 1`（第一条 ClientHello）与我们产出的**完整握手消息**比，
//! 以下字段必须**逐字节相同**：
//!
//! | 字段 | 为什么可比 |
//! |---|---|
//! | `legacy_version` / 密码套件 / 压缩方法 | 夹具是确定的 |
//! | 扩展的**数量、顺序、类型、体** | 这些夹具的预设全是 `Stable`（Chrome 106 才引入乱序，夹具里没有它） |
//! | 总长（含填充的算术） | 填充由总长决定，而总长不含任何随机值 |
//! | 32 字节客户端随机数 | uTLS 的测试配置是 `Rand: zeroSource{}` ⇒ 夹具里是 32 个零；我们直接给零 |
//! | 32 字节 session id | 同上 ⇒ 夹具里是 32 个零；我们把 `SessionId::Random(32)` 换成 `Fixed(32 个零)`（**这是唯一一处对 spec 的改写**，理由见下） |
//!
//! 折成哨兵的只有**每连接随机**的东西：GREASE 取值、`key_share` 的公钥字节
//! （长度照比）、GREASE-ECH 的体。见 `common::normalize_body`。
//!
//! ## 为什么可以改写 `session_id`
//!
//! uTLS 的 session id 来自 `config.rand()`（`u_parrots.go` 的 `ApplyPreset`：
//! `io.ReadFull(uconn.config.rand(), sessionID[:])`），而那个配置在测试里是
//! `zeroSource{}` —— 即**每连接随机的零**。我们这边它由 `SessionId::Random(32)`
//! 从 seed 抽出来，值必然不同。把它换成 `Fixed(vec![0; 32])` 正是「把同一类
//! 每连接随机量中立掉」，而不是「迁就夹具改 spec」：换成 `Fixed` 之后
//! **长度与内容都与夹具一致**，任何其它字段错一个字节都会红。

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use utls::hello::{ClientHelloId, ClientHelloSpec, HandshakeInputs, SessionId};
use utls::values as v;

mod common;
use common::*;

const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/utls-testdata");

/// uTLS 的 `getUTLSTestConfig()`（`u_conn_test.go:243-256`）里那个 ServerName。
/// 绝大多数夹具的配置都来自它。
const UTLS_TEST_SNI: &str = "foobar.com";

/// `TestUTLSHandshakeClientParrotChrome_58_setclienthello` 里被
/// `SetClientRandom` 钉死的那个随机数（`u_conn_test.go:513`）—— 是**可打印的 ASCII**，
/// 32 字节，逐字节比对过：`b"Custom ClientRandom h^xbw8bf0sn3"`。
const SETCLIENTHELLO_RANDOM: &[u8] = b"Custom ClientRandom h^xbw8bf0sn3";

/// 一个夹具该怎么对账。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Case {
    /// 用预设的 spec 产出。`sni` 是 uTLS 那边测试配置里的 `ServerName`。
    Preset {
        id: ClientHelloId,
        sni: Option<&'static str>,
        /// `RemoveSNIExtension()`：**删掉槽位**，而不是让它变零字节。
        remove_sni: bool,
        /// `Some(..)` ⇒ 夹具里的随机数是被 `SetClientRandom` 钉死的。
        fixed_random: Option<&'static [u8]>,
    },
    /// uTLS 的 `Fingerprinter` 路径：把预设自己的产出**反解**成一个新 spec 再发一遍。
    /// 本仓的等价物是 `from_bytes` + `for_replay`，而 SNI 在反解后是 `Opaque`
    /// （见 `parse` 的契约），所以它与「同一预设 + 那个 SNI」的产出必然相同 ——
    /// 这条就是在**验证这个必然性**。
    Fingerprinted { id: ClientHelloId, sni: Option<&'static str> },
    /// 明确不对账，附理由。**理由必须写在案**：安静的跳过看起来像通过。
    Skip(&'static str),
}

fn preset(s: &str) -> ClientHelloId {
    preset_from_utls_str(s).unwrap_or_else(|| {
        panic!(
            "夹具名里的预设串 {s:?} 不在 `common::preset_from_utls_str` 的表里。\
             上游加了新预设的夹具 —— 去核对 u_parrots.go 再补表，不要放宽这条"
        )
    })
}

/// 从夹具文件名推出该怎么对账。
///
/// 名字是**唯一**的配置来源：uTLS 的 `clientTest.name` 由
/// `"UTLS-" + 密码套件 + "-" + hello.helloName() + 后缀` 拼成，而 `helloName()` 就是
/// `ClientHelloID.Str()`（例如 `Chrome-70`）。所以「预设」直接从名字尾部读出来，
/// 不需要手抄一张 55 行的表 —— 手抄的表会漂，而名字不会。
fn classify(name: &str) -> Case {
    // ── 名字里带不了配置的那几条，逐个点名 ──
    if name == "Client-TLSv13-UTLS-HelloRetryRequest-Chrome-70" {
        // `TestUTLSHelloRetryRequest`（u_conn_test.go:174-188）用的是 `testConfig.Clone()`，
        // 而 `testConfig`（handshake_test.go:458）**不设 ServerName** ⇒ SNI 为空 ⇒
        // 那条扩展零字节、不写出去（`hostnameInSNI("") == ""`）。
        // 这正是先前被误判成「夹具 provenance 不明」的那一条：**是我们错、夹具对**。
        return Case::Preset {
            id: preset("Chrome-70"),
            sni: Some(""),
            remove_sni: false,
            fixed_random: None,
        };
    }
    if name == "Client-TLSv12-UTLS-setclienthello-ECDHE-RSA-AES128-GCM-SHA256-Chrome-58" {
        return Case::Preset {
            id: preset("Chrome-58"),
            sni: Some(UTLS_TEST_SNI),
            remove_sni: false,
            fixed_random: Some(SETCLIENTHELLO_RANDOM),
        };
    }
    if name.contains("setclienthello") {
        // 剩下的这条是 `…-Chrome-58setclienthello`（后缀黏在预设串上）。当前源码里
        // **没有任何测试**构造这个名字（`helloName()` 只会返回 `ClientHelloID.Str()`，
        // 而 `Str()` 不带这个后缀）。它是更早版本测试留下的录音：长度 188，与现在
        // 230 字节的 Chrome-58 完全不同。拿它当判据等于拿一个过期的答案判我们。
        return Case::Skip(
            "当前源码里没有测试构造这个名字，且长度（188）与现行 Chrome-58 的 230 不符 —— \
             是从前某个版本留下的录音，不是现行行为的判据",
        );
    }
    if name.contains("raw-capture-fingerprinted") {
        return Case::Skip(
            "uTLS 的 `Fingerprinter` 会把捕获里的 SNI 丢掉、由 `config.ServerName` 重新填上，\
             并重算填充 —— 复现它需要「把反解出的 Opaque SNI 换回 ServerName 槽位」这一步。\
             该捕获本身（u_fingerprinter_test.go:695 的内联十六进制）已经作为\
             `real_world_client_hello_round_trips` 单独对账，覆盖更强",
        );
    }

    // ── 后缀 ──
    let (base, suffix) = ["-fingerprinted", "-OmitSNI", "-ServerNameIP", "-EmptyServerName"]
        .iter()
        .find_map(|s| name.strip_suffix(s).map(|b| (b, Some(*s))))
        .unwrap_or((name, None));

    // 预设串是去掉后缀之后的**尾部**：`…-ECDHE-RSA-AES128-GCM-SHA256-Chrome-70`。
    let token = ["Chrome-58", "Chrome-70", "Firefox-55", "Firefox-63", "Golang-0"]
        .into_iter()
        .find(|t| base.ends_with(t))
        .unwrap_or_else(|| {
            panic!(
                "夹具 {name:?} 的尾部不是任何一个已知预设串（已去掉后缀 {suffix:?}）。\
                 上游改名了或加了新预设 —— 去核对 u_parrots.go 的 `ClientHelloID.Str()`"
            )
        });
    let id = preset(token);
    if id == ClientHelloId::Golang {
        return Case::Skip(
            "HelloGolang 在本架构里没有 spec（`SpecError::EngineDefined`）：它的意思是\
             「用引擎自己的 ClientHello」，对应 rustls 自己那套，不属于本 crate 的指纹层",
        );
    }

    match suffix {
        Some("-fingerprinted") => {
            // `u_fingerprinter_test.go:519/554`：`serverName := "foobar"`（不是
            // `getUTLSTestConfig` 的 `"foobar.com"`），配置是**新造**的
            // `getUTLSTestConfig()` 再 `newConfig.ServerName = serverName`。
            Case::Fingerprinted { id, sni: Some("foobar") }
        }
        Some("-OmitSNI") => {
            // `TestUTLSRemoveSNIExtension`（u_conn_test.go:191）：配置仍是
            // `getUTLSTestConfig()`（SNI `foobar.com`），但 SNI **槽位被删掉**。
            Case::Preset {
                id,
                sni: Some(UTLS_TEST_SNI),
                remove_sni: true,
                fixed_random: None,
            }
        }
        Some("-ServerNameIP") => Case::Preset {
            id,
            sni: Some("1.1.1.1"),
            remove_sni: false,
            fixed_random: None,
        },
        Some("-EmptyServerName") => Case::Preset {
            id,
            sni: Some(""),
            remove_sni: false,
            fixed_random: None,
        },
        None => Case::Preset {
            id,
            sni: Some(UTLS_TEST_SNI),
            remove_sni: false,
            fixed_random: None,
        },
        Some(other) => unreachable!("未处理的后缀 {other}"),
    }
}

/// 按 `Case` 造出「我们应该发出的那条 ClientHello」以及它的输入。
fn build(case: Case) -> (ClientHelloSpec, HandshakeInputs) {
    let id = match case {
        Case::Preset { id, .. } | Case::Fingerprinted { id, .. } => id,
        Case::Skip(r) => panic!("Skip 的夹具不该走到 build：{r}"),
    };
    let mut spec = ClientHelloSpec::from_preset(id).unwrap_or_else(|e| panic!("{id}: {e}"));

    // 夹具那边的 session id 来自 `config.rand() == zeroSource{}` ⇒ 32 个零。
    // 换成 `Fixed` 是把「每连接随机的零」这件事中立掉，理由见文件头。
    if matches!(spec.session_id, SessionId::Random(_)) {
        spec.session_id = SessionId::Fixed(vec![0u8; 32]);
    }
    if case.remove_sni_flag() {
        assert!(spec.remove_server_name(), "{id}: spec 里没有 server_name 槽位可删");
    }

    let sni = case.sni();
    let mut inputs = canonical_inputs(&spec, sni);
    // 夹具的 `Rand: zeroSource{}` 意味着客户端随机数是 32 个零（`setclienthello`
    // 那条是被 `SetClientRandom` 钉死的 ASCII）。
    inputs.client_random = match case.fixed_random() {
        Some(r) => {
            assert_eq!(r.len(), 32, "钉死的随机数必须是 32 字节");
            let mut a = [0u8; 32];
            a.copy_from_slice(r);
            a
        }
        None => [0u8; 32],
    };
    (spec, inputs)
}

impl Case {
    fn sni(self) -> Option<&'static str> {
        match self {
            Case::Preset { sni, .. } | Case::Fingerprinted { sni, .. } => sni,
            Case::Skip(_) => None,
        }
    }
    fn fixed_random(self) -> Option<&'static [u8]> {
        match self {
            Case::Preset { fixed_random, .. } => fixed_random,
            _ => None,
        }
    }
    fn remove_sni_flag(self) -> bool {
        matches!(self, Case::Preset { remove_sni: true, .. })
    }
}

// ── Go 文本十六进制转储 ─────────────────────────────────────────────────────

/// 取夹具文件第 `flow` 条记录里的 **ClientHello 握手消息**（去掉记录头）。
///
/// Go 的转储每行是 `偏移 8 字节 8 字节 |ASCII|` —— **两组 8 字节**。
/// 只按第一组抓会丢掉后半行（踩过：对账里一半字节凭空消失，而看起来只是「不匹配」）。
///
/// 为什么要按记录扫而不是直接取 `[5..]`：**第二飞（`Flow 3`）前面还有一个兼容用的
/// ChangeCipherSpec**（`14 03 03 00 01 01`，RFC 8446 §4.1.2 的中间盒兼容措施），
/// 所以握手记录不在偏移 0。取「内容类型是 0x16 且长度正好吃掉剩余字节」的那条。
fn flow_client_hello(text: &str, flow: u32) -> Vec<u8> {
    let mut record: Vec<u8> = Vec::new();
    let mut want = false;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix(">>> Flow ") {
            let n: u32 = rest
                .split_whitespace()
                .next()
                .and_then(|s| s.parse().ok())
                .unwrap_or_else(|| panic!("Flow 头认不出来：{line:?}"));
            if n == flow {
                want = true;
            } else if want {
                break; // 只要这一条
            }
            continue;
        }
        if !want {
            continue;
        }
        let hex_part = line.split('|').next().unwrap();
        for tok in hex_part.split_whitespace() {
            if tok.len() == 2 && tok.bytes().all(|b| b.is_ascii_hexdigit()) {
                record.push(u8::from_str_radix(tok, 16).expect("十六进制"));
            }
        }
    }
    assert!(!record.is_empty(), "夹具的 Flow {flow} 里没读到字节");

    // 扫出那条「正好吃掉剩余字节」的握手记录。
    for i in 0..record.len().saturating_sub(4) {
        if record[i] != 0x16 {
            continue;
        }
        let len = u16::from_be_bytes([record[i + 3], record[i + 4]]) as usize;
        if i + 5 + len == record.len() {
            return record[i + 5..].to_vec();
        }
    }
    panic!(
        "Flow {flow} 里没找到一条长度自洽的握手记录（{} 字节，开头 {:02x?}）",
        record.len(),
        &record[..record.len().min(8)]
    )
}

fn fixture_files() -> BTreeMap<String, PathBuf> {
    let dir = Path::new(DIR);
    let mut out = BTreeMap::new();
    for e in std::fs::read_dir(dir).unwrap_or_else(|e| panic!("读不到夹具目录 {DIR}：{e}")) {
        let p = e.expect("目录项").path();
        if !p.is_file() {
            continue;
        }
        let name = p.file_name().unwrap().to_string_lossy().to_string();
        // 目录里的**说明**不是夹具（`README.md` 记的是出处与口径）。
        // 除此之外的意外文件必须响：安静地忽略会让「上游换了个命名」变成静默地少比一条。
        if name.ends_with(".md") || name.starts_with('.') {
            continue;
        }
        assert!(
            name.starts_with("Client-TLSv1"),
            "夹具目录里出现了预期外的文件 {name:?}：它既不是 `Client-TLSv1*` 夹具、\
             也不是说明文件。要么把它移走，要么明确它的对账口径"
        );
        out.insert(name, p);
    }
    assert!(!out.is_empty(), "夹具目录是空的 —— 空不是通过");
    out
}

// ── 对账 ────────────────────────────────────────────────────────────────────

/// 逐字段比，好让失败信息**指名字段**而不是甩两个 500 字节的数组。
fn assert_same_hello(fixture_name: &str, ours: &[u8], theirs: &[u8]) {
    let a = layout(ours);
    let b = layout(theirs);
    let ctx = |what: &str| format!("{fixture_name}: {what}");

    assert_eq!(
        a.legacy_version, b.legacy_version,
        "{}",
        ctx("legacy_version（夹具 vs 我们）")
    );
    assert_eq!(a.random, b.random, "{}", ctx("客户端随机数"));
    assert_eq!(a.session_id, b.session_id, "{}", ctx("session id"));
    // 密码套件里的 GREASE 取值每连接都不同（它的用途就是这个），折成哨兵再比：
    // **位置、数量与其余取值**仍然逐序严比。
    assert_eq!(
        normalize_u16_list(&a.cipher_suites),
        normalize_u16_list(&b.cipher_suites),
        "{}",
        ctx("密码套件（含顺序；GREASE 折成同一个哨兵）")
    );
    assert_eq!(
        a.compression_methods, b.compression_methods,
        "{}",
        ctx("压缩方法")
    );

    // 扩展：先比数量与类型（顺序敏感），再逐条比**体**（掩掉每连接随机的部分）。
    // GREASE 扩展**自身**的类型也每连接不同，所以类型序列先折成哨兵；
    // 但「哪一个是空体、哪一个带 1 字节」仍由下面的体比较钉住。
    let (ta, tb): (Vec<u16>, Vec<u16>) = (
        a.extensions.iter().map(|(t, _)| normalize_ext_type(*t)).collect(),
        b.extensions.iter().map(|(t, _)| normalize_ext_type(*t)).collect(),
    );
    assert_eq!(
        ta, tb,
        "{}",
        ctx("扩展类型序列（数量/顺序）—— 第一个不同的位置见两侧数组")
    );
    let mut compared = 0usize;
    for (i, ((ty, ab), (_, bb))) in a.extensions.iter().zip(b.extensions.iter()).enumerate() {
        let na = normalize_body(*ty, ab);
        let nb = normalize_body(*ty, bb);
        assert_eq!(
            na,
            nb,
            "{}",
            ctx(&format!(
                "第 {i} 条扩展（类型 {ty} = 0x{ty:04x}）的体不同：\
                 我们 {} 字节 / 夹具 {} 字节",
                ab.len(),
                bb.len()
            ))
        );
        compared += 1;
    }
    assert!(compared > 0, "{}", ctx("一条扩展都没比到"));
    assert_eq!(
        ours.len(),
        theirs.len(),
        "{}",
        ctx("整条 ClientHello 的长度（填充算术或某个体的长度错了）")
    );
}

/// 主对账：夹具目录里的每一条都必须有一个明确归属（比过 / 有理由地跳过），
/// 且**比过的那些必须逐字节相同**。
#[test]
fn every_utls_testdata_fixture_matches_or_is_explicitly_skipped() {
    let files = fixture_files();
    let mut compared = 0usize;
    let mut skipped: Vec<(String, &'static str)> = Vec::new();
    let mut seen_cases: BTreeMap<&'static str, usize> = BTreeMap::new();

    for (name, path) in &files {
        // ── 上游的空录音 ──
        // 有 5 个夹具在**上游仓库里就是 0 字节**（`ls -l` 可验）。理由：uTLS 的测试
        // 先 `O_CREATE|O_TRUNC` 打开录音文件，再跑握手，握手失败时 `t.Fatalf` 直接
        // 退出、录音没写 —— 留下一个 0 字节文件并被提交进仓库。
        // 这条按**文件事实**判，而不是按名字列表判：上游哪天把它填上了，
        // 这里会自动开始比它，不需要谁来改表。
        if std::fs::metadata(path).expect("stat").len() == 0 {
            skipped.push((
                name.clone(),
                "上游仓库里这个文件就是 0 字节（测试在写录音前就退出了）—— 没有 Flow 1 可比",
            ));
            continue;
        }
        let case = classify(name);
        match case {
            Case::Skip(reason) => {
                skipped.push((name.clone(), reason));
                continue;
            }
            Case::Preset { .. } | Case::Fingerprinted { .. } => {}
        }
        let text = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("读 {name} 失败：{e}"));
        let theirs = flow_client_hello(&text, 1);
        let (spec, inputs) = build(case);
        let ours = spec
            .marshal(&inputs)
            .unwrap_or_else(|e| panic!("{name}: marshal 失败：{e}"))
            .into_bytes();

        // 夹具里的 `Flow 1` 是**记录**（5 字节头 + 握手消息）；上面已去掉头。
        assert_same_hello(name, &ours, &theirs);

        let key = match case {
            Case::Preset { remove_sni: true, .. } => "Preset(OmitSNI)",
            Case::Preset { fixed_random: Some(_), .. } => "Preset(钉死随机数)",
            Case::Preset { sni: Some(""), .. } => "Preset(SNI 空)",
            Case::Preset { sni: Some("1.1.1.1"), .. } => "Preset(SNI 是 IP)",
            Case::Preset { .. } => "Preset",
            Case::Fingerprinted { .. } => "Fingerprinted",
            Case::Skip(_) => unreachable!(),
        };
        *seen_cases.entry(key).or_default() += 1;
        compared += 1;
    }

    // ── 计数：夹具集合变了就要有人来看一眼 ──
    // 不写死 55：那是个「上游加一条就变红」的魔法数。改成断言**每一类都还在**，
    // 以及「比过的数量 + 跳过的数量 == 目录里的文件数」（这条是结构的，不会漂）。
    assert_eq!(
        compared + skipped.len(),
        files.len(),
        "有夹具既没比也没跳过 —— 分类漏了一条"
    );
    // 跳过必须是**少数**：这条挡的是「分类写歪了，于是大半夹具被悄悄跳过」。
    // 用比例而不是魔法数 —— 上游加夹具时这里不该红。
    assert!(
        compared * 2 >= files.len(),
        "比过的夹具只有 {compared} 条，而目录里有 {} 个文件 —— 跳过成了多数，\
         分类多半写歪了",
        files.len()
    );
    for must in ["Preset", "Preset(SNI 空)", "Preset(SNI 是 IP)", "Preset(OmitSNI)", "Fingerprinted"] {
        assert!(
            seen_cases.contains_key(must),
            "没有任何夹具落在 {must} 这一类里 —— 那一类行为现在没人验了。\
             已比类别：{seen_cases:?}"
        );
    }
    assert!(
        skipped.iter().all(|(_, r)| !r.is_empty()),
        "跳过必须带理由（空理由等于安静的通过）"
    );

    // 让跳过清单每次都打出来：它是**结论**，不是日志。
    eprintln!("── uTLS testdata 对账：比过 {compared} 条，跳过 {} 条 ──", skipped.len());
    for (n, r) in &skipped {
        eprintln!("  跳过 {n}\n       理由：{r}");
    }
    for (k, n) in &seen_cases {
        eprintln!("  比过 {k}：{n} 条");
    }
}

/// `-OmitSNI` 与「SNI 为空」在同一预设上**产物逐字节相同**（对 `Stable` 预设）。
///
/// 这不是巧合而是两条机制的必然：删掉槽位 vs 留下零字节的槽位，对 `Stable` 预设
/// 来说后者不占长度、前者少一个恒等置换下的元素 —— 结果一样。
/// uTLS 自带的 `…-Chrome-70-OmitSNI` 与 `…-Chrome-70-EmptyServerName` 两条夹具
/// **逐字节相同**，就是这件事的观测证据。
///
/// 对 `Shuffled` 预设两者**必须不同**（少一个槽位就少一次抽取）—— 这半边才是
/// 真正的守卫：它证明「零字节槽位仍参与洗牌」这条语义没被简化掉。
#[test]
fn omitting_the_sni_slot_equals_an_empty_sni_only_when_stable() {
    let stable = ClientHelloSpec::from_preset(ClientHelloId::Chrome(70)).unwrap();
    assert_eq!(stable.variability, utls::hello::Variability::Stable);
    let empty = canonical_inputs(&stable, Some(""));
    let mut removed = stable.clone();
    assert!(removed.remove_server_name());
    let a = stable.marshal(&empty).unwrap().into_bytes();
    let b = removed.marshal(&empty).unwrap().into_bytes();
    assert_eq!(a, b, "Stable 预设上「删掉 SNI 槽位」与「SNI 为空」该逐字节相同");

    let shuffled = ClientHelloSpec::from_preset(ClientHelloId::Chrome(106)).unwrap();
    assert_eq!(shuffled.variability, utls::hello::Variability::Shuffled);
    let mut removed_shuffled = shuffled.clone();
    assert!(removed_shuffled.remove_server_name());
    let a = shuffled.marshal(&canonical_inputs(&shuffled, Some(""))).unwrap().into_bytes();
    let b =
        removed_shuffled.marshal(&canonical_inputs(&shuffled, Some(""))).unwrap().into_bytes();
    assert_ne!(
        a, b,
        "Shuffled 预设上两者必须不同：删掉槽位会少一次洗牌抽取。\
         相同就说明「零字节槽位仍参与洗牌」这条语义没实现"
    );
}

/// **HRR 第二飞**：夹具的 `Flow 3` 就是 uTLS 发出的第二条 ClientHello。
///
/// 这是本仓唯一一条**上游录下的第二飞**判据。它同时验两件事：
///
/// 1. 我们的第二飞与夹具逐字节相同（除了掩掉的 GREASE 与公钥字节）；
/// 2. **RFC 8446 §4.1.2 的那条约束**：第二飞只许改 `key_share` / `cookie` / PSK / padding，
///    其余逐字节不变 —— 这条先对**夹具**成立（否则说明我理解错了），再对**我们**成立。
///    第 2 条是关键：它意味着「复用同一份 `HandshakeInputs`」不是一句风格建议，
///    而是可被判据抓住的行为（GREASE 与乱序都是从那份输入里抽的）。
#[test]
fn hello_retry_second_flight_matches_the_recording() {
    const NAME: &str = "Client-TLSv13-UTLS-HelloRetryRequest-Chrome-70";
    let path = Path::new(DIR).join(NAME);
    let text = std::fs::read_to_string(&path).expect("读夹具");
    let first = flow_client_hello(&text, 1);
    let second = flow_client_hello(&text, 3);

    // uTLS 的 `TestUTLSHelloRetryRequest` 让 openssl 用 P-256，于是服务器回 HRR 要 P-256。
    let (spec, inputs) = build(classify(NAME));
    let retry = spec.for_hello_retry(v::CURVE_P256).expect("第二飞的 spec");

    // ⚠️ 第二飞**复用同一份输入**：`canonical_inputs*` 是 `(spec, sni, seed)` 的纯函数，
    // 两次都用同一个 seed 与同一个 SNI，所以 marshal 起手时随机流的状态相同 ——
    // GREASE 与乱序因此与第一飞完全一致（这正是 RFC 要求的那件事）。
    // 客户端随机数**逐字节复用**（RFC 8446 §4.1.2 要求；`build` 给的就是夹具里那 32 个零）。
    let ours_first = spec.marshal(&inputs).unwrap().into_bytes();
    let mut retry_inputs = canonical_inputs(&retry, inputs.sni.as_deref());
    retry_inputs.client_random = inputs.client_random;
    let ours_second = retry.marshal(&retry_inputs).unwrap().into_bytes();

    // ── 1. 与夹具逐字节比 ──
    assert_same_hello(NAME, &ours_first, &first);
    assert_same_hello(&format!("{NAME} 的第二飞"), &ours_second, &second);

    // ── 2. 「只改 key_share 与 padding」这条约束：先验夹具，再验我们 ──
    for (who, a, b) in
        [("夹具", &first[..], &second[..]), ("我们", &ours_first[..], &ours_second[..])]
    {
        let la = layout(a);
        let lb = layout(b);
        assert_eq!(la.legacy_version, lb.legacy_version, "{who}: 第二飞改了 legacy_version");
        assert_eq!(la.random, lb.random, "{who}: 第二飞改了客户端随机数（RFC 禁止）");
        assert_eq!(la.session_id, lb.session_id, "{who}: 第二飞改了 session id（RFC 禁止）");
        assert_eq!(la.cipher_suites, lb.cipher_suites, "{who}: 第二飞改了密码套件（RFC 禁止）");
        assert_eq!(
            la.compression_methods, lb.compression_methods,
            "{who}: 第二飞改了压缩方法（RFC 禁止）"
        );
        assert_eq!(
            a.len(),
            b.len(),
            "{who}: 第二飞的总长变了（填充该让出 key_share 长出来的那部分）"
        );
        let (ta, tb): (Vec<u16>, Vec<u16>) = (
            la.extensions.iter().map(|(t, _)| normalize_ext_type(*t)).collect(),
            lb.extensions.iter().map(|(t, _)| normalize_ext_type(*t)).collect(),
        );
        assert_eq!(ta, tb, "{who}: 第二飞改了扩展的类型序列（含顺序）");
        for (i, ((ty, ba), (_, bb))) in la.extensions.iter().zip(lb.extensions.iter()).enumerate() {
            if *ty == v::EXT_KEY_SHARE || *ty == v::EXT_PADDING {
                continue;
            }
            assert_eq!(
                ba, bb,
                "{who}: 第二飞改了第 {i} 条扩展（类型 {ty}）—— RFC 只允许改 \
                 key_share / cookie / PSK / padding"
            );
        }
    }

    // ── 3. 夹具里这一对差异的**具体形状**：key_share 只剩 P-256 一项 ──
    let ks = |h: &[u8]| -> Vec<u8> {
        layout(h).extensions.iter().find(|(t, _)| *t == v::EXT_KEY_SHARE).unwrap().1.to_vec()
    };
    let first_ks = ks(&first);
    let second_ks = ks(&second);
    assert_ne!(first_ks, second_ks, "夹具的第二飞该换了 key_share");
    assert_eq!(
        &second_ks[..4],
        &[0x00, 0x45, 0x00, 0x17],
        "夹具的第二飞 key_share 该只有 P-256 一项（列表长 0x45、组 0x0017）"
    );
    assert_eq!(
        ks(&ours_second).len(),
        second_ks.len(),
        "我们的 key_share 体长该与夹具相同（65 字节公钥 ⇒ 71 字节）"
    );
}

/// uTLS 测试里内联的那条**真实世界捕获**的 ClientHello：反解再重发必须逐字节相同。
///
/// 这是唯一一条**不是我们造的**输入：它来自 u_fingerprinter_test.go:695 的
/// `byteString`（一个真浏览器发给 `people-pa.clients6.google.com` 的握手，31 字符 SNI、
/// `record_size_limit`、`padding(143)`、12 条扩展、18 个密码套件）。
/// 它比我们自己的往返测试强，因为它的形状不是我们编码器的形状。
#[test]
fn real_world_client_hello_round_trips() {
    let path = Path::new(DIR).parent().unwrap().join("raw-capture.bin");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("读不到 {}：{e}", path.display()));
    let capture = decode_hex(text.trim());
    // 捕获本身是**记录**（`16 03 01 …`），去掉 5 字节记录头就是握手消息。
    assert_eq!(capture[0], 0x16, "捕获不是握手记录");
    let rec_len = u16::from_be_bytes([capture[3], capture[4]]) as usize;
    assert_eq!(rec_len + 5, capture.len(), "捕获的记录长度与实际不符");
    let hello = &capture[5..];

    let spec = ClientHelloSpec::from_bytes(hello).unwrap_or_else(|e| panic!("反解失败：{e}"));
    let replay = HandshakeInputs::for_replay(hello).expect("回放输入");
    let again = spec.marshal(&replay).unwrap().into_bytes();
    assert_same_hello("raw-capture.bin（uTLS 测试内联的真实捕获）", &again, hello);
}
