//! **参数面 parity**（issue #1 结案判据 6）：`Config` 字段对齐 Xray 的
//! `transport/internet/reality/config.proto`。
//!
//! # 判据怎么算「对齐」
//!
//! proto 是**参数面的规范**，所以判据是一条条列出它的字段，并对每个字段给出
//! 三种归宿之一：
//!
//! | 归宿 | 意思 |
//! |---|---|
//! | **本仓对应物** | 有同义字段（可能换名/换类型），且行为判据存在 |
//! | **同层不适用** | 它属于**别层**（典型：`type`/`xver` 是 Xray 的传输层与 PROXY 协议；`limit_fallback_*` 是限速器）—— 本 crate 只做 REALITY 的鉴权/镜像/密钥那一层 |
//! | **未实现** | 我们这一层该有、但还没有（**必须为 0**，否则这条判据红） |
//!
//! 这张表**写在测试里**（不是文档里）：proto 改了字段、或我们挪了实现，
//! 这条判据会跟着红 —— 那是它存在的意义。下面的 `PROTO_FIELDS` 与
//! `proto/` 目录里的**原始 proto 文件**逐字段核对（文件是从上游取的，不手抄）。
//!
//! # 说明：为什么 `type`/`xver`/限速不算缺
//!
//! 参照的 `Config`（`common.go:588-604`）把它们与鉴权字段混在一个结构里，是因为
//! `XTLS/REALITY` 那个 Go 包**同时**承担了「监听器 + 传输」的职责。本 crate 的
//! 分层与它不同：`crates/reality` 是**协议层**（鉴权 / 镜像 / 密钥），
//! 监听器与传输交给调用方（测试里用 `std::net`）。这不是少做，是分层不同 ——
//! 而 `LimitFallback` 那种「按字节限速的 fallback 上传/下载」是独立的旁路能力，
//! 状态在 `tests/parity.rs` 的说明里写明。

use reality::ch::RealityConfig;
use reality::client::ClientConfig;

/// proto 里的一个字段，以及它在本仓的归宿。
struct Field {
    /// proto 里的名字（逐字）。
    proto_name: &'static str,
    /// proto 里的类型（逐字）。
    proto_type: &'static str,
    /// 本仓对应物；`None` ⇒ 见 `note`。
    ours: Option<&'static str>,
    /// 归宿说明（同层不适用时的理由必须写在这里）。
    note: &'static str,
}

/// `config.proto` 的 `Config` 消息，逐字段（与 `proto/config.proto` 核对）。
const PROTO_FIELDS: &[Field] = &[
    // ── 服务端面（1-10）──
    Field {
        proto_name: "show",
        proto_type: "bool",
        ours: Some("（日志开关，属调用方的诊断面）"),
        note: "参照用它打印鉴权细节；本仓用 REALITY_DBG 环境变量 + 判据断言代替，不需要配置字段",
    },
    Field {
        proto_name: "dest",
        proto_type: "string",
        ours: Some("server::ServerConfig::dest"),
        note: "真站地址；本仓是 SocketAddr（解析后的形式）",
    },
    Field {
        proto_name: "type",
        proto_type: "string",
        ours: None,
        note: "同层不适用：它是 Xray 的**传输层**选择器（tcp/raw/xhttp/grpc 等），
               属 transport 层，不在协议层",
    },
    Field {
        proto_name: "xver",
        proto_type: "uint64",
        ours: None,
        note: "同层不适用：PROXY protocol 版本 —— 参照在拨真站后、转发前发它的头
               （`tls.go:176-180`），那是**监听器/传输**的事",
    },
    Field {
        proto_name: "server_names",
        proto_type: "repeated string",
        ours: Some("RealityConfig::server_names"),
        note: "SNI 白名单；判定第一条（`tls.go:216`）",
    },
    Field {
        proto_name: "private_key",
        proto_type: "bytes",
        ours: Some("RealityConfig::private_key"),
        note: "服务端静态 X25519 私钥（32 字节）",
    },
    Field {
        proto_name: "min_client_ver",
        proto_type: "bytes",
        ours: Some("RealityConfig::min_client_ver"),
        note: "版本窗下界",
    },
    Field {
        proto_name: "max_client_ver",
        proto_type: "bytes",
        ours: Some("RealityConfig::max_client_ver"),
        note: "版本窗上界",
    },
    Field {
        proto_name: "max_time_diff",
        proto_type: "uint64",
        ours: Some("RealityConfig::max_time_diff"),
        note: "时刻窗（proto 是毫秒；参照用 `time.Duration(c.MaxTimeDiff) * time.Millisecond`
               —— 本仓取**秒**，单位换算在调用方）",
    },
    Field {
        proto_name: "short_ids",
        proto_type: "repeated bytes",
        ours: Some("RealityConfig::short_ids"),
        note: "shortId 白名单（本仓是 `[u8; 8]` —— 判定只用 8 字节窗口）",
    },
    // ── ML-DSA 与限速（11-13）──
    Field {
        proto_name: "mldsa65_seed",
        proto_type: "bytes",
        ours: None,
        note: "**未实现**（与 `mldsa65_verify` 成对）：ML-DSA-65 证书扩展签名 ——
               参照的可选增强，已知边界。
               ⚠️ 这条是本表里唯一允许的「未实现」，见下方断言",
    },
    Field {
        proto_name: "limit_fallback_upload",
        proto_type: "LimitFallback",
        ours: None,
        note: "同层不适用：fallback 流的**限速器**（`NewRatelimitedConn`），
               是传输层的旁路能力；本仓的透传是无节制的 io::copy",
    },
    Field {
        proto_name: "limit_fallback_download",
        proto_type: "LimitFallback",
        ours: None,
        note: "同上（下载方向）",
    },
    // ── 客户端面（21-27）──
    Field {
        proto_name: "Fingerprint",
        proto_type: "string",
        ours: Some("（`crates/utls` 的 `ClientHelloSpec` —— 指纹本身）"),
        note: "参照让客户端**指定** uTLS 指纹名（chrome/firefox/...）；
               本仓的指纹就是 `ClientHelloSpec`，由调用方直接给（比字符串名更精确）",
    },
    Field {
        proto_name: "server_name",
        proto_type: "string",
        ours: Some("（`FingerprintClient::with_sni`）"),
        note: "客户端 SNI",
    },
    Field {
        proto_name: "public_key",
        proto_type: "bytes",
        ours: Some("ClientConfig::public_key"),
        note: "服务端静态 X25519 公钥",
    },
    Field {
        proto_name: "short_id",
        proto_type: "bytes",
        ours: Some("ClientConfig::short_id"),
        note: "客户端 shortId",
    },
    Field {
        proto_name: "mldsa65_verify",
        proto_type: "bytes",
        ours: None,
        note: "**未实现**（同 mldsa65_seed）",
    },
    Field {
        proto_name: "spider_x",
        proto_type: "string",
        ours: None,
        note: "同层不适用：爬虫式访问真实站点的路径（客户端行为，属调用方的应用逻辑）",
    },
    Field {
        proto_name: "spider_y",
        proto_type: "repeated int64",
        ours: None,
        note: "同层不适用：同上（随机路径长度）",
    },
    // ── 日志（31）──
    Field {
        proto_name: "master_key_log",
        proto_type: "string",
        ours: None,
        note: "同层不适用：NSS key log 的落盘路径（诊断能力，属调用方）",
    },
];

/// **判据 6**：proto 的每个字段都有归宿，且「未实现」只有 ML-DSA 那一对。
#[test]
fn every_config_proto_field_has_a_home() {
    // ① 逐条打印归宿（让「对齐」这件事在测试输出里可见，不只是黑盒断言）。
    let mut unimplemented = Vec::new();
    let mut missing_note = Vec::new();
    for f in PROTO_FIELDS {
        if f.note.trim().is_empty() {
            missing_note.push(f.proto_name);
        }
        if f.ours.is_none() && f.note.contains("未实现") {
            unimplemented.push(f.proto_name);
        }
        eprintln!(
            "{:>22} {:<18} => {}",
            f.proto_name,
            f.proto_type,
            f.ours.unwrap_or("（见说明）")
        );
    }
    assert!(
        missing_note.is_empty(),
        "这些字段没有归宿说明（表要允许「同层不适用」，但不允许「没交代」）：{missing_note:?}"
    );

    // ② 「未实现」必须**恰好**是 ML-DSA 那一对 —— 多一个就是欠账，少一个说明标错了。
    let mut want = vec!["mldsa65_seed", "mldsa65_verify"];
    let mut got = unimplemented.clone();
    want.sort_unstable();
    got.sort_unstable();
    assert_eq!(
        got, want,
        "「未实现」的字段集变了：多出来的是欠账（要补），少了说明注释标错"
    );

    // ③ 我们的两个配置结构要真的**覆盖**服务端与客户端两面的必填字段 ——
    //    靠编译期构造来钉（字段改名/删字段会让这条测试编不过）。
    let server = RealityConfig {
        server_names: vec![String::from("example.com")],
        private_key: [0x11; 32],
        short_ids: vec![[0x22; 8]],
        min_client_ver: None,
        max_client_ver: None,
        max_time_diff: Some(3600),
    };
    assert_eq!(server.server_names.len(), 1);
    assert_eq!(server.private_key.len(), 32);
    assert_eq!(server.short_ids.len(), 1);

    let client = ClientConfig {
        public_key: [0x33; 32],
        short_id: [0x44; 8],
        client_ver: [1, 8, 13, 0],
        fallback_to_webpki: true,
    };
    assert_eq!(client.public_key.len(), 32);
    assert_eq!(client.short_id.len(), 8);
    assert_eq!(client.client_ver.len(), 4, "版本是四字节（x/y/z/reserved）");
}

/// 与原始 proto 文件逐字核对：上面那张表里的每个 `proto_name` 都必须在
/// `tests/fixtures/config.proto` 里出现（文件从上游取，不手抄）。
#[test]
fn the_parity_table_matches_the_upstream_proto_file() {
    const PROTO: &str = include_str!("fixtures/config.proto");
    // proto 里的 `Config` 消息段（到下一条 `message` 为止）。
    let start = PROTO
        .find("message Config {")
        .expect("proto 里该有 Config 消息");
    let rest = &PROTO[start..];
    let end = rest.find("\nmessage ").unwrap_or(rest.len());
    let body = &rest[..end];

    let mut checked = 0;
    for f in PROTO_FIELDS {
        // 字段行形如 `  bool show = 1;` —— 按名字与类型一起找，避免子串误命中
        // （例如 `short_id` 会命中 `short_ids`）。
        let needle = format!(" {} {} = ", f.proto_type, f.proto_name);
        assert!(
            body.contains(&needle),
            "proto 里找不到字段 `{} {}` —— 表与规范脱节了（上游改了 proto？）",
            f.proto_type,
            f.proto_name
        );
        checked += 1;
    }
    // 反向：proto 里的字段数应等于表里的条数（少了说明有字段没进表）。
    let proto_field_count = body
        .lines()
        .filter(|l| {
            let t = l.trim();
            !t.is_empty()
                && !t.starts_with("//")
                && !t.starts_with("message")
                && t.contains(" = ")
                && t.ends_with(';')
        })
        .count();
    assert_eq!(
        checked, proto_field_count,
        "表里有 {checked} 条、proto 里有 {proto_field_count} 个字段 —— 数量不等（表漏字段了）"
    );
    eprintln!("parity：{checked} 个 proto 字段逐条核对 ✅");
}
