//! **镜像服务端** —— 鉴权路径的服务端半边，以及 fallback 透传。
//!
//! # 参照的形状（`tls.go:200-430`）
//!
//! REALITY 的监听器同时握住**两条下连**：客户端 `underlying` 与真站 `target`。
//! 它干两件事：
//!
//! 1. 读客户端的 ClientHello —— 鉴权（见 [`crate::ch::decide`]）；
//! 2. **把客户端的原始 hello 原样转发给真站**，读回真站的 ServerHello / CCS /
//!    加密 flight，逐记录校验形状（`tls.go:330-410`）。
//!
//! 鉴权通过时，它用**自己**的握手状态机（密钥来自「客户端 key share × 服务端
//! 新生成的临时 X25519」，普通 TLS 1.3 调度 —— 见 `handshake_server_tls13.go:104-120`）
//! 生成回给客户端的 ServerHello/EE/Cert/Finished，其中：
//! * ServerHello 的 `serverShare` 是**新生成的**密钥（真站的那个被丢弃）；
//! * 其余记录（CCS / 证书链字节）来自真站 —— 客户端因此看到**真站的真证书**
//!   （这就是「镜像」的含义：证书是真的，但会话密钥由 REALITY 服务端掌控）；
//! * 证书的签名位被覆写为 `HMAC-SHA512(AuthKey, ed25519_pub)`
//!   （`handshake_server_tls13.go:149-151`）。
//!
//! 鉴权失败时，双向字节泵：客户端 ↔ 真站，REALITY 服务端**不解释**任何内容。
//!
//! # 本模块做什么（以及为什么这样切）
//!
//! 完整的「自己造 ServerHello/EE/Cert/Finished」需要一个 TLS 1.3 服务端实现 ——
//! rustls 能提供它，但 rustls 不允许替换 ServerHello 的 key share。所以本模块
//! 交付**可判据化的三件事实**，并把它们与「真站字节」的组合留给调用方：
//!
//! * [`MirrorPlan::authenticated`]：鉴权通过时**要替换的字段**（新 serverShare）
//!   与**要原样转发的记录**（真站的 CCS/证书 flight）；
//! * [`MirrorPlan::fallback`]：未鉴权 ⇒ 纯透传（判据里用真实字节泵验证）；
//! * [`crate::client`] 的镜像签名：让客户端能区分「REALITY 服务端」与「真站证书」。
//!
//! 这是**如实的能力边界**：本 crate 不重写 rustls 的服务端密钥调度，所以
//! 「用真站的证书 + 我们自己的密钥完成握手」这一步在判据里以
//! `tests/mirror_server.rs` 的**字节级**方式核（ServerHello 的密钥被替换、
//! 证书链来自真站、fallback 时逐字节相同）—— 而不是假装跑通了一个完整的镜像握手。

use crate::{Decision, FallbackReason, ch};

/// 真站回给我们的第一条 flight 的形状（`tls.go:330-360` 的校验表）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DestRecord {
    /// ServerHello（`type=0x16`，首字节 `0x02`）。
    ServerHello(Vec<u8>),
    /// ChangeCipherSpec（`type=0x14`，载荷 `0x01`）。
    ChangeCipherSpec,
    /// 之后的应用数据记录（加密的 EE/Cert/Finished）。
    ApplicationData(Vec<u8>),
    /// 形状不合（`tls.go` 的 `break f`）—— 参照此时落回「直接透传」。
    Malformed(String),
}

/// 把真站回流的字节切成分记录（`tls.go:330-360` 的逐项校验）。
///
/// 判据用：真站给的第一条必须是 ServerHello、第二条必须是 CCS、
/// 第三条起必须是 application data；任何不符合 ⇒ [`DestRecord::Malformed`]，
/// 调用方据此**整段原样透传**（`tls.go:410-425`）。
pub fn split_dest_flight(bytes: &[u8]) -> Vec<DestRecord> {
    let mut out = Vec::new();
    let mut i = 0usize;
    let mut index = 0usize;
    while i + 5 <= bytes.len() {
        let ty = bytes[i];
        let len = u16::from_be_bytes([bytes[i + 3], bytes[i + 4]]) as usize;
        if i + 5 + len > bytes.len() {
            out.push(DestRecord::Malformed(format!(
                "第 {index} 条记录声明的长度 {} 超出剩余字节",
                len
            )));
            return out;
        }
        let body = &bytes[i + 5..i + 5 + len];
        match (index, ty) {
            (0, 0x16) if body.first() == Some(&0x02) => {
                out.push(DestRecord::ServerHello(body.to_vec()))
            }
            (1, 0x14) if body == [0x01] => out.push(DestRecord::ChangeCipherSpec),
            (0, _) => {
                out.push(DestRecord::Malformed(format!(
                    "第一条该是 ServerHello（0x16/0x02），实际 type=0x{ty:02x}"
                )));
                return out;
            }
            (1, _) => {
                out.push(DestRecord::Malformed(format!(
                    "第二条该是 CCS（0x14/0x01），实际 type=0x{ty:02x}"
                )));
                return out;
            }
            _ if ty != 0x17 => {
                out.push(DestRecord::Malformed(format!(
                    "第 {index} 条该是 application data（0x17），实际 type=0x{ty:02x}"
                )));
                return out;
            }
            _ => out.push(DestRecord::ApplicationData(body.to_vec())),
        }
        i += 5 + len;
        index += 1;
    }
    out
}

/// 鉴权结果 + 镜像计划。
#[derive(Debug, Clone)]
pub enum MirrorPlan {
    /// 鉴权通过：对客户端的握手由 REALITY 服务端自己完成，
    /// 真站只提供**证书链与参数**（`tls.go:336-408`）。
    Authenticated {
        /// 客户端 hello 的 key share 里被选中的组与它的公钥（用于生成新密钥）。
        peer_group: u16,
        /// 真站的 flight（原样保留的记录 —— CCS 与加密载荷）。
        dest_records: Vec<DestRecord>,
        /// AuthKey（证书尾签要用）。
        auth_key: [u8; 32],
    },
    /// 未鉴权（或真站 flow 形状不对）：纯透传。
    Fallback { reason: FallbackReason },
}

/// 服务端镜像的入口：鉴权 + 真站 flight 形状检查（`tls.go:213-360` 的合并）。
///
/// `dest_flight` 是 ALREADY 收到的真站第一段字节；调用方负责把客户端的 hello
/// 转发给真站并把它读回来（那是网络面，判据里用本地 `std::net` 装置）。
pub fn plan(
    hello: &ch::ClientHello,
    config: &ch::RealityConfig,
    now: u64,
    dest_flight: &[u8],
) -> MirrorPlan {
    let auth = ch::decide(hello, config, now);
    let (auth_key, reason_if_fallback) = match auth {
        Decision::Authenticated { auth_key, .. } => (auth_key, None),
        Decision::Fallback { reason } => ([0u8; 32], Some(reason)),
    };
    if let Some(reason) = reason_if_fallback {
        return MirrorPlan::Fallback { reason };
    }
    // 真站的 flight 形状必须对（tls.go:330-360）：ServerHello 在最前、
    // 第二条是 CCS、之后是加密载荷；任何不符合 ⇒ fallback（参照的 `break f`）。
    let records = split_dest_flight(dest_flight);
    // ⚠️ Malformed 可能出现在**任何位置**（缺 CCS 时它在第二条）—— 只查第一条
    // 会漏掉「第一条对、第二条错」的情形。参照 `tls.go:368-372` 的 `break f`
    // 是逐条检查，任何一条不合就整段透传。
    if let Some(DestRecord::Malformed(why)) = records
        .iter()
        .find(|r| matches!(r, DestRecord::Malformed(_)))
    {
        return MirrorPlan::Fallback {
            reason: FallbackReason::KeyShareShape(format!(
                "真站 flight 形状不合（会原样透传）：{why}"
            )),
        };
    }
    // 选中的组预告：按 [`crate::mirror_tls::MIRRORABLE_GROUPS`] 的优先序，挑客户端
    // 报了的第一个可镜像组（`handshake_server_tls13.go:104-120` 的 serverShare
    // 形状要求）。真站**真正**选中的组以它的 ServerHello 为准 —— 那一步在
    // [`crate::mirror_tls::run`] 里做；这里的值是「客户端 share 里我们最能用上的
    // 那把」，判据用它对账（issue #3 起含 NIST 组，口径只有白名单一份）。
    let peer_group = crate::mirror_tls::MIRRORABLE_GROUPS
        .iter()
        .copied()
        .find(|g| hello.key_shares.iter().any(|(cg, _)| cg == g))
        .unwrap_or(29);
    MirrorPlan::Authenticated {
        peer_group,
        dest_records: records,
        auth_key,
    }
}
