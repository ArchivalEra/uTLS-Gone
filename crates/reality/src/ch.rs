//! 原始 ClientHello 的**最小解析** —— REALITY 鉴权需要的字段，不多不少。
//!
//! 与 `crates/utls` 的解析器分工不同：那边把 hello 反解成**可编辑的 spec**
//! （每连接随机量折成 Opaque）；这里只读**鉴权要用的事实** —— random、sessionId、
//! SNI、key shares（**含线序与原始字节**：REALITY 的判定依赖 MLKEM768 在前、
//! 其末 32 字节是 X25519 分量 —— 那是 spec 模型刻意不表达的东西）。
//!
//! 解析失败的形状与 Go 参照对齐：`readClientHello` 对畸形 hello 报错 ⇒
//! `tls.go:213` 的 `err != nil` ⇒ fallback，而不是 panic。

use crate::FallbackReason;
use crate::auth::{SESSION_ID_LEN, SESSION_ID_OFFSET};

/// ClientHello 的固定布局：`raw[39:71]` 是 32 字节的 sessionId
/// （`tls.go:255` 的注释「sessionId points to raw[39:]」）。
/// 鉴权视角下的一条 ClientHello。
#[derive(Debug, Clone)]
pub struct ClientHello {
    /// `random[0:32]`（完整 32 字节；salt 取 `[0:20]`、nonce 取 `[20:32]`）。
    pub random: [u8; 32],
    /// `sessionId`（32 字节；REALITY 客户端恒为 32 —— AEAD 密文）。
    pub session_id: [u8; 32],
    /// 原始字节（含 sessionId）。AAD 的基底：判定时把 `[39:71]` 置零。
    pub raw: Vec<u8>,
    /// SNI（首个 server_name 的 host；无 SNI 扩展或空 ⇒ `None`）。
    pub server_name: Option<String>,
    /// key shares（**线序**）：`(group, 原始字节)`。
    pub key_shares: Vec<(u16, Vec<u8>)>,
}

impl ClientHello {
    /// 从**握手消息**（`type(1) || u24 || body`）解析。入参口径与
    /// `crates/utls` 的 `ClientHelloSpec::from_bytes` 相同：剥记录头是调用方的事。
    ///
    /// ⚠️ 与 utls 解析器的取舍不同：这里对**所有**扩展只按类型识别、其余忽略，
    /// 遇到长度不自洽的扩展**报错**（鉴权层宁可 fallback 也不猜）。
    pub fn parse(msg: &[u8]) -> Result<Self, FallbackReason> {
        let bad = |m: String| FallbackReason::KeyShareShape(format!("ClientHello 解析：{m}"));
        if msg.len() < 4 || msg[0] != 1 {
            return Err(bad(String::from("不是 ClientHello 握手消息")));
        }
        let declared = ((msg[1] as usize) << 16) | ((msg[2] as usize) << 8) | msg[3] as usize;
        if declared + 4 != msg.len() {
            return Err(bad(String::from("长度字段与实际不符")));
        }
        let mut p = 4usize;
        p += 2; // legacy_version
        if p + 32 > msg.len() {
            return Err(bad(String::from("random 越界")));
        }
        let mut random = [0u8; 32];
        random.copy_from_slice(&msg[p..p + 32]);
        p += 32;
        if p >= msg.len() {
            return Err(bad(String::from("sessionId 长度字节越界")));
        }
        let sid_len = msg[p] as usize;
        p += 1;
        if sid_len != 32 || p + 32 > msg.len() {
            // REALITY 客户端恒发 32 字节 sessionId（AEAD 密文）；其余长度直接 fallback。
            return Err(bad(format!("sessionId 长度 {sid_len} ≠ 32")));
        }
        let mut session_id = [0u8; 32];
        session_id.copy_from_slice(&msg[p..p + 32]);
        p += 32;
        // cipher_suites
        if p + 2 > msg.len() {
            return Err(bad(String::from("cipher_suites 长度越界")));
        }
        let cs = u16::from_be_bytes([msg[p], msg[p + 1]]) as usize;
        p += 2 + cs;
        // compression_methods
        if p >= msg.len() {
            return Err(bad(String::from("compression 长度越界")));
        }
        let comp = msg[p] as usize;
        p += 1 + comp;
        // extensions
        if p + 2 > msg.len() {
            return Err(bad(String::from("extensions 长度越界")));
        }
        let exts = u16::from_be_bytes([msg[p], msg[p + 1]]) as usize;
        p += 2;
        if p + exts != msg.len() {
            return Err(bad(String::from("extensions 区长度与实际不符")));
        }
        let region = &msg[p..p + exts];

        let mut server_name = None;
        let mut key_shares = Vec::new();
        let mut q = 0usize;
        while q + 4 <= region.len() {
            let ty = u16::from_be_bytes([region[q], region[q + 1]]);
            let bl = u16::from_be_bytes([region[q + 2], region[q + 3]]) as usize;
            let body = region
                .get(q + 4..q + 4 + bl)
                .ok_or_else(|| bad(format!("扩展 0x{ty:04x} 的体越界（声明 {bl}）")))?;
            match ty {
                0x0000 => {
                    // server_name：`list_len(2) || type(1)=0 || len(2) || host`
                    if body.len() >= 5 && body[0] == 0 && body[2] == 0 {
                        let host_len = u16::from_be_bytes([body[3], body[4]]) as usize;
                        if body.len() == 5 + host_len {
                            server_name = Some(String::from_utf8_lossy(&body[5..]).into_owned());
                        }
                    }
                }
                0x0033 => {
                    // key_share：`list_len(2) || (group(2) || len(2) || data)*`
                    if body.len() < 2 {
                        return Err(bad(String::from("key_share 体过短")));
                    }
                    let list = u16::from_be_bytes([body[0], body[1]]) as usize;
                    if list + 2 != body.len() {
                        return Err(bad(String::from("key_share 列表长度与体不符")));
                    }
                    let mut r = 2usize;
                    while r + 4 <= body.len() {
                        let group = u16::from_be_bytes([body[r], body[r + 1]]);
                        let kl = u16::from_be_bytes([body[r + 2], body[r + 3]]) as usize;
                        let data = body
                            .get(r + 4..r + 4 + kl)
                            .ok_or_else(|| bad(format!("key_share 组 0x{group:04x} 的公钥越界")))?;
                        key_shares.push((group, data.to_vec()));
                        r += 4 + kl;
                    }
                }
                _ => {}
            }
            q += 4 + bl;
        }

        Ok(Self {
            random,
            session_id,
            raw: msg.to_vec(),
            server_name,
            key_shares,
        })
    }

    /// AAD 形态：原始字节里 **sessionId 置零**（`tls.go:255-257` 与客户端
    /// 封包前的 `Raw[39:71]` 置零对齐）。
    pub fn aad_with_zeroed_session_id(&self) -> Vec<u8> {
        let mut aad = self.raw.clone();
        aad[SESSION_ID_OFFSET..SESSION_ID_OFFSET + SESSION_ID_LEN].fill(0);
        aad
    }

    /// REALITY 要求的 X25519 共享提取（`tls.go:219-239` 的形状与顺序检查）：
    /// `X25519MLKEM768`（末 32 字节为其 X25519 分量）必须在前，可选 `X25519`
    /// 在后，各最多一次。任何其它形状 ⇒ [`FallbackReason::KeyShareShape`]。
    ///
    /// 常量与 Go 对齐：ML-KEM-768 封装密钥 1184 字节，共享字节 1216 = 1184 + 32。
    pub fn reality_peer_pub(&self) -> Result<[u8; 32], FallbackReason> {
        // X25519MLKEM768 = 4588；X25519 = 29（0x001D）。码点与
        // `crates/utls/src/values.rs` 同源（X25519_MLKEM768 / X25519）。
        // ⚠️ 常量名不能只叫 X25519：match 分支 `X25519 =>` 会被当成**新绑定**
        // （变量遮蔽常量），任何组都命中它 —— GREASE/P-256 的 share 会被误判。
        const GROUP_MLKEM768: u16 = 4588;
        const GROUP_X25519: u16 = 29;
        let shape = |m: &str| Err(FallbackReason::KeyShareShape(String::from(m)));
        let mut mlkem: Option<&(u16, Vec<u8>)> = None;
        let mut x25519: Option<&(u16, Vec<u8>)> = None;
        for (i, (group, data)) in self.key_shares.iter().enumerate() {
            match *group {
                GROUP_MLKEM768 => {
                    if data.len() != 1184 + 32 {
                        return shape(&format!("X25519MLKEM768 的公钥长 {} ≠ 1216", data.len()));
                    }
                    if mlkem.is_some() {
                        return shape("X25519MLKEM768 出现两次");
                    }
                    if x25519.is_some() {
                        return shape(
                            "X25519MLKEM768 必须在 X25519 之前（tls.go:228-239 的顺序检查）",
                        );
                    }
                    mlkem = self.key_shares.get(i);
                }
                GROUP_X25519 => {
                    if data.len() != 32 {
                        return shape(&format!("X25519 的公钥长 {} ≠ 32", data.len()));
                    }
                    if x25519.is_some() {
                        return shape("X25519 出现两次");
                    }
                    x25519 = self.key_shares.get(i);
                }
                // 其余组（GREASE、P-256……）与 REALITY 鉴权无关：PeerPub 的取值
                // 只看 MLKEM768 分量与独立 X25519，其它 share 原样跳过。
                _ => {}
            }
        }
        // tls.go:239-241：没有 MLKEM768 分量 ⇒ reject outdated/strange Client Hello。
        let mlkem = mlkem.ok_or_else(|| {
            FallbackReason::KeyShareShape(String::from(
                "没有 X25519MLKEM768（REALITY 要求它在最前，哪怕 X25519 在场）",
            ))
        })?;
        // peerPub 优先取独立 X25519（tls.go:236-238 的 secondary choice 语义相反：
        // `peerPub = peerPub2` 只在**没有**独立 X25519 时发生）。
        let peer = match x25519 {
            Some((_, data)) => data,
            None => &mlkem.1[mlkem.1.len() - 32..],
        };
        let mut out = [0u8; 32];
        out.copy_from_slice(peer);
        Ok(out)
    }
}

/// FallbackReason 的构造辅助（保持 `ch.rs` 主体可读）。
impl From<String> for FallbackReason {
    fn from(m: String) -> Self {
        FallbackReason::KeyShareShape(m)
    }
}

/// REALITY 服务端的判定配置（与 Go `Config` 的鉴权相关字段一一对应；
/// `Dest`/`Show`/限速等属于代理面，不进判定）。
#[derive(Debug, Clone)]
pub struct RealityConfig {
    /// SNI 白名单（Go `ServerNames map[string]bool`）。
    pub server_names: Vec<String>,
    /// 服务端静态 X25519 私钥（Go `PrivateKey []byte`，32 字节）。
    pub private_key: [u8; 32],
    /// shortId 白名单（Go `ShortIds map[[8]byte]bool`）。
    pub short_ids: Vec<[u8; 8]>,
    /// 客户端版本下界（含）；`None` = 不检查。
    pub min_client_ver: Option<[u8; 4]>,
    /// 客户端版本上界（含）；`None` = 不检查。
    pub max_client_ver: Option<[u8; 4]>,
    /// 时刻窗（秒）；`None`/`0` = 不检查（Go `MaxTimeDiff`）。
    pub max_time_diff: Option<u64>,
}

use crate::Decision;
use crate::auth;

/// REALITY 鉴权判定 —— `tls.go:213-275` 的整段，一条不少：
/// SNI 白名单 → key share 形状/顺序 → X25519 → AuthKey 派生 → sessionId AEAD →
/// 版本窗 → 时刻窗 → shortId 白名单。任何一步失败 ⇒ [`Decision::Fallback`]。
///
/// `now` 由调用方给（unix 秒）—— 与 Go 的 `time.Since(ClientTime)` 对应；
/// 确定性输入是判据可复现的前提。
pub fn decide(hello: &ClientHello, config: &RealityConfig, now: u64) -> Decision {
    // tls.go:216：SNI 白名单。
    match &hello.server_name {
        Some(name) if config.server_names.iter().any(|s| s == name) => {}
        Some(name) => {
            return Decision::Fallback {
                reason: FallbackReason::ServerNameNotAllowed(name.clone()),
            };
        }
        None => {
            return Decision::Fallback {
                reason: FallbackReason::ServerNameNotAllowed(String::from("(无 SNI)")),
            };
        }
    }

    // tls.go:219-241：key share 形状/顺序 + X25519。
    let peer_pub = match hello.reality_peer_pub() {
        Ok(p) => p,
        Err(reason) => return Decision::Fallback { reason },
    };
    let shared = match auth::x25519(&config.private_key, &peer_pub) {
        Ok(s) => s,
        Err(reason) => return Decision::Fallback { reason },
    };
    let auth_key = auth::auth_key(&shared, &hello.random);

    // tls.go:250-258：sessionId 的 AEAD Open（AAD = sessionId 置零）。
    let plaintext = match auth::open_session_id(
        &auth_key,
        &hello.random,
        &hello.aad_with_zeroed_session_id(),
        &hello.session_id,
    ) {
        Ok(p) => p,
        Err(reason) => return Decision::Fallback { reason },
    };

    let mut client_ver = [0u8; 4];
    client_ver.copy_from_slice(&plaintext[0..4]);
    let client_time = u32::from_be_bytes([plaintext[4], plaintext[5], plaintext[6], plaintext[7]]);
    let mut short_id = [0u8; 8];
    short_id.copy_from_slice(&plaintext[8..16]);

    // tls.go:269-271：版本窗。
    if let Some(min) = &config.min_client_ver
        && ver_value(&client_ver) < ver_value(min)
    {
        return Decision::Fallback {
            reason: FallbackReason::ClientVersion { got: client_ver },
        };
    }
    if let Some(max) = &config.max_client_ver
        && ver_value(&client_ver) > ver_value(max)
    {
        return Decision::Fallback {
            reason: FallbackReason::ClientVersion { got: client_ver },
        };
    }
    // tls.go:270：时刻窗（Go 用 Abs() —— 双向都要在窗内）。
    if let Some(max_diff) = config.max_time_diff
        && max_diff > 0
        && now.abs_diff(client_time as u64) > max_diff
    {
        return Decision::Fallback {
            reason: FallbackReason::TimeOutsideWindow { got: client_time },
        };
    }
    // tls.go:272：shortId 白名单。
    if !config.short_ids.contains(&short_id) {
        return Decision::Fallback {
            reason: FallbackReason::ShortIdNotAllowed(short_id),
        };
    }

    Decision::Authenticated {
        plaintext,
        client_ver,
        client_time,
        short_id,
        shared,
        auth_key,
    }
}

/// Go `Value(hs.c.ClientVer[:]...)`：版本字节按大端比较
/// （`tls.go:269-271` —— `Value` 是 varint 风格的逐字节比较，等价于大端序）。
fn ver_value(v: &[u8; 4]) -> u32 {
    u32::from_be_bytes(*v)
}
