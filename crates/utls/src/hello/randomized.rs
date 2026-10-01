//! uTLS 的 `Randomized` 家族：**加权随机指纹**。
//!
//! uTLS 的 `HelloRandomized` / `HelloRandomizedALPN` / `HelloRandomizedNoALPN` 不是固定
//! 的 spec，而是**每次调用生成一份**：拿一串加权掷币，从一套「可选成分」里抽出一份
//! 看起来像真浏览器的 ClientHello。它是 uTLS 里最容易和参照实现分叉的一块 ——
//! 因为它的输出由**取随机的顺序**定义，任何一处顺序错位都会让整条流偏掉。
//!
//! # 为什么这份移植能逐字对账
//!
//! uTLS 的 `ClientHelloID` 带 `Seed *PRNGSeed`，也就是**随机化指纹支持固定种子**。
//! 而它的 PRNG（`u_prng.go`）是确定性的：一个 SHAKE256 流，上面套 Go `math/rand` 的方法。
//! 所以只要把那条流与那些方法逐字移植，**同一个种子就会产出同一份 spec** ——
//! 于是这块可以离线与参照实现逐字段对账（见 `tests/fixtures/utls-randomized.json`）。
//!
//! # 三条容易抄错的地方（都是这次实测踩过或差点踩到的）
//!
//! 1. **掷币在 Go 的 `||` / `&&` 里是左侧 —— 所以它总是发生。**
//!    `r.FlipWeightedCoin(w) || TLSVersMax == TLS13` 短路掉的是**右边那个比较**
//!    （没有副作用），币已经掷过了。把顺序写成 `TLSVersMax == TLS13 || r.flip(..)`
//!    就会在 TLS1.3 时**少掷一枚币**，从此整条流错位 ——
//!    而症状是「密码套件全对、扩展全错」，因为错位发生在洗牌之后。
//!    第一版就是这么错的，顺序必须与 Go 源码逐字一致。
//! 2. **`Shuffle` 用的不是一个算法。** Go 的 `math/rand.Shuffle` 对 `i > 2^31-2` 用
//!    `Int63n`、对更小的 `i` 用未导出的 `int31n`（Lemire 乘法法），**不是** `Int31n`
//!    （它是拒绝采样）。两者对同一位流给出不同结果。
//! 3. **ALPS 那次掷币走的是另一条流**：uTLS 用 `newPRNGWithSaltedSeed(seed, "ALPS")`
//!    派生一个独立 PRNG（HKDF-SHA3-256），所以那次掷币**不消耗**主流。
//!
//! # 关于依赖
//!
//! 这里用 `sha3` 与 `hkdf`。它们看起来与「指纹层不碰密码学」那条纪律冲突，但**不是**：
//! 那条纪律管的是**密钥材料与 TLS 状态**。这里的哈希不是用来保密的，它是这条流的
//! **定义** —— uTLS 源码自己写着「This PRNG is _not_ for security use cases」。
//! 要让指纹与参照实现一致，这条流就必须逐字节一致。

use hkdf::Hkdf;
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::{Sha3_256, Shake256};

use super::ClientHelloId;
use super::randomized_tables as t;
use super::spec::{
    ApplicationSettingsAlps, ClientHelloSpec, CodePoint, Extension, Padding, SessionId, SpecError,
    Variability,
};
use crate::values as v;

/// uTLS 的 `Weights`（`u_common.go`）—— 17 个加权掷币的概率。
///
/// 字段名与 uTLS 一一对应，好让两边对照时不需翻译。默认值在 [`DEFAULT_WEIGHTS`]。
#[derive(Clone, Copy, Debug)]
pub struct Weights {
    pub extensions_append_alpn: f64,
    pub tls_vers_max_set_version_tls13: f64,
    pub cipher_suites_remove_random_ciphers: f64,
    pub sig_and_hash_algos_append_ecdsa_with_sha1: f64,
    pub sig_and_hash_algos_append_ecdsa_with_p521_and_sha512: f64,
    pub sig_and_hash_algos_append_pss_with_sha256: f64,
    pub sig_and_hash_algos_append_pss_with_sha384_pss_with_sha512: f64,
    pub curve_ids_append_x25519: f64,
    pub curve_ids_append_curve_p521: f64,
    pub extensions_append_padding: f64,
    pub extensions_append_status: f64,
    pub extensions_append_sct: f64,
    pub extensions_append_reneg: f64,
    pub extensions_append_ems: f64,
    pub first_key_share_set_curve_p256: f64,
    pub key_share_append_random_groups: f64,
    pub extensions_append_alps: f64,
}

/// uTLS 的 `DefaultWeights`（`u_common.go:693-711`），逐个抄录。
pub const DEFAULT_WEIGHTS: Weights = Weights {
    extensions_append_alpn: 0.7,
    tls_vers_max_set_version_tls13: 0.4,
    cipher_suites_remove_random_ciphers: 0.4,
    sig_and_hash_algos_append_ecdsa_with_sha1: 0.63,
    sig_and_hash_algos_append_ecdsa_with_p521_and_sha512: 0.59,
    sig_and_hash_algos_append_pss_with_sha256: 0.51,
    sig_and_hash_algos_append_pss_with_sha384_pss_with_sha512: 0.9,
    curve_ids_append_x25519: 0.71,
    curve_ids_append_curve_p521: 0.46,
    extensions_append_padding: 0.62,
    extensions_append_status: 0.74,
    extensions_append_sct: 0.46,
    extensions_append_reneg: 0.75,
    extensions_append_ems: 0.77,
    first_key_share_set_curve_p256: 0.00, // uTLS 注释：legacy setting
    key_share_append_random_groups: 0.50,
    extensions_append_alps: 0.33,
};

// ── PRNG：SHAKE256 流 + Go math/rand 的方法 ────────────────────────────────

/// uTLS 的 `prng`（`u_prng.go`）。
///
/// 它是「一个 SHAKE256 流」，同时以 Go `math/rand` 的 **Source** 身份被使用 ——
/// 注意 `prng.Seed()` 在 uTLS 里是**空实现**，而 `rand.New(p)` 不种子化，
/// 所以这里**不需要**移植 Go 那个 607 元素的 `rngCooked` 表，只需要它的**方法**。
struct Prng {
    xof: Box<dyn XofReader>,
}

impl Prng {
    fn new(seed: &[u8; 32]) -> Self {
        let mut h = Shake256::default();
        h.update(seed);
        Prng {
            xof: Box::new(h.finalize_xof()),
        }
    }

    /// uTLS 的 `newPRNGWithSaltedSeed(seed, salt)`：HKDF-SHA3-256 派生出的**独立**流。
    fn salted(seed: &[u8; 32], salt: &str) -> Self {
        let hk = Hkdf::<Sha3_256>::new(Some(salt.as_bytes()), seed);
        let mut out = [0u8; 32];
        hk.expand(&[], &mut out)
            .expect("32 字节在 HKDF 的输出上限内");
        Prng::new(&out)
    }

    /// uTLS 的 `Uint64()`：8 字节**大端**。
    fn uint64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.xof.read(&mut b);
        u64::from_be_bytes(b)
    }

    /// uTLS 的 `Int63()`：`Uint64() & (1<<63 - 1)`。
    fn int63(&mut self) -> i64 {
        (self.uint64() & ((1u64 << 63) - 1)) as i64
    }

    /// Go `math/rand.Rand.Uint32()`：`uint32(Int63() >> 31)`。
    fn uint32(&mut self) -> u32 {
        (self.int63() >> 31) as u32
    }

    fn int31(&mut self) -> i32 {
        (self.int63() >> 32) as i32
    }

    /// Go **导出**的 `Rand.Int31n` —— **拒绝采样**。`Intn` 走的是它。
    ///
    /// ⚠️ 它与下面的 `int31n_lemire` **不是**同一算法：Go 的 `Intn` 用这个、
    /// `Shuffle` 用那个。第一版把两者混成一个，靠「`int31` 从未被使用」这条
    /// 编译警告才发现 —— 而它的症状会是「几百次掷币里有几次走反」，
    /// 从产物上几乎无法察觉。
    fn int31n(&mut self, n: i32) -> i32 {
        debug_assert!(n > 0);
        if n & (n - 1) == 0 {
            return self.int31() & (n - 1);
        }
        let max = i32::MAX - ((1u32 << 31) % (n as u32)) as i32;
        let mut v = self.int31();
        while v > max {
            v = self.int31();
        }
        v % n
    }

    /// Go **未导出**的 `Rand.int31n` —— **Lemire 乘法法**。`Shuffle` 用的是它。
    fn int31n_lemire(&mut self, n: i32) -> i32 {
        let n = n as u32;
        let mut v = self.uint32();
        let mut prod = u64::from(v) * u64::from(n);
        let mut low = prod as u32;
        if low < n {
            let thresh = n.wrapping_neg() % n;
            while low < thresh {
                v = self.uint32();
                prod = u64::from(v) * u64::from(n);
                low = prod as u32;
            }
        }
        (prod >> 32) as i32
    }

    /// Go `math/rand.Rand.Int63n`：拒绝采样；2 的幂时直接掩码。
    fn int63n(&mut self, n: i64) -> i64 {
        debug_assert!(n > 0);
        if n & (n - 1) == 0 {
            return self.int63() & (n - 1);
        }
        // Go 的 `int64((1<<63) - 1 - (1<<63)%uint64(n))`：全程 uint64 算术，最后才转 i64。
        let max = (((1u64 << 63) - 1) - ((1u64 << 63) % (n as u64))) as i64;
        let mut v = self.int63();
        while v > max {
            v = self.int63();
        }
        v % n
    }

    /// Go `math/rand.Rand.Intn`（uTLS 外面还套了「n<=0 返回 0」）。
    fn intn(&mut self, n: i64) -> i64 {
        if n <= 0 {
            return 0;
        }
        // Go 写的是 `n <= 1<<31-1`，也就是「装得进 int32」。
        if n <= i32::MAX as i64 {
            i64::from(self.int31n(n as i32))
        } else {
            self.int63n(n)
        }
    }

    /// Go `math/rand.Rand.Perm`。注意它在 `i=0` 时也走一次迭代（Go 为了兼容性保留了
    /// 那次「把 m[0] 与 m[0] 交换」的迭代）—— 少一次就少消耗一次随机数，流会错位。
    fn perm(&mut self, n: usize) -> Vec<usize> {
        let mut m = vec![0usize; n];
        for i in 0..n {
            let j = self.intn((i + 1) as i64) as usize;
            m[i] = m[j];
            m[j] = i;
        }
        m
    }

    /// Go `math/rand.Rand.Shuffle`：Fisher-Yates，`i` 大时走 `Int63n`、小时走 `int31n`。
    fn shuffle<T>(&mut self, v: &mut [T]) {
        let mut i = v.len() as i64 - 1;
        while i > (1i64 << 31) - 2 {
            let j = self.int63n(i + 1) as usize;
            v.swap(i as usize, j);
            i -= 1;
        }
        while i > 0 {
            let j = self.int31n_lemire((i + 1) as i32) as usize;
            v.swap(i as usize, j);
            i -= 1;
        }
    }

    /// uTLS 的 `FlipWeightedCoin`。
    fn flip(&mut self, weight: f64) -> bool {
        let weight = if weight > 1.0 { 1.0 } else { weight };
        let f = self.int63() as f64 / i64::MAX as f64;
        f > 1.0 - weight
    }
}

// ── 生成器 ─────────────────────────────────────────────────────────────────

/// uTLS 的三个随机化 ID。
fn kind_of(id: ClientHelloId) -> Option<u8> {
    match id {
        ClientHelloId::Randomized => Some(0),
        ClientHelloId::RandomizedAlpn => Some(1),
        ClientHelloId::RandomizedNoAlpn => Some(2),
        _ => None,
    }
}

fn is_rc4(c: u16) -> bool {
    matches!(c, 0xc007 | 0xc011 | 0x0005) // ECDHE_ECDSA / ECDHE_RSA / RSA with RC4_128_SHA
}

/// uTLS 的 `removeRandomCiphers`：**就地**删，概率随位置递增，第一个永不删。
fn remove_random_ciphers(r: &mut Prng, s: &mut Vec<u16>, max_removal_probability: f64) {
    if s.len() <= 1 {
        return;
    }
    let float_len = s.len() as f64;
    let mut i = 1usize;
    while i < s.len() {
        // 注意 `float_len` 用的是**原始**长度，且删除后 i 不前进（Go 的 `i--` + `i++`）。
        if r.flip(max_removal_probability * i as f64 / float_len) {
            s.remove(i);
        } else {
            i += 1;
        }
    }
}

/// uTLS 的 `shuffledCiphers`：打乱**完整的** `cipherSuites` 表。
///
/// `randomTag` 是一个排列（两两不同），所以比较器是**全序** ⇒ 排序结果与排序算法无关，
/// 这里可以直接用 `sort_by` 而不必复刻 Go 的 pdqsort。
fn shuffled_ciphers(r: &mut Prng) -> Vec<u16> {
    let perm = r.perm(t::SUITE_TABLE.len());
    let mut sortable: Vec<(bool, usize, u16)> = t::SUITE_TABLE
        .iter()
        .enumerate()
        .map(|(i, (id, is_tls12))| (!*is_tls12, perm[i], *id))
        .collect();
    sortable.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
    sortable.into_iter().map(|x| x.2).collect()
}

/// `makeSupportedVersions(min, max)`（uTLS `u_conn.go:806`）—— 从 max 递减到 min。
fn make_supported_versions(min: u16, max: u16) -> Vec<u16> {
    (0..=(max - min)).map(|i| max - i).collect()
}

/// 生成一份随机化指纹。
///
/// **同一个 `seed` 永远产出同一份 spec** —— 这是可对账的前提，也是 uTLS 的
/// `ClientHelloID.Seed` 的用途。
///
/// `next_protos` 是 ALPN 的候选（uTLS 的 `uconn.config.NextProtos`）；为空且抽中 ALPN 时
/// 用 uTLS 的默认值 `h2, http/1.1`。
pub(crate) fn generate(
    id: ClientHelloId,
    seed: &[u8; 32],
    next_protos: &[Vec<u8>],
    weights: &Weights,
) -> Result<ClientHelloSpec, SpecError> {
    let kind = kind_of(id).ok_or(SpecError::PresetUnavailable(id))?;
    let mut r = Prng::new(seed);

    // ⚠️ `Randomized` 这里要掷一次币；另外两个变体**不掷**（uTLS 的 switch 分支如此）。
    let with_alpn = match kind {
        1 => true,
        2 => false,
        _ => r.flip(weights.extensions_append_alpn),
    };

    let mut suites = shuffled_ciphers(&mut r);

    let (tls_vers_min, tls_vers_max) = if r.flip(weights.tls_vers_max_set_version_tls13) {
        // 候选顺序是 [TLS1.0, TLS1.2]，用 Intn(2) 取。
        let min = [v::VERSION_TLS10, v::VERSION_TLS12][r.intn(2) as usize];
        let mut t13 = t::DEFAULT_CIPHER_SUITES_TLS13.to_vec();
        r.shuffle(&mut t13);
        // TLS 1.3 的套件排在前面（流行实现都这样）
        t13.extend_from_slice(&suites);
        suites = t13;
        // TLS 1.3 禁止 RC4
        suites.retain(|c| !is_rc4(*c));
        (min, v::VERSION_TLS13)
    } else {
        (v::VERSION_TLS10, v::VERSION_TLS12)
    };

    remove_random_ciphers(
        &mut r,
        &mut suites,
        weights.cipher_suites_remove_random_ciphers,
    );

    // ── 签名算法 ──
    let mut sigalgs: Vec<u16> = vec![
        v::ECDSA_WITH_P256_AND_SHA256,
        v::PKCS1_WITH_SHA256,
        v::ECDSA_WITH_P384_AND_SHA384,
        v::PKCS1_WITH_SHA384,
        v::PKCS1_WITH_SHA1,
        v::PKCS1_WITH_SHA512,
    ];
    if r.flip(weights.sig_and_hash_algos_append_ecdsa_with_sha1) {
        sigalgs.push(v::ECDSA_WITH_SHA1);
    }
    if r.flip(weights.sig_and_hash_algos_append_ecdsa_with_p521_and_sha512) {
        sigalgs.push(v::ECDSA_WITH_P521_AND_SHA512);
    }
    // ⚠️ 掷币在 Go 里是 **`||` 的左侧**，所以它**总是**发生；被短路跳过的是右边那个比较
    // （它没有副作用）。第一版把两者写反了 —— 于是 TLS1.3 时少掷一枚币、整条流错位，
    // 而症状是「密码套件全对、扩展全错」。顺序必须与 Go 源码逐字一致。
    if r.flip(weights.sig_and_hash_algos_append_pss_with_sha256) || tls_vers_max == v::VERSION_TLS13
    {
        sigalgs.push(v::PSS_WITH_SHA256);
        if r.flip(weights.sig_and_hash_algos_append_pss_with_sha384_pss_with_sha512) {
            sigalgs.push(v::PSS_WITH_SHA384);
            sigalgs.push(v::PSS_WITH_SHA512);
        }
    }
    r.shuffle(&mut sigalgs);

    // ── 支持组 ──
    let mut curves: Vec<u16> = Vec::new();
    // ⚠️ 同上：掷币是 `&&` 的左侧 ⇒ 总是发生。
    if r.flip(weights.curve_ids_append_x25519) && tls_vers_max == v::VERSION_TLS13 {
        curves.push(v::X25519_MLKEM768);
    }
    // ⚠️ 同上：掷币是左侧 ⇒ 总是发生。
    if r.flip(weights.curve_ids_append_x25519) || tls_vers_max == v::VERSION_TLS13 {
        curves.push(v::X25519);
    }
    curves.push(v::CURVE_P256);
    curves.push(v::CURVE_P384);
    if r.flip(weights.curve_ids_append_curve_p521) {
        curves.push(v::CURVE_P521);
    }

    // ── 扩展列表（顺序即 uTLS 的构造顺序；末尾还会整体洗一次牌）──
    let mut exts: Vec<Extension> = vec![
        Extension::ServerName,
        Extension::Opaque {
            id: v::EXT_SESSION_TICKET,
            body: Vec::new(),
        },
        Extension::SignatureAlgorithms(sigalgs.iter().map(|c| CodePoint::Fixed(*c)).collect()),
        Extension::Opaque {
            id: v::EXT_EC_POINT_FORMATS,
            body: vec![1, v::POINT_FORMAT_UNCOMPRESSED],
        },
        Extension::SupportedGroups(curves.iter().map(|c| CodePoint::Fixed(*c)).collect()),
    ];

    if with_alpn {
        let protos = if next_protos.is_empty() {
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        } else {
            next_protos.to_vec()
        };
        exts.push(Extension::Alpn(protos));
    }

    // ⚠️ 同上：掷币是左侧 ⇒ 总是发生。
    if r.flip(weights.extensions_append_padding) || tls_vers_max == v::VERSION_TLS13 {
        exts.push(Extension::Padding(Padding::BoringStyle));
    }
    if r.flip(weights.extensions_append_status) {
        exts.push(Extension::Opaque {
            id: v::EXT_STATUS_REQUEST,
            body: vec![v::STATUS_TYPE_OCSP, 0, 0, 0, 0],
        });
    }
    if r.flip(weights.extensions_append_sct) {
        exts.push(Extension::Opaque {
            id: v::EXT_SCT,
            body: Vec::new(),
        });
    }
    if r.flip(weights.extensions_append_reneg) {
        exts.push(Extension::Opaque {
            id: v::EXT_RENEGOTIATION_INFO,
            body: vec![0],
        });
    }
    if r.flip(weights.extensions_append_ems) {
        exts.push(Extension::Opaque {
            id: v::EXT_EXTENDED_MASTER_SECRET,
            body: Vec::new(),
        });
    }

    if tls_vers_max == v::VERSION_TLS13 {
        let mut shares = vec![v::X25519];
        if r.flip(weights.first_key_share_set_curve_p256) {
            shares[0] = v::CURVE_P256;
        } else {
            if r.flip(weights.key_share_append_random_groups) {
                shares.push(v::CURVE_P256);
            }
            if r.flip(weights.key_share_append_random_groups) {
                shares.insert(0, v::X25519_MLKEM768);
            }
        }
        exts.push(Extension::KeyShare(
            shares.iter().map(|g| CodePoint::Fixed(*g)).collect(),
        ));
        exts.push(Extension::Opaque {
            id: v::EXT_PSK_KEY_EXCHANGE_MODES,
            body: vec![1, v::PSK_MODE_DHE],
        });
        exts.push(Extension::SupportedVersions(
            make_supported_versions(tls_vers_min, tls_vers_max)
                .iter()
                .map(|x| CodePoint::Fixed(*x))
                .collect(),
        ));

        if with_alpn {
            // ⚠️ 这条流是**派生**出来的，不消耗主流的随机数（见模块头第 3 条）。
            let mut ra = Prng::salted(seed, "ALPS");
            if ra.flip(weights.extensions_append_alps) {
                // uTLS 的随机化生成器用的是 `ApplicationSettingsExtension`，也就是
                // **旧**码点 17513（与 Chrome 133 的新码点不同）。
                exts.push(Extension::ApplicationSettings(ApplicationSettingsAlps {
                    protocols: vec![b"h2".to_vec()],
                }));
            }
        }
    }

    // 最后整体洗一次牌 —— 这次**没有**位置固定的元素（与 Chrome 预置的乱序不同）。
    r.shuffle(&mut exts);

    Ok(ClientHelloSpec {
        legacy_version: v::LEGACY_VERSION,
        cipher_suites: suites.iter().map(|c| CodePoint::Fixed(*c)).collect(),
        compression_methods: vec![v::COMPRESSION_NONE],
        extensions: exts,
        session_id: SessionId::Random(32),
        // 生成出来的顺序已经是固定的；**不要**再让编码器洗一次。
        variability: Variability::Stable,
    })
}
