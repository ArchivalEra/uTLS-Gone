//! **X25519（OS 熵源 keygen）的判据**。
//!
//! 判什么（按严重性排序）：
//!
//! 1. **对拍**：`public_from_private` / `agree` 与 x25519-dalek 在固定标量与
//!    派生标量上**逐字节相同** —— 曲线语义由权威的独立实现钉住（aws-lc 的 C 与
//!    dalek 谁错了都会红）；
//! 2. **低阶对端必须被拒**：全零对端（以及任何产生全零共享的对端）⇒ `Err` ——
//!    这是绕开 EVP 路径后**必须自己带**的检查（少了它，会话密钥能被对端变成
//!    已知常数），是本 crate 存在理由的一部分；
//! 3. **trait 面**：`X25519.start()` 产出 32 字节公钥、自洽 complete、每次 keygen
//!    都是新鲜密钥（两次公钥不同）；
//! 4. **换源助手**：`with_os_random_x25519` 只换 X25519、组数与顺序不变、幂等。

use x25519_dalek::{PublicKey, StaticSecret};
use x25519_os::{X25519, X25519_LEN, agree, public_from_private, with_os_random_x25519};

/// 固定标量（含 clamp 边角：全 0x01、全 0xff）+ 派生标量，覆盖足够多样本。
fn scalars() -> Vec<[u8; 32]> {
    let mut out = vec![[1u8; 32], [0xffu8; 32], [0u8; 32]];
    // 派生一批「看起来随机」的标量（确定性 ⇒ 判据可复现）。
    let mut s = [0x42u8; 32];
    for _ in 0..8 {
        for b in &mut s {
            *b = b.wrapping_mul(31).wrapping_add(7);
        }
        out.push(s);
    }
    out
}

/// **判据 1（对拍）**：公钥与共享密钥和 dalek 逐字节相同。
#[test]
fn matches_x25519_dalek_on_public_keys_and_shared_secrets() {
    for scalar in scalars() {
        let want_pub = *PublicKey::from(&StaticSecret::from(scalar)).as_bytes();
        assert_eq!(
            public_from_private(&scalar),
            want_pub,
            "公钥与 dalek 不一致（scalar 前 8 字节 {:02x?}）",
            &scalar[..8]
        );

        let want_shared = StaticSecret::from(scalar).diffie_hellman(&PublicKey::from(want_pub));
        let got = agree(&scalar, &want_pub).expect("合法对端该成功");
        assert_eq!(
            got.as_slice(),
            want_shared.as_bytes(),
            "共享密钥与 dalek 不一致"
        );
    }
}

/// **判据 2（低阶对端）**：全零对端 ⇒ `Err`（全零共享密钥必须被拒，不许出密钥）。
#[test]
fn a_low_order_peer_is_rejected_not_a_known_secret() {
    let scalar = [0x11u8; 32];
    let zero_peer = [0u8; 32];
    assert!(agree(&scalar, &zero_peer).is_err(), "全零对端该被拒");
}

/// **判据 3（trait 面）**：start/complete 自洽 + 密钥新鲜。
#[test]
fn the_trait_impl_starts_completes_and_generates_fresh_keys() {
    let a = X25519.start().expect("keygen");
    assert_eq!(a.pub_key().len(), X25519_LEN, "X25519 公钥 32 字节");

    // 自洽：对**自己的**公钥 complete 成功且 32 字节（合法 DH 形状）。
    let own_pub = a.pub_key().to_vec();
    let shared = a.complete(&own_pub).expect("对端 = 自己的公钥该成功");
    assert_eq!(shared.secret_bytes().len(), X25519_LEN);

    // 新鲜：两次 keygen 的公钥不同（熵源真的在动 —— 固定私钥实现会在这里红）。
    let b = X25519.start().expect("keygen");
    assert_ne!(
        own_pub,
        b.pub_key(),
        "两次 keygen 的公钥不该相同 —— 熵源没有在动？"
    );

    // 对端形状不对 ⇒ 响亮拒绝（用新的 keygen —— complete 消费交换）。
    let c = X25519.start().expect("keygen");
    assert!(
        c.complete(&[0u8; 16]).is_err(),
        "16 字节的『公钥』该被形状检查拒绝"
    );
}

/// **判据 4（换源助手）**：只换 X25519、组数与顺序不变、幂等。
#[test]
fn with_os_random_x25519_swaps_only_x25519_and_is_idempotent() {
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let before: Vec<rustls::NamedGroup> = provider.kx_groups.iter().map(|g| g.name()).collect();

    let swapped = with_os_random_x25519(provider);
    let after: Vec<rustls::NamedGroup> = swapped.kx_groups.iter().map(|g| g.name()).collect();

    assert_eq!(before, after, "组清单与顺序不该变");
    assert!(
        after.contains(&rustls::NamedGroup::X25519),
        "X25519 该还在清单里"
    );

    // 幂等：再换一次还是同一形状。
    let twice = with_os_random_x25519(swapped);
    let twice_groups: Vec<rustls::NamedGroup> = twice.kx_groups.iter().map(|g| g.name()).collect();
    assert_eq!(after, twice_groups, "重复换源该幂等");
}
