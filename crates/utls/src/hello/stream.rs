//! 每连接变化的确定性来源。
//!
//! **设计要点：把「每连接不同」建模成一个值，而不是一个 trait。**
//! [`HandshakeInputs`](super::HandshakeInputs) 里存一个私有 32 字节 seed，`marshal`
//! 从它确定性展开。这一个选择换来三件事：
//!
//! 1. `marshal` 成为**纯函数** —— 同参数逐字节相同，黄金字节测试可以直接写；
//! 2. **HRR 第二飞自动逐字节一致** —— 同一个 seed 重展开，GREASE/乱序/填充全部复现，
//!    而这正是 RFC 8446 §4.1.2 要求的（第二飞只许改 key_share/cookie/PSK/padding）；
//! 3. **测试不需要任何 mock** —— 它唯一需要的东西「确定性」是接口里的一个值，不是 seam。
//!
//! ⚠️ 本模块**不是密码学 RNG，也绝不用于密钥材料**。它的唯一用途是指纹的每连接变化：
//! GREASE 取值、扩展乱序、GREASE-ECH 的 config_id 与载荷。密钥材料由引擎提供
//! （见 `HandshakeInputs::key_exchange`）。

use crate::values::GREASE_VALUES;

/// SplitMix64 的混合函数（Steele 等，public domain 算法）。
#[inline]
fn mix(mut z: u64) -> u64 {
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// 从 32 字节 seed 确定性展开的字节流。
#[derive(Clone)]
pub(crate) struct Stream {
    state: u64,
}

impl Stream {
    pub(crate) fn new(seed: &[u8; 32]) -> Self {
        let mut state = 0x9E37_79B9_7F4A_7C15u64;
        for chunk in seed.chunks(8) {
            let mut w = [0u8; 8];
            w[..chunk.len()].copy_from_slice(chunk);
            state = mix(state ^ u64::from_le_bytes(w));
        }
        if state == 0 {
            // 全零 seed 也要能动：state 恒为 0 会让流退化成常量。
            state = 0x0123_4567_89AB_CDEF;
        }
        Stream { state }
    }

    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        mix(self.state)
    }

    fn next_u32(&mut self) -> u32 {
        (self.next_u64() >> 32) as u32
    }

    /// 传输参数那条流：**同一个 seed 派生，但与 hello 的流不同域**。
    ///
    /// 为什么不能共用：QUIC 的传输参数扩展就在 ClientHello 里，它的 GREASE 版本
    /// 必须与 hello 里其它 GREASE 值**不相关**（相关本身就是一种指纹信号）；
    /// 但又必须能从同一个 seed 复现（HRR 第二飞）。域分离常量就是同时满足这两条的办法。
    pub(crate) fn for_transport_parameters(seed: &[u8; 32]) -> Self {
        let mut s = Self::new(seed);
        s.state = s.state.wrapping_add(0xD1B5_4A32_D192_ED03);
        if s.state == 0 {
            s.state = 1;
        }
        s
    }

    pub(crate) fn u8(&mut self) -> u8 {
        self.next_u64() as u8
    }

    pub(crate) fn fill(&mut self, out: &mut [u8]) {
        for b in out.iter_mut() {
            *b = self.u8();
        }
    }

    /// 无偏取 `[0, n)`；`n <= 1` 时返回 0。
    ///
    /// 用拒绝采样而不是取模：GREASE 只有 16 个取值，取模偏置确实没人会发现 ——
    /// 但「没人会发现」不是把偏置留下来的理由，而且这里多写四行的成本是零。
    pub(crate) fn below(&mut self, n: u32) -> u32 {
        if n <= 1 {
            return 0;
        }
        let limit = u32::MAX - (u32::MAX % n);
        loop {
            let v = self.next_u32();
            if v < limit {
                return v % n;
            }
        }
    }

    /// 取一个 GREASE 值（`0x?a?a` 16 选 1）。
    pub(crate) fn grease(&mut self) -> u16 {
        GREASE_VALUES[self.below(GREASE_VALUES.len() as u32) as usize]
    }

    /// Fisher-Yates 洗牌，带「位置不动」白名单。
    ///
    /// 语义与 uTLS 的 `ShuffleChromeTLSExtensions` 一致：GREASE / padding / PSK 三类
    /// 扩展**位置不变**，其余互相置换。uTLS 的做法是在 `rand.Shuffle` 的回调里
    /// 「若 i 或 j 命中白名单就跳过这次交换」，其效果正是：白名单元素永不参与交换 ⇒
    /// 既保持位置，又只让非白名单元素互相置换。这里逐行复刻该语义。
    ///
    /// ⚠️ **只复刻语义，不复刻具体抽取**：uTLS 的 j 来自 Go 的 `rand.NewSource`
    /// （lagged Fibonacci），我们用的是自己的流。这不构成保真度损失 ——
    /// 在 uTLS 里这个抽取本身就来自 crypto/rand，每次连接都不同；
    /// 有意义的不变量是「顺序是一个置换、白名单不动、JA4 稳定」，而不是某次抽取。
    pub(crate) fn shuffle(&mut self, order: &mut [usize], pinned: &[bool]) {
        let n = order.len();
        for i in (1..n).rev() {
            let j = self.below((i + 1) as u32) as usize;
            if pinned.get(i).copied().unwrap_or(false) || pinned.get(j).copied().unwrap_or(false) {
                continue;
            }
            order.swap(i, j);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seed(n: u8) -> [u8; 32] {
        [n; 32]
    }

    #[test]
    fn deterministic_from_seed() {
        let mut a = Stream::new(&seed(7));
        let mut b = Stream::new(&seed(7));
        for _ in 0..64 {
            assert_eq!(a.u8(), b.u8());
        }
    }

    #[test]
    fn different_seeds_differ() {
        let mut a = Stream::new(&seed(1));
        let mut b = Stream::new(&seed(2));
        let va: Vec<u8> = (0..32).map(|_| a.u8()).collect();
        let vb: Vec<u8> = (0..32).map(|_| b.u8()).collect();
        assert_ne!(va, vb);
    }

    #[test]
    fn zero_seed_still_moves() {
        let mut s = Stream::new(&[0u8; 32]);
        let v: Vec<u8> = (0..32).map(|_| s.u8()).collect();
        assert!(v.iter().any(|&b| b != v[0]), "全零 seed 的流退化成常量了");
    }

    #[test]
    fn grease_values_are_grease() {
        let mut s = Stream::new(&seed(3));
        for _ in 0..256 {
            assert!(crate::values::is_grease(s.grease()));
        }
    }

    #[test]
    fn below_is_in_range() {
        let mut s = Stream::new(&seed(4));
        for n in 1..40u32 {
            for _ in 0..64 {
                assert!(s.below(n) < n);
            }
        }
    }

    #[test]
    fn shuffle_is_a_permutation_and_pins_are_fixed() {
        let mut s = Stream::new(&seed(5));
        let pinned = [true, false, false, true, false, true];
        for _ in 0..200 {
            let mut order: Vec<usize> = (0..pinned.len()).collect();
            s.shuffle(&mut order, &pinned);
            let mut sorted = order.clone();
            sorted.sort_unstable();
            assert_eq!(sorted, (0..pinned.len()).collect::<Vec<_>>(), "不是置换");
            for (i, &p) in pinned.iter().enumerate() {
                if p {
                    assert_eq!(order[i], i, "白名单元素动了位置");
                }
            }
        }
    }
}
