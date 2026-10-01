# 01: 预设指纹怎么进事实台账

**What to build:** 让每个预设的指纹值**由一次可复跑的测量产生**，而不是谁手抄进文档。

**Status:** resolved

结案日期：2026-09-30。

## 结论

结算件已落地：`crates/utls/examples/reflect-facts.rs`。`zreflect/facts.py` 的
`_fingerprint_facts()` 跑它，把 `key=value` 行收进台账（键名形如 `fp_<预设>_<指标>`）。
台账里已出现 7 条 Chrome 133 的指纹事实，其中包含 JA3 的文本与 MD5、总长、密码套件数、
扩展数，以及两条**稳定性**指标（`fp_chrome_133_len_stable` / `fp_chrome_133_ja3_stable`）。

结案时顺带抓到两个「安静的错」，都已修并留痕：

1. **采集器的路径判断写死在 `examples/reflect-facts.rs`**，而结算件在
   `crates/utls/examples/` 下 —— 症状是**指纹事实一条都不出现**（不是报错，是少一整类事实）。
   改成按后缀发现（`_find_under`），workspace 布局变了也照样找到。
2. **键名被加了两次 `fp_` 前缀**（示例自己打一次、采集器再加一次），产出
   `fp_fp_chrome_133_…`。是**掉条守卫**一次列出 7 条抓到的，已记入 `retractions.json` 的 R-004。

## 复跑

```sh
cargo run --quiet --example reflect-facts     # 结算件本身
python3 zreflect/facts.py                     # 收进台账（值变了会被守卫拦下）
python3 zreflect/facts.py show fp_chrome_133_ja3_md5
```

**Settling:** `cargo run --quiet --example reflect-facts` —— rc=0 且输出含 `chrome_133_ja3_md5=`
⇒ 结算件在产出指纹；rc≠0 或没有该行 ⇒ 结算件坏了

**Type:** task

- [x] 落地指纹核心到能序列化出第一个预设的 ClientHello
- [x] 写 `examples/reflect-facts.rs`，输出 `key=value` 形态的指纹值
- [x] 跑 `python3 zreflect/facts.py`，确认台账里出现 `fp_` 开头的键
- [x] 把结论回填到 `STATE.md`，`Status:` 改 `resolved`，**别删这个文件**
