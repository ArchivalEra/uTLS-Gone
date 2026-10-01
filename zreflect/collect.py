#!/usr/bin/env python3
"""事实采集器的契约与帮手 —— 从 Octave-Full-Wasm 的 `.githooks/handoff_facts.py` 迁移。

`measure()`（facts.py）怎么写，决定了台账里的数是**测出来的**还是**编出来的**。
那边把采集器单独成一个模块、并把下面四条原则写在文件头，因为这个模块同时喂两个
消费者（重算机器块的生成器 + 查陈旧断言的闸门）—— **两边必须用同一套读法**，
否则口径分叉，闸门查的就是另一套数字了。

四条原则（都是那边踩出来的，采集器必须遵守）：

  1. **只读持久盘产物**，不跑服务、不碰网络。pre-commit 里不该依赖"某个东西正在跑"。
  2. **不引入会自己在变的输入**：机器块里不放"墙上时钟"、不放 HEAD 的 sha ——
     否则同一个提交里 `--check` 永远不收敛。要用时间就用**提交日期**。
  3. **读不到就明说**：产物不在（换了机器 / 没挂盘）⇒ `unavailable(what, why)`，
     让调用方决定是警告还是跳过。**绝不编一个数字** —— 0 是一个数字，会被人当结果引用。
  4. **贵的测量要有缓存**：先从现有机器块里回收上一次的测量值（`prev_values`），
     输入没变就沿用。那边用它免掉"每次提交都重压 36 MiB"。
"""
import re

from gate import repo                                    # noqa: F401  (re-export 便利)


def unavailable(what, why):
    """「读不到」的诚实形状。调用方（渲染/闸门）必须把它渲染成明说，不许当成 0。"""
    return {"ok": False, "why": why}


def parse_prev_values(doc_text, row_pattern, group_names):
    """从现有机器块里回收上一次的测量值（原则 4 的通用形状）。

    `row_pattern`：一行的正则，用命名分组 `(?P<名字>…)` 标出要回收的值；
    `group_names`：要回收的分组名元组。返回 {行首键: {名字: 值}}。

    返回的值是**字符串** —— 数字不数字由采集器自己解释（它知道口径）。
    典型用法：先把上次的 (raw, gz) 拿回来，输入没变就跳过贵的测量。
    """
    out = {}
    if not doc_text:
        return out
    pat = re.compile(row_pattern)
    for m in pat.finditer(doc_text):
        key = m.group(1)
        rec = {}
        for name in group_names:
            try:
                rec[name] = m.group(name)
            except IndexError as error:
                # 未命名分组 = 配置错，必须响，不许静默拿错值。
                raise SystemExit(
                    "FATAL: parse_prev_values：行正则里没有命名分组 %r —— "
                    "回收靠命名分组，别用位置分组（换行序 = 静默拿错值）" % name) from error
        out[key] = rec
    return out
