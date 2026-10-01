#!/usr/bin/env python3
"""把台账渲染成文档里的机器块 —— **数字的唯一产地**。

生成器（`facts.py`）与闸门（`check_facts.py`）必须共用这一个函数，
否则「块对不对」两边口径会分叉：生成器改了排版，闸门还按旧排版比，于是永远不一致
（或者更糟：两边都改成了宽松匹配，于是永远「一致」）。
"""
BLOCK_BEGIN = "<!-- AUTO:FACTS -->"
BLOCK_END = "<!-- /AUTO:FACTS -->"

PREAMBLE = [
    "> 本区块由 `zreflect/facts.py --render-doc` 从 `FACTS.json` 渲染，**不要手改**"
    "（pre-commit 会重算并 `git add`）。",
    "> 正文里的「测出来的数字」只在这里生产：要引用就写 `[[键名]]`，不要手抄数字。",
]


def _fmt(v):
    if isinstance(v, str) and len(v) == 64:
        return "`%s…`" % v[:16]
    return "**%s**" % (v if isinstance(v, str) else str(v))


def render_block(ledger):
    """台账 → 机器块（含首尾标记）。**纯函数**：同一份台账渲染两次逐字节相同。"""
    from ledger import facts_of                          # noqa: PLC0415

    f = facts_of(ledger)
    lines = [BLOCK_BEGIN] + list(PREAMBLE) + [""]
    if not f:
        # 零值守卫：**空台账必须明写「为空」**，不许渲染成一张安静的空表 ——
        # 空表看起来像「一切正常」，而事实是「一条都没量到」。
        lines += ["**台账为空** —— 一条事实都没有。空不是「通过」：先查 measure() 是不是坏了。", ""]
    else:
        lines += ["| 键 | 值 | 复跑命令 |", "|---|---|---|"]
        for k in sorted(f):
            e = f[k] if isinstance(f[k], dict) else {"value": f[k]}
            lines.append("| `%s` | %s | `%s` |" % (k, _fmt(e.get("value")), e.get("cmd", "?")))
        lines += ["", "%d 条事实。" % len(f)]
    lines.append(BLOCK_END)
    return "\n".join(lines)


def body_of(block):
    """取块内的正文（两端标记之间），供「块与台账一致」的比较用。"""
    if BLOCK_BEGIN not in block:
        return ""
    return block.split(BLOCK_BEGIN, 1)[1].split(BLOCK_END, 1)[0]


def prose_of(doc_text):
    """文档里**块以外**的正文（裸数字要在这里面查）。"""
    if BLOCK_BEGIN not in doc_text:
        return doc_text
    pre = doc_text.split(BLOCK_BEGIN, 1)[0]
    post = doc_text.split(BLOCK_END, 1)[-1] if BLOCK_END in doc_text else ""
    return pre + post


# ── 自证 ──────────────────────────────────────────────────────────────────────
def _cases():
    full = {"facts": {"a": 4752, "s": {"value": "b" * 64, "cmd": "c"}}}
    return [
        # ① 正常不报
        ("每个键都出现在块里", lambda: all(k in render_block(full) for k in ("a", "s"))),
        ("值是原值（4752 在块里）", lambda: "**4752**" in render_block(full)),
        ("sha 截断显示（不整条摊开）", lambda: "`" + "b" * 16 + "…`" in render_block(full)),
        ("块渲染是纯函数（渲染两次逐字节相同）",
         lambda: render_block(full) == render_block(full)),
        ("prose_of 只取块以外的正文（块内的表格被排除，块外的字保留）",
         lambda: (lambda d: ("正文" in prose_of(d) and "tail" in prose_of(d)
                             and "| 键 |" not in prose_of(d) and "| 键 |" in d))(
             "正文\n" + render_block(full) + "\ntail")),
        ("没有块标记时 prose_of 退回整篇（找不到块 ≠ 可以当空）",
         lambda: prose_of("没有标记的文档") == "没有标记的文档"),
        # ② 该报的必须报（渲染层的「该报」= 必须发生变化，不许是常量）
        ("★ 台账少一条 ⇒ 块跟着变（块不是常量）",
         lambda: render_block(full) != render_block({"facts": {"a": 4752}})),
        # ③ 空输入必须报
        ("★ 空台账 ⇒ 必须明写「台账为空」，且不许渲染出一张表",
         lambda: "台账为空" in render_block({"facts": {}})
         and "| 键 |" not in render_block({"facts": {}})),
        ("★ 空台账与有台账的块必须不同（空不是「都一样」）",
         lambda: render_block({"facts": {}}) != render_block(full)),
    ]


def _selftest():
    import os                                            # noqa: PLC0415
    import sys                                           # noqa: PLC0415
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from gate import selftest                            # noqa: PLC0415
    return selftest("render（数字的唯一产地）", _cases())


if __name__ == "__main__":
    import os                                            # noqa: PLC0415
    import sys                                           # noqa: PLC0415
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    sys.exit(_selftest())
