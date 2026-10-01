#!/usr/bin/env python3
"""事实闸门：文档里的块必须与台账一致，正文不许出现裸数字，引用不许指向不存在的键。

三条规则对应三种真实事故：

  · 块与台账不一致 —— 有人手改了块（或者改了台账忘了重渲染）；
  · 正文裸数字 —— 数字被手抄进散文，从这一刻起它就开始腐烂；
  · 引用不存在的键 —— 键被改名/删掉，引用原地变成一句没有出处的断言。
"""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from gate import GATE_REPO, repo, selftest               # noqa: E402
from ledger import _value, facts_of, load                # noqa: E402
from render import BLOCK_BEGIN, BLOCK_END, body_of, prose_of, render_block  # noqa: E402

# 正文引用数字的写法：`[[键名]]`。刻意选一个不可能是自然语言的形状 ——
# 这样「有没有引用」是**可判定的**，不靠正则猜散文。
CITE_RE = re.compile(r"\[\[([A-Za-z_][A-Za-z0-9_]*)\]\]")

BARE_MIN = 100   # 小于这个值的整数不查裸数字：1/2/3 遍地都是，查了全是噪音


def problems(ledger, doc_text):
    """返回问题清单（纯函数：自证要用）。空列表 = 通过。"""
    out = []
    f = facts_of(ledger)
    if not f:
        # 零值守卫：台账空着不是「没有违规」，是「什么都没量」。
        return ["台账为空 —— 空不是通过（零值守卫）：先查 measure_example() 是不是坏了"]
    if BLOCK_BEGIN not in doc_text or BLOCK_END not in doc_text:
        return ["文档里没有 %s / %s 标记 —— 找不到块 ≠ 块是对的（零值守卫）"
                % (BLOCK_BEGIN, BLOCK_END)]

    if body_of(doc_text).strip() != body_of(render_block(ledger)).strip():
        out.append("文档里的块与台账不一致 ⇒ 跑 `python3 zreflect/facts.py --render-doc`")

    prose = prose_of(doc_text)
    for i, line in enumerate(prose.splitlines(), 1):
        for k in CITE_RE.findall(line):
            if k not in f:
                out.append("正文第 %d 行引用了**不存在**的键：`%s`" % (i, k))

    for k, entry in sorted(f.items()):
        v = _value(entry)
        if isinstance(v, bool) or not isinstance(v, int) or v < BARE_MIN:
            continue
        for i, line in enumerate(prose.splitlines(), 1):
            if str(v) in line and ("[[%s]]" % k) not in line:
                out.append("正文第 %d 行出现裸数字 %s（属于 `%s`）⇒ 改写成 [[%s]]" % (i, v, k, k))
    return out


def run(argv):
    doc = argv[0] if argv else os.environ.get("REFLECT_DOC", "STATE.md")
    p = doc if os.path.isabs(doc) else repo(doc)
    if not os.path.exists(p):
        print("FATAL: 文档不存在：%s —— 找不到文件不许算通过（零值守卫）" % p, file=sys.stderr)
        return 2
    led = load(repo(os.environ.get("REFLECT_FACTS", "FACTS.json")))
    probs = problems(led, open(p, encoding="utf-8").read())
    for x in probs:
        print("  · %s" % x, file=sys.stderr)
    if probs:
        print("事实闸门：%d 个问题" % len(probs), file=sys.stderr)
        return 1
    print("事实闸门：OK（%d 条事实，块一致、无裸数字、无坏引用）" % len(facts_of(led)))
    return 0


LED = {"facts": {"count": {"value": 4752, "cmd": "c"}}}


def _cases():
    good = "这里没有裸数字。\n" + render_block(LED)
    return [
        # ① 正常不报
        ("块一致 + 无裸数字 ⇒ 不报", lambda: problems(LED, good) == []),
        ("正文引用存在的键 ⇒ 不报",
         lambda: problems(LED, "见 [[count]]\n" + render_block(LED)) == []),
        ("小整数（< 100）不算裸数字", lambda: problems(
            {"facts": {"n": {"value": 3, "cmd": "c"}}}, "有 3 个\n" + render_block({"facts": {"n": {"value": 3, "cmd": "c"}}})) == []),
        # ② 该报的必须报
        ("★ 块与台账不一致 ⇒ 必须报",
         lambda: any("不一致" in x for x in problems(LED, "x\n" + render_block({"facts": {}})))),
        ("★ 正文裸数字 ⇒ 必须报",
         lambda: any("裸数字" in x for x in problems(LED, "速度是 4752 次\n" + render_block(LED)))),
        ("★ 引用不存在的键 ⇒ 必须报",
         lambda: any("不存在" in x for x in problems(LED, "见 [[nope]]\n" + render_block(LED)))),
        # ③ 空输入必须报
        ("★ 空台账 ⇒ 必须报（空不是通过）", lambda: problems({"facts": {}}, good) != []),
        ("★ 文档没有块标记 ⇒ 必须报", lambda: problems(LED, "完全没有块的文档") != []),
    ]


if __name__ == "__main__":
    sys.exit(selftest("check_facts（块一致性 / 裸数字 / 坏引用）", _cases())
             if "--selftest" in sys.argv else run(sys.argv[1:]))
