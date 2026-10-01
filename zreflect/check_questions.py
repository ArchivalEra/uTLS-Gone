#!/usr/bin/env python3
"""悬案闸门：**未结案的问题必须挂一个能跑的结算件。**

一条悬案 = `questions/NN-slug.md`，头部必须有：

    **Status:** ready-for-agent
    **Settling:** zreflect/facts.py —— rc=0 ⇒ 守卫生效；rc=2 ⇒ 守卫没拦住

规则与理由：

  · `Settling:` 必须写**仓库内的相对路径**或一条能直接跑的命令，不许写「见某笔记」——
    指向散文的结算件等于没有结算件。
  · 两种结论必须给出**不同的退出码 / 可区分的输出**，否则它证伪不了任何东西。
  · **结算件还不存在的悬案是合法悬案** —— 那这张单的第一个交付物就是造它。这种情况
    写 `Settling: 不存在 —— 本工单的第一交付物`。如实写「不存在」是有信息的；
    编一个假路径会让闸门绿着骗人。
  · 结案后改 `Status: resolved`，**别删文件** —— 「我们决定不查这个」本身就是一条结论。
"""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from gate import GATE_REPO, repo, require_nonempty, selftest   # noqa: E402

VALID_STATUS = ("needs-triage", "needs-info", "ready-for-agent",
                "ready-for-human", "wontfix", "resolved")
NONE_LIKE = ("不存在", "none", "None", "n/a", "N/A")
PATHISH = (".py", ".sh", ".mjs", ".js", ".md", "/")


def field(text, name):
    """取 `**Name:** 值` / `**Name**: 值` / `Name: 值` 三种写法的值（行首，第一个匹配）。

    ⚠️ 这里踩过一次：正则写成 `\\*{0,2}Name\\*{0,2}\\s*:` —— 它匹配不了 `**Status:**`
    （真实顺序是 `**` + `Status` + `:` + `**`，冒号**在**那对星号中间）。于是所有字段都读成
    None，闸门把「合规的悬案」也报成「缺字段」。**冒号后面还要容许一对星号**。
    """
    m = re.search(r"(?mi)^\*{0,2}%s\*{0,2}\s*:\s*\*{0,2}\s*(.+?)\s*$" % re.escape(name), text)
    return m.group(1).strip() if m else None


def problems(files, exists=None):
    """返回问题清单（纯函数：自证要用）。`files` = {文件名: 正文}。

    `exists` 可注入（测试夹具用）—— 默认判断相对仓库根的路径是否存在。
    """
    out = []
    if not files:
        # 零值守卫：一条悬案都没收到 ⇒ 「没有缺结算件的悬案」是空话。
        return ["一条悬案都没收集到 —— 空输入不是通过（零值守卫）：先查 questions/ 目录"]
    chk = exists or (lambda p: os.path.exists(os.path.join(GATE_REPO, p)))
    for name, text in sorted(files.items()):
        st = field(text, "Status")
        if not st:
            out.append("%s：缺 `**Status:**` 行" % name)
        elif st.split()[0] not in VALID_STATUS:
            out.append("%s：Status 不合法：%s（合法：%s）"
                       % (name, st, ", ".join(VALID_STATUS)))
        sv = field(text, "Settling")
        if not sv:
            out.append("%s：缺 `**Settling:**` 行 —— 没有结算件的悬案只能算「猜想」" % name)
            continue
        if sv.startswith(NONE_LIKE):
            # 接受「第一交付物」与「第一个交付物」两种写法 —— 约定文档里写的是后者，
            # 检查器只认前者的话，**合规的悬案会被判成不合规**（本仓实测踩到：
            # 15 张单里那张用了自然语序的，被自己的闸门报「没说明第一交付物」）。
            if "第一交付物" not in sv.replace("的", ""):
                out.append("%s：Settling 写了「不存在」，但没说明**第一交付物就是它** —— "
                           "否则读者不知道下一步干什么" % name)
            continue
        if not any(t in sv for t in ("rc=", "⇒", "=>")):
            out.append("%s：Settling 没给出**可区分的两种结论**（写成 `… —— rc=0 ⇒ A；rc=7 ⇒ B`）"
                       " —— 只描述做法、不描述判据的东西证伪不了任何事" % name)
        tok = sv.split()[0].strip("`")
        if any(tok.endswith(x) or x in tok for x in PATHISH) and not chk(tok):
            out.append("%s：Settling 指的结算件**不存在**：%s" % (name, tok))
    return out


def collect(d=None):
    # 名字可配（issue #1 ②）：默认 questions/，可用 REFLECT_QUESTIONS 换
    d = d or os.environ.get("REFLECT_QUESTIONS", "questions")
    root = os.path.join(GATE_REPO, d)
    files = {}
    if os.path.isdir(root):
        for f in sorted(os.listdir(root)):
            if f.endswith(".md"):
                files["%s/%s" % (d, f)] = open(os.path.join(root, f), encoding="utf-8",
                                               errors="replace").read()
    return files


def run(argv):
    files = collect(argv[0] if argv else None)
    try:
        require_nonempty("check_questions", files, "悬案文件（questions/*.md）")
    except SystemExit as e:
        print("%s" % e, file=sys.stderr)
        return 2
    probs = problems(files)
    for x in probs:
        print("  · %s" % x, file=sys.stderr)
    if probs:
        print("悬案闸门：%d 个问题" % len(probs), file=sys.stderr)
        return 1
    n_open = sum(1 for t in files.values() if (field(t, "Status") or "") != "resolved")
    print("悬案闸门：OK（%d 条悬案，其中未结案 %d）" % (len(files), n_open))
    return 0


def _q(status="ready-for-agent", settling="zreflect/facts.py —— rc=0 ⇒ 生效；rc=2 ⇒ 没拦住"):
    return "# 01: 示例\n\n**Status:** %s\n\n**Settling:** %s\n" % (status, settling)


def _cases():
    ok = {"questions/01.md": _q()}
    return [
        # ① 正常不报
        ("合规悬案（结算件存在）⇒ 不报",
         lambda: problems(ok, exists=lambda p: True) == []),
        ("结算件标「不存在 —— 本工单的第一交付物」⇒ 不报（合法悬案；「的」不影响判定）",
         lambda: problems({"questions/02.md": _q(settling="不存在 —— 本工单的第一交付物是造它")},
                          exists=lambda p: False) == []),
        ("resolved 的悬案同样要合规", lambda: problems(
            {"questions/03.md": _q(status="resolved")}, exists=lambda p: True) == []),
        # ② 该报的必须报
        ("★ 缺 Settling ⇒ 必须报",
         lambda: any("缺 `**Settling:**`" in x for x in problems(
             {"questions/04.md": _q(settling="")}, exists=lambda p: True))),
        ("★ 结算件路径不存在 ⇒ 必须报",
         lambda: any("不存在" in x and "结算件" in x for x in problems(ok, exists=lambda p: False))),
        ("★ Settling 没给出两种结论 ⇒ 必须报",
         lambda: any("可区分" in x for x in problems(
             {"questions/05.md": _q(settling="跑一下看看")}, exists=lambda p: True))),
        ("★ Status 不合法 ⇒ 必须报",
         lambda: any("不合法" in x for x in problems(
             {"questions/06.md": _q(status="随便写的")}, exists=lambda p: True))),
        ("★ Settling 写「不存在」但**没说明第一交付物** ⇒ 必须报（如实写「不存在」有信息，"
         "但不说下一步干什么等于把问题丢回去）",
         lambda: any("第一交付物" in x for x in problems(
             {"questions/08.md": _q(settling="不存在")}, exists=lambda p: False))),
        ("★ 缺 Status ⇒ 必须报",
         lambda: any("缺 `**Status:**`" in x for x in problems(
             {"questions/07.md": "**Settling:** x.py —— rc=0 ⇒ a；rc=1 ⇒ b"},
             exists=lambda p: True))),
        # ③ 空输入必须报
        ("★ 一条悬案都没有 ⇒ 必须报（零值守卫）", lambda: problems({}, exists=lambda p: True) != []),
    ]


if __name__ == "__main__":
    sys.exit(selftest("check_questions（悬案必须挂结算件）", _cases())
             if "--selftest" in sys.argv else run(sys.argv[1:]))
