#!/usr/bin/env python3
"""陈旧断言闸门：活状态里的 sha 断言必须有出处，退役名不许回来当现状。

从 Octave-Full-Wasm 的 `.githooks/check-handoff.py` 迁移并泛化（那边是 L1–L4 四条
项目规则；这里留下的是**机制**，各仓库用自己的台账与退役名单喂它）：

  **R1 sha 断言的出处**（原 L1 的泛化）
  活状态正文里，靠近 sha / hash / 校验 / 指纹 字样的十六进制串，三种归宿：
      ① 它是台账里的一条事实（整串或渲染出的 16 位前缀都能对上）；
      ② 那一行自带历史标记（历史 / 退役 / 已翻案……）；
      ③ 那一行带**明确出处**（交付包名、反引号 commit sha）。
  三者都不是 ⇒ 它就是一句没有出处的「现在如此」—— 换了构建还挂着旧 sha 的那种。
  那边踩过的形状：换带 GL 的构建之后，头部还挂着旧 sha 没人发现。
  ⚠️ 两个出口（历史标记 / 明确出处）都是从血里来的：没有历史出口，人只能删掉历史；
     出口写成"任何裸 sha"，假断言就整行豁免（那边实测漏检过一次）。

  **R2 退役名**（原 L3 的泛化）
  退役组件名**独立成词**地出现在活状态里 = 「还在用它」的断言。
  ⚠️ 独立成词是必须的：分支名 / 文件名里的退役词是在**指路**（历史留档），
  不是当前状态的断言。名单用 `REFLECT_RETIRED` 配（逗号分隔）；不配 = 本条规则
  **明说未启用**，不假装查过。

  历史章节用 `REFLECT_HISTORY_SECS` 声明（如 `5,9,10`）——编号对不上的照样算活状态。

用法：
  python3 zreflect/check_stale.py            # 违规即非零（pre-commit / pre-push 用）
  python3 zreflect/check_stale.py --list     # 只列不改、永远 0（人工巡检）
  python3 zreflect/check_stale.py --selftest
"""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from gate import repo, require_nonempty, selftest        # noqa: E402
from ledger import _value, facts_of, load                # noqa: E402
from living import DATED_RECORD, HIST_MARK, living_lines  # noqa: E402

DOCS = tuple(d for d in os.environ.get(
    "REFLECT_DOCS", "STATE.md,AGENTS.md,README.md").split(",") if d)
HIST_SECS = tuple(s for s in os.environ.get("REFLECT_HISTORY_SECS", "").split(",") if s)
RETIRED = tuple(s for s in os.environ.get("REFLECT_RETIRED", "").split(",") if s)

SHA_NEAR = re.compile(r"sha|hash|校验|指纹", re.I)
SHA_TOKEN = re.compile(r"(?<![0-9a-f`])([0-9a-f]{8,64})(?![0-9a-f`])")


def _sha_facts(f):
    """台账里的 sha 类事实值（64 位串就是 sha；别的长度的串不猜）。"""
    out = set()
    for entry in (f or {}).values():
        v = _value(entry)
        if isinstance(v, str) and re.fullmatch(r"[0-9a-f]{64}", v or ""):
            out.add(v)
    return out


def _is_sourced(line):
    """这一行自己带了**明确**出处（历史标记 / 交付名 / 反引号 sha）。"""
    return bool(HIST_MARK.search(line) or DATED_RECORD.search(line))


def problems(ledger, docs, retired=RETIRED, hist_secs=None):
    """返回问题清单（纯函数：自证要用）。`docs` = {文件名: 正文}。

    `hist_secs=None` ⇒ 用模块级的 `REFLECT_HISTORY_SECS`；自证显式传，才能测到它。
    """
    hist = HIST_SECS if hist_secs is None else hist_secs
    out = []
    f = facts_of(ledger)
    if not f:
        return ["台账为空 —— 空不是通过（零值守卫）：先查 measure() 是不是坏了"]
    if not docs:
        return ["一份活状态文档都没扫到 —— 空输入不是通过（零值守卫）"]
    shas = _sha_facts(f)
    for name, body in sorted(docs.items()):
        for lineno, line, is_living in living_lines(body, hist):
            if not is_living or not SHA_NEAR.search(line) or _is_sourced(line):
                continue
            toks = SHA_TOKEN.findall(line)
            if not toks:
                continue
            if not shas:
                out.append("%s:%d sha 断言无出处：台账里**没有任何 sha 类事实**，"
                           "先把它量进台账（带复跑命令），再引用" % (name, lineno))
                continue
            for tok in toks:
                if not any(tok == s or s.startswith(tok) or tok.startswith(s[:len(tok)])
                           for s in shas):
                    out.append("%s:%d sha 断言无出处：`%s` 不在台账里 —— "
                               "改写成 [[键名]] 引用，或带上历史标记/出处"
                               % (name, lineno, tok[:16]))
    # R2 退役名：名单不配 = 未启用（run() 会明说，这里不打印 —— 纯函数保持安静）。
    for name, body in sorted(docs.items()):
        for lineno, line, is_living in living_lines(body, hist):
            if not is_living or _is_sourced(line):
                continue
            for w in retired:
                if re.search(r"(?<![0-9A-Za-z_-])%s(?![0-9A-Za-z_.-])" % re.escape(w),
                             line, re.I):
                    out.append("%s:%d 退役名 `%s` 出现在活状态里 —— 要么它没退役，"
                               "要么这行带上历史标记" % (name, lineno, w))
    return out


def run(argv):
    docs = {}
    for name in DOCS:
        p = repo(name)
        if os.path.exists(p):
            docs[name] = open(p, encoding="utf-8", errors="replace").read()
    try:
        require_nonempty("check_stale", docs, "被扫描的活状态文档")
    except SystemExit as e:
        print("%s" % e, file=sys.stderr)
        return 2
    facts_name = os.environ.get("REFLECT_FACTS", "FACTS.json")
    if not os.path.exists(repo(facts_name)):
        print("FATAL: 缺事实台账（%s）。先跑 python3 zreflect/facts.py 量一遍。"
              % facts_name, file=sys.stderr)
        return 2
    probs = problems(load(repo(facts_name)), docs)
    for x in probs:
        print("  · %s" % x, file=sys.stderr)
    if probs:
        print("陈旧断言检测：%d 个问题" % len(probs), file=sys.stderr)
        return 0 if "--list" in argv else 1
    if not RETIRED:
        print("R2（退役名）：REFLECT_RETIRED 未配置 ⇒ 本条规则未启用（要启用："
              "REFLECT_RETIRED=名1,名2）", file=sys.stderr)
    print("陈旧断言检测：OK（扫了 %d 份文档；退役名 %s）"
          % (len(docs), "未配置" if not RETIRED else "%d 个" % len(RETIRED)))
    return 0


def _cases():
    led_sha = {"facts": {"site_sha": {"value": "a" * 64, "cmd": "sha256sum x", "source": "s"}}}
    led_plain = {"facts": {"n": {"value": 7, "cmd": "echo 7", "source": "s"}}}
    bare = "部署 sha256 deadbeefdeadbeef00cafe00\n"
    return [
        # ① 正常不报
        ("sha 与台账一致（16 位前缀也能对上）⇒ 不报",
         lambda: problems(led_sha, {"A.md": "部署 sha256 %s…（截断显示）\n" % ("a" * 16)}) == []),
        ("带历史标记的 sha ⇒ 不报",
         lambda: problems(led_plain, {"A.md": "旧 sha abcdef01（已翻案，见 R-1）\n"}) == []),
        ("台账无 sha + 正文无 sha 断言 ⇒ 不报",
         lambda: problems(led_plain, {"A.md": "今天是好日子\n"}) == []),
        ("声明过的历史章节里的 sha ⇒ 不报",
         lambda: problems(led_plain, {"A.md": "## 5 历史\n" + bare}, hist_secs=("5",)) == []),
        ("退役名未配置 ⇒ 不报（但 run() 会明说未启用）",
         lambda: problems(led_plain, {"A.md": "还在用老组件\n"}, retired=()) == []),
        ("退役名只在指路（分支/文件名）⇒ 不报",
         lambda: problems(led_plain, {"A.md": "见 NOTES-osmesa.md 与 osmesa-分支\n"},
                          retired=("osmesa",)) == []),
        # ② 该报的必须报
        ("★ sha 不在台账且无出处 ⇒ 必须报",
         lambda: any("不在台账里" in x for x in problems(
             led_sha, {"A.md": bare}))),
        ("★ 台账里没有任何 sha 事实但正文断言了 sha ⇒ 必须报",
         lambda: any("没有任何 sha 类事实" in x for x in problems(
             led_plain, {"A.md": bare}))),
        ("★ 未声明历史章节 ⇒ 里面的 sha 照查（默认从严）",
         lambda: any("sha 断言无出处" in x for x in problems(
             led_plain, {"A.md": "## 5 历史\n" + bare}, hist_secs=()))),
        ("★ 退役名独立成词出现在活状态 ⇒ 必须报",
         lambda: any("退役名" in x for x in problems(
             led_plain, {"A.md": "后端还在用 osmesa\n"}, retired=("osmesa",)))),
        ("★ 无编号章节也是活状态（默认从严）⇒ 藏进去的退役名必须报",
         lambda: any("退役名" in x for x in problems(
             led_plain, {"A.md": "## 常见问题\n还在用 osmesa\n"}, retired=("osmesa",)))),
        # ③ 空输入必须报
        ("★ 台账空 ⇒ 必须报", lambda: problems({"facts": {}}, {"A.md": "x\n"}) != []),
        ("★ 一份文档都没扫到 ⇒ 必须报", lambda: problems(led_plain, {}) != []),
    ]


if __name__ == "__main__":
    sys.exit(selftest("check_stale（陈旧断言：sha 出处 + 退役名）", _cases())
             if "--selftest" in sys.argv else run(sys.argv[1:]))
