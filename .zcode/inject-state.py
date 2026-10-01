#!/usr/bin/env python3
"""SessionStart hook：把「现在是什么」注入上下文。

挂法见 `.zcode/config.json`。它做的只有两件事：列出**未结案的悬案**，以及台账的规模。
为什么值得占一个 hook：会话开始时 agent 手上没有状态，于是它会**重新提出已经结案的问题**、
或者**照抄一份过期的数字**。这个脚本把那两件事的输入摆在桌面上。

⚠️ 输出必须短。注入的内容会进上下文，一屏以上会挤掉真正的工作内容。

⚠️ 为什么默认输出 JSON 而不是纯文本（本仓实测修正）：
ZCode 把 hook 的 **stdout 按严格 JSON 解析**，形状必须是
`{"hookSpecificOutput": {"hookEventName": <事件名>, "additionalContext": <文本>}}`；
**任何多余的键都会导致验证失败、效果被丢弃**。上游那份直接用 `print()` 输出纯文本，
在 ZCode 下**注入从未生效过**（只在日志里留一条 failed）—— 这正是本系统要抓的那类
「机制躺在仓库里、闸门从未被执行」。所以：非终端运行时发 JSON，人手工运行时发纯文本
（`--text` 或检测到 tty）。
"""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "zreflect"))

from gate import GATE_REPO                                   # noqa: E402

EVENT = "SessionStart"


def state_lines():
    """把活状态编成短行。**只读持久盘**（采集器契约第 1 条）。"""
    out = ["── uTLS-rs · 活状态 ──"]

    # 1) 未结案的悬案
    try:
        from check_questions import collect, field           # noqa: PLC0415
        qs = collect(os.environ.get("REFLECT_QUESTIONS", "questions"))
        open_qs = [(n, field(t, "Status") or "?") for n, t in sorted(qs.items())
                   if (field(t, "Status") or "") != "resolved"]
        if not qs:
            out.append("悬案：**一条都没有** —— questions/ 是空的，这本身可疑，不是好消息")
        elif not open_qs:
            out.append("悬案：%d 条，全部已结案。" % len(qs))
        else:
            out.append("悬案：未结案 %d / 共 %d —— 先读这些，别重新提出已结案的问题："
                       % (len(open_qs), len(qs)))
            for n, st in open_qs[:6]:
                out.append("   · %s  [%s]" % (n, st))
            if len(open_qs) > 6:
                out.append("   · …还有 %d 条" % (len(open_qs) - 6))
    except Exception as e:                                   # noqa: BLE001
        out.append("悬案：读不到（%r）—— 门开着，别把「读不到」当成「没有」" % e)

    # 2) 台账规模
    try:
        from ledger import facts_of, load                    # noqa: PLC0415
        f = facts_of(load(os.path.join(GATE_REPO, os.environ.get("REFLECT_FACTS",
                                                                "FACTS.json"))))
        out.append("台账：%d 条事实（数字请写 [[键名]] 引用，别手抄）" % len(f))
    except Exception as e:                                   # noqa: BLE001
        out.append("台账：读不到（%r）" % e)

    # 3) 翻案条数
    try:
        from ledger import load as _load                      # noqa: PLC0415
        n = len(_load(os.path.join(GATE_REPO, "retractions.json")).get("retractions") or [])
        out.append("翻案：%d 条（这些断言**不许**再当现状出现）" % n)
    except Exception:                                        # noqa: BLE001
        pass
    return out


def main(argv):
    text = "\n".join(state_lines())
    # 人手工跑 / 显式要文本 ⇒ 纯文本；作为 hook 跑 ⇒ ZCode 的严格 JSON 信封
    if "--text" in argv or sys.stdout.isatty():
        print(text)
        return 0
    print(json.dumps({"hookSpecificOutput": {"hookEventName": EVENT,
                                             "additionalContext": text}},
                     ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
