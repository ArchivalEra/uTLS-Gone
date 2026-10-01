#!/usr/bin/env python3
"""Stop hook：把机器块刷新进活状态文档。

挂法与理由见 `.zcode/config.json`。这个脚本存在的唯一理由是**它永远不许阻塞会话**：

ZCode 的 hook 退出码语义是 `0` 放行、`2` 阻塞、其它非零算错误。而 `facts.py --render-doc`
在台账缺失时会 `SystemExit(2)` —— 直接挂上去的话，**一次台账缺文件就会把 Stop 变成阻塞**。
所以这里把失败一律降级为「stderr 说一句 + 退出 0」：既留在日志里可查，又不拿会话当人质。

⚠️ 它**只重算机器块**（纯本地、无网络），不跑闸门 —— 闸门是 pre-commit 的事。
"""
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
DOC = os.environ.get("REFLECT_DOC", "STATE.md")


def main():
    try:
        r = subprocess.run([sys.executable, os.path.join(REPO, "zreflect", "facts.py"),
                            "--render-doc", DOC],
                           capture_output=True, text=True, timeout=120, cwd=REPO)
    except (OSError, subprocess.SubprocessError) as e:
        print("reflect: 刷新机器块失败（%r）—— 不影响会话" % e, file=sys.stderr)
        return 0
    if r.returncode != 0:
        # 刻意不 return 非零：见模块头。诊断进 stderr，ZCode 会记进日志。
        tail = (r.stderr or r.stdout or "").strip().splitlines()[-1:] or [""]
        print("reflect: 机器块未刷新（rc=%d，%s）" % (r.returncode, tail[0]), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
