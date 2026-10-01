#!/usr/bin/env python3
"""复跑命令闸门：把台账里每条 `cmd` **真的跑一遍**，与 `value` 比。

# 为什么它非有不可（这是这套系统里最后一个「写了但没人验」的字段）

采集器的契约（`zreflect/collect.py` 原则一）写着「那条复跑命令必须**真的能跑**」，
但此前**没有任何检查器在验证这句话**：

- 事实闸门只查 `value`（块一致 / 裸数字 / 坏引用）；
- 两道改口守卫**刻意排除** `cmd`（`changed_keys` 只比 `value`，理由是「改 cmd 是文档维护」）。

于是 `cmd` 可以烂掉而四闸全绿 —— 而它恰好是「这条事实能被复跑」的唯一凭证。
更微妙的一层：`facts.py` 重算时走的是**采集器代码**（`measure_facts()`），
**不是**这些命令串；所以哪怕命令串写错了（改名、grep 模式错、shell 方言不对），
台账照样重算得出来。这个闸门把两者接上：**命令串的输出必须等于台账里的值**。

# 两个实现上的要点

1. **生产者合并**：~294 条事实的命令是 `cargo run … | grep '^<键>='`。逐条跑等于把同一个
   例子跑 294 遍；这里按「`|` 之前的生产者」分组，**每个生产者只跑一次**，
   再对每条事实用它的 grep 模式取值 —— 跑的还是那条命令（含那个 grep 模式），只是不重复。
2. **shell 方言**：Python 的 `shell=True` 用的是 `/bin/sh`（本机 dash）。
   所以 `cmd` 里**不许有 bash 专属写法**（`<(...)`、`[[`）。本仓实测抓到过一条
   （`fork_patch_matches_markers` 原来写成 `diff <(…) <(…)`），已改成 POSIX 写法。
   这一条本身就是这个闸门的价值：它把「命令在 dash 下跑不了」从「没人发现」变成红。
"""
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from gate import GATE_REPO, repo, selftest               # noqa: E402
from ledger import _value, facts_of, load                # noqa: E402

TIMEOUT = 900          # 单个生产者最多跑 15 分钟（`cargo run` 首次要编译）

# `… | grep '^<键>='`：把「生产者」与「键」拆开，键相同的生产者只跑一次。
# ⚠️ 键可能以**数字**开头（`360_7_ext_count`）—— 第一版只允许字母/下划线打头，
# 于是那批事实全走了「plain」取值路，报出一堆假「不一致」（自证夹具里没这个形状，
# 是**真台账**把它抓出来的：这正说明自证夹具的覆盖面有限、得靠真实输入兜底）。
KEYGREP_RE = re.compile(r"^(?P<producer>.+?)\s*\|\s*grep\s+-?[A-Za-z]*\s*'(?P<key>\^?[A-Za-z0-9_]+)='\s*$")
# 特殊取值器：命令的输出不是「整行就是值」，得抠一下。
VERSION_RE = re.compile(r'version\s*=\s*"([^"]+)"')


def _extract(cmd, out):
    """从一条命令的输出里取出「值」。取不出来返回 None（调用方要报，不许当通过）。"""
    lines = [l for l in out.splitlines() if l.strip()]
    if not lines:
        return None
    m = KEYGREP_RE.match(cmd)
    if m:                       # `key=value` ⇒ 值是等号之后那截（不是整行）
        key = m.group("key").lstrip("^")
        for line in lines:
            if line.startswith(key + "="):
                return line[len(key) + 1:]
        return None
    if "rustls" in cmd and "version" in cmd:
        m = VERSION_RE.search(out)
        return m.group(1) if m else None
    # 其余命令：第一行的整行（`rustc --version`、`wc -l`、`echo yes || echo NO`、
    # `python3 -c "print(len(...))"` 都是这个形状）。
    return lines[0].strip()


def _run(cmd, cache, cwd):
    """跑一条命令（带缓存）。返回 (rc, stdout+stderr)。"""
    if cmd not in cache:
        try:
            p = subprocess.run(cmd, shell=True, cwd=cwd, capture_output=True,
                               text=True, timeout=TIMEOUT)
            cache[cmd] = (p.returncode, p.stdout + p.stderr)
        except subprocess.TimeoutExpired:
            cache[cmd] = (124, "<超时：%ds>" % TIMEOUT)
    return cache[cmd]


def problems(ledger, runner, skip_keys=()):
    """纯函数：入参是**台账**（与兄弟闸门同一约定），`runner(cmd)` 返回 (rc, out)。
    返回问题清单，空 = 通过。自证要能注入假 runner，所以这里不碰进程、只收结果。

    `skip_keys`：**机器相关**的事实（`rustc --version` 那种）在别的机器上必然产出不同的值，
    所以允许调用方点名跳过 —— 但**必须显式点名并打印出来**（见 `run()` 读的
    `REFLECT_CMDS_SKIP`）。默认一个都不跳，本地判据因此仍是满的。
    """
    facts = facts_of(ledger)
    if not facts:
        # 零值守卫：台账空着不是「没有违规」，是「什么都没量」。
        return ["台账为空 —— 空不是通过（零值守卫）"]

    out = []
    checked = 0
    skipped = []
    machine = []
    for key, entry in sorted(facts.items()):
        cmd = entry.get("cmd") or ""
        want = _value(entry)
        if key in skip_keys:                      # 调用方点名的机器相关项
            machine.append(key)
            continue
        if isinstance(want, dict):                # 「量不到」的诚实形状：没有值可比
            skipped.append(key)
            continue
        rc, text = runner(cmd)
        if rc != 0:
            out.append("`%s`：命令退出码 %s（%s）" % (key, rc, cmd[:80]))
            continue
        got = _extract(cmd, text)
        if got is None:
            out.append("`%s`：从输出里取不出值（命令：%s）" % (key, cmd[:80]))
            continue
        if got != str(want):
            out.append("`%s`：命令产出 %r，台账记的是 %r（命令：%s）" % (key, got, str(want), cmd[:80]))
            continue
        checked += 1
    if out:
        return out
    if not checked:
        return ["一条命令都没验到 —— 零值守卫：全跳过不是通过"]
    if skipped:
        # 如实说：这些是「量不到」的事实，命令本身无从比对。
        print("  注意：%d 条事实是「量不到」形状，命令未比对：%s"
              % (len(skipped), ", ".join(skipped[:5])), file=sys.stderr)
    if machine:
        # 更要紧的是这条：跳过的**是有值可比、只是换台机器就不一样**的那些。
        print("  注意：按 REFLECT_CMDS_SKIP 跳过 %d 条机器相关事实（不比对）：%s"
              % (len(machine), ", ".join(machine)), file=sys.stderr)
    return []


def run(argv):
    led = load(repo(os.environ.get("REFLECT_FACTS", "FACTS.json")))
    f = facts_of(led)
    cache = {}
    cwd = GATE_REPO
    skip_keys = tuple(k for k in os.environ.get("REFLECT_CMDS_SKIP", "").split(",") if k)

    def runner(cmd):
        # 生产者合并：`producer | grep '^key='` ⇒ 只跑 producer 一次，
        # 然后按那条 key 从缓存的全量输出里取行 —— 跑的含 grep 的语义（取哪一行）。
        m = KEYGREP_RE.match(cmd)
        if m:
            producer, key = m.group("producer"), m.group("key").lstrip("^")
            rc, text = _run(producer, cache, cwd)
            if rc != 0:
                return rc, text
            for line in text.splitlines():
                if line.startswith(key + "="):
                    return 0, line
            return 0, ""                       # 没那一行 ⇒ 取不出值 ⇒ 报
        return _run(cmd, cache, cwd)

    probs = problems(led, runner, skip_keys)
    for x in probs:
        print("  · %s" % x, file=sys.stderr)
    if probs:
        print("复跑命令闸门：%d 个问题" % len(probs), file=sys.stderr)
        return 1
    print("复跑命令闸门：OK（%d 条事实的 cmd 全部产出记录值）" % len(f))
    return 0


# ── 自证：三档用例（正常不报 / 该报的必须报 / 空输入必须报）────────────────────
GOOD = {"facts": {"n": {"value": 7, "cmd": "echo 7"}}}


def _cases():
    def runner(rc=0, out="7"):
        return lambda cmd: (rc, out)

    return [
        # ① 正常不报
        ("命令产出与值一致 ⇒ 不报", lambda: problems(GOOD, runner()) == []),
        ("★ 生产者合并：`producer | grep '^k='` 那条路也走通 ⇒ 不报",
         lambda: problems({"facts": {"k": {"value": "v", "cmd": "echo k=v | grep '^k='"}}},
                          lambda c: (0, "k=v")) == []),
        # ② 该报的必须报
        ("★ 命令产出与值不一致 ⇒ 必须报",
         lambda: any("台账记的是" in x for x in problems(GOOD, runner(out="8")))),
        ("★ 命令退出码非 0 ⇒ 必须报",
         lambda: any("退出码" in x for x in problems(GOOD, runner(rc=2)))),
        ("★ 从输出里取不出值（空输出）⇒ 必须报",
         lambda: any("取不出值" in x for x in problems(GOOD, runner(out="")))),
        # ③ 空输入必须报
        ("★ 空台账 ⇒ 必须报（空不是通过）", lambda: problems({}, runner()) != []),
    ]


if __name__ == "__main__":
    sys.exit(selftest("check_cmds（复跑命令与记录值一致）", _cases())
             if "--selftest" in sys.argv else run(sys.argv[1:]))
