#!/usr/bin/env python3
"""事实台账的 CLI：量一遍、写台账、渲染机器块，以及**两道守卫**。

用法
    python3 zreflect/facts.py                      # 量一遍并写 FACTS.json（掉条/改口会拒绝）
    python3 zreflect/facts.py --allow-drop         # 允许本次掉条（掉掉的键会打出来）
    python3 zreflect/facts.py --accept-changes     # 允许本次改口（旧值→新值会打出来）
    python3 zreflect/facts.py --render-doc [文件]  # 把机器块写进文档（默认 STATE.md）
    python3 zreflect/facts.py --check [文件]       # 文档里的块是否与台账一致
    python3 zreflect/facts.py show [键]            # 打印某条事实
    python3 zreflect/facts.py --selftest           # 自证：两道守卫必须都能红

⚠️ **量不到的项不写**（宁缺勿假）。比如「最近一次全绿回归」只在有日志的机器上量得出来；
没日志就把那条事实**留空**，而不是写 0 —— 0 是一个数字，会被人当结果引用。
"""
import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from gate import GATE_REPO, repo, selftest             # noqa: E402
from ledger import (changed_keys, dropped_keys, fact,  # noqa: E402
                    facts_of, load, _short)
from render import BLOCK_BEGIN, BLOCK_END, body_of, prose_of, render_block  # noqa: E402

LEDGER_NAME = os.environ.get("REFLECT_FACTS", "FACTS.json")
OUT = repo(LEDGER_NAME)
DOC = os.environ.get("REFLECT_DOC", "STATE.md")


# ══ 你的部分 ══════════════════════════════════════════════════════════════════
# uTLS-rs 量什么。规矩来自 zreflect/collect.py：**只读持久盘、不碰网络、
# 不引入会自己在变的输入、读不到就不写**（绝不编 0 —— 0 是一个数字，会被人当结果引用）。
# 每条 fact 的第二个参数是**复跑命令**：它必须真的能跑，否则这条事实又变回散文。
#
# ⚠️ 本项目的核心事实是**每个预设的指纹**（见 _fingerprint_facts）。它们不由手抄得来，
# 而由仓内那条验证 CLI 跑出来 —— 这正是这套系统要的形状：文档里的指纹值只能来自
# 一次可复跑的测量。结算件还不存在时**一条都不写**（挂在 questions/ 里当悬案）。

SKIP_DIRS = {".git", "target", "__pycache__", "node_modules", ".venv"}

FIND_SKIP = ("-not -path './.git/*' -not -path './target/*' "
             "-not -path '*/__pycache__/*' -not -path './crates/rustls/*'")


# vendored 的上游代码：**不能和我们自己的代码混在一起数**。
#
# 为什么单列：`rs_files` / `rs_lines` 原本的意思是「本项目的规模」。fork 进来之后，
# 如果把它们算进去，那两条事实就从「我们写了多少」变成「我们搬了多少」——
# 数字还是那个数字，含义却变了，而**没有任何闸门会发现含义变了**。
# 所以 vendored 部分单独成事实（`fork_*`），两条口径各有各的复跑命令。
VENDOR_PREFIXES = ("crates/rustls/",)


def _is_vendor(path):
    rel = os.path.relpath(path, GATE_REPO)
    return any(rel.startswith(px) for px in VENDOR_PREFIXES)


def _iter_files(vendor="exclude"):
    """走一遍仓库。跳过的目录与下面复跑命令里的 FIND_SKIP 保持同一口径。

    `vendor`：`"exclude"` 只数我们自己写的，`"only"` 只数 vendored 的。
    """
    for root, dirs, files in os.walk(GATE_REPO):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for f in files:
            if f.endswith(".pyc"):
                continue
            p = os.path.join(root, f)
            if vendor == "exclude" and _is_vendor(p):
                continue
            if vendor == "only" and not _is_vendor(p):
                continue
            yield p


def _count(ext, vendor="exclude", skip_facts_block=False):
    """(文件数, 行数)。数不出来的文件不计数 —— 宁缺勿假。

    `skip_facts_block`：**跳过机器块内部的那些行**。`.md` 的度量必须开它 ——
    因为机器块是渲染进文档的，而块里又渲染了 `md_lines` 自己：把它算进去，
    这条事实就**永远追不上自己**（实测：`--render-doc` 一跑，`md_lines` 立刻过期，
    于是复跑命令**恒定**失败）。这属于采集器契约第 2 条「不引入会自己在变的输入」。
    """
    n = lines = 0
    for p in _iter_files(vendor):
        if not p.endswith(ext):
            continue
        n += 1
        try:
            with open(p, encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError:
            continue
        if skip_facts_block and BLOCK_BEGIN in text:
            text = text.split(BLOCK_BEGIN, 1)[0]
        lines += text.count("\n") + (1 if text and not text.endswith("\n") else 0)
    return n, lines


def _first_line(cmd):
    """跑一条本地命令取首行；不存在/失败 ⇒ None（调用方据此**不写**这条事实）。"""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=30, cwd=GATE_REPO)
    except (OSError, subprocess.SubprocessError):
        return None
    out = (r.stdout or "").strip().splitlines()
    return out[0].strip() if r.returncode == 0 and out else None


def _count_named(dir_rel, prefix, suffix):
    """数 dir_rel 下 prefix 开头、suffix 结尾的文件；目录不在 ⇒ None。"""
    d = repo(dir_rel)
    if not os.path.isdir(d):
        return None
    return sum(1 for f in os.listdir(d) if f.startswith(prefix) and f.endswith(suffix))


def _rustls_pin():
    """我们**构建时用**的 rustls 版本要求；没有显式版本时退回补丁的位置。

    ⚠️ **两遍扫描是必需的**，而第一版只有一遍 —— 于是它先撞到 `[patch.crates-io]`
    里那条（`rustls = { path = "crates/rustls" }`，**不含版本号**），返回了 `"patched"`。
    那个值技术为真、却毫无信息量：问「我们钉的是哪个 rustls」，答「补丁过的」。
    实测在接入 fork 之后才暴露（在此之前 `rustls` 根本不是依赖，这条事实压根不存在）。
    要钉住的东西在 `[dependencies]` 里，所以先找它，再退回补丁路径。
    """
    try:
        import tomllib                                     # noqa: PLC0415  (3.11+)
    except ImportError:
        return None
    patch_path = None
    for p in _iter_files():
        if not p.endswith("Cargo.toml"):
            continue
        try:
            with open(p, "rb") as fh:
                d = tomllib.load(fh)
        except (OSError, ValueError):
            continue
        for table in ("dependencies", "dev-dependencies", "build-dependencies"):
            v = (d.get(table) or {}).get("rustls")
            if v is None:
                continue
            if isinstance(v, str):
                return v
            if v.get("version"):
                return v["version"]
        spec = ((d.get("patch") or {}).get("crates-io") or {}).get("rustls")
        if spec is not None and patch_path is None:
            patch_path = spec.get("path") or spec.get("git") or "patched"
    return patch_path


def _modified_by_us():
    """fork 里带 `FORK(utls-rs)` 标记的文件 —— 也就是我们真的改过的那些。"""
    out = []
    for p in _iter_files(vendor="only"):
        if not p.endswith(".rs"):
            continue
        try:
            with open(p, encoding="utf-8", errors="replace") as fh:
                if "FORK(utls-rs)" in fh.read():
                    out.append(p)
        except OSError:
            pass
    return out


def _iter_files_of(root):
    """遍历**任意**目录下的文件（`_iter_files` 是按仓库相对路径设计的）。"""
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            yield os.path.join(dirpath, name)


def _find_under(rel_suffix):
    """在仓库里找以 `rel_suffix` 结尾的文件（跳过 .git/target/缓存目录）。

    为什么不用写死的路径：workspace 一改布局（crates/*/examples/…），写死的路径就悄悄失效，
    而失效的表现是**指纹事实一条都不出现** —— 那不是报错，是「安静地少了一整类事实」。
    所以这里按后缀发现，布局变了也照样找到。
    """
    if not rel_suffix:
        return None
    tail = os.sep + rel_suffix.lstrip("/")
    for p in _iter_files():
        if p.endswith(tail):
            return p
    return None


def _fingerprint_facts(facts):
    """★ 本项目真正的事实：每个预设的指纹。

    形状：仓内 `examples/reflect-facts.rs` 打印 `key=value` 行，这里逐条收进台账 ——
    于是**文档里的指纹值只能来自一次可复跑的测量**，而不是谁手抄的。
    结算件还不存在 ⇒ 一条都不写（挂在 questions/ 里当悬案，不编假值）。
    """
    src = _find_under("examples/reflect-facts.rs")
    if src is None:
        return
    cmd = ["cargo", "run", "--quiet", "--example", "reflect-facts"]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=300, cwd=GATE_REPO)
    except (OSError, subprocess.SubprocessError):
        return                                              # 跑不起来 ⇒ 不写，不编
    if r.returncode != 0:
        return
    for line in (r.stdout or "").splitlines():
        if "=" not in line or line.lstrip().startswith("#"):
            continue
        k, _, v = line.partition("=")
        k, v = k.strip(), v.strip()
        if k and v:
            facts["fp_%s" % k] = fact(
                v, "cargo run --quiet --example reflect-facts | grep '^%s='" % k,
                "examples/reflect-facts.rs",
                "指纹：由验证 CLI 实测，**不手抄**")


def measure_facts():
    """量本项目的事实。**量不到的项不写**（不是写 0）。"""
    facts = {}

    # ── 工具链：会随升级改口，而改口正是要被抓到的（两道守卫会拦）──
    for key, cmd in (("rustc_version", ["rustc", "--version"]),
                     ("cargo_version", ["cargo", "--version"])):
        v = _first_line(cmd)
        if v:
            facts[key] = fact(v, " ".join(cmd), "toolchain")

    # ── 仓库规模（**不含** vendored 的上游）──
    for ext, key, what in ((".rs", "rs", "我们自己写的 Rust"), (".py", "py", "闸门/采集器"),
                           (".md", "md", "文档")):
        n, lines = _count(ext, skip_facts_block=(ext == ".md"))
        facts["%s_files" % key] = fact(
            n, "find . -name '*%s' %s | wc -l" % (ext, FIND_SKIP), "repo", what)
        # ⚠️ `.md` 的行数**跳过机器块**：块里渲染了 md_lines 自己，算进去就永远追不上。
        # 下面那条命令与这个口径一一对应（`awk` 从块标记起不再打印）。
        cmd = ("find . -name '*%s' %s -exec cat {} + | wc -l" % (ext, FIND_SKIP)
               if ext != ".md"
               # `FNR==1{b=0}` 是必需的：`-exec … {} +` 把所有文件喂给同一个 awk，
               # 不按文件重置就会「第一个带块的文件之后全被跳过」（实测踩到：126 vs 1068）。
               else "find . -name '*.md' %s -exec awk 'FNR==1{b=0} /%s/{b=1} !b' {} + | wc -l"
                    % (FIND_SKIP, BLOCK_BEGIN))
        facts["%s_lines" % key] = fact(lines, cmd, "repo", what)

    # ── vendored 上游：单独两条，口径与上面互不污染 ──
    n, lines = _count(".rs", vendor="only")
    if n:
        facts["fork_rs_files"] = fact(
            n, "find crates/rustls -name '*.rs' | wc -l", "crates/rustls",
            "vendored 的 rustls fork（**不是**我们写的）")
        facts["fork_rs_lines"] = fact(
            lines, "find crates/rustls -name '*.rs' -exec cat {} + | wc -l", "crates/rustls",
            "同上")
        facts["fork_rs_modified"] = fact(
            len(_modified_by_us()), "grep -rc 'FORK(utls-rs)' crates/rustls/src --include='*.rs' "
            "| grep -v ':0' | wc -l", "crates/rustls",
            "我们**改过**的 fork 文件数（其余是上游原文）")

    # ── 补丁自身的规模：README 里曾经**手抄**过这几个数字，而手抄的会腐烂 ──
    # （`crates/rustls-fork/README.md` 的「补丁应当成为一条台账事实」那条就是在说这件事。）
    pdiff = repo("crates/rustls-fork/patch.diff")
    if os.path.exists(pdiff):
        try:
            lines = open(pdiff, encoding="utf-8", errors="replace").read().splitlines()
        except OSError:                                    # pragma: no cover
            lines = []
        # 口径与复跑命令逐字对应：`^diff --git` / `^@@` / 去掉 `+++` `---` 头的增删行。
        facts["fork_patch_files"] = fact(
            sum(1 for l in lines if l.startswith("diff --git")),
            "grep -c '^diff --git' crates/rustls-fork/patch.diff", "crates/rustls-fork/",
            "补丁改动的文件数（含新建的 fork.rs）")
        facts["fork_patch_hunks"] = fact(
            sum(1 for l in lines if l.startswith("@@")),
            "grep -c '^@@' crates/rustls-fork/patch.diff", "crates/rustls-fork/",
            "补丁的 hunk 数 —— rebase 时按 hunk 定位，所以它是「要维护的行数」的尺度")
        facts["fork_patch_plus"] = fact(
            sum(1 for l in lines if l.startswith("+") and not l.startswith("+++")),
            "grep '^+' crates/rustls-fork/patch.diff | grep -vc '^+++'", "crates/rustls-fork/",
            "补丁新增行数")
        facts["fork_patch_minus"] = fact(
            sum(1 for l in lines if l.startswith("-") and not l.startswith("---")),
            "grep '^-' crates/rustls-fork/patch.diff | grep -vc '^---'", "crates/rustls-fork/",
            "补丁删除行数")
        # 「补丁是不是**旧**的」这件事，上面四条数目里一条也看不出来 —— 本轮踩到：
        # 文件数照样 9，而 `hs.rs` 的会话 id 修复根本没进补丁（`patch.diff` 比 `src` 旧）。
        # 能自动量的那一半是这条不变式：**补丁的文件数 == 带 `FORK(utls-rs)` 标记的文件数**。
        # （另一半——「把它打到原始树上能重现我们的树」——见 `crates/rustls-fork/README.md`，
        # 那条要一份原始 tarball，不适合放在每次提交都跑的采集器里。）
        if "fork_rs_modified" in facts:
            facts["fork_patch_matches_markers"] = fact(
                "yes" if sum(1 for l in lines if l.startswith("diff --git"))
                == facts["fork_rs_modified"]["value"] else "NO",
                # ⚠️ 这条命令必须是 **POSIX sh**（`check_cmds.py` 用 `shell=True` 跑，
        # 本机是 dash）：`diff <(…) <(…)` 是 bash 专属，实测被闸门当场抓红
        # （`exit 2: Syntax error: "(" unexpected`）。这一条本身就是那个闸门的存在理由。
        "[ \"$(grep -c '^diff --git' crates/rustls-fork/patch.diff)\" = "
        "\"$(grep -rl 'FORK(utls-rs)' crates/rustls/src --include='*.rs' | wc -l)\" ] "
        "&& echo yes || echo NO",
                "crates/rustls-fork/",
                "不变式：patch.diff 的文件数 == 带 FORK(utls-rs) 标记的文件数"
                "（不等 ⇒ 补丁漏了文件，或漏了标记）")

    # ── REALITY 等价实现（crates/reality）──
    # 它有自己的对外承诺，所以值得自己的事实。三条都**从代码/测试里量**，
    # 不手抄（手抄的数字会腐烂 —— 本仓的规矩）。
    r_src = repo("crates/reality/src")
    r_tests = repo("crates/reality/tests")
    if os.path.isdir(r_src):
        n, lines = 0, 0
        for p in _iter_files_of(r_src):
            if p.endswith(".rs"):
                n += 1
                try:
                    lines += sum(1 for _ in open(p, encoding="utf-8", errors="replace"))
                except OSError:
                    pass
        facts["reality_files"] = fact(
            n, "find crates/reality/src -name '*.rs' | wc -l", "crates/reality/",
            "REALITY 等价实现的规模（我们写的）")
        facts["reality_lines"] = fact(
            lines, "find crates/reality/src -name '*.rs' -exec cat {} + | wc -l",
            "crates/reality/", "同上")
    if os.path.isdir(r_tests):
        # 判据条数：数 `#[test]`，**包含被 `#[ignore]` 的那条**（它也是判据，
        # 只是需要外部二进制；不数进来会让「一共几条」这件事对不上测试输出）。
        # ⚠️ 口径：`tests/` 与 `src/` 都要数 —— 有的判据是模块内嵌的（`#[cfg(test)]`，
        # 例如 `mirror_tls::split_tests` 要访问私有 `RecordKeys`）。只数 `tests/`
        # 会让台账**低估**自己（本仓最恨的那种漂移）。
        n = 0
        for root in (r_src, r_tests):
            if not os.path.isdir(root):
                continue
            for p in _iter_files_of(root):
                if not p.endswith(".rs"):
                    continue
                try:
                    n += open(p, encoding="utf-8", errors="replace").read().count("#[test]")
                except OSError:
                    pass
        facts["reality_tests"] = fact(
            n, "grep -rc '#\\[test\\]' crates/reality/tests crates/reality/src --include='*.rs' "
            "| awk -F: '{s+=$2} END {print s}'", "crates/reality/",
            "判据条数（含需要 stock Xray 的 #[ignore]；tests/ 与 src/ 内嵌判据一起数）")

    # ── 闸门与台账的健康度（**发现式**计数，与 gates-selftest.sh 同一口径）──
    gates = _count_named("zreflect", "check_", ".py")
    if gates is not None:
        facts["gate_count"] = fact(gates, "ls zreflect/check_*.py | wc -l", "zreflect/",
                                   "闸门数：登记是被发现的，不是被记得的")

    qrel = os.environ.get("REFLECT_QUESTIONS", "questions")
    qdir = repo(qrel)
    if os.path.isdir(qdir):
        qs = sorted(f for f in os.listdir(qdir) if f.endswith(".md"))
        if qs:
            facts["question_count"] = fact(len(qs), "ls %s/*.md | wc -l" % qrel, qrel + "/",
                                           "悬案总数")
            # ⚠️ **必须用闸门自己的解析器**读 Status，不能拿子串在全文里找 "resolved"：
            # 每条悬案文件里都有一句操作说明「把 `Status:` 改 `resolved`」，子串匹配会把
            # **全部**悬案算成已结案。本仓实测踩到：4 条未结案被量成 0，而且那个 0 已经
            # 渲染进了 STATE.md 的机器块。修法不是收紧正则，是**共用同一个读法** ——
            # 见 collect.py 的原则：「采集器与闸门必须用同一套读法，否则口径分叉」。
            try:
                from check_questions import field as _qfield   # noqa: PLC0415
            except ImportError:                                # pragma: no cover
                _qfield = None
            openq = 0
            for f in qs:
                try:
                    body = open(os.path.join(qdir, f), encoding="utf-8", errors="replace").read()
                except OSError:
                    continue
                st = (_qfield(body, "Status") if _qfield else None) or "?"
                if st.split()[0] != "resolved":
                    openq += 1
            facts["open_questions"] = fact(
                openq,
                "python3 -c \"import sys;sys.path.insert(0,'zreflect');"
                "from check_questions import collect,field;"
                "print(sum(1 for t in collect('%s').values() "
                "if (field(t,'Status') or '')!='resolved'))\"" % qrel,
                qrel + "/",
                "未结案的悬案 —— 读法与闸门同源（别改成子串匹配）")

    rrel = os.environ.get("REFLECT_RETRACTIONS", "retractions.json")
    rp = repo(rrel)
    if os.path.exists(rp):
        try:
            with open(rp, encoding="utf-8") as fh:
                n = len(json.load(fh).get("retractions") or [])
            facts["retraction_count"] = fact(
                n, "python3 -c \"import json;print(len(json.load(open('%s'))['retractions']))\""
                   % rrel, rrel, "已被推翻、不许再当现状出现的断言")
        except (OSError, ValueError):
            pass

    # ── 依赖钉法：整个 fork 方案挂在它上面 ──
    v = _rustls_pin()
    if v:
        facts["rustls_pin"] = fact(
            # 只认**依赖声明**那一行：`[patch.crates-io]` 里那条是 `path = "crates/rustls"`，
            # 不含版本号 —— 用它当复跑命令会得到一个不含台账值的输出。
            v, "grep -rh '^rustls *= *{ *version' --include='Cargo.toml' . | head -1",
            "Cargo.toml",
            "钉住的 rustls —— 补丁要对它 rebase")

    # ── ★ 指纹事实（结算件存在时才有）──
    _fingerprint_facts(facts)
    return facts


# ══ 以下不用改 ════════════════════════════════════════════════════════════════
def write_doc(path_rel, ledger):
    """把块写进文档（就地替换）。没有标记就报错，**不悄悄追加** ——
    悄悄追加会让「块过期」变成「有两份块」，那是更难查的坏法。"""
    p = path_rel if os.path.isabs(path_rel) else repo(path_rel)
    if not os.path.exists(p):
        print("FATAL: %s 不存在。先手工放一次 %s / %s 两个标记。" % (p, BLOCK_BEGIN, BLOCK_END),
              file=sys.stderr)
        return 2
    text = open(p, encoding="utf-8").read()
    if BLOCK_BEGIN not in text or BLOCK_END not in text:
        print("FATAL: %s 缺 %s / %s 标记（第一次落地时要手工放一次）"
              % (p, BLOCK_BEGIN, BLOCK_END), file=sys.stderr)
        return 2
    pre, _, rest = text.partition(BLOCK_BEGIN)
    _, _, post = rest.partition(BLOCK_END)
    new = pre + render_block(ledger) + post
    if new != text:
        open(p, "w", encoding="utf-8").write(new)
        print("已刷新 %s 的事实块" % path_rel)
    else:
        print("%s 的事实块无变化" % path_rel)
    return 0


def check_doc(path_rel, ledger):
    p = path_rel if os.path.isabs(path_rel) else repo(path_rel)
    if not os.path.exists(p):
        print("FATAL: 文档 %s 不存在（--check 不能因为找不到文件就算通过）" % p, file=sys.stderr)
        return 2
    text = open(p, encoding="utf-8").read()
    if BLOCK_BEGIN not in text or BLOCK_END not in text:
        print("FATAL: %s 缺事实块标记" % path_rel, file=sys.stderr)
        return 2
    if body_of(text) != body_of(render_block(ledger)):
        print("FATAL: %s 的事实块与 FACTS.json 不一致 ⇒ 跑 --render-doc" % path_rel, file=sys.stderr)
        return 1
    print("%s 的事实块与台账一致" % path_rel)
    return 0


def measure(argv):
    """量一遍并写台账。**必须接 `argv`** —— 两道守卫都要读它。

    ⚠️ 这里踩过：`measure()` 曾经没有 `argv` 参数，而守卫里写着 `not in argv`。
    因为 `and` 短路，**只在真的掉条时**才走到那句 ⇒ 报的不是「掉了哪几条」而是一段
    NameError traceback；`--allow-drop` 从未生效过。写盘被拦住只是**顺带**（异常早于写盘），
    那不叫守卫，那叫故障。所以本文件把 argv 显式传进来，并且守卫自己也吃一条反向断言。
    """
    facts = measure_facts()

    old = facts_of(load(OUT)) if os.path.exists(OUT) else {}

    # 守卫一：掉条（键没了）
    dropped = dropped_keys(old, facts)
    if dropped and "--allow-drop" not in argv:
        print("FATAL: 本次会从台账里**掉掉 %d 条事实**（输入不在？）：%s"
              % (len(dropped), ", ".join(dropped)), file=sys.stderr)
        print("       台账不写。要么把输入准备好，要么显式 `--allow-drop`"
              "（并把掉掉的键记进 HISTORY）。", file=sys.stderr)
        return 2
    if dropped:
        print("⚠ --allow-drop：本次掉掉 %d 条：%s" % (len(dropped), ", ".join(dropped)),
              file=sys.stderr)

    # 守卫二：改口（值换了）
    changed = changed_keys(old, facts)
    if changed and "--accept-changes" not in argv:
        print("FATAL: 本次重测会**改掉 %d 条事实的值**（未经接受的改口）：" % len(changed),
              file=sys.stderr)
        for k, o, n in changed:
            print("       %-24s %s → %s" % (k, _short(o), _short(n)), file=sys.stderr)
        print("       台账不写。逐条确认这些变化**是实测出来的**（不是输入不在/量错了）之后，"
              "再显式 `--accept-changes`。", file=sys.stderr)
        return 2
    if changed:
        print("⚠ --accept-changes：本次接受 %d 条改口：" % len(changed))
        for k, o, n in changed:
            print("       %-24s %s → %s" % (k, _short(o), _short(n)))

    if not facts:
        print("FATAL: 一条事实都没量到。空台账不是通过（零值守卫）。", file=sys.stderr)
        return 2

    import time                                         # noqa: PLC0415
    doc = {"schema": 1, "generated": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
           "_why": "事实台账：每条 = 一个**测出来**的值 + 复跑命令 + 出处。"
                   "别手改，跑 zreflect/facts.py。",
           "facts": facts}
    with open(OUT, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=1, ensure_ascii=False)
        fh.write("\n")
    print("已写出 %s（%d 条事实）" % (os.path.relpath(OUT, GATE_REPO), len(facts)))
    for k, v in sorted(facts.items()):
        print("  %-20s %s" % (k, v["value"]))
    return 0


def _load_or_die():
    """读台账；**没有就给出可操作的提示**而不是原始 traceback。
    为什么单列：新仓库第一次用时台账还不存在，而这个脚本今天会直接抛
    FileNotFoundError —— 那是"为本仓写死"的味道（我们那边永远有 FACTS.json）。
    语义仍是 fail-loud（空台账照样拒绝渲染），只是**把下一步写在错误里**。"""
    if not os.path.exists(OUT):
        print("FATAL: 还没有台账 %s\n"
              "       先在仓库根跑一遍量测：python3 zreflect/facts.py\n"
              "       然后再 --render-doc 把机器块写进文档。" % os.path.basename(OUT),
              file=sys.stderr)
        raise SystemExit(2)
    return load(OUT)


def main(argv):
    if argv and argv[0] == "--render":
        sys.stdout.write(render_block(_load_or_die()) + "\n")
        return 0
    if argv and argv[0] == "--render-doc":
        return write_doc(argv[1] if len(argv) > 1 else DOC, _load_or_die())
    if argv and argv[0] == "--check":
        return check_doc(argv[1] if len(argv) > 1 else DOC, _load_or_die())
    if argv and argv[0] == "show":
        led = _load_or_die()
        f = facts_of(led)
        keys = [argv[1]] if len(argv) > 1 else sorted(f)
        rc = 0
        for k in keys:
            if k not in f:
                print("没有这条事实：%s（现有：%s）" % (k, ", ".join(sorted(f))), file=sys.stderr)
                rc = 1
                continue
            e = f[k] if isinstance(f[k], dict) else {"value": f[k]}
            print("%-20s %s" % (k, e.get("value")))
            print("    出处  %s" % e.get("source", "?"))
            print("    复跑  %s" % e.get("cmd", "?"))
            if e.get("note"):
                print("    备注  %s" % e["note"])
        return rc
    return measure(argv)


CASES = [
    # ① 正常不报
    ("不掉条 ⇒ 守卫不报", lambda: dropped_keys({"a": 1}, {"a": 1, "b": 2}) == []),
    ("值没变 ⇒ 改口守卫不报", lambda: changed_keys({"a": {"value": 1}},
                                                   {"a": {"value": 1}}) == []),
    # ② 该报的必须报
    ("★ 掉条 ⇒ 守卫报出来", lambda: dropped_keys({"a": 1, "b": 2}, {"a": 1}) == ["b"]),
    ("★ 改口 ⇒ 守卫报出来且带旧值→新值",
     lambda: changed_keys({"a": {"value": 1}}, {"a": {"value": 2}}) == [("a", 1, 2)]),
    # ③ 空输入必须报
    ("★ 空文档（没有块标记）⇒ check_doc 必须报，不许算通过",
     lambda: (lambda: (open("/tmp/_zr_empty.md", "w").write("空空如也\n"),
                       check_doc("/tmp/_zr_empty.md", {"facts": {"a": 1}}))[1])() == 2),
    ("★ 文档文件不存在 ⇒ check_doc 必须报（不许因为找不到就算通过）",
     lambda: check_doc("/tmp/_zr_no_such_file_%d.md" % os.getpid(), {"facts": {"a": 1}}) == 2),
]


if __name__ == "__main__":
    sys.exit(selftest("facts.py（两道守卫 + 文档一致性）", CASES)
             if "--selftest" in sys.argv else main(sys.argv[1:]))
