#!/bin/sh
# 闸门自证：**发现**闸门（不靠手写名单）+ 每个闸门必须先证明自己会红。
#
# 为什么是「发现」而不是「清单」：手写名录一定会漂。加新检查器时忘了登记，那个检查器
# 就变成「没人盯着的检查器」—— 而名录本身还绿着告诉你一切正常。实测过：一个自证脚本
# 自己拿某个检查器的 `0/0` bug 当立论依据，而那个检查器至今不在它的名单里。
# 所以这里反过来：**登记是被发现的，不是被记得的。**
#
# 用法：sh gates-selftest.sh          跑全部闸门
#       sh gates-selftest.sh --selftest   证明这个 runner 自己会红（它也需要）
set -u
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

run_gates() {
  # $1 = 仓库根。全绿返回 0；否则返回 1。
  d=$1
  n=0
  bad=0
  for g in "$d"/zreflect/check_*.py; do
    [ -f "$g" ] || continue
    n=$((n + 1))
    rel=${g#"$d"/}
    if ! grep -q -- '--selftest' "$g"; then
      echo "  ❌ $rel 没有 --selftest（未登记的闸门 = 没人盯着的闸门）"
      bad=$((bad + 1))
      continue
    fi
    out=$(GATE_REPO="$d" python3 "$g" --selftest 2>&1)
    if [ $? -ne 0 ]; then
      echo "  ❌ $rel"
      printf '%s\n' "$out" | tail -3 | sed 's/^/      /'
      bad=$((bad + 1))
    else
      echo "  ✅ $rel  $(printf '%s\n' "$out" | tail -1)"
    fi
  done
  if [ "$n" -eq 0 ]; then
    echo "  ❌ 一个闸门都没发现 —— 零值守卫：空输入不是通过"
    return 1
  fi
  if [ "$bad" -ne 0 ]; then
    echo "  ---- 发现 $n 个闸门，其中 $bad 个有问题"
    return 1
  fi
  echo "  ---- 发现 $n 个闸门，全部能红 ✅"
  return 0
}

selftest() {
  t=$(mktemp -d)
  bad=0
  mkdir -p "$t/good/zreflect" "$t/nomark/zreflect" "$t/failing/zreflect" "$t/empty/zreflect"

  # 夹具①：广告了 --selftest 且全过 ⇒ 应该全绿
  cat >"$t/good/zreflect/check_ok.py" <<'EOF'
import sys
print("=== ok 自证：3 PASS / 0 fail ===")
sys.exit(0 if "--selftest" in sys.argv else 0)
EOF
  # 夹具②：没广告 --selftest ⇒ 必须红
  cat >"$t/nomark/zreflect/check_silent.py" <<'EOF'
import sys
sys.exit(0)
EOF
  # 夹具③：广告了但自证失败 ⇒ 必须红
  cat >"$t/failing/zreflect/check_bad.py" <<'EOF'
import sys
print("=== bad 自证：1 PASS / 1 fail ===")
sys.exit(1 if "--selftest" in sys.argv else 0)
EOF
  # 夹具④：一个闸门都没有 ⇒ 必须红（零值守卫）

  show() { printf '%s' "$1" | sed 's/^/      /'; }

  out=$(run_gates "$t/good" 2>&1) && { echo "  PASS | 全绿夹具 ⇒ runner 绿"; } \
    || { echo "  fail | 全绿夹具 ⇒ runner 却是红的（阳性对照失败：runner 可能是'总是红'）"; show "$out"; bad=1; }

  out=$(run_gates "$t/nomark" 2>&1) && { echo "  fail | 缺 --selftest 的闸门 ⇒ runner 竟然绿了"; bad=1; } \
    || echo "  PASS | 缺 --selftest 的闸门 ⇒ runner 红"

  out=$(run_gates "$t/failing" 2>&1) && { echo "  fail | 自证失败的闸门 ⇒ runner 竟然绿了"; bad=1; } \
    || echo "  PASS | 自证失败的闸门 ⇒ runner 红"

  out=$(run_gates "$t/empty" 2>&1) && { echo "  fail | 一个闸门都没有 ⇒ runner 竟然绿了（零值守卫失效）"; bad=1; } \
    || echo "  PASS | 一个闸门都没有 ⇒ runner 红（零值守卫）"

  rm -rf "$t"
  if [ "$bad" -eq 0 ]; then
    echo "=== gates-selftest 自证：4 PASS / 0 fail ==="
    return 0
  fi
  echo "=== gates-selftest 自证：有失败 ==="
  return 1
}

if [ "${1:-}" = "--selftest" ]; then
  selftest
else
  echo "闸门自证（发现式名录）："
  run_gates "$HERE"
fi

# ── 跨仓库可配置性自证（**没有硬编码**的可证伪证据）────────────────────────────
# 做法：搭一个**临时夹具仓库**，把三个名字全换掉（REFLECT_FACTS/REFLECT_DOC/DOCS），
#       三个闸门必须仍全绿；再用**默认名字**跑同一夹具 —— **必须红**
#       （否则说明这一节是恒真的空转，什么都没证明）。
configurable_selftest() {
  tmp=$(mktemp -d)
  printf 'x = 1\n' > "$tmp/a.py"
  # 机器块标记要**先手工放一次**（工具自己的约定：找不到块 ≠ 块是对的）
  printf '# 标题\n\n正文引用 [[py_files]] 与 [[md_files]]（引用键，不手抄数字）。\n\n<!-- AUTO:FACTS -->\n<!-- /AUTO:FACTS -->\n' > "$tmp/NOTES.md"
  printf '# AGENTS\n' > "$tmp/AGENTS.md"
  printf '{"schema":1,"retractions":[]}\n' > "$tmp/RETRACT.json"        # 换名：REFLECT_RETRACTIONS
  mkdir -p "$tmp/cases"                                                  # 换名：REFLECT_QUESTIONS
  printf '# 例2\n\n**Status:** ready-for-agent\n\n**Settling:** `python3 a.py` —— rc=0 ⇒ A；rc=7 ⇒ B\n' > "$tmp/cases/02-y.md"
  # 生成台账并把机器块渲染进 **NOTES.md**（名字全换掉）
  # ① 先量一遍（新仓库的正确顺序：量测 → 渲染）
  GATE_REPO="$tmp" REFLECT_FACTS=LEDGER.json REFLECT_DOC=NOTES.md \
    python3 "$HERE/zreflect/facts.py" >/dev/null 2>&1
  # ② 再把机器块渲染进 NOTES.md（名字全换掉）
  GATE_REPO="$tmp" REFLECT_FACTS=LEDGER.json REFLECT_DOC=NOTES.md \
    python3 "$HERE/zreflect/facts.py" --render-doc NOTES.md >/dev/null 2>&1
  ok=0; n=0
  for g in "$HERE"/zreflect/check_*.py; do
    n=$((n + 1))
    if GATE_REPO="$tmp" REFLECT_FACTS=LEDGER.json REFLECT_DOC=NOTES.md \
       REFLECT_DOCS=NOTES.md,AGENTS.md REFLECT_RETRACTIONS=RETRACT.json \
       REFLECT_QUESTIONS=cases python3 "$g" >/dev/null 2>&1; then
      ok=$((ok + 1))
    else
      echo "  ❌ 换名字后 $g 红了（说明名字还被写死在代码里）"
    fi
  done
  [ "$n" -gt 0 ] || { echo "  ❌ 夹具里一个闸门都没跑到"; rm -rf "$tmp"; return 1; }
  # 反向：用**默认名字**跑同一夹具 ⇒ **每一个依赖改名输入的闸门都必须红**。
  # ⚠️ 这一段的判据第一版只数了个数（`red>0`）—— 分辨力不足：夹具当时没换
  #    retractions.json/questions 的名字，那两个闸门绿着却被算作"证明过了"
  #    （issue #1 ② 的原话）。现在逐个点名，缺一个红就失败。
  red_need="check_facts.py check_retractions.py check_questions.py"
  red=""
  for g in "$HERE"/zreflect/check_*.py; do
    b=$(basename "$g")
    if ! GATE_REPO="$tmp" python3 "$g" >/dev/null 2>&1; then red="$red $b"; fi
  done
  for b in $red_need; do
    case " $red " in *" $b "*) ;; *) echo "  ❌ 默认名字下 $b **没有红** ⇒ 换名自证对它的名字什么都没证明"; red=""; break;; esac
  done
  rm -rf "$tmp"
  [ "$ok" = "$n" ] && [ -n "$red" ] || {
    echo "  ❌ 可配置性自证不成立（换名全绿=$ok/$n；默认名下没红的闸门=[$red_need]）"; return 1; }
  echo "  ✅ 四个名字全换（LEDGER.json/NOTES.md/RETRACT.json/cases）$ok/$n 全绿；默认名字下 [$red_need] 全红 ⇒ 没有硬编码"
  return 0
}
echo "── 跨仓库可配置性 ──"
configurable_selftest || bad=$((bad + 1))

