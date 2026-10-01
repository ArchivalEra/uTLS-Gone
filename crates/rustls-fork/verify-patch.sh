#!/usr/bin/env sh
# 一条命令验证 `patch.diff` 的两条判据 —— **CI 的 `patch-repro` job 调的就是这个脚本**，
# 所以「本地过」与「CI 过」是同一份代码、同一套判据，不会各自漂移。
#
# 两条判据（缺一不可，理由见 README「二之前」一节）：
#   ① 补丁里的文件数 == `crates/rustls/src` 里带 `FORK(utls-rs)` 标记的文件数；
#   ② 把补丁打到**原始** `rustls-0.23.45.crate` 上，得到的树与 `crates/rustls`
#      **逐文件相同**。
#
# 为什么两条都要：本轮踩到过「①过、②不过」——`hs.rs` 的一处修复没进补丁
# （`patch.diff` 比 `src` 旧），而文件数照样相等。「文件数相等」只是必要条件，
# **打出来能重现**才是判据。
#
# ⚠️ 判据②的口径是**整棵 crate**（只排除 `.git` 与 `target`），比 CI 早先只比 `src/`
# 更强，也覆盖 README 里那条手工配方。两种口径统一到这一处，避免「两个判据都叫
# 补丁可重现」。
#
# 用法：
#   sh crates/rustls-fork/verify-patch.sh [工作目录]
# 默认工作目录 `/tmp/rs-patch-verify`（首次会去 static.crates.io 取 tarball，之后复用）。
# 取不到 tarball 时如实失败：这是**需要联网**的判据，别把它伪装成离线可跑。
set -eu

REPO=$(cd "$(dirname "$0")/../.." && pwd)
PATCH="$REPO/crates/rustls-fork/patch.diff"
VENDORED="$REPO/crates/rustls"
W=${1:-/tmp/rs-patch-verify}
VERSION=0.23.45

[ -f "$PATCH" ] || {
    echo "找不到 $PATCH" >&2
    exit 2
}

mkdir -p "$W"
cd "$W"

# ── 取原始 tarball（缓存） ──
if [ ! -f "rustls-$VERSION.crate" ]; then
    echo "取 rustls-$VERSION.crate …"
    curl -sSLO "https://static.crates.io/crates/rustls/rustls-$VERSION.crate" || {
        echo "取不到 tarball —— 这条判据需要联网（CI 上直接可达）" >&2
        exit 1
    }
fi

# ── 原始树 + git 基线 ──
rm -rf "rustls-$VERSION"
tar xzf "rustls-$VERSION.crate"
cd "rustls-$VERSION"
git init -q .
git add -A
git -c user.email=x@y -c user.name=x commit -qm pristine

# ── 判据①：文件数 ──
files=$(grep -c '^diff --git' "$PATCH")
marked=$(grep -rl 'FORK(utls-rs)' "$VENDORED/src" --include='*.rs' | wc -l)
echo "判据① 补丁文件数=$files  带 FORK(utls-rs) 标记的文件数=$marked"
if [ "$files" != "$marked" ]; then
    echo "⚠️ 判据①不过：补丁覆盖的文件与带标记的文件不是同一批" >&2
    echo "   （多半是新改了一个文件却没重新生成 patch.diff，见 README「二之前」）" >&2
    exit 1
fi

# ── 判据②：打上去能否逐文件重现 vendored 那棵树 ──
git apply "$PATCH"
if diff -r -x .git -x target . "$VENDORED"; then
    echo "判据② 打出来的树与 crates/rustls 逐文件相同 ✅"
else
    echo "⚠️ 判据②不过：上面的差异就是补丁与 vendored 树的出入" >&2
    exit 1
fi

echo "OK：补丁可重现（两条判据都过）"
