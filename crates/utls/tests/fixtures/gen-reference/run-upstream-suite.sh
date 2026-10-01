#!/usr/bin/env bash
# 跑**上游全套 go test**，不 `-skip`、不走代理。
#
# 为什么需要它：上游有两条测试（`tls_test.go` 的 `TestVerifyHostname` 与
# `TestRealResumption`）带 `testenv.MustHaveExternalNetwork(t)`，目标写死了
# `www.google.com` / `yahoo.com`。本机直连不到那两个域名，于是此前只有两条路：
# 经一个 SOCKS5h 代理跑（配方见 `questions/09-full-suite-oracle.md`），
# 或在 CI 上把这两条 `-skip` 掉 —— 后者不是「不带跳过地跑通」。
#
# 这两条真正判的机制**与对端是谁无关**：
#   * `TestVerifyHostname`：证书链能验过，且拿**另一个名字**去验必须失败
#     ⇒ 需要「证书 SAN 与自身主机名一致」的对端；
#   * `TestRealResumption`：真握手 + 读票据 + 第二次连接 `DidResume`
#     ⇒ 需要「支持 TLS 1.3 会话票据」的对端。
# 所以把目标域名换成**直连可达**且两条都满足的 `www.baidu.com`
# （实测依据：`probes/egress_candidates_test.go` 的探针，本机无代理直连跑过）。
#
# ⚠️ 换的是**目标域名**，不是判据；上游树在磁盘上**一个字节都不动** ——
# 用 Go 自带的 `-overlay` 在**构建期**把 `tls_test.go` 换成临时目录里的改写稿。
# `VerifyHostname("www.yahoo.com")` **故意留着不换**：它就是断言失败的那一半。
#
# 用法：
#   run-upstream-suite.sh [参照树目录] [go test 的额外参数...]
# 默认参照树 `/tmp/utls-ref/utls-master`（取回命令见 ../README.md）。
#
# ⚠️ 本脚本刻意写成 **POSIX sh**（不用 bashism）：CI 与很多发行版的 `/bin/sh` 是 dash，
# 而 `set -o pipefail` 在旧 dash 上是 `Illegal option`（实测：GitHub runner 上红了第一次）。
# 这里也没有需要 pipefail 的管道，所以直接不用它。
set -eu

REF=${1:-/tmp/utls-ref/utls-master}
if [ $# -ge 1 ]; then
    shift
fi
REF=$(realpath "$REF")
[ -f "$REF/tls_test.go" ] || {
    echo "找不到 $REF/tls_test.go —— 参照树没取回？取回命令见 ../README.md" >&2
    exit 2
}

W=$(mktemp -d)
trap 'rm -rf "$W"' 0

sed -e 's|www\.google\.com|www.baidu.com|g' \
    -e 's|"yahoo\.com:443"|"www.baidu.com:443"|g' \
    -e 's|ServerName:         "yahoo\.com"|ServerName:         "www.baidu.com"|' \
    -e 's|Host: yahoo\.com|Host: www.baidu.com|' \
    "$REF/tls_test.go" > "$W/tls_test.go"

# 换错方向会**静默地**少判一半，所以两条都断言：
#   ① 失配名必须还在（否则 `TestVerifyHostname` 失去了它要证的那半边）；
#   ② 不能再残留任何外网域名（否则这两条又会因连不上而失败）。
grep -q 'VerifyHostname("www.yahoo.com")' "$W/tls_test.go" || {
    echo "改写把失配名 www.yahoo.com 也换掉了 —— TestVerifyHostname 会失去它要证的半边" >&2
    exit 1
}
if grep -q 'www\.google\.com' "$W/tls_test.go"; then
    echo "改写后仍残留 www.google.com（这条会因连不上而失败）：" >&2
    grep -n 'www\.google\.com' "$W/tls_test.go" >&2
    exit 1
fi
# `yahoo.com` **只允许**以「失配名」的身份留在那两行里（判据的另一半）；
# 任何**会去连**的写法（`:443` 拨号、`ServerName:`、`Host:` 头）都必须已被换掉。
if grep -n 'yahoo\.com' "$W/tls_test.go" \
    | grep -qvE 'VerifyHostname\("www\.yahoo\.com"\)|verify www\.yahoo\.com'; then
    echo "改写后仍残留会去连的外网域名（这两条会因连不上而失败）：" >&2
    grep -n 'yahoo\.com' "$W/tls_test.go" >&2
    exit 1
fi

printf '{"Replace":{"%s":"%s"}}\n' "$REF/tls_test.go" "$W/tls_test.go" > "$W/overlay.json"

cd "$REF"

# ── 把**我们自己的探针**从树里摘掉，再跑 ──
# `ech_utls_server.rs` 那条判据会把 `ech_server_live_test.go` 复制进树里；手工跑探针时
# 也可能留下别的几个。它们不是上游套件的一部分，而且有的要真外网、跑不了就
# `t.Skip` —— 留在树里会让下面的「跳过集恰如预期」响（本轮实测就这么红过一次，
# 而那次是**脚本对了**：树不干净）。只按**确切文件名**删，都是本仓 probes/ 里的
# 已知文件；上游自己的 `ech_test.go` 不在名单里，绝不动。
removed=""
for probe in ech_inner_probe_test.go ech_decoder_probe_test.go ech_confirmation_probe_test.go \
             ech_server_probe_test.go ech_server_live_test.go ech_live_probe_test.go \
             egress_candidates_test.go; do
    if [ -f "$REF/$probe" ]; then
        rm -f "$REF/$probe"
        removed="$removed $probe"
    fi
done
if [ -n "$removed" ]; then
    echo "（摘掉了本仓留在参照树里的探针：$removed —— 它们不属于上游套件）"
fi

# 模块代理：默认 `off` —— 本地这一跑因此**顺带证明它不需要联网取模块**（依赖都在
# module cache 里）。CI runner 的缓存是冷的，必须显式覆盖（见 ci.yml 的 `upstream-no-skip`）。
: "${GOPROXY:=off}"
export GOPROXY
set +e
go test -count=1 -timeout 480s -json -overlay="$W/overlay.json" "$@" ./... \
    > "$W/run.json" 2> "$W/err"
rc=$?
set -e
[ -s "$W/err" ] && tail -20 "$W/err" >&2

python3 - "$W/run.json" <<'PY' >&2
import json, sys, collections
c = collections.Counter()
top = {}
skips, fails = set(), set()
for line in open(sys.argv[1]):
    line = line.strip()
    if not line.startswith('{'):
        continue
    try:
        ev = json.loads(line)
    except json.JSONDecodeError:
        continue
    t = ev.get('Test')
    if not t:
        continue
    a = ev.get('Action')
    c[a] += 1
    if '/' not in t:
        top[t] = a
    if a == 'skip':
        skips.add(t)
    elif a == 'fail':
        fails.add(t)
tp = sum(1 for a in top.values() if a == 'pass')
print(f"上游套件（无代理 · 不 -skip）：顶层 {tp} PASS / {len(fails)} FAIL / {len(skips)} SKIP")
for s in sorted(skips):
    print(f"  skip：{s}")
for f in sorted(fails):
    print(f"  FAIL：{f}")
PY

# ── 「不 -skip」这句话必须可判，而不是一句声明 ──
# 唯一允许的跳过是上游自己 `t.Skip` 的那条（`u_conn_test.go:63`）。
# 出现任何**别的**跳过，就是有人（或某个新版本上游）在安静地少跑东西 —— 必须响。
allowed='TestUTLSHandshakeClientParrotGolang'
unexpected=$(python3 - "$W/run.json" "$allowed" <<'PY'
import json, sys
allowed = sys.argv[2]
skips = set()
for line in open(sys.argv[1]):
    line = line.strip()
    if not line.startswith('{'):
        continue
    try:
        ev = json.loads(line)
    except json.JSONDecodeError:
        continue
    if ev.get('Test') and ev.get('Action') == 'skip':
        skips.add(ev['Test'])
print(' '.join(sorted(s for s in skips if s != allowed)))
PY
)
if [ -n "$unexpected" ]; then
    echo "⚠️ 除上游自己跳的那条之外还有跳过：$unexpected —— 「不 -skip」不再成立" >&2
    exit 1
fi

# ── 「真的跑了东西」也必须可判 ──
# 只断言「没有意外的跳过」是不够的：**一条测试都没跑**（包名解析成空、源码树取错、
# `-run` 意外命中零条）同样是 0 FAIL / 0 SKIP，两个 job 都会安静地绿。
# 所以这里要一个**正数**。不写死 222：那会因上游加一条测试而红（本仓的规矩：
# 写死计数是「上游一改就响」的魔法数，见 `utls_testdata.rs` 里同一条理由），
# 只断言「非空」，并把实测值打出来给人看。
if [ "$(python3 - "$W/run.json" <<'PY'
import json, sys
n = 0
for line in open(sys.argv[1]):
    line = line.strip()
    if not line.startswith('{'):
        continue
    try:
        ev = json.loads(line)
    except json.JSONDecodeError:
        continue
    t = ev.get('Test')
    if t and '/' not in t and ev.get('Action') == 'pass':
        n += 1
print(n)
PY
)" = "0" ]; then
    echo "⚠️ 顶层 PASS 数为 0 —— 这一跑什么都没验到（不是「通过」）" >&2
    exit 1
fi

exit $rc
