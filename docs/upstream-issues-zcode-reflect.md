# 待提 issue：zcode-reflect 的三个机制缺口

**状态**：未提。`gh` 现在用不了 —— `gh auth status` 报 `The token in ~/.config/gh/hosts.yml is invalid`，
`gh repo create` / `gh repo view` 都是 `HTTP 401`。（注意：当时 `gh api repos/...` 这类 **REST** 调用是通的，
挂的是 **GraphQL** 端点 —— 所以「gh 用不了」要分端点说，别一概而论。）
token 修好后把下面三条拿去提即可，互相独立，可以拆成三个 issue。

三条都带复跑方式。**标了「实测」的是在本仓真跑出来的；标了「按文档判定」的是读 schema 推的，
没有活体触发**（SessionStart 无法从会话内触发）。

---

## 1. `cmd` 是整套系统里唯一「写了但没人验」的字段

**现象**：`zreflect/collect.py` 的原则一写着「那条复跑命令必须**真的能跑**，否则这条事实
就又变成了一句散文」—— 但没有任何检查器在验证这句话。`check_facts.py` 只校验 `value`
（块一致性 / 裸数字 / 坏引用）；`ledger.py` 的 `changed_keys()` 还**刻意**把 `cmd` 排除在
改口守卫之外，注释里给的理由很正当（改 `cmd` 是文档维护的正常动作，若也要显式接受，
守卫会变噪音、最后被 `--accept-changes` 一律糊过去）。两个理由各自都对，合起来的结果是：
**`cmd` 成了唯一一个写了却无人验证的字段，而它恰好是「这条事实能被复跑」的唯一凭证。**

**为什么要紧**：一条悄悄失效的 `cmd` 会让台账看起来**完全正常** —— 值对、块一致、闸门全绿。
这与「闸门躺在仓库里从未被执行」是同一个形状的故障，只是这次失效的不是闸门，是事实的凭证。

**证据（实测）**：在 uTLS-rs 上（12 条事实）逐条复跑 `cmd` 并与 `value` 比对，**12 PASS / 0 FAIL** ——
也就是说现在**没有坏的**，但那是**手工**做的，加下一条事实时不会自动发生。

```sh
cd <任意接了这套系统的仓库>
python3 - <<'PY'
import json, subprocess
d = json.load(open('FACTS.json'))['facts']
bad = 0
for k in sorted(d):
    e = d[k]
    r = subprocess.run(e['cmd'], shell=True, capture_output=True, text=True)
    got = (r.stdout or '').strip()
    ok = str(e['value']) == got or str(e['value']) in got
    bad += 0 if ok else 1
    print(('PASS ' if ok else 'FAIL '), k, '|', e['cmd'][:60])
print('=== %d FAIL ===' % bad)
PY
```

**建议**：加 `zreflect/check_cmds.py` —— 复跑每条 `cmd`、与 `value` 比对、不一致即红；
三档自证齐全（正常不报 / 值不符必须报 / **空台账必须报**）。`gates-selftest.sh` 的发现式名录
会自动把它收进来，**不需要登记**。注意 `cmd` 里有引号与管道，用 `shell=True` 跑，
并且只比首行/整数（版本串含空格与括号）。

---

## 2. `.zcode/config.json` 的形状不是 ZCode 认的形状（且与自己的 README 走散）

**现象**：仓里那份 `.zcode/config.json` 是：

```json
{ "hooks": { "SessionStart": [ { "command": "python3 .zcode/inject-state.py" } ] } }
```

对照 ZCode 的 schema（`zcode-guide` 的 `diagnosing-hooks`，第 1、2 节）：

- **配置文件**的形状是 `hooks.events.<Event>`，条目是 `{ matcher?, hooks: [ {type, command, …} ] }`。
  仓里这份用的是 `hooks.<Event>`，**而且条目里没有 `type`、也没有 `hooks` 数组包裹** ——
  它既不是配置文件形状，也不是插件文件形状。
- 配置文件 hook **默认禁用**，需 `"hooks": { "enabled": true, … }`。

**按文档判定：它不会被识别为一个 hook。** 所以会话开始时**没有活状态注入** ——
而「agent 手上没有状态，于是重新提出已结案的问题、照抄过期的数字」正是这个 hook 存在的唯一理由。

**第二层（独立于此）**：`inject-state.py` 直接 `print()` 纯文本。ZCode 把 hook 的 **stdout
按严格 JSON 解析**，形状是 `{"hookSpecificOutput": {"hookEventName": …, "additionalContext": …}}`，
**多余一个键就验证失败、效果被丢弃**（文档 pitfall 8：跑了但效果被丢弃、标记为 failed）。
所以即便 hook 被识别，注入也会被丢掉 —— 只在日志里留一条 failed，而**日志看起来像小毛病**。

**第三层：同一件事写在两处，于是走散。** README 里给的示例**是对的**（有 `enabled: true`、
用 `${ZCODE_PROJECT_DIR}`、是 `events` 形状），但仓里那个文件不是那个形状。
这正是这套系统自己列的「同一件知识写在好几处会走散」，只是这次走散的是它自己的接线。

**一个需要标定的细节（别照抄我的结论）**：缺 `enabled: true` 在这台机器上**未必**是拦路的 ——
全局装了会提供 hooks 的插件（`video-agent-kit`），而文档说有插件提供 hook 时
**runner 会被自动启用**。所以真正对不上的可能是**形状**，不是那个开关。
这一条我没有活体触发，**建议修好后真触发一次，去日志里看 outcome**，别停在「读文档推断」。

**建议**：
- 文件改成配置形状：`{"hooks": {"enabled": true, "events": {"SessionStart": [{matcher, hooks:[{type, command, …}]}]}}}`；
- `inject-state.py`：非 tty 时发 JSON 信封，人手工跑时（`--text` 或 tty）才发纯文本；
- README 里那段示例与仓里文件**对齐**，或者干脆把它从 README 里删掉、只留文件（一处生产，别处引用）。

**顺带一个 Stop hook 的陷阱（值得写进 README）**：`facts.py` 在台账缺失时 `SystemExit(2)`，
而 ZCode 的退出码语义是 `0` 放行、**`2` 阻塞**、其它非零算错误。所以把
`facts.py --render-doc` 直接挂进 `Stop`，**一次台账缺文件就会把会话当人质**。
要么包一层「永远退出 0、诊断走 stderr」，要么别挂 Stop。

---

## 3. pre-commit 说「重算机器块」，实际只做重渲染 —— 事实会静默过期

**现象**：`reflect-hooks/pre-commit` 的注释与 README 都写「重算机器块」，但它调的是
`facts.py --render-doc`，而 `--render-doc` 走的是 `_load_or_die()` → `write_doc()`，
**从不调用 `measure()`** —— 它只按**现有台账**重渲染。于是：改了仓库内容、但没手动跑
`facts.py` 时，台账与机器块**彼此一致、而且都过期**。

而两条把关的都只查这种「彼此一致」：`check_facts.py` 比块↔台账，pre-push 的 `--check`
比块↔台账。**全部会绿。**

**为什么要紧**：`facts.py --render-doc` 与 `facts.py`（无参数）在名字上极像，
在「会不会测量」上完全不同。一个把「事实保持新鲜」寄托在 pre-commit 上的人，
得到的是「事实永远陈旧、闸门永远绿」—— 又一个「机制的名字描述了意图、
实现描述了别的东西」。

**证据（实测）**：在 uTLS-rs 上放一个探针文件（`md_files` 应变 8 → 9），然后跑 pre-commit
与 pre-push 各自的那条命令：

```sh
echo hello > _tmp_stale_probe.md
python3 zreflect/facts.py --render-doc STATE.md   # "事实块无变化"      rc=0
python3 zreflect/facts.py --check STATE.md        # "与台账一致"        rc=0
for g in zreflect/check_*.py; do python3 "$g" >/dev/null 2>&1 && echo "绿" || echo "红"; done
                                                  # 四个闸门全绿
python3 zreflect/facts.py                         # ★ 只有这条才发现：
                                                  #   FATAL: 改掉 2 条事实的值：md_files 8 → 9
                                                  #   rc=2，拒绝写盘
rm -f _tmp_stale_probe.md
```

即：**一条会把事实改成新值的改动，在 pre-commit / pre-push / 四个闸门看来全是绿的。**

**建议**：二选一，但必须说清是哪个 ——

- **(a) 让 pre-commit 真的重算**（跑无参数的 `facts.py`）。代价是每次提交都可能因两道守卫
  而中断 —— 但这**正是那两道守卫的设计意图**（「逐条确认这些变化是实测出来的」）。
  真这么做，第 3 条就自动消失了。
- **(b) 保留「只渲染」**，但把注释与 README 里的**「重算」改成「重渲染」**，
  并**明说事实的新鲜度由谁负责**（人工？CI？还是某个 `--check` 变体？）。
  现在的写法是：名字承诺了 A，实现做的是 B，而读者只看到名字。

---

---

## 4. 台账里的复跑命令含 shell 引号，放进变量就静默失效

**现象**：`FACTS.json` 每条的 `cmd` 里有单引号（例如
`find . -name '*.rs' -not -path './.git/*' | wc -l`）。**照字面粘进 shell 跑是对的**；
但一旦有人（包括我）把它塞进一个变量再展开：

```sh
SKIP="-not -path './.git/*' -not -path './target/*'"
find . -name '*.rs' $SKIP | wc -l      # ← 单引号成了字面字符，过滤全部失效
```

过滤失效的表现不是报错，而是**数出比台账多一个文件**（多出来的是 `target/` 里的构建产物），
于是核对者会开始怀疑**台账错了**，而错的是核对方式。这次实测就绕了一圈：
先以为采集器漏了一个文件，最后才发现是引号。

**为什么要紧**：复跑命令是这套系统里「这条事实能被验证」的唯一凭证，而它的正确性依赖
**调用者逐字使用它**。这个前提没人写下来过 —— 一旦有人图省事用变量包一层，
失效方式是安静的（多一个数、少一个数），而那恰好是这套系统存在的理由。

**建议**：二选一 ——
(a) 在 `cmd` 里避免 shell 引号（换成不含空格/通配符的写法，或写成一条 `python3 -c ...`）；
(b) 在文档里明说：**`cmd` 必须逐字复制执行，不要放进变量或改写**。
另可考虑给 `check_facts` 加一条：对每条 `cmd` 做一次 shellcheck 式的最小检查（可选，代价是引入新依赖）。

**证据 / 复跑**：把任一 `find` 型命令里的 `-not -path '…'` 塞进变量再展开，对比两条命令的文件数。


---

## 5. 机器块渲染的事实，不许从**它所在的文档**里度量

**现象**：`STATE.md` 末尾有个机器块，块里渲染了 `md_lines` —— 而 `md_lines` 又是在数
`STATE.md` 自己有多少行。于是：

```
测一遍 → 渲染块（块变长）→ md_lines 立刻过期 → 复跑命令**恒定**失败
```

**它不是偶尔失败，是永远失败**，而且失败的方式很隐蔽：`check_facts` 比的是「块 ↔ 台账」，
两边一起陈旧，所以闸门**全绿**；只有真的按台账里那条复跑命令去数，才发现对不上。
这正违反 `collect.py` 的原则 2「不引入会自己在变的输入」—— 只不过那个「会自己变的输入」
是文档自己的一部分。

**为什么值得单列**：这类事实有一个很难受的性质 —— 它**看起来是健康的**（有值、有 cmd、
闸门绿），但它的 cmd 永远不可能通过。而「复跑命令必须真的能跑」是这套系统的核心承诺
（见第 1 条），一条永远跑不通的 cmd 会让人开始怀疑整套东西。

**证据 / 复跑**：

```sh
cd <一个用机器块的仓库>
# 让文档里的块长大（例如多量一条事实），然后：
python3 zreflect/facts.py --render-doc STATE.md
python3 zreflect/facts.py --render-doc STATE.md   # 再渲染一次
# 用台账里 md_lines 的 cmd 复跑 → 对不上（修复前）
```

**建议**：二选一 ——
(a) 文档行数类的事实**跳过机器块**（本仓采用：`.md` 的 `md_lines` 只数块以外的行，
    复跑命令用 `awk 'FNR==1{b=0} /<块起始标记>/{b=1} !b'`）；
(b) 让 `collect.py` 在度量阶段就能识别「这条值出现在机器块里」，并**明说**该口径不可行。
⚠️ 顺带一条踩坑：`-exec … {} +` 会把多个文件喂给**同一个** `awk` 进程，
所以按文件重置的状态（`FNR==1{b=0}`）是必需的 —— 漏了它，第一个带块的文件之后全被跳过，
而输出看起来仍然「像个行数」。


## 与 uTLS-rs 的关系

- 第 1 条在本仓已立成悬案：`questions/05-verify-rerun-commands.md`，结算件 = `check_cmds.py`。
- 第 2、3 条本仓已按正确形状接线 / 规避，所以它们是**上游问题**，不是本仓的待办：
  `.zcode/config.json` 用的是配置文件形状 + `enabled: true` + `events`；
  `.zcode/stop-refresh.py` 永远退出 0（诊断走 stderr），不拿会话当人质。
- 本仓实测数据：12 条事实的 `cmd` 全部复跑通过；`gates-selftest.sh` 发现 4 个闸门、
  36 条断言全过；跨仓库可配置性自证通过。
