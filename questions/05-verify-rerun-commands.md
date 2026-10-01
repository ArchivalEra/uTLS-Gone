# 05: 复跑命令是不是真的能跑，没有任何闸门在查

**What to build:** 一个闸门 `zreflect/check_cmds.py`：对 `FACTS.json` 里每条 fact 的 `cmd`
复跑一遍，把输出与 `value` 比对，不一致就红。它要广告 `--selftest` 且三档用例齐全
（`gates-selftest.sh` 的**发现式名录**会自动把它收进来，不需要登记）。

为什么这是一条真实缺口：采集器契约（`zreflect/collect.py`）的原则一写着
「那条复跑命令必须**真的能跑**，否则这条事实就又变成了一句散文」—— 但**没有任何检查器
在验证这句话**。事实闸门查的是「块与台账一致 / 裸数字 / 坏引用」，全部只关心 `value`；
`cmd` 字段被两道改口守卫**刻意排除**（`changed_keys` 只比 `value`，理由是「改 cmd 是文档
维护的正常动作」）。于是 `cmd` 是这套系统里唯一一个「写了但没人验」的字段 —— 而它恰好
是「这条事实能被复跑」的唯一凭证。

本仓当前的实测状态：十二条命令手工全量比对 **12 PASS / 0 FAIL**。但那是这次手工做的，
下一次新增事实时不会自动发生；一条悄悄失效的 `cmd` 会一直看起来很正常。

**Blocked by:** None (can start immediately)

**Status:** resolved

**Settling:** 不存在 —— 本工单的第一交付物是 `zreflect/check_cmds.py`。
它存在之后，本单用「`sh gates-selftest.sh` 报发现 5 个闸门」来结案。

## 交付物：`zreflect/check_cmds.py`（已落地）

- **生产者合并**：~294 条事实的 cmd 是 `cargo run … | grep '^<键>='`。逐条跑等于把同一个例子
  跑 294 遍；这里按「`|` 之前的生产者」分组，**每个生产者只跑一次**，再按各条事实的
  grep 模式取行 —— 跑的还是那条命令（含它的 grep 模式），只是不重复。
- **取值形状**：`key=value` 取等号之后那截；`rustc/cargo --version`、`wc -l`、
  `echo yes || echo NO`、`python3 -c print(len(...))` 取首行整行；`rustls_pin` 那条
  从 `version = "X"` 里抠（与采集器同一口径）。
- **零值守卫**：台账空 ⇒ 报；一条都没验到 ⇒ 报；「量不到」形状的事实明说跳过、不当通过。
- **自证 6 PASS / 0 fail**（含生产者合并那条路、值不符必报、退出码非 0 必报、取不出值必报）。

## 它上线第一分钟就抓到三件事（这就是它的价值）

1. **一条命令是 bash 专属写法**：`fork_patch_matches_markers` 的 cmd 写成
   `diff <(…) <(…)` —— `shell=True` 用的是 `/bin/sh`（dash），当场 `exit 2:
   Syntax error: "(" unexpected`。已改成 POSIX 的 `[ "$(…)" = "$(…)" ] && echo yes || echo NO`。
2. **闸门自己有个取值 bug**：键可能以**数字**打头（`360_7_ext_count`），第一版正则只允许
   字母/下划线 ⇒ 那批事实走了「整行」取值路 ⇒ 一堆假「不一致」。**自证夹具里没有这个形状，
   是真台账抓出来的** —— 又一次说明自证夹具的覆盖面有限。
3. **四条事实确实陈旧**（`gate_count` 4→5、`md_lines`、`open_questions` 3→2、`py_files`/`py_lines`）——
   它们此前只能靠人记得跑 `facts.py` 才发现；现在有闸门盯着。

**实测**：`python3 zreflect/check_cmds.py` ⇒ `复跑命令闸门：OK（321 条事实的 cmd 全部产出记录值）`。

**Type:** task

- [x] 写 `zreflect/check_cmds.py`：复跑每条 cmd，比对 value，零值守卫（台账空要报）
- [x] 三档自证：正常不报 / 值不符必须报 / 空台账必须报（6 用例全过）
- [x] 注意 `cmd` 里有引号与管道，用 `shell=True` 跑并只比首行/整数
- [x] 确认 `gates-selftest.sh` 自动发现了它（**别去改名录**，那是发现式的）——
      现在是「发现 **5** 个闸门，全部能红 ✅」，跨仓库可配置性也变成 5/5 全绿
- [x] 结论回填，`Status:` 改 `resolved`，**别删这个文件**
