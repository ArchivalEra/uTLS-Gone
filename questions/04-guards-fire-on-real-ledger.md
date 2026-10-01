# 04: 两道守卫在本仓的真实台账上真的会拦住吗

**What to build:** 一次在**本仓真实台账**上的实测，证明「掉条」与「改口」两道守卫会拒绝写盘。

为什么值得单独一张单：那套机制在它抽出来的那个项目里，最有价值的一条教训正是
**一条守卫因为一个未定义变量，从落地起就没有生效过**，而它失效的方式是「只在真的该报警时才崩」。
自证夹具能证明守卫的断言成立，但证明不了「接到真实输入、真实台账之后它还活着」——
两者是不同的东西。`gates-selftest.sh` 覆盖前者，这张单覆盖后者。

**Blocked by:** None (can start immediately)

**Status:** resolved

**Settling:** zreflect/facts.py —— rc=0 ⇒ 两道守卫与文档一致性的断言全过（可结案）；rc≠0 ⇒ 有守卫失效，先修守卫再谈别的

## 复跑方式

```sh
python3 zreflect/facts.py --selftest    # 守卫自身的断言
sh gates-selftest.sh                    # 发现式名录：每个闸门先证明自己会红
```

手工注入假值看它真会拦（这是本单真正想问的）：

```sh
cp FACTS.json /tmp/facts.bak
python3 - <<'PY'
import json; p='FACTS.json'; d=json.load(open(p))
k=sorted(d['facts'])[0]
print("注入前:", k, "=", d['facts'][k]['value'])
d['facts'][k]['value'] = 999
json.dump(d, open(p,'w'), indent=1, ensure_ascii=False)
PY
python3 zreflect/facts.py; echo "rc=$?"     # 期望 rc=2，且文件里仍是 999（拒绝写盘）
cp /tmp/facts.bak FACTS.json
```

## 实测结果（2026-10-01，本仓真实台账）

| 命令 | rc | 观察 |
|---|---|---|
| `python3 zreflect/facts.py --selftest` | **0** | 6 PASS / 0 fail（含两条 ★ 用例：掉条必报、改口必报且带旧值→新值） |
| `sh gates-selftest.sh` | **0** | 四个闸门各自自证全绿；「四个名字全换」4/4 全绿而默认名字下三闸全红 ⇒ 无硬编码 |
| 注入假值（`cargo_version = 999`）后跑 `python3 zreflect/facts.py` | **2** | 报 `cargo_version  999 → cargo 1.98.1 (797e8a9bc …)`，**文件里仍是 999**（拒绝写盘）；随后已从备份还原 |

结论：两道守卫在**真实台账**上确实活着 —— 报出来、且**不改盘**。
「只在自证夹具里活着」这个担心不成立。

**Type:** task

- [x] 跑上面三条，记录每条的 rc（0 / 0 / 2）
- [x] 确认注入假值后守卫报「旧值 → 新值」**并且文件没被改**（注入值仍在盘上）
- [x] 结论回填，`Status:` 改 `resolved`，**别删这个文件**
