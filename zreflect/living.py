#!/usr/bin/env python3
"""活状态抽取：一份文档里，哪些行是「现在如此」，哪些是「当时如此」。

从 Octave-Full-Wasm 的 `.githooks/check-handoff.py` 迁移（那里第一次长出这套判定）。
它要解决的问题：闸门想查「断言与产物是否矛盾」，但**不是每一行都该查** ——
append-only 的历史章节里，数字是"当时如此"，拿来跟今天的产物比毫无意义，
硬查只会逼人把历史改成现在，那就毁了记录。

三条硬规矩（全是那里踩出来的，别改回更"聪明"的版本）：

  1. **默认从严**。除明确声明的历史章节外，一切章节（**含无编号的**）都是活状态。
     那边第一版只把"带数字且不在历史名单里"的章节当活状态，于是"## 附 · …"这类
     无编号段落**继承上一节的状态判定** —— 往那儿塞一条过时断言，检查器视而不见。
  2. **行内出口**。一行自己说清是历史（历史 / 退役 / 曾经的 / 已翻案 / 更正……）
     就豁免。没有这个出口，人只能把历史删掉或把章节挪走 —— 机制的目的是
     「不许**悄悄**留在那儿当现状」，不是毁掉记录。
  3. **带出处的记录豁免，但出处必须明确**。交付包名（含 8 位日期）或**反引号里的
     commit sha** 才算出处。⚠️ 那边第一版还加了一个宽松的裸 sha 正则，结果
     "一条含过期 sha 的假断言"被当成"带出处的历史条目"整行豁免 —— 漏检就是这么来的。
     宽松识别的出口，等于给假断言发了通行证。
"""
import re

# 行内历史标记（与翻案台账的更正标记同一份词表 —— 词表只生产一次）。
HIST_MARK = re.compile(
    r"历史|退役|留档|曾经的|当年的|当时的|之前那份|此前|当时|收口前"
    r"|已翻案|更正|是错的|误读|推翻|曾写|已作废|不再成立"
    r"|superseded|retracted|deprecated")

# 带**明确**出处的记录：`xx-20260921` 型交付名，或反引号里的 commit sha。
# ⚠️ 故意不认裸 sha：见上面规矩 3。
DATED_RECORD = re.compile(r"[A-Za-z0-9._-]*-\d{8}|`[0-9a-f]{7,64}`")


def section_is_living(heading, historical_secs=()):
    """一个 `## ` 标题下的正文是不是活状态。

    · 带编号且在 `historical_secs` 里 ⇒ 历史（append-only，别拿今天的产物去比它）；
    · 其余一律活状态 —— **包括无编号章节**（默认从严，见模块头规矩 1）。
    """
    m = re.match(r"^##\s+([0-9]+)", heading)
    if m:
        return m.group(1) not in {str(s) for s in historical_secs}
    if heading.startswith("## 附"):
        return False          # 文末机器维护的区块（由渲染器负责），闸门不扫
    return True


def living_lines(text, historical_secs=()):
    """把文档切成行，标出每行是不是活状态。返回 [(行号, 行, 是否活状态), …]。

    ⚠️ 文件**头部**（第一个 `## ` 之前）是活状态 —— 那边实测过：头部恰好是
    "wasm sha …、全量 N 套 M 项"这种最该查的状态行，第一版曾把引用块整段跳过，
    等于把最要紧的断言放走了。这里的头部**参与判定**（行内出口仍然有效）。
    """
    out = []
    keep = True
    for i, ln in enumerate(text.split("\n"), 1):
        if re.match(r"^##\s+", ln):
            keep = section_is_living(ln, historical_secs)
        out.append((i, ln, keep))
    return out
