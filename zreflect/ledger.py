#!/usr/bin/env python3
"""事实台账的数据层：读写 + 两道守卫。**纯函数，所以能自证。**

重测有两个静默的坏法，各配一道守卫：

  · **掉条** —— 输入不在 ⇒ 事实静默**消失**。守卫 `dropped_keys()`。
  · **改口** —— 输入变了、或量错了 ⇒ 事实静默**变成另一个数**。守卫 `changed_keys()`。

改口那条更阴：如果闸门只对少数几个 sha 回盘核对，其余条目的旧值一旦被覆盖，
**再也查不到它变过**。所以守卫的范围要窄而准。
"""
import json


def load(path, missing_ok=False):
    """读 JSON。`missing_ok=True` 时**缺文件返回空表** ——
    给"新仓库第一次跑"用：那时台账还不存在，而 `facts.py` 的两道守卫
    （掉条 / 改口）必须能处理"没有上一版"这件事。**默认仍是硬错误**：
    调用方要显式说自己接受缺失，免得把"路径写错了"静默当成"还没有台账"。"""
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except FileNotFoundError:
        if missing_ok:
            return {}
        raise


def facts_of(ledger):
    """台账里的 facts 表（容忍两种形状：带外壳的文档 / 直接就是表）。"""
    led = ledger or {}
    return led.get("facts") if isinstance(led, dict) and "facts" in led else (led or {})


def dropped_keys(old_facts, new_facts):
    """本次重测会掉掉哪些**键**（纯函数：自证要用）。"""
    return sorted(set(old_facts or {}) - set(new_facts or {}))


def _value(entry):
    """一条事实的**值**。容忍 dict 形状与裸值形状。"""
    return entry.get("value") if isinstance(entry, dict) else entry


def _short(v, n=24):
    """把值缩到一行（64 位 sha 只留前 16 位），给「改口」提示用。"""
    s = v if isinstance(v, str) else str(v)
    if len(s) == 64:
        return s[:16] + "…"
    return s if len(s) <= n else s[:n] + "…"


def changed_keys(old_facts, new_facts):
    """本次重测会把哪些键的**值**换掉。返回 `[(键, 旧值, 新值)]`。

    ⚠️ **只比 `value`**，不比 `cmd`/`source`/`note` —— 那些是「复跑方式」的描述，
    改它们是文档维护的正常动作。若连它们也要显式接受，守卫会变成噪音，
    最后被 `--accept-changes` 一律糊过去，守卫就废了。
    这也意味着：**新增的键不算改口**（那是新增，不该被这条拦住）。
    """
    olds = old_facts or {}
    out = []
    for k, nv in sorted((new_facts or {}).items()):
        if k not in olds:
            continue
        ov = _value(olds[k])
        if ov != _value(nv):
            out.append((k, ov, _value(nv)))
    return out


def fact(value, cmd, source, note=""):
    """造一条事实：值 + 复跑命令 + 出处（+ 可选备注）。"""
    d = {"value": value, "cmd": cmd, "source": source}
    if note:
        d["note"] = note
    return d


# ── 自证（三档：正常不报 / 该报的必须报 / 空输入必须报）──────────────────────────
def _cases():
    from gate import raises                            # noqa: PLC0415
    return [
        # ① 正常不报
        ("掉条：不掉条时不报", lambda: dropped_keys({"a": 1}, {"a": 1, "c": 3}) == []),
        ("改口：值没变时不报", lambda: changed_keys({"a": {"value": 1}}, {"a": {"value": 1}}) == []),
        ("改口：只改 cmd/source 不算改口（否则守卫变噪音）",
         lambda: changed_keys({"a": {"value": 1, "cmd": "旧"}},
                              {"a": {"value": 1, "cmd": "新"}}) == []),
        # ② 该报的必须报
        ("★ 掉条：键没了必须报出来", lambda: dropped_keys({"a": 1, "b": 2}, {"a": 1}) == ["b"]),
        ("★ 改口：值换了必须报出来，且带旧值→新值",
         lambda: changed_keys({"a": {"value": 1}}, {"a": {"value": 2}}) == [("a", 1, 2)]),
        # ③ 空输入必须报（这里是「不许报」的对面：空起步是合法的第一次生成）
        ("空台账起步 ⇒ 掉条不报（第一次生成不许被自己拦住）",
         lambda: dropped_keys({}, {"a": 1}) == []),
        ("空台账起步 ⇒ 改口不报", lambda: changed_keys({}, {"a": {"value": 1}}) == []),
        # 附：形状
        ("facts_of 容忍两种形状", lambda: facts_of({"facts": {"a": 1}}) == {"a": 1}
         and facts_of({"a": 1}) == {"a": 1}),
        ("sha 型长值在提示里被截断", lambda: _short("a" * 64) == "a" * 16 + "…"),
        ("raises 能识别「确实报了」", lambda: raises(lambda: (_ for _ in ()).throw(SystemExit(2)))),
    ]


def _selftest():
    from gate import selftest                          # noqa: PLC0415
    return selftest("ledger（两道守卫）", _cases())


if __name__ == "__main__":
    import sys                                        # noqa: PLC0415
    sys.path.insert(0, __import__("os").path.dirname(__import__("os").path.abspath(__file__)))
    sys.exit(_selftest())
