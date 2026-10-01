#!/usr/bin/env python3
"""闸门平台：零值守卫 + 三档自证。

它解决的**不是**「没有检查」，而是**检查在输入消失时静默变绿**。真实踩过的三种：

  · 三个站点同时缺 `VERSION` ⇒ 一致性闸门报「完全一致」；
  · 声明的集合是空的 ⇒ 出厂核对报 `verdict: "ok"`；
  · 自检脚本 `0/0` ⇒ 算「全部通过」。

所以任何检查器都必须能回答两句话：**输入空了我报吗？**、**该报的我会报吗？**
`require_nonempty()` 答第一句，`selftest()` 的三类用例答第二句。
"""
import os
import sys

# 被检查的仓库根：默认是本包的上一级，可用 GATE_REPO 覆盖（测试夹具靠它）。
GATE_REPO = os.environ.get("GATE_REPO") or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def repo(*parts):
    """拼一个指向被检查仓库的绝对路径。"""
    return os.path.join(GATE_REPO, *parts)


def require_nonempty(name, seq, what="输入"):
    """零值守卫：收集阶段什么都没收到 ⇒ 报错，**不许当「干净」**。

    这是本包最重要的一行。绝大多数「闸门假装通过」的事故，根因都是这里没守：
    遍历一个不存在的目录得到空集，然后「没有发现违规」——两句都是真的，结论是错的。
    """
    items = list(seq)
    if not items:
        raise SystemExit(
            "FATAL: %s：%s 是空的。空输入不是「全部通过」—— 要么收集逻辑坏了，"
            "要么路径给错了。先修输入，别关闸门。" % (name, what)
        )
    return items


def raises(fn):
    """「该报错的必须报错」—— 反向断言用。返回 True 表示它确实报了 SystemExit。"""
    try:
        fn()
    except SystemExit:
        return True
    return False


def selftest(name, cases):
    """跑三档用例。每个 case = (标签, callable) -> bool。

    必须写齐三类：
      ① 正常不报（阳性对照 —— 否则「总是报错」也能骗过自证）
      ② 该报的必须报（反向断言 —— 否则这个检查器可能是装饰）
      ③ 空输入必须报（零值守卫）
    """
    bad = 0
    for label, fn in cases:
        try:
            ok = bool(fn())
        except SystemExit as e:
            ok, label = False, "%s（未预期的 SystemExit：%s）" % (label, e)
        except Exception as e:                      # noqa: BLE001
            ok, label = False, "%s（异常 %r）" % (label, e)
        print("%s | %s" % ("PASS" if ok else "fail", label))
        bad += 0 if ok else 1
    print("=== %s 自证：%d PASS / %d fail ===" % (name, len(cases) - bad, bad))
    return 1 if bad else 0


def main_selftest_or(args, name, cases, run):
    """`--selftest` 走自证，否则走 `run(args)`。每个检查器都用它收尾。"""
    if "--selftest" in args:
        return selftest(name, cases)
    return run([a for a in args if a != "--selftest"])


if __name__ == "__main__":
    print("闸门平台。被检查的仓库根：%s" % GATE_REPO)
    print("用法：在你的检查器里 `from gate import selftest, require_nonempty`。")
    sys.exit(0)
