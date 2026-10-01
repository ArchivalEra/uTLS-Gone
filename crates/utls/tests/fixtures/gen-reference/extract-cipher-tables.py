#!/usr/bin/env python3
"""从 Go uTLS 的源码里提取随机化生成器需要的密文套件表，输出成 Rust。

为什么要一个脚本而不是手抄：这几张表加起来几十条，**抄错一条不会编译失败** ——
它只会让「随机化指纹」与参照实现悄悄分叉，而分叉的表现是几百条加权布尔值里的一个走反，
排查起来几乎无从下手。脚本 + 产物一起入库，表就永远可复现。

用法：
    python3 extract-cipher-tables.py /tmp/utls-ref/utls-master > ../../src/hello/randomized_tables.rs
"""
import re
import sys


def block(src, start_pat):
    i = src.index(start_pat)
    i = src.index('{', i)
    depth = 0
    for j in range(i, len(src)):
        if src[j] == '{':
            depth += 1
        elif src[j] == '}':
            depth -= 1
            if depth == 0:
                return src[i + 1:j]
    raise SystemExit('unbalanced: ' + start_pat)


def names_of(b):
    b = re.sub(r'//[^\n]*', '', b)
    return [n for n in re.findall(r'[A-Za-z_][A-Za-z0-9_]*', b)
            if n.startswith(('TLS_', 'FAKE_', 'DISABLED_'))]


def main(root):
    cs = open(root + '/cipher_suites.go').read()
    df = open(root + '/defaults.go').read()

    consts = {}
    for m in re.finditer(r'^\t([A-Za-z0-9_]+)\s+uint16\s*=\s*(0x[0-9a-fA-F]+)', cs, re.M):
        consts[m.group(1)] = int(m.group(2), 16)
    for m in re.finditer(r'^\t([A-Za-z0-9_]+)\s*=\s*([A-Za-z0-9_]+)\s*$', cs, re.M):
        consts.setdefault(m.group(1), consts.get(m.group(2)))

    pref = names_of(block(cs, 'var cipherSuitesPreferenceOrder = []uint16'))

    entries = []
    for line in block(cs, 'var cipherSuites = []*cipherSuite{').split('\n'):
        line = line.split('//')[0].strip()
        if not line.startswith('{'):
            continue
        parts = [p.strip() for p in line.strip('{},').split(',')]
        if not parts or not parts[0].startswith('TLS_'):
            continue
        entries.append((parts[0], 'suiteTLS12' in ' '.join(parts[5:])))

    disabled = set()
    for pat in ('var disabledCipherSuites = map[uint16]bool',
                'var rsaKexCiphers = map[uint16]bool',
                'var tdesCiphers = map[uint16]bool'):
        disabled |= set(names_of(block(cs, pat)))

    default12 = [n for n in pref if n not in disabled]
    default13 = names_of(block(df, 'var defaultCipherSuitesTLS13 = []uint16'))

    def c(name):
        if name not in consts:
            raise SystemExit('未知常量: ' + name)
        return consts[name]

    out = []
    w = out.append
    w('//! **自动生成 —— 不要手改。**')
    w('//!')
    w('//! 由 `crates/utls/tests/fixtures/gen-reference/extract-cipher-tables.py`')
    w('//! 从 Go uTLS 源码提取。重新生成：')
    w('//!')
    w('//! ```sh')
    w('//! python3 extract-cipher-tables.py /tmp/utls-ref/utls-master > randomized_tables.rs')
    w('//! ```')
    w('//!')
    w('//! 为什么这些数字不能手抄：见该脚本的文件头。')
    w('')
    # `defaultCipherSuites(true)` 在 uTLS 的随机化生成器里是**死代码**：
    #   p.CipherSuites = defaultCipherSuites(true)          ← 赋了
    #   ...
    #   p.CipherSuites = removeRandomCiphers(r, shuffledSuites, …)   ← 又被覆盖
    # 所以这里**不生成**那两张表（生成了也是 dead_code），只把它印成注释，
    # 好让「我们用的是全表 shuffle 而不是默认表」这个差异在产物里看得见。
    w('// uTLS 里 `defaultCipherSuites(true)`（= 下面这张偏好序减去 disabled/rsaKex/tdes）')
    w('// 算出来的结果**从未被使用** —— `p.CipherSuites` 随后被 `removeRandomCiphers` 的结果')
    w('// 覆盖。本仓因此不生成那两张表。为可追溯，把偏好序印在这里：')
    for n in pref:
        w('//   0x%04x %s' % (c(n), n))
    w('// 减去（默认禁用）:')
    for n in sorted(disabled):
        w('//   0x%04x %s' % (c(n), n))
    w('// ⇒ `defaultCipherSuites(true)` 是 %d 条。' % len(default12))
    w('')
    w('/// Go `defaultCipherSuitesTLS13`（`defaults.go`）。')
    w('#[rustfmt::skip]')
    w('pub(crate) const DEFAULT_CIPHER_SUITES_TLS13: &[u16] = &[')
    for n in default13:
        w('    0x%04x, // %s' % (c(n), n))
    w('];')
    w('')
    w('/// Go 的 `cipherSuites` 表，**按源码顺序**，第二项是 `flags & suiteTLS12 != 0`。')
    w('///')
    w('/// 顺序即语义：`shuffledCiphers` 用 `randomTag` 与「是否 TLS1.2」排序这张表，')
    w('/// 所以抄错顺序 = 抄错指纹。')
    w('#[rustfmt::skip]')
    w('pub(crate) const SUITE_TABLE: &[(u16, bool)] = &[')
    for n, tls12 in entries:
        w('    (0x%04x, %s), // %s' % (c(n), 'true ' if tls12 else 'false', n))
    w('];')
    print('\n'.join(out))


if __name__ == '__main__':
    main(sys.argv[1])
