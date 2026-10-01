#!/bin/sh
# 安装 git hooks（core.hooksPath 指向本目录）—— 从 Octave-Full-Wasm 的 install.sh 迁移。
#
# 为什么值得一个安装脚本：hooks 不装 = 一套没人执行的闸门，而**日志一切正常**。
# 那边的教训族是"部署了 ≠ 在跑"的同款：机制躺在仓库里，闸门从未生效过。
set -e
cd "$(dirname "$0")/.."
git config core.hooksPath reflect-hooks
chmod +x reflect-hooks/pre-commit reflect-hooks/pre-push
echo "hooks 已挂载：$(git config core.hooksPath)"
echo "（卸载：git config --unset core.hooksPath）"
