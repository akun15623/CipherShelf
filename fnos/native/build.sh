#!/bin/bash
# 从源码仓库根目录构建飞牛 fnOS Native 应用包（secure-vault.fpk）
# 用法：在仓库根目录执行 ./fnos/native/build.sh
# 前置：已安装 fnpack（https://developer.fnnas.com/docs/cli/fnpack）
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"   # 源码仓库根目录
PKG="$ROOT/fnos/native/secure-vault"          # fnpack 包目录
SERVER="$PKG/app/server"                      # 包内服务目录（由本脚本生成，不进 git）

echo "==> 清理旧构建产物"
rm -rf "$SERVER"
mkdir -p "$SERVER"

echo "==> 复制源码到 app/server/"
cp "$ROOT/crypto.py" "$ROOT/app.py" "$ROOT/encrypt.py" "$ROOT/decrypt.py" "$ROOT/requirements.txt" "$SERVER/"
cp -r "$ROOT/static" "$SERVER/static"

echo "==> 复制依赖 wheels（离线安装用）"
if [ -d "$ROOT/fnos/native/wheels" ]; then
    cp -r "$ROOT/fnos/native/wheels" "$SERVER/wheels"
fi

echo "==> fnpack build"
cd "$PKG"
rm -f "$PKG/secure-vault.fpk"
fnpack build

echo ""
echo "==> 完成：$PKG/secure-vault.fpk"
