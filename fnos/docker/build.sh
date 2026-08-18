#!/bin/bash
# 从源码仓库根目录构建飞牛 fnOS Docker 应用包（ciphershelf.fpk）+ 导出镜像 tar
# 用法：在仓库根目录执行 ./fnos/docker/build.sh
# 前置：已安装 fnpack、docker daemon 可用
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"   # 源码仓库根目录
PKG="$ROOT/fnos/docker/ciphershelf"          # fnpack 包目录
IMAGE="ciphershelf:latest"

echo "==> 构建 Docker 镜像（源码根 Dockerfile）"
docker build -t "$IMAGE" "$ROOT"

echo "==> 导出镜像 tar（离线分发用）"
docker save "$IMAGE" -o "$ROOT/fnos/docker/ciphershelf-image.tar"
echo "    镜像 tar：$ROOT/fnos/docker/ciphershelf-image.tar"

echo "==> fnpack build"
cd "$PKG"
rm -f "$PKG/ciphershelf.fpk"
fnpack build

echo ""
echo "==> 完成：$PKG/ciphershelf.fpk"
echo "==> 分发：飞牛设备先 docker load 镜像 tar，再安装 fpk"
