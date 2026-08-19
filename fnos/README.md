# 飞牛 fnOS 应用打包

本目录把仓库根目录的 ciphershelf 源码打包成飞牛 fnOS Docker 应用（`.fpk`）。安装向导填写 NAS 数据目录绝对路径，应用镜像包含运行依赖。

## 目录结构

```
fnos/
├── gen_icons.py              # 图标生成脚本
├── README.md                 # 本文件
└── docker/                   # Docker 形态（本地镜像）
    ├── build.sh              #   docker build → docker save → fnpack build
    ├── README.md
    └── ciphershelf/         #   fnpack 包骨架（compose 用本地镜像）
```

## 构建

```bash
./fnos/docker/build.sh
```

应用包产物位于 `fnos/docker/ciphershelf/ciphershelf.fpk`；构建脚本还会生成供离线导入的镜像 tar（该文件由 `.gitignore` 忽略）。

## 重新生成图标

```bash
python3 fnos/gen_icons.py fnos/docker/ciphershelf
```

详细构建、安装和离线镜像说明见 [docker/README.md](./docker/README.md)。
