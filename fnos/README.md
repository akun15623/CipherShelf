# 飞牛 fnOS 应用打包

本目录把仓库根目录的 ciphershelf 源码打包成飞牛 fnOS 应用（`.fpk`），提供两种形态：

| 形态 | 目录 | 数据目录选择 | 依赖 | 适用场景 |
|------|------|------------|------|---------|
| **Native** | [`native/`](./native/) | 应用设置里**点选飞牛目录**（授权目录）| 预打包 wheel 离线装 | 想用飞牛原生目录选择器 |
| **Docker** | [`docker/`](./docker/) | 安装向导手填绝对路径 | 镜像内置 | 稳定可靠、零联网、兼容旧习惯 |

两种形态共用同一份源码（仓库根目录的 `crypto.py` / `app.py` / `static/`），构建脚本各自从根目录复制代码，**不会产生代码分叉**。

## 目录结构

```
fnos/
├── gen_icons.py              # 图标生成脚本（两个形态共用，改配色可重跑）
├── README.md                 # 本文件
├── native/                   # Native 形态（点选授权目录）
│   ├── build.sh              #   拷源码 → fnpack build
│   ├── wheels/               #   预打包 cp312 依赖
│   ├── README.md
│   └── ciphershelf/         #   fnpack 包骨架（app/server/ 由 build.sh 生成）
└── docker/                   # Docker 形态（本地镜像）
    ├── build.sh              #   docker build → docker save → fnpack build
    ├── README.md
    └── ciphershelf/         #   fnpack 包骨架（compose 用本地镜像）
```

## 构建

```bash
# Native 形态
./fnos/native/build.sh

# Docker 形态
./fnos/docker/build.sh
```

产物分别在各自的 `ciphershelf/ciphershelf.fpk`。

## 重新生成图标

```bash
python3 fnos/gen_icons.py fnos/native/ciphershelf
python3 fnos/gen_icons.py fnos/docker/ciphershelf
```

## 形态选择建议

- **想要「点选目录」体验** → Native 版（见 [native/README.md](./native/README.md)，授权目录机制有若干真机验证点）
- **想要零联网、稳定可靠** → Docker 版（见 [docker/README.md](./docker/README.md)，需先在飞牛设备 `docker load` 镜像）
