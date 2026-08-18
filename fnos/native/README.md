# 飞牛 fnOS Native 应用打包

本目录将仓库根目录的 secure-vault 源码打包成飞牛 fnOS **Native** 应用（`.fpk`），支持在应用设置里**点选飞牛文件系统目录**作为数据目录。

> 想要「Docker 容器隔离 + 零联网依赖」请用 [Docker 形态](../docker/)。

## 目录结构

```
fnos/native/
├── build.sh                 # 构建脚本：从根目录拷源码 → fnpack build
├── wheels/                  # 预打包 Python 依赖（cp312 + manylinux x86_64，离线安装）
├── README.md
└── secure-vault/            # fnpack 包骨架（appname=secure-vault）
    ├── manifest             # install_dep_apps=python312 + 授权目录开启
    ├── cmd/                 # 生命周期脚本（main / install_callback / ...）
    ├── config/              # privilege + resource
    ├── wizard/config        # 应用设置：加解密密码
    ├── ICON.PNG / ICON_256.PNG
    └── app/ui/              # 桌面入口（iframe）+ 图标
```

`secure-vault/app/server/`（后端代码 + wheels）**不进 git**，由 `build.sh` 从仓库根目录自动生成，保证源码只有一份、永不漂移。

## 构建

```bash
./fnos/native/build.sh
```

产物：`fnos/native/secure-vault/secure-vault.fpk`

前置要求：安装 [fnpack](https://developer.fnnas.com/docs/cli/fnpack)。

## 安装与使用

1. 飞牛 **应用中心 → 手动安装 → 选 `secure-vault.fpk`**
2. 等待安装（离线装依赖，依赖 wheel 已预打包）
3. 进入**应用设置**，完成两项配置：
   - **授权目录**：点选要加密的数据文件夹（飞牛原生目录选择器）
   - **加解密密码**：设置 ≥ 8 位密码
4. 应用中心**启动** → 桌面「文件夹加解密」图标 → 输入密码进入

> 未配置授权目录时应用仍能启动（占位目录），打开后会看到引导页，按提示去设置点选目录并重启。

## 关键机制

| 项 | 说明 |
|----|------|
| 数据目录 | 应用设置「授权目录」点选 → `TRIM_DATA_ACCESSIBLE_PATHS`（取第一个）|
| 密码 | 应用设置配置 → `wizard_password` → 环境变量 `VAULT_PASSWORD` |
| 运行时 | `install_dep_apps=python312`，venv 在 `${TRIM_PKGVAR}/venv` |
| 依赖 | 包内 wheels 离线安装，失败回退清华源 |
| 端口 | 8090（可在应用设置改，`TRIM_SERVICE_PORT` 跟随）|

⚠️ 密码即密钥，忘记无法找回；改密码前需先解密还原已加密目录。
