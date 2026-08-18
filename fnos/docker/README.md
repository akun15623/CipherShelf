# 飞牛 fnOS Docker 应用

本目录将仓库根目录的 secure-vault 源码打包成飞牛 fnOS **Docker** 应用（`.fpk`）。数据文件夹在**安装向导里手填绝对路径**（不走授权目录点选）。

> 想要「应用设置里点选目录」请用 [Native 形态](../native/)。

## 目录结构

```
fnos/docker/
├── build.sh                 # docker build → docker save → fnpack build
├── README.md
└── secure-vault/            # fnpack 包骨架（appname=secure-vault）
    ├── manifest             # 端口 8090，ctl_stop=true
    ├── app/docker/docker-compose.yaml   # 本地镜像 secure-vault:latest
    ├── config/resource      # docker-project
    ├── config/privilege
    ├── wizard/install       # 安装向导：密码 + 数据文件夹路径
    ├── cmd/                 # 生命周期（status 检查容器）
    ├── ICON.PNG / ICON_256.PNG
    └── app/ui/              # 桌面入口（iframe）+ 图标
```

## 构建

```bash
./fnos/docker/build.sh
```

产物：

| 文件 | 说明 |
|------|------|
| `secure-vault/secure-vault.fpk` | 应用包（约 9 KB，可安装）|
| `secure-vault-image.tar` | Docker 镜像导出（约 158 MB，`docker load` 导入）|

## 安装前提（重要）

本应用 compose 使用**本地镜像** `secure-vault:latest`（`pull_policy: never`，不去外网拉取），**飞牛设备上必须先有该镜像**：

```bash
docker load -i secure-vault-image.tar
```

导入后确认 `docker images secure-vault` 能看到 `secure-vault:latest`（约 160MB）。

## 安装与使用

1. 飞牛 **应用中心 → 手动安装 → 选 `secure-vault.fpk`**
2. 安装向导分两步：
   - **设置加解密密码**（≥ 8 位，务必牢记）
   - **设置数据文件夹**（填 NAS 绝对路径，如 `/vol1/1000/Documents`，会挂载进容器 `/data`）
3. 桌面出现「文件夹加解密」图标 → 输入密码进入
4. 勾选要加密的文件夹 → 「加密选中」就地加密；勾选已加密目录 → 「解密选中」还原

## 关键信息

| 项 | 值 |
|----|----|
| 应用名 | secure-vault（显示名：文件夹加解密）|
| 服务端口 | 8090（宿主机）→ 8080（容器）|
| 平台 | x86 |
| 数据目录 | 安装向导配置（`wizard_data_path` 挂载到容器 `/data`）|
| 密码 | 安装向导配置，存环境变量 `VAULT_PASSWORD` |

## ⚠️ 注意事项

1. **密码 = 密钥，忘记无法找回**，已加密文件永久不可读。
2. **改密码 = 换密钥**：改密码前先解密还原已加密目录。
3. 密码明文存在应用环境变量（飞牛应用设置页可见），这是「环境变量预设密码」方案的特性。
4. 端口 8090 被占用时可在应用设置里改（compose 用 `TRIM_SERVICE_PORT` 自动跟随）。
5. **数据文件夹**：填的路径不存在时 Docker 会自动创建空目录——务必填真实存在的目录。
