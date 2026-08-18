# Secure Vault

一个自托管的文件夹就地加解密工具。文件内容、文件名和目录名都会加密；解密时凭原密码和目录内的 `.svault` 索引还原。

> 当前状态：安全加固后的早期版本。首次用于重要数据前，请在副本上完整测试，并始终保留独立备份。软件不能替代备份。

## 安全特性

- 新写入格式为 v2：AES-256-GCM 分块加密，认证完整文件头、`file_id`、块序号和索引关系。
- 每个加密目录具有随机 `vault_salt`，通过 HKDF 派生独立数据密钥；同一密码不会让不同目录直接复用 AES 密钥。
- 索引使用 AES-GCM 整体加密，并在解密前严格校验 schema、路径、重复项和父子关系。
- 先写同文件系统 staging，再通过事务日志切换；提交失败自动回滚，启动时恢复未完成的事务。
- Web 磁盘修改任务全局串行，拒绝父子重叠路径、符号链接逃逸和根目录操作。
- v1 旧数据保持只读解密兼容；新加密一律写 v2。

## 快速开始

先修改 `docker-compose.yml` 中的数据卷路径，然后运行：

```bash
docker compose up -d --build
```

安全默认值只监听 `127.0.0.1:6070`。本机访问：

```text
http://127.0.0.1:6070
```

首次使用需创建至少 12 位密码。仓库不再提供默认密码。

如需从其他设备访问，请配置 HTTPS 反向代理，并同时：

```yaml
environment:
  SVAULT_COOKIE_SECURE: "1"
ports:
  - "127.0.0.1:6070:8080"
```

不要直接把应用端口暴露到公网。

## CLI

```bash
# 密码交互输入，不回显
python3 encrypt.py /data/照片

# 原地解密
python3 decrypt.py /data/照片

# 导出到一个尚不存在的目录；原密文保留
python3 decrypt.py /data/照片 -o /restore/照片
```

`--password` 会把密码留在 shell 历史中，不推荐使用。KDF 参数属于格式的一部分，不能通过命令行修改。

## 数据与恢复

- 密码没有找回功能；忘记密码会永久失去数据。
- `.svault` 是恢复所必需的索引，备份必须包含完整加密目录，不能只复制密文文件。
- v1 目录可以直接解密。若要迁移为 v2，请先用原密码解密，再重新加密；不要手工修改格式版本字节。
- 加解密会拒绝符号链接、junction、FIFO、socket、设备文件及嵌套 `.svault`，不会静默删除这些对象。
- v2 保存普通文件/目录的 mode、mtime；POSIX 平台还保存 uid、gid 和扩展属性。Windows ACL 不保证跨平台还原。
- 加密期间源文件发生大小变化会中止操作并保留原目录。仍建议停止会写入目标目录的程序后再加密。
- 删除明文备份不等于物理安全擦除；日志型文件系统、快照、SSD 磨损均衡和 NAS 备份中仍可能存在旧明文副本。
- 事务异常时可能保留 `.svault-backup-*` 和 `.svault-txn-*.json`。不要手工删除；先停止服务并保留副本，再进行恢复。

## 密码与部署

密码经 PBKDF2-HMAC-SHA256（600,000 次）派生密码根密钥，再结合每个目录的随机 salt 通过 HKDF 派生数据密钥。密码或密钥不会写入 `.svault`。

可选的 `VAULT_PASSWORD` 会把明文密码放进容器/进程环境，能读取 compose、容器配置或 `/proc` 的用户可能看到它。优先使用 Web 首次创建流程；不要把真实密码提交到仓库。

Docker 镜像默认以 UID/GID 1000 的非 root 用户运行。挂载目录必须允许该用户读写；不要为了省事给数据目录设置全局可写权限。

## 开发与测试

```bash
python -m unittest -v test_crypto test_app
```

`test_app.py` 需要 `requirements-dev.txt`。安全测试覆盖文件头/密文篡改、跨文件替换、恶意索引、事务回滚、v1 兼容、Web 路径越界、任务隔离和并发串行化。

## 安全报告

请先阅读 [SECURITY.md](SECURITY.md)，不要在公开 issue 中附带可直接利用的漏洞细节或真实用户数据。

## 许可证

[MIT](LICENSE)。第三方组件说明见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。
