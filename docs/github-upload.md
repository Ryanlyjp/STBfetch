# GitHub 上传与敏感信息边界

## 可上传内容

上传源码、测试、前端静态文件、Docker 配置、README、文档、`.gitignore`、`.dockerignore` 和 `.env.example`。`.env.example` 只有占位密码，不能用作生产密码。

## 禁止上传内容

以下内容属于本机运行数据或敏感材料，必须留在服务器：

- `.env` 和任何本地环境文件
- `data/`，包括 `secure_store.json`、截图、日志、账号文件和扩展压缩包
- `local.har` 或任何 `*.har` 抓包文件
- `progress.md`、浏览器配置目录和本地 Compose override 文件

`.gitignore` 已覆盖这些路径；`.dockerignore` 也会阻止它们进入 backend 镜像构建上下文。

## 上传前检查

在 `sbeans` 目录执行：

```bash
git init
git status --short --ignored
git check-ignore -v .env data/secure_store.json data/screenshots local.har
git add --dry-run .
```

输出中不应出现 `.env`、`data/`、任何 HAR 文件或 `progress.md`。如果曾经把敏感文件提交过，新增忽略规则不会从 Git 历史删除它们，必须在发布前清理历史并轮换相关密码、Cookie、代理凭据和账号密码。

## 从 GitHub 部署

1. `flaresolverr/` 已包含定制 solver 的源码、依赖和 Dockerfile；Compose 会从该目录构建，不需要再同步同级的外部 FlareSolverr 项目。
2. 在服务器执行 `cp -n .env.example .env`，编辑 `.env` 设置新的随机 `SBEANS_ADMIN_PASSWORD`。
3. 执行 `./start.sh`，确认 `curl http://127.0.0.1:8087/api/health` 返回健康状态。
4. Cloudflare Tunnel 只转发到 `http://127.0.0.1:8087`；不要公开 backend 或 FlareSolverr 端口。

运行中的 `data/secure_store.json` 不要删除或覆盖，否则会丢失已保存记录。更新源码时保留服务器上的 `.env` 和 `data/`，只重新构建容器。
