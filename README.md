# SBeans

Student Beans 本地登录操作台。面板提交账号和可选代理池，后端为账号并发执行同页登录和代码采集。

## 本机部署

```bash
cp -n .env.example .env
# 编辑 .env，设置只在本机使用的 SBEANS_ADMIN_PASSWORD
./start.sh
```

- 面板：`http://127.0.0.1:8087`
- 后端健康检查：`http://127.0.0.1:8087/api/health`
- 初始面板密码：读取项目 `.env` 中的 `SBEANS_ADMIN_PASSWORD`

服务器只在本机回环地址提供前端入口，后端和 FlareSolverr 仅在 Docker 内部网络开放，并由前端 Nginx 代理 `/api/`。Tunnel 应指向 `http://127.0.0.1:8087`。临时账号按 `邮箱 密码` 每行一条输入；代理支持 `user:pass@host:port`、`host:port:user:pass` 和标准代理 URL。

面板可保存账号记录，首次添加时手动填写时间；登录成功并从 VOXI 得到下次采集时间后，会自动更新对应账号记录，哪怕个别计划码失败也会保留有效日期。账号与密码使用当前面板密码派生的密钥加密保存在 `data/secure_store.json`，列表只返回邮箱与时间。成功拿到完整四组 VOXI 码的账号会自动写入同一密文中的优惠码库，按账号和下次日期归档，四个码和共享下次时间可分别复制。在线修改面板密码时会重新加密账号记录和优惠码库，`.env` 仅用于首次创建存储。实时日志通过同源流式响应展示，只保留登录完成、登录状态验证、访问 VOXI、提取结果和失败/重试等关键步骤；下次时间统一显示为新加坡时间的 `YYYY-MM-DD HH:mm` 24 小时格式。

Turnstile、登录和代码采集必须由同一次 FlareSolverr Camoufox 会话完成：backend 将账号传给内网 solver，Camoufox 在同一页面处理 Cookie、Turnstile、账号填写、登录提交和 VOXI 页面 GraphQL POST，代理也只由这一浏览器使用，不再把 token 或 Camoufox 的 Firefox UA 注入第二个 Chromium。进入 VOXI 页面后先等待 10 秒让 viewer token 和页面脚本稳定；当前每个计划的 POST 只尝试 1 次，页面没有内容或 viewer token 时也只检查 1 次，不重复消耗账号。代码采集不点击 `affiliateLink`，只返回四个计划的码和结束日期。Cookie 同意弹窗会等待延迟挂载，并使用原生浏览器点击后确认遮罩隐藏；挑战 iframe 尚未挂载时，solver 会从 Turnstile 容器坐标执行真实鼠标点击，并在日志中标注 `widget-mouse` 或 `iframe-mouse` 策略。登录端使用带 `client_id` 和 `user_return_to` 的 Student Beans OAuth 登录入口，solver 会在同一上下文中等待 `Log in` 按钮启用、提交并返回 API 状态和最终 URL；仅调试开关开启时返回截图。慢速或代理网络下表单会保持校验，摘要日志只注明登录完成、状态验证、VOXI 访问、提取数量和下次时间。FlareSolverr 不可用、未返回 token 或同页登录未确认成功时，本次代理尝试立即失败；当前每个账号只执行 1 次完整尝试，失败后直接返回，便于定位固定流程问题。只有四个计划全部成功才会归档。日志不显示 token、优惠码、Cookie、账号密码或代理凭据。多个账号任务并发运行，代理池用独占租约防止同一时刻重复使用同一地址，代理不足时排队；没有代理时直连任务串行。登录任务运行时可以点击“结束任务”手动停止。

登录判断先等待当前地址离开登录路径且密码输入框消失，然后等待同一标签页出现 `Account Settings` 或已经落到 `www.studentbeans.com/uk`。如果仍在 accounts 域，随后在同一 Camoufox 标签页以原始登录页为 Referer 访问 `/uk/authorisation/passthrough`，完整跟随 HAR 中的 OAuth authorize → callback → `www.studentbeans.com/uk` 链路，确认站点域回调完成后才打开 VOXI 目标页面；任一阶段未到预期时本次尝试失败。只有打开调试截图开关时才会保留最多 3 张最新阶段截图，并在日志中记录摘要步骤；任务运行时点击“结束任务”会同时请求 backend 取消活动任务并中断 SSE，避免只停前端显示而留下后台任务。面板代理池会自动保存在当前浏览器的本地存储中，重新打开页面后恢复。

截图保存在 `data/screenshots/`。停止服务使用 `docker-compose down`。

## 上传到 GitHub

仓库只应包含源码、测试、Docker 配置和 `.env.example`。真实 `.env`、`data/` 运行时目录、账号记录、截图、`*.har` 抓包、日志和 `progress.md` 已通过忽略规则排除；上传前请按 [docs/github-upload.md](docs/github-upload.md) 执行检查。定制 FlareSolverr 源码已内置在 `flaresolverr/`，其运行数据或凭据仍不得复制进本项目。
