# AWS WAF CAPTCHA

## 配置

视觉 provider 需要接收图片并返回文本。推荐使用 OpenAI 兼容 API，在本机 `.env` 设置到 `/v1` 的基地址：

```text
VISION_API_URL=https://api.example.com/v1
VISION_API_KEY=your-provider-api-key
VISION_MODEL=your-vision-chat-model
VISION_API_MODE=chat_completions
VISION_AUTH_HEADER=Authorization
VISION_AUTH_PREFIX=Bearer
```

`VISION_API_URL` 保持不变，只将模式改为 Responses：

```text
VISION_API_MODE=responses
```

### URL、版本和鉴权

- `VISION_API_URL` 是 API 基地址，通常填到 `/v1`，代码会根据 mode 自动追加 `/chat/completions` 或 `/responses`。
- OpenAI 标准基地址通常是 `https://api.openai.com/v1`；某些代理商可能使用其他版本路径，应以其文档提供的 API 基地址为准。
- 不要把 `/chat/completions` 或 `/responses` 再填进 `VISION_API_URL`，否则 adapter 会重复追加路径。
- `VISION_AUTH_HEADER=Authorization`、`VISION_AUTH_PREFIX=Bearer` 会发送 `Authorization: Bearer <key>`。
- 需要 `x-api-key` 的 provider 设置 `VISION_AUTH_HEADER=x-api-key`、`VISION_AUTH_PREFIX=`，会发送 `x-api-key: <key>`。
- 当前不支持把 key 放在 query 参数、签名请求或其他私有鉴权协议中。
- 原生 Anthropic Messages、原生 Gemini 等非 OpenAI 兼容协议不能直接选择上述模式；需要使用 provider 提供的 OpenAI 兼容 endpoint，或后续增加专用协议 adapter。

### 模型和响应模式

`VISION_API_MODE=chat_completions` 自动请求 `${VISION_API_URL}/chat/completions`，发送 `messages[].content[]`，图片类型是 `image_url`，读取 `choices[0].message.content`；`VISION_API_MODE=responses` 自动请求 `${VISION_API_URL}/responses`，发送 `input[].content[]`，图片类型是 `input_image`，读取 `output_text` 或 `output[].content[].text`。这里的 `completion` 指 Chat Completions 协议，不是旧的纯文本 `/completions` endpoint；旧接口通常不能接收图片。

`VISION_MODEL` 必须是“图片输入、文本输出”的多模态聊天或推理模型。普通纯文本聊天模型不能识别这些图片；只负责生成图片的模型（例如 provider 定义为 image-generation 的 `gpt-image-2`）也不适合返回 CAPTCHA 图片索引。模型必须最终返回类似 `[0, 3, 7]` 的图片索引数组。

如果 `VISION_API_URL`、`VISION_API_KEY`、`VISION_MODEL` 全部留空，系统兼容旧配置 `GEMINI_API_KEY`，使用内置 Gemini REST 请求和 `gemini-3.6-flash`。只填写部分 `VISION_*` 配置会直接报缺少配置，不会错误回退到旧 key。

仓库不需要配置 AWS WAF 的 `api_key`：该值由 Student Beans 登录页发出的 AWS WAF `problem` 请求携带，adapter 会在当前 Camoufox 页面上下文中读取。图片和目标文字会发送到你配置的视觉 provider，应按你的数据处理、服务条款和费用要求配置。

为降低多账号任务触发速率限制的概率，同一 FlareSolverr 进程内的视觉请求会串行执行，连续请求至少间隔 20 秒。普通 HTTP 429 最多按 `Retry-After`（没有时等待 30 秒）重试 1 次；provider 报告预付费额度耗尽时不会重试。

## 流程

1. Camoufox 填写账号并完成 Turnstile；提交前会再次检查并关闭延迟出现的 OneTrust Cookie 遮罩。
2. 点击 `Log in`，捕获同一页面第一次产生的 AWS WAF `problem` URL 和响应内容。
3. 使用这份原始 `problem` 响应中的图片、目标、状态和密钥字段，保持识别内容与 UI 一一对应；只有图片识别请求发往视觉 provider，不再二次请求 `problem`。
4. 根据视觉 provider 返回的索引，在当前 `awswaf-captcha` 弹窗中点击对应图片并点击 `Confirm`，由页面原生完成 `verify`、`voucher` 和 token 状态更新；不重新加载页面、不手动写入 token/cookie，也不再次点击 `Log in`，因为 Confirm 会自动重放触发 challenge 的原登录请求。

同页任务的 backend 等待时间覆盖页面加载、Turnstile 等待、登录提交和代码采集阶段；页面加载或表单填写消耗的时间不会挤占 Turnstile 的完整等待窗口。OneTrust 延迟出现时，solver 会在提交前使用页面原生接受按钮处理，并在按钮被遮罩动画覆盖时触发该按钮自己的 DOM click 处理。

面板沿用摘要结果显示，不展示无法从阻塞式 FlareSolverr 请求中实时取得的伪阶段进度。任务失败时会保留失败摘要，并显示脱敏后的错误类型、发生位置和上游原因，例如 `Vision API request failed: TimeoutError`；响应中的 key、token、password、secret、authorization 和 cookie 字段会被遮罩。AWS WAF Confirm 失败时还会显示 `/verify`、`/voucher` 的状态、响应是否可解析、业务结果字段、token 是否变化，以及图片控件/Canvas 的选中统计和点击坐标，用来区分识别错误、点击未生效和 WAF 业务拒绝。响应体无法解析时仍显示 HTTP 状态码，不会把原始请求体、图片或凭据显示到面板。

adapter 不记录 provider key、AWS WAF `api_key`、token、voucher 或图片内容。包含这些数据的 HAR 文件和运行日志不得提交到 Git。

## 运行前检查

```bash
grep -E '^(VISION_API_URL|VISION_API_KEY|VISION_MODEL|VISION_API_MODE)=' .env
docker-compose config >/dev/null
docker-compose up -d --build --force-recreate flaresolverr backend
```

日志中的成功标志是 `Camoufox AWS WAF solved`，并且后续必须出现第二次登录 API 响应和登录成功；仅出现 Turnstile 成功不算完成。

面板的“WAF 识别失败时重试一次”开关默认关闭。开启后，backend 仅在第一次会话已结束且失败位置为 `AWS WAF视觉识别` 时创建一次新的 Camoufox 会话；该次重试会重新走完整登录流程，并按当前代理池规则领取一个可用代理。第二次失败或任何其他失败类型都会直接结束任务。
