# AI智能试卷分析系统

当前项目是一个静态前端页面 + Cloudflare Worker 后端。前端仍在 `index.html`，后端放在 `worker/`，账号、会话、试卷记录和题库结果使用 Cloudflare D1 保存。

## 试卷分析流程

1. 在“试卷分析”页面先选择或拖拽所有文件。
2. 文件进入“待分析文件”列表后，再选择分析方式：
   - 默认方式：百度 OCR + DeepSeek API。
   - 多模态模型：OpenAI GPT 多模态 API。
3. 分析结果会写入 D1，并同步回前端题库、筛选、检索与整理页面。

## 本地启动

```bash
npm install
copy worker\.dev.vars.example worker\.dev.vars
```

编辑 `worker\.dev.vars`，填入真实密钥：

```text
BAIDU_OCR_API_KEY=your_baidu_ocr_api_key
BAIDU_OCR_SECRET_KEY=your_baidu_ocr_secret_key
DEEPSEEK_API_KEY=your_deepseek_api_key
OPENAI_API_KEY=your_openai_api_key
ALLOWED_ORIGIN=http://localhost:5500
```

首次使用账号功能前初始化本地 D1：

```bash
npm run db:migrate:local
```

启动 Worker：

```bash
npm run dev:worker
```

前端是静态 HTML，可以用任意静态服务打开。默认后端地址是 `http://127.0.0.1:8787`；如需覆盖，可在浏览器控制台设置：

```js
localStorage.setItem('exam_analyzer_api_base', 'http://127.0.0.1:8787')
```

## 检查

```bash
npm run check
```

## 线上部署

当前 Worker 已部署到：

```text
https://exam-analyzer-worker.edu-qingxue.workers.dev
```

线上 D1：

```text
database_name = exam-analyzer-db
database_id = c5bf5074-6b93-45ea-8c58-4d51cb8625eb
```

GitHub Pages 前端地址：

```text
https://mythnocode.github.io/AIedu/
```

线上前端在 `github.io` 域名下会自动请求 Worker 线上地址；本地打开时默认请求 `http://127.0.0.1:8787`。

线上真实分析前，需要给 Worker 设置 Secrets：

```bash
cd worker
npx wrangler secret put BAIDU_OCR_API_KEY
npx wrangler secret put BAIDU_OCR_SECRET_KEY
npx wrangler secret put DEEPSEEK_API_KEY
npx wrangler secret put OPENAI_API_KEY
```

设置完密钥后重新部署：

```bash
npm run deploy:worker
```
