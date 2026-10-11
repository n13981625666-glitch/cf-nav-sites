# cf-nav-sites

网址导航：左侧分类、紧凑卡片、可上传图标，运行在 Cloudflare Workers + KV 上，免服务器、免费额度足够个人使用。

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/n13981625666-glitch/cf-nav-sites)

## 特性

- **分类侧边栏**：桌面端左侧固定、滚动联动高亮，手机端自动变成顶部横向分类条。
- **紧凑卡片**：只显示图标、名称、一行描述，不显示链接地址。
- **图标**：可上传（浏览器端自动缩放为 128px PNG，支持点选 / 拖入 / 粘贴）；没上传时由 Worker 自动抓取并缓存网站图标；都没有时显示首字母头像。
- **搜索**：按 `/` 聚焦，搜索时按 Enter 直接打开第一个结果；可搜名称、描述、网址、分类名。
- **后台按分类管理**：分类增删改与拖拽排序；链接拖拽排序；把链接拖到左侧分类即可移动；描述框带「·」快捷插入（`Alt + .`）。
- **常用网站**：按点击次数自动把前 8 个网站放到首页最上方的「⭐ 常用网站」（点击数存在 KV 的 `nav:clicks`，跨设备共享；删除链接后其计数自动忽略）。
- 日 / 夜主题，自动保存。

## 一键部署

1. 点击上方按钮，授权 GitHub。
2. 部署页填写 `PASSWORD`（管理密码，至少 6 位）。KV 命名空间会自动创建。
3. 部署完成后打开 Worker 地址即可浏览；右上角进入管理页，用密码登录后添加分类和链接。

> 点击按钮后 Cloudflare 会把仓库复制到你的 GitHub 账号下并开启自动构建，之后推送代码即自动更新。

## 手动部署

```bash
git clone https://github.com/YOUR_USER/YOUR_REPO && cd YOUR_REPO
npm install
npx wrangler kv namespace create NAV_KV   # 把输出的 id 填进 wrangler.jsonc 的 kv_namespaces
npx wrangler secret put PASSWORD
npm run deploy
```

## 配置

| 名称 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `PASSWORD` | Secret | 是 | 管理密码，至少 6 位；未设置时站点只显示配置提示页 |
| `NAV_KV` | KV 绑定 | 是 | 保存分类、链接和上传的图标 |
| `AI` | Workers AI 绑定 | 否 | 启用「AI 生成描述」；`wrangler.jsonc` 里已配置，不需要可删除 |
| `AI_MODEL` | 变量 | 否 | 优先使用的 Workers AI 文本模型；默认依次尝试 `@cf/zai-org/glm-4.7-flash`、`@cf/meta/llama-3.1-8b-instruct-fp8`，前一个失败自动换下一个 |
| `SITE_TITLE` | 变量 | 否 | 站点名称，默认「网址导航」 |
| `REQUIRE_LOGIN` | 变量 | 否 | 设为 `"true"` 则首页也需要登录，默认公开浏览、仅管理需要密码 |

`SITE_TITLE` 和 `REQUIRE_LOGIN` 写在 `wrangler.jsonc` 的 `vars` 里，修改后重新部署生效。

## 导入书签与 AI 描述

- 管理页「导入」支持浏览器 / OneNav 导出的书签 HTML：文件夹变成分类，网址相同的自动跳过，`名称 - 描述` 会自动拆开。
- 绑定了 Workers AI 后，编辑弹窗里会出现「AI 生成描述」，列表上方有「AI 补全描述」可批量处理没有描述的链接。Worker 会抓取网页标题和简介，再让模型总结成一句话；抓取失败时仅凭域名推测，界面会提示核对。
- 该功能只对已登录的管理员开放，并拒绝内网和本机地址。使用的是 Cloudflare Workers AI 的免费额度，额度和可用模型以 Cloudflare 官方文档为准。
- 本地 `wrangler dev` 时 AI 绑定会走线上服务，需要已登录 Cloudflare 账号。

## 关于图标

- 上传的图标存放在 KV（每个约几 KB），没有被任何链接引用的图标会在保存数据时自动清理（仅清理 1 小时前上传的）。
- 自动获取的网站图标由 Worker 通过 Google 图标服务（失败时再试站点自己的 `/favicon.ico`）抓取并缓存，浏览器不会直接访问第三方，国内网络也能显示。这意味着你的链接域名会被 Worker 发给 Google 的图标服务；介意的话请给每个链接上传图标。
- 未登录的访客只能取已保存链接的域名图标，不会被当作开放代理。

## 本地开发

```bash
cp .dev.vars.example .dev.vars   # 填上 PASSWORD
npm install
npm run dev
```

## 限制与安全

- 最多 60 个分类、1000 个链接；单个图标不超过 100KB（页面会自动压缩）。
- 登录后下发 7 天有效的 HMAC 签名 Cookie（HttpOnly / Secure / SameSite=Strict）。
- 登录接口没有内置限速，建议在 Cloudflare 里为 `/login` 加一条速率限制规则。
- 没有做链接可用性检测：Worker 单次请求的子请求数量有限，链接多时无法在一次页面加载里全部探测。

## 许可证

MIT
