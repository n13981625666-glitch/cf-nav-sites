# cf-nav-sites

网址导航：左侧分类、紧凑卡片、可上传图标，运行在 Cloudflare Workers + KV 上，免服务器、免费额度足够个人使用。

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/n13981625666-glitch/cf-nav-sites)

## 特性

- **分类侧边栏**：桌面端左侧固定、滚动联动高亮，手机端自动变成顶部横向分类条。
- **紧凑卡片**：只显示图标、名称、一行描述，不显示链接地址。
- **图标**：可上传（浏览器端自动缩放为 128px PNG，支持点选 / 拖入 / 粘贴）；没上传时由 Worker 自动抓取并缓存网站图标；都没有时显示首字母头像。
- **搜索**：按 `/` 聚焦，搜索时按 Enter 直接打开第一个结果；可搜名称、描述、网址、分类名。
- **后台按分类管理**：分类增删改与拖拽排序；链接拖拽排序；把链接拖到左侧分类即可移动；描述框带「·」快捷插入（`Alt + .`）。
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
| `SITE_TITLE` | 变量 | 否 | 站点名称，默认「网址导航」 |
| `REQUIRE_LOGIN` | 变量 | 否 | 设为 `"true"` 则首页也需要登录，默认公开浏览、仅管理需要密码 |

`SITE_TITLE` 和 `REQUIRE_LOGIN` 写在 `wrangler.jsonc` 的 `vars` 里，修改后重新部署生效。

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
