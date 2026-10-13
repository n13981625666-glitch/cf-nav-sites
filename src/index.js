// ============================================================
//  cf-nav-sites — 网址导航（Cloudflare Workers + KV）
//
//  绑定：  NAV_KV        KV 命名空间（保存分类、链接、上传的图标）
//  Secret：PASSWORD      管理密码（必填，至少 6 位）
//  变量：  SITE_TITLE    站点名称（可选，默认「网址导航」）
//          REQUIRE_LOGIN 设为 "true" 则首页也需要登录（默认公开浏览，仅管理需要密码）
//
//  功能：
//   - 左侧分类侧边栏（滚动联动），紧凑卡片，不显示链接地址
//   - 图标：可上传（浏览器端压缩为 128px PNG），未上传时自动获取网站图标，
//     再失败则显示首字母头像
//   - 管理后台按分类管理：分类增删改与拖拽排序、链接拖拽排序、拖到分类即可移动
// ============================================================

const DATA_KEY = 'nav:data';
const CLICKS_KEY = 'nav:clicks';
const HALF_LIFE_DAYS = 30; // 点击权重每 30 天减半，常用榜跟随近期使用习惯
const ICON_PREFIX = 'icon:';
const TOKEN_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const MAX_LINKS = 1000;
const MAX_CATS = 60;
const MAX_ICON_BYTES = 100 * 1024;
const ICON_ID_RE = /^[a-f0-9]{12}$/;

const DEFAULT_DATA = {
    categories: [
        { id: 'tools', name: '常用工具' },
        { id: 'dev', name: '开发工具' },
        { id: 'media', name: '影音娱乐' }
    ],
    links: [
        { id: 'excalidraw', title: 'Excalidraw', desc: '手绘风白板 · 画图草图', url: 'https://excalidraw.com/', cat: 'tools', icon: '' },
        { id: 'squoosh', title: 'Squoosh', desc: '图片压缩 · 格式转换', url: 'https://squoosh.app/', cat: 'tools', icon: '' },
        { id: 'github', title: 'GitHub', desc: '代码托管 · 开源协作', url: 'https://github.com/', cat: 'dev', icon: '' },
        { id: 'cloudflare', title: 'Cloudflare', desc: '控制台 · Workers 与域名', url: 'https://dash.cloudflare.com/', cat: 'dev', icon: '' },
        { id: 'mdn', title: 'MDN', desc: 'Web 开发文档', url: 'https://developer.mozilla.org/', cat: 'dev', icon: '' },
        { id: 'youtube', title: 'YouTube', desc: '视频 · 音乐', url: 'https://www.youtube.com/', cat: 'media', icon: '' }
    ]
};

// ---------- 通用工具 ----------
function escapeHtml(value = '') {
    return String(value)
        .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

function safeJson(data) {
    return JSON.stringify(data)
        .replace(/</g, '\\u003c').replace(/>/g, '\\u003e')
        .replace(/\u2028/g, '\\u2028').replace(/\u2029/g, '\\u2029');
}

function json(data, status = 200) {
    return new Response(JSON.stringify(data), {
        status, headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' }
    });
}

function html(body, status = 200) {
    return new Response(body, {
        status,
        headers: {
            'Content-Type': 'text/html; charset=utf-8',
            'Cache-Control': 'no-store',
            'X-Content-Type-Options': 'nosniff',
            'Referrer-Policy': 'same-origin'
        }
    });
}

function randomHex(bytes) {
    return Array.from(crypto.getRandomValues(new Uint8Array(bytes)), b => b.toString(16).padStart(2, '0')).join('');
}

// ---------- 认证（HMAC 签名 token） ----------
async function hmacSign(secret, message) {
    const key = await crypto.subtle.importKey(
        'raw', new TextEncoder().encode(secret),
        { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
    );
    const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(message));
    let bin = '';
    for (const b of new Uint8Array(sig)) bin += String.fromCharCode(b);
    return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function timingSafeEqual(a, b) {
    if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
    let diff = 0;
    for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
    return diff === 0;
}

async function makeAuthToken(password) {
    const exp = Date.now() + TOKEN_TTL_MS;
    return `${exp}.${await hmacSign(password, String(exp))}`;
}

async function verifyAuthToken(token, password) {
    if (!token) return false;
    const dot = token.indexOf('.');
    if (dot === -1) return false;
    const exp = token.slice(0, dot);
    const sig = token.slice(dot + 1);
    if (!exp || !sig || Date.now() > Number(exp)) return false;
    return timingSafeEqual(sig, await hmacSign(password, exp));
}

async function isAuthenticated(request, password) {
    const cookie = request.headers.get('Cookie') || '';
    const m = cookie.match(/(?:^|;\s*)auth_token=([^;]+)/);
    if (!m) return false;
    let token;
    try { token = decodeURIComponent(m[1]); } catch { return false; }
    return verifyAuthToken(token, password);
}

// ---------- 数据规范化 ----------
function cleanUrl(v) {
    let p;
    try { p = new URL(String(v ?? '').trim()); } catch { throw new Error('网址无效：' + String(v ?? '').slice(0, 60)); }
    if (!/^https?:$/.test(p.protocol)) throw new Error('只支持 http / https 网址');
    return p.href;
}

// strict=true：保存时校验，出错抛异常；strict=false：读取时宽松处理，跳过坏数据，绝不丢失其余数据
function normalizeData(raw, strict) {
    const src = raw && typeof raw === 'object' ? raw : {};

    const cats = [];
    const catIds = new Set();
    const catNames = new Set();
    for (const c of Array.isArray(src.categories) ? src.categories : []) {
        const name = String(c?.name ?? '').trim().slice(0, 24);
        if (!name) continue;
        const nk = name.toLowerCase();
        if (catNames.has(nk)) {
            if (strict) throw new Error('分类名称重复：' + name);
            continue;
        }
        catNames.add(nk);
        let id = String(c?.id ?? '').trim();
        if (!/^[a-zA-Z0-9_-]{1,24}$/.test(id) || catIds.has(id)) {
            do { id = randomHex(3); } while (catIds.has(id));
        }
        catIds.add(id);
        cats.push({ id, name });
    }
    if (cats.length > MAX_CATS) {
        if (strict) throw new Error('分类过多（最多 ' + MAX_CATS + ' 个）');
        cats.length = MAX_CATS;
    }
    if (!cats.length) { cats.push({ id: 'default', name: '常用' }); catIds.add('default'); }

    const arr = Array.isArray(src.links) ? src.links : [];
    if (strict && arr.length > MAX_LINKS) throw new Error('链接过多（最多 ' + MAX_LINKS + ' 个）');

    const ids = new Set();
    const links = [];
    for (const l of arr.slice(0, MAX_LINKS)) {
        try {
            const title = String(l?.title ?? '').trim().slice(0, 40);
            if (!title) throw new Error('名称不能为空');
            const url = cleanUrl(l?.url);
            let id = String(l?.id ?? '').trim();
            if (!/^[a-zA-Z0-9_-]{1,40}$/.test(id) || ids.has(id)) {
                do { id = randomHex(5); } while (ids.has(id));
            }
            ids.add(id);
            const icon = ICON_ID_RE.test(String(l?.icon ?? '')) ? String(l.icon) : '';
            links.push({
                id, title, url,
                desc: String(l?.desc ?? '').trim().slice(0, 80),
                cat: catIds.has(l?.cat) ? l.cat : cats[0].id,
                icon
            });
        } catch (e) {
            if (strict) throw e;
        }
    }
    return { categories: cats, links };
}

async function getData(env) {
    try {
        const raw = await env.NAV_KV.get(DATA_KEY, 'json');
        if (raw && typeof raw === 'object') return normalizeData(raw, false);
    } catch (e) { /* ignore */ }
    return normalizeData(DEFAULT_DATA, false);
}

// 点击记录：{ 链接id: { s: 分数, t: 上次更新时间戳 } }，分数随时间指数衰减（半衰期 HALF_LIFE_DAYS）
function decayFactor(from, now) {
    return Math.pow(0.5, Math.max(0, now - from) / (HALF_LIFE_DAYS * 86400000));
}

// 读取原始记录，只保留仍存在的链接；兼容旧格式（纯数字）
async function getClickRecords(env, data) {
    try {
        const raw = await env.NAV_KV.get(CLICKS_KEY, 'json');
        const ids = new Set(data.links.map(l => l.id));
        const now = Date.now();
        const out = {};
        if (raw && typeof raw === 'object') {
            for (const [k, v] of Object.entries(raw)) {
                if (!ids.has(k)) continue;
                const sc = typeof v === 'number' ? v : v?.s;
                const t = typeof v === 'number' ? now : v?.t;
                if (Number.isFinite(sc) && sc > 0 && Number.isFinite(t)) out[k] = { s: sc, t };
            }
        }
        return out;
    } catch (e) { return {}; }
}

// 当前时刻的衰减后分数：{ 链接id: 分数 }（过低的忽略）
function currentScores(records) {
    const now = Date.now();
    const out = {};
    for (const [k, r] of Object.entries(records)) {
        const v = r.s * decayFactor(r.t, now);
        if (v >= 0.05) out[k] = Math.round(v * 1000) / 1000;
    }
    return out;
}

// 删除不再被引用的图标（只清理 1 小时前上传的，避免误删刚上传、尚未保存的图标）
async function cleanupIcons(env, data) {
    const used = new Set(data.links.map(l => l.icon).filter(Boolean));
    const cutoff = Date.now() - 3600 * 1000;
    let cursor;
    do {
        const r = await env.NAV_KV.list({ prefix: ICON_PREFIX, cursor });
        for (const k of r.keys) {
            const id = k.name.slice(ICON_PREFIX.length);
            const t = (k.metadata && k.metadata.t) || 0;
            if (!used.has(id) && t < cutoff) await env.NAV_KV.delete(k.name);
        }
        cursor = r.list_complete ? undefined : r.cursor;
    } while (cursor);
}

// 抓取网站图标：先 Google 图标服务，再尝试站点自己的 /favicon.ico
async function fetchFavicon(host) {
    const tries = [
        `https://www.google.com/s2/favicons?domain=${encodeURIComponent(host)}&sz=128`,
        `https://${host}/favicon.ico`
    ];
    for (const u of tries) {
        try {
            const r = await fetch(u, {
                headers: { 'User-Agent': 'Mozilla/5.0 (compatible; cf-nav-sites)' },
                signal: AbortSignal.timeout(4000)
            });
            if (!r.ok) continue;
            const ct = (r.headers.get('content-type') || '').split(';')[0].trim().toLowerCase();
            if (!/^image\/(png|x-icon|vnd\.microsoft\.icon|jpeg|gif|webp)$/.test(ct)) continue;
            const buf = await r.arrayBuffer();
            if (buf.byteLength < 50 || buf.byteLength > 200 * 1024) continue;
            return { buf, ct };
        } catch (e) { /* try next */ }
    }
    return null;
}

// ============================================================
//  AI 生成一句话描述（Cloudflare Workers AI，可选）
// ============================================================
// 依次尝试，前一个失败（下线 / 额度 / 空结果）就换下一个。可用 AI_MODEL 变量把自定义模型放到最前面。
const AI_MODELS_DEFAULT = ['@cf/zai-org/glm-4.7-flash', '@cf/meta/llama-3.1-8b-instruct-fp8'];

function isBlockedHost(h) {
    h = String(h || '').toLowerCase();
    if (!h.includes('.') || h.includes(':') || h === 'localhost') return true;
    if (/\.(local|localhost|internal|lan|home|corp)$/.test(h)) return true;
    const m = h.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
    if (m) {
        const a = +m[1], b = +m[2];
        if (a === 0 || a === 10 || a === 127 || a >= 224) return true;
        if (a === 169 && b === 254) return true;
        if (a === 172 && b >= 16 && b <= 31) return true;
        if (a === 192 && b === 168) return true;
        if (a === 100 && b >= 64 && b <= 127) return true;
    }
    return false;
}

function decodeEntities(t) {
    return t.replace(/&nbsp;/g, ' ').replace(/&lt;/g, '<').replace(/&gt;/g, '>')
        .replace(/&quot;/g, '"').replace(/&#0?39;|&apos;/g, "'")
        .replace(/&#(\d+);/g, (_, n) => { try { return String.fromCodePoint(+n); } catch { return ''; } })
        .replace(/&amp;/g, '&');
}

async function fetchPageInfo(u) {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 7000);
    try {
        const res = await fetch(u, {
            headers: {
                'User-Agent': 'Mozilla/5.0 (compatible; NavSiteBot/1.0)',
                'Accept': 'text/html,application/xhtml+xml;q=0.9,*/*;q=0.5',
                'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8'
            },
            redirect: 'follow',
            signal: ctrl.signal
        });
        if (!res.ok) return null;
        try { if (isBlockedHost(new URL(res.url).hostname)) return null; } catch { /* ignore */ }
        const ct = res.headers.get('content-type') || '';
        if (ct && !/html|xml|text/i.test(ct)) return null;

        // 最多读取 300KB
        const reader = res.body.getReader();
        const parts = [];
        let size = 0;
        while (size < 300 * 1024) {
            const { done, value } = await reader.read();
            if (done) break;
            parts.push(value);
            size += value.length;
        }
        try { reader.cancel(); } catch { /* ignore */ }
        const buf = new Uint8Array(size);
        let off = 0;
        for (const p of parts) { buf.set(p, off); off += p.length; }

        let charset = (ct.match(/charset=([\w-]+)/i) || [])[1];
        if (!charset) charset = (new TextDecoder('utf-8').decode(buf.subarray(0, 2048)).match(/<meta[^>]+charset=["']?([\w-]+)/i) || [])[1];
        let htmlText;
        try { htmlText = new TextDecoder(charset || 'utf-8').decode(buf); } catch { htmlText = new TextDecoder('utf-8').decode(buf); }

        const meta = (re) => {
            const m = htmlText.match(re);
            return m ? decodeEntities(m[1]).replace(/\s+/g, ' ').trim() : '';
        };
        const title = meta(/<title[^>]*>([\s\S]*?)<\/title>/i);
        const description =
            meta(/<meta[^>]+(?:name|property)=["'](?:description|og:description|twitter:description)["'][^>]*content=["']([^"']*)["']/i) ||
            meta(/<meta[^>]+content=["']([^"']*)["'][^>]*(?:name|property)=["'](?:description|og:description|twitter:description)["']/i);
        const siteName =
            meta(/<meta[^>]+property=["']og:site_name["'][^>]*content=["']([^"']*)["']/i) ||
            meta(/<meta[^>]+content=["']([^"']*)["'][^>]*property=["']og:site_name["']/i);
        const h1 = meta(/<h1[^>]*>([\s\S]*?)<\/h1>/i).replace(/<[^>]+>/g, '').trim();
        const text = decodeEntities(
            htmlText.replace(/<(script|style|noscript|svg|head)[\s\S]*?<\/\1>/gi, ' ').replace(/<[^>]+>/g, ' ')
        ).replace(/\s+/g, ' ').trim().slice(0, 500);

        if (!title && !description && !text) return null;
        return { title: title.slice(0, 200), description: description.slice(0, 400), siteName: siteName.slice(0, 80), h1: h1.slice(0, 120), text };
    } catch {
        return null;
    } finally {
        clearTimeout(timer);
    }
}

async function describeSite(env, rawUrl, hintTitle) {
    const u = cleanUrl(rawUrl);
    if (isBlockedHost(new URL(u).hostname)) throw new Error('不支持该地址');
    if (!env.AI) throw new Error('未绑定 Workers AI：请在 wrangler.jsonc 中添加 "ai": {"binding": "AI"} 后重新部署');

    const info = await fetchPageInfo(u);
    const lines = ['网址：' + u];
    if (info) {
        if (info.title) lines.push('网站标题：' + info.title);
        if (info.siteName) lines.push('网站名称：' + info.siteName);
        if (info.description) lines.push('网站简介：' + info.description);
        if (info.h1) lines.push('页面主标题：' + info.h1);
        if (info.text) lines.push('正文片段：' + info.text);
    } else {
        if (hintTitle) lines.push('用户给的名称：' + String(hintTitle).slice(0, 60));
        lines.push('（无法读取网页内容，请根据域名和名称谨慎推测；不确定时用概括性的说法）');
    }

    const messages = [
        {
            role: 'system',
            content: '你是网址导航站的编辑。根据给出的网站信息，用一句简体中文概括这个网站是做什么的。' +
                '要求：不超过 25 个汉字；不要出现网站名称；不要加句号；只输出这句描述本身，不要引号、前缀或任何解释。'
        },
        { role: 'user', content: lines.join('\n') }
    ];
    const models = [...(env.AI_MODEL ? [String(env.AI_MODEL).trim()] : []), ...AI_MODELS_DEFAULT]
        .filter((m, i, a) => m && a.indexOf(m) === i);
    let t = '', lastErr = '';
    for (const model of models) {
        try {
            const opts = /glm|kimi|qwen3|gpt-oss|deepseek/i.test(model)
                ? { messages, max_completion_tokens: 600, temperature: 0.3 }   // 推理类模型要给思考留足空间
                : { messages, max_tokens: 80, temperature: 0.3 };
            const out = await env.AI.run(model, opts);
            let raw = out?.response ?? out?.result?.response ?? out?.choices?.[0]?.message?.content ?? '';
            raw = String(raw).replace(/<think>[\s\S]*?<\/think>/gi, '').trim().split('\n').find(x => x.trim()) || '';
            raw = raw.trim().replace(/^(一句话)?(描述|简介)[:：]\s*/, '')
                .replace(/^["“”「『'\s]+|["“”」』'\s]+$/g, '')
                .replace(/[。．.！!\s]+$/, '').slice(0, 40);
            if (raw) { t = raw; break; }
            lastErr = model + ' 返回为空';
        } catch (e) {
            lastErr = String(e?.message || e).slice(0, 160);
        }
    }
    if (!t && lastErr && !/返回为空/.test(lastErr)) throw new Error('AI 调用失败：' + lastErr);
    if (!t) throw new Error('AI 没有返回内容，请重试');

    let name = '';
    if (info) {
        name = info.siteName || (info.title.split(/\s+[-–—|·]\s+|[|｜]/)[0] || '').trim();
        if (name.length > 40) name = '';
    }
    return { desc: t, name, guessed: !info };
}

// ============================================================
//  Worker 入口
// ============================================================
export default {
    async fetch(request, env, ctx) {
        const url = new URL(request.url);
        const path = url.pathname;

        const PASSWORD = env.PASSWORD ? String(env.PASSWORD) : '';
        const TITLE = String(env.SITE_TITLE || '网址导航').slice(0, 30);
        const REQUIRE_LOGIN = String(env.REQUIRE_LOGIN || '').toLowerCase() === 'true';

        // 未配置时只显示提示页，不提供任何默认密码
        if (PASSWORD.length < 6) return html(setupPage(TITLE, 'password'), 503);
        if (!env.NAV_KV) return html(setupPage(TITLE, 'kv'), 503);

        const authed = await isAuthenticated(request, PASSWORD);

        // ---------------- 上传的图标 ----------------
        if (path.startsWith('/icon/') && request.method === 'GET') {
            if (REQUIRE_LOGIN && !authed) return new Response('Unauthorized', { status: 401 });
            const id = path.slice(6);
            if (!ICON_ID_RE.test(id)) return new Response('Not Found', { status: 404 });
            const { value } = await env.NAV_KV.getWithMetadata(ICON_PREFIX + id, 'arrayBuffer');
            if (!value) return new Response('Not Found', { status: 404 });
            return new Response(value, {
                headers: {
                    'Content-Type': 'image/png',
                    'Cache-Control': (REQUIRE_LOGIN ? 'private' : 'public') + ', max-age=31536000, immutable',
                    'X-Content-Type-Options': 'nosniff'
                }
            });
        }

        // ---------------- 网站图标代理（由 Worker 抓取并缓存，国内也能显示） ----------------
        if (path.startsWith('/favicon/') && request.method === 'GET') {
            if (REQUIRE_LOGIN && !authed) return new Response('Unauthorized', { status: 401 });
            let host = '';
            try { host = decodeURIComponent(path.slice(9)).toLowerCase(); } catch (e) { /* ignore */ }
            if (!/^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$/.test(host) || !host.includes('.')) {
                return new Response('Bad host', { status: 400 });
            }
            // 未登录的访客只能取已保存链接的域名，防止被当作开放代理
            if (!authed) {
                const d = await getData(env);
                const ok = d.links.some(l => { try { return new URL(l.url).hostname.toLowerCase() === host; } catch { return false; } });
                if (!ok) return new Response('Not Found', { status: 404 });
            }
            const cache = caches.default;
            const cacheKey = new Request(url.origin + '/favicon/' + host + '?s=128'); // 带 ?s=128：让之前缓存的 64px 旧图标失效
            const hit = await cache.match(cacheKey);
            if (hit) return hit;
            const icon = await fetchFavicon(host);
            if (!icon) {
                return new Response('No icon', { status: 404, headers: { 'Cache-Control': 'public, max-age=600' } });
            }
            const res = new Response(icon.buf, {
                headers: {
                    'Content-Type': icon.ct,
                    'Cache-Control': 'public, max-age=604800',
                    'X-Content-Type-Options': 'nosniff'
                }
            });
            ctx.waitUntil(cache.put(cacheKey, res.clone()));
            return res;
        }

        // ---------------- 汇报点击（用于「常用网站」） ----------------
        // 浏览器每小时汇总上报一次：body 为 JSON { 链接id: 次数 }，一次上报只写一次 KV
        if (path === '/click' && request.method === 'POST') {
            if (REQUIRE_LOGIN && !authed) return new Response(null, { status: 401 });
            try {
                const raw = await request.text();
                if (raw.length > 16384) return new Response(null, { status: 413 });
                const batch = JSON.parse(raw);
                if (!batch || typeof batch !== 'object' || Array.isArray(batch)) return new Response(null, { status: 400 });
                const data = await getData(env);
                const rec = await getClickRecords(env, data);
                const now = Date.now();
                let changed = false;
                for (const [id, n] of Object.entries(batch)) {
                    const cnt = Math.min(Math.floor(Number(n)), 500); // 单个链接单次上报最多计 500，防止被刷
                    if (!(cnt > 0) || !data.links.some(l => l.id === id)) continue;
                    const old = rec[id];
                    rec[id] = { s: (old ? old.s * decayFactor(old.t, now) : 0) + cnt, t: now };
                    changed = true;
                }
                if (changed) {
                    // 顺手清掉已衰减到可忽略的旧记录
                    for (const [k, r] of Object.entries(rec)) {
                        if (r.s * decayFactor(r.t, now) < 0.05) delete rec[k];
                    }
                    await env.NAV_KV.put(CLICKS_KEY, JSON.stringify(rec));
                }
            } catch (e) { return new Response(null, { status: 400 }); }
            return new Response(null, { status: 204 });
        }

        // ---------------- API（需要登录） ----------------
        if (path.startsWith('/api/')) {
            if (!authed) return json({ error: 'Unauthorized' }, 401);

            if (path === '/api/data' && request.method === 'GET') {
                return json(await getData(env));
            }

            if (path === '/api/data' && request.method === 'PUT') {
                try {
                    const data = normalizeData(await request.json(), true);
                    await env.NAV_KV.put(DATA_KEY, JSON.stringify(data));
                    ctx.waitUntil(cleanupIcons(env, data).catch(() => {}));
                    return json({ success: true, data });
                } catch (e) {
                    return json({ error: e.message || '保存失败' }, 400);
                }
            }

            if (path === '/api/icon' && request.method === 'POST') {
                try {
                    const buf = await request.arrayBuffer();
                    if (buf.byteLength < 8 || buf.byteLength > MAX_ICON_BYTES) throw new Error('图标大小需小于 100KB');
                    const sig = new Uint8Array(buf, 0, 8);
                    const PNG = [137, 80, 78, 71, 13, 10, 26, 10];
                    if (!PNG.every((b, i) => sig[i] === b)) throw new Error('仅支持 PNG 图标（页面会自动转换）');
                    const id = randomHex(6);
                    await env.NAV_KV.put(ICON_PREFIX + id, buf, { metadata: { t: Date.now() } });
                    return json({ id });
                } catch (e) {
                    return json({ error: e.message || '上传失败' }, 400);
                }
            }

            if (path === '/api/describe' && request.method === 'POST') {
                try {
                    const b = await request.json();
                    return json(await describeSite(env, b?.url, b?.title));
                } catch (e) {
                    const msg = e.message || '生成失败';
                    return json({ error: msg }, /Workers AI/.test(msg) ? 501 : 400);
                }
            }

            return json({ error: 'Not Found' }, 404);
        }

        // ---------------- 登录 / 退出 ----------------
        const safeNext = (v) => (v === '/' ? '/' : '/admin');

        if (path === '/login' && request.method === 'GET') {
            if (authed) return new Response(null, { status: 302, headers: { Location: '/admin' } });
            return html(loginPage(false, TITLE, safeNext(url.searchParams.get('next'))));
        }

        if (path === '/login' && request.method === 'POST') {
            const form = await request.formData();
            const input = String(form.get('password') || '');
            const next = safeNext(String(form.get('next') || ''));
            if (timingSafeEqual(input, PASSWORD)) {
                const token = await makeAuthToken(PASSWORD);
                return new Response(null, {
                    status: 302,
                    headers: {
                        Location: next,
                        'Set-Cookie': `auth_token=${encodeURIComponent(token)}; Max-Age=604800; Path=/; HttpOnly; Secure; SameSite=Strict`
                    }
                });
            }
            return html(loginPage(true, TITLE, next));
        }

        if (path === '/logout') {
            return new Response(null, {
                status: 302,
                headers: {
                    Location: '/',
                    'Set-Cookie': 'auth_token=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=Strict'
                }
            });
        }

        // ---------------- 管理后台 ----------------
        if (path === '/admin') {
            if (!authed) return new Response(null, { status: 302, headers: { Location: '/login' } });
            return html(adminPage(TITLE, !!env.AI));
        }

        // ---------------- 首页 ----------------
        if (path === '/') {
            if (REQUIRE_LOGIN && !authed) return html(loginPage(false, TITLE, '/'));
            const data = await getData(env);
            const clicks = currentScores(await getClickRecords(env, data));
            return html(homePage(data, TITLE, authed, clicks));
        }

        return new Response('Not Found', { status: 404 });
    }
};

// ============================================================
//  共享：主题 / 基础样式 / 公共前端脚本
// ============================================================
const FAVICON_LINK = `<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'%3E%3Crect width='24' height='24' rx='6' fill='%234f46e5'/%3E%3Cpath d='M12 5l-6 3.5v7L12 19l6-3.5v-7z' fill='none' stroke='white' stroke-width='1.8' stroke-linejoin='round'/%3E%3C/svg%3E">`;

const THEME_INIT = `<script>try{var t=localStorage.getItem('theme');if(!t)t=matchMedia('(prefers-color-scheme: light)').matches?'light':'dark';document.documentElement.dataset.theme=t}catch(e){document.documentElement.dataset.theme='dark'}</script>`;

const ICON_SUN = `<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/></svg>`;
const ICON_MOON = `<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"/></svg>`;
const THEME_BTN = `<button class="icon-btn" id="themeBtn" type="button" aria-label="切换主题" title="切换主题"><span class="i-sun">${ICON_SUN}</span><span class="i-moon">${ICON_MOON}</span></button>`;

const THEME_JS = `
(function(){
  var b=document.getElementById('themeBtn');
  if(!b)return;

  b.addEventListener('click',function(){
    var root=document.documentElement;
    var n=root.dataset.theme==='light'?'dark':'light';

    /* 切换主题时临时关闭所有过渡动画 */
    root.classList.add('theme-switching');
    root.dataset.theme=n;

    try{localStorage.setItem('theme',n)}catch(e){}

    /* 等主题颜色完成更新后，再恢复正常交互动画 */
    requestAnimationFrame(function(){
      requestAnimationFrame(function(){
        root.classList.remove('theme-switching');
      });
    });
  });
})();
`;

const BASE_CSS = `
:root{
  --tb:60px;
  --bg:#09090b;--surface:#111113;--surface2:#1a1a1e;--border:#26262b;--border-strong:#3a3a42;
  --text:#fafafa;--muted:#9a9aa5;--faint:#6b6b76;
  --accent:#7c83ff;--accent-soft:rgba(124,131,255,.14);--accent-fg:#0b0b14;
  --ok:#34d399;--bad:#f87171;--warn:#fbbf24;
  --shadow:0 1px 2px rgba(0,0,0,.4),0 8px 30px rgba(0,0,0,.25);
  color-scheme:dark;
}
[data-theme=light]{
  --bg:#f5f6f8;--surface:#ffffff;--surface2:#f0f1f4;--border:#e3e5ea;--border-strong:#cfd2da;
  --text:#14151a;--muted:#5d6270;--faint:#8b90a0;
  --accent:#4f46e5;--accent-soft:rgba(79,70,229,.09);--accent-fg:#ffffff;
  --ok:#059669;--bad:#dc2626;--warn:#d97706;
  --shadow:0 1px 2px rgba(20,21,26,.06),0 8px 30px rgba(20,21,26,.07);
  color-scheme:light;
}
*{margin:0;padding:0;box-sizing:border-box}
/* 明暗主题切换期间：禁止整页动画与颜色过渡 */
html.theme-switching *,
html.theme-switching *::before,
html.theme-switching *::after{
  transition:none!important;
  animation:none!important;
  scroll-behavior:auto!important;
}
html{-webkit-text-size-adjust:100%}
body{font-family:ui-sans-serif,-apple-system,BlinkMacSystemFont,'Segoe UI','PingFang SC','Hiragino Sans GB','Microsoft YaHei',Roboto,sans-serif;background:var(--bg);color:var(--text);min-height:100vh;line-height:1.5;-webkit-font-smoothing:antialiased}
body::before{content:'';position:fixed;inset:0;pointer-events:none;z-index:0;background:radial-gradient(900px 420px at 50% -120px,var(--accent-soft),transparent 70%)}
a{color:inherit;text-decoration:none}
button,input,select{font-family:inherit;font-size:inherit;color:inherit}
button{cursor:pointer}
:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
.i-sun{display:none}.i-moon{display:inline-flex}
[data-theme=dark] .i-sun{display:inline-flex}[data-theme=dark] .i-moon{display:none}

.icon-btn{display:inline-flex;align-items:center;justify-content:center;width:38px;height:38px;border-radius:10px;border:1px solid var(--border);background:var(--surface);color:var(--muted);transition:.15s;flex:none}
.icon-btn:hover{color:var(--text);border-color:var(--border-strong);background:var(--surface2)}
.btn{display:inline-flex;align-items:center;justify-content:center;gap:6px;height:38px;padding:0 16px;border-radius:10px;border:1px solid var(--border);background:var(--surface);color:var(--text);font-weight:500;font-size:14px;transition:.15s;white-space:nowrap}
.btn:hover{border-color:var(--border-strong);background:var(--surface2)}
.btn-primary{background:var(--accent);border-color:var(--accent);color:var(--accent-fg)}
.btn-primary:hover{background:var(--accent);filter:brightness(1.1)}
.btn-sm{height:32px;padding:0 12px;font-size:13px}
.btn:disabled{opacity:.5;cursor:not-allowed}
.input{width:100%;height:40px;padding:0 12px;border-radius:10px;border:1px solid var(--border);background:var(--surface);color:var(--text);outline:none;transition:.15s}
.input::placeholder{color:var(--faint)}
.input:focus{border-color:var(--accent);box-shadow:0 0 0 3px var(--accent-soft)}
.chip{display:inline-flex;align-items:center;gap:4px;height:22px;padding:0 9px;border-radius:999px;font-size:12px;font-weight:500;background:var(--surface2);border:1px solid var(--border);color:var(--muted);white-space:nowrap}

/* 图标：上传图 / 网站图标 / 首字母头像 */
.ico{width:34px;height:34px;flex:none;border-radius:9px;overflow:hidden;background:var(--surface2);border:1px solid var(--border);display:flex;align-items:center;justify-content:center}
.ico img{width:100%;height:100%;object-fit:contain;padding:4px}
.ico[data-k=full]{background:transparent;border-color:rgba(100,110,135,.16)}
.ico[data-k=full] img{padding:0;object-fit:cover}
.ico[data-k=logo]{background:#fff;border-color:rgba(100,110,135,.16)}
.ico[data-k=logo] img{padding:17%}
.ico[data-k=logo][data-tone=light]{background:#262a37;border-color:rgba(255,255,255,.08)}
[data-theme=dark] .ico[data-k=full]{border-color:rgba(255,255,255,.08)}
[data-theme=dark] .ico[data-k=logo]{background:rgba(255,255,255,.075);border-color:rgba(255,255,255,.08)}
[data-theme=dark] .ico[data-k=logo][data-tone=dark]{background:#eef0f6;border-color:transparent}
[data-theme=dark] .ico[data-k=logo][data-tone=light]{background:rgba(255,255,255,.075)}
.ico-fb{width:100%;height:100%;display:flex;align-items:center;justify-content:center;background:hsl(var(--h) 52% 46%);color:#fff;font-weight:650;font-size:15px}

.search{position:relative;flex:1;min-width:0}
.search>svg{position:absolute;left:12px;top:50%;transform:translateY(-50%);color:var(--faint);pointer-events:none}
.search .input{padding-left:38px}
.topbar{position:sticky;top:0;z-index:20;height:var(--tb);background:color-mix(in srgb,var(--bg) 82%,transparent);backdrop-filter:blur(14px);-webkit-backdrop-filter:blur(14px)}
.tb-in{height:100%;display:flex;align-items:center;gap:10px;max-width:var(--mw,1240px);margin:0 auto;padding:0 20px}
@media(max-width:860px){.tb-in{padding:0 14px}}
.footer{margin-top:20px;padding:18px 0 28px;border-top:1px solid var(--border);color:var(--faint);font-size:12px}
@media (prefers-reduced-motion:reduce){*,*::before,*::after{animation-duration:.01ms!important;transition-duration:.01ms!important}}
`;

// 首页与后台共用：转义、图标渲染（含加载失败时回退为首字母头像）
const COMMON_JS = String.raw`
window.NavUI=(function(){
  function esc(v){return String(v==null?'':v).replace(/[&<>"']/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]})}
  function hostOf(u){try{return new URL(u).hostname}catch(e){return ''}}
  function norm(s){return String(s==null?'':s).toLowerCase().replace(/\s+/g,'')}
  function hue(s){var h=0;s=String(s);for(var i=0;i<s.length;i++)h=(h*31+s.charCodeAt(i))>>>0;return h%360}
  function fallback(title){
    var t=String(title||'?').trim()||'?';
    var ch=Array.from(t)[0]||'?';
    return '<span class="ico-fb" style="--h:'+hue(t)+'">'+esc(ch.toUpperCase())+'</span>';
  }
  /* 已经处理过的图标结果（按原始地址缓存），搜索 / 重新渲染时直接带上，避免闪烁和重复计算 */
  var normCache={};
  function icon(l){
    var inner,src,t=esc(l.title);
    if(l.icon){src='/icon/'+esc(l.icon)}
    else{var h=hostOf(l.url);src=h?'/favicon/'+encodeURIComponent(h)+'?s=128':''}
    if(!src)return '<span class="ico">'+fallback(l.title)+'</span>';
    var c=normCache[src];
    inner='<img class="ico-img" alt="" loading="lazy" data-t="'+t+'"'+(c?' data-n="1"':'')+' src="'+(c&&c.u?c.u:src)+'">';
    return '<span class="ico"'+(c?' data-k="'+c.k+'" data-tone="'+c.t+'"':'')+'>'+inner+'</span>';
  }
  document.addEventListener('error',function(e){
    var t=e.target;
    if(t&&t.classList&&t.classList.contains('ico-img')&&t.parentNode){t.parentNode.innerHTML=fallback(t.getAttribute('data-t'))}
  },true);
  /* 统一图标形状（首页普通模式、聚焦模式、管理页都生效）：
     1) 边缘整圈不透明的「满铺方图」→ 直接裁成统一圆角，不再套底板；
     2) 透明底 / 圆形 / 异形的 logo → 裁掉多余空白、居中缩放到同样的视觉大小，放进同一块底板；
     3) 按 logo 明暗挑底板：白色 logo 在亮色主题用深色底板，黑色 logo 在暗色主题用浅色底板，保证看得清。 */
  function normalizeIcon(img){
    if(img.getAttribute('data-n'))return;
    img.setAttribute('data-n','1');
    var ico=img.parentNode,kind='logo',tone='mid',src0=img.getAttribute('src'),newUrl='';
    try{
      var w=img.naturalWidth,h=img.naturalHeight;
      if(!w||!h)throw 0;
      var N=64,c=document.createElement('canvas');c.width=c.height=N;
      var x=c.getContext('2d',{willReadFrequently:true});
      x.drawImage(img,0,0,N,N);
      var d=x.getImageData(0,0,N,N).data,k,i,j;
      var edge=0,opq=0;
      for(k=12;k<N-12;k++){
        [d[(k)*4+3],d[((N-1)*N+k)*4+3],d[(k*N)*4+3],d[(k*N+N-1)*4+3]].forEach(function(a){edge++;if(a>200)opq++});
      }
      var minX=N,minY=N,maxX=-1,maxY=-1,ls=0,ln=0;
      for(j=0;j<N;j++)for(i=0;i<N;i++){
        var o=(j*N+i)*4,a=d[o+3];
        if(a>24){
          if(i<minX)minX=i;if(i>maxX)maxX=i;if(j<minY)minY=j;if(j>maxY)maxY=j;
          if(a>100){ls+=(.2126*d[o]+.7152*d[o+1]+.0722*d[o+2])/255;ln++}
        }
      }
      var lum=ln?ls/ln:.5;
      tone=lum<.3?'dark':lum>.82?'light':'mid';
      if(opq/edge>.9){kind='full'}
      else if(maxX>=0){
        var sx=minX/N*w,sy=minY/N*h,sw=(maxX-minX+1)/N*w,sh=(maxY-minY+1)/N*h;
        var out=document.createElement('canvas');out.width=out.height=128;
        var ox=out.getContext('2d'),sc=Math.min(128/sw,128/sh),dw=sw*sc,dh=sh*sc;
        ox.imageSmoothingQuality='high';
        ox.drawImage(img,sx,sy,sw,sh,(128-dw)/2,(128-dh)/2,dw,dh);
        newUrl=out.toDataURL('image/png');
        img.src=newUrl;
      }
    }catch(e){}
    normCache[src0]={k:kind,t:tone,u:newUrl};
    if(ico){ico.setAttribute('data-k',kind);ico.setAttribute('data-tone',tone)}
  }
  document.addEventListener('load',function(e){
    var t=e.target;
    if(t&&t.classList&&t.classList.contains('ico-img'))normalizeIcon(t);
  },true);
  return {esc:esc,hostOf:hostOf,norm:norm,icon:icon,fallback:fallback};
})();`;

// ============================================================
//  未配置提示页
// ============================================================
function setupPage(title, kind) {
    const msg = kind === 'kv'
        ? '尚未绑定 KV 命名空间。请在 Worker 的 Settings → Bindings 中添加 KV 绑定，变量名填 <code>NAV_KV</code>。'
        : '尚未设置管理密码。请在 Worker 的 Settings → Variables and Secrets 中添加名为 <code>PASSWORD</code> 的 Secret（至少 6 位）。';
    return `<!DOCTYPE html>
<html lang="zh-CN" data-theme="dark"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>需要配置 · ${escapeHtml(title)}</title>${FAVICON_LINK}${THEME_INIT}
<style>${BASE_CSS}body{display:flex;align-items:center;justify-content:center;padding:20px}
.c{position:relative;z-index:1;max-width:460px;background:var(--surface);border:1px solid var(--border);border-radius:18px;padding:28px;box-shadow:var(--shadow)}
h1{font-size:20px;margin-bottom:10px}p{color:var(--muted);font-size:14px}code{background:var(--surface2);border:1px solid var(--border);border-radius:6px;padding:1px 6px;font-size:13px;color:var(--text)}</style>
</head><body><div class="c"><h1>还差一步配置</h1><p>${msg}</p><p style="margin-top:10px">保存后刷新本页即可。</p></div></body></html>`;
}

// ============================================================
//  登录页
// ============================================================
function loginPage(hasError, title, next) {
    return `<!DOCTYPE html>
<html lang="zh-CN" data-theme="dark">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>登录 · ${escapeHtml(title)}</title>
${FAVICON_LINK}
${THEME_INIT}
<style>
${BASE_CSS}
body{display:flex;align-items:center;justify-content:center;padding:20px}
.wrap{position:relative;z-index:1;width:100%;max-width:380px}
.card{background:var(--surface);border:1px solid var(--border);border-radius:20px;padding:36px 30px 28px;box-shadow:var(--shadow)}
.logo{width:44px;height:44px;border-radius:12px;background:var(--accent-soft);color:var(--accent);display:flex;align-items:center;justify-content:center;margin-bottom:18px}
h1{font-size:22px;font-weight:650;letter-spacing:-.01em}
.sub{color:var(--muted);font-size:14px;margin:4px 0 24px}
.field{position:relative;margin-bottom:14px}
.field .input{height:46px;padding-right:44px}
.eye{position:absolute;right:6px;top:50%;transform:translateY(-50%);width:34px;height:34px;border:none;background:none;color:var(--faint);border-radius:8px;display:flex;align-items:center;justify-content:center}
.eye:hover{color:var(--text)}
.submit{width:100%;height:46px;font-size:15px}
.err{margin-bottom:14px;padding:10px 12px;border-radius:10px;font-size:13px;color:var(--bad);background:color-mix(in srgb,var(--bad) 10%,transparent);border:1px solid color-mix(in srgb,var(--bad) 30%,transparent)}
.foot{text-align:center;font-size:12px;margin-top:18px}
.foot a{color:var(--faint)}.foot a:hover{color:var(--text)}
.theme{position:fixed;top:16px;right:16px;z-index:5}
</style>
</head>
<body>
<div class="theme">${THEME_BTN}</div>
<div class="wrap">
  <form class="card" method="POST" action="/login" autocomplete="off">
    <input type="hidden" name="next" value="${escapeHtml(next)}">
    <div class="logo"><svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="11" width="16" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/></svg></div>
    <h1>${next === '/' ? '访问验证' : '管理登录'}</h1>
    <div class="sub">${escapeHtml(title)} · 请输入密码</div>
    ${hasError ? '<div class="err">密码错误，请重试</div>' : ''}
    <div class="field">
      <input class="input" type="password" id="pw" name="password" placeholder="密码" required autofocus>
      <button class="eye" type="button" id="eye" aria-label="显示密码"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/></svg></button>
    </div>
    <button class="btn btn-primary submit" type="submit">进入</button>
    ${next === '/' ? '' : '<div class="foot"><a href="/">← 返回导航</a></div>'}
  </form>
</div>
<script>
document.getElementById('eye').addEventListener('click',function(){var p=document.getElementById('pw');p.type=p.type==='password'?'text':'password';});
${THEME_JS}
</script>
</body>
</html>`;
}

// ============================================================
//  首页：左侧分类 + 紧凑卡片
// ============================================================
const HOME_CSS = `
.page{position:relative;z-index:1;max-width:1240px;margin:0 auto;padding:0 20px}
.brand{display:flex;align-items:center;gap:10px;font-weight:650;font-size:16px;letter-spacing:-.01em;margin-right:8px;flex:none}
.brand .mark{width:30px;height:30px;border-radius:9px;background:var(--accent);color:var(--accent-fg);display:flex;align-items:center;justify-content:center}
.search{max-width:520px}
.search .input{padding-right:44px}
.kbd{position:absolute;right:10px;top:50%;transform:translateY(-50%);font-size:11px;color:var(--faint);border:1px solid var(--border);border-radius:6px;padding:1px 6px;background:var(--surface2);pointer-events:none}
.tb-sp{flex:1}
.layout{display:grid;grid-template-columns:200px minmax(0,1fr);gap:28px;align-items:start;padding-top:8px}
.side{position:sticky;top:calc(var(--tb) + 8px);max-height:calc(100vh - var(--tb) - 24px);overflow-y:auto;display:flex;flex-direction:column;gap:2px;padding:2px 0;scrollbar-width:thin}
.side-item{display:flex;justify-content:space-between;align-items:center;gap:8px;padding:8px 12px;border-radius:10px;color:var(--muted);font-size:14px;font-weight:500;transition:background .15s,color .15s}
.side-item .nm{min-width:0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.side-item .n{font-size:12px;opacity:.6;flex:none}
.side-item:hover{background:var(--surface2);color:var(--text)}
.side-item.active{background:var(--accent-soft);color:var(--accent)}
.main{min-width:0}
.sec{scroll-margin-top:calc(var(--tb) + 12px);margin-bottom:26px}
.sec h2{font-size:15px;font-weight:650;margin:4px 0 12px;display:flex;align-items:center;gap:8px}
.sec h2 .cnt{font-size:12px;color:var(--faint);font-weight:500}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(228px,1fr));gap:10px}
.card{display:flex;align-items:center;gap:12px;padding:11px 12px;min-height:60px;min-width:0;background:var(--surface);border:1px solid var(--border);border-radius:12px;transition:transform .15s,border-color .15s,box-shadow .15s}
.card:hover{border-color:var(--accent);transform:translateY(-2px);box-shadow:var(--shadow)}
.card.first{border-color:var(--accent);box-shadow:0 0 0 3px var(--accent-soft)}
.txt{min-width:0;display:flex;flex-direction:column}
.t{font-weight:600;font-size:14px;line-height:1.4;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.d{font-size:12px;line-height:1.4;margin-top:4px;color:var(--faint);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.empty{text-align:center;color:var(--faint);padding:80px 0}
.empty a{color:var(--accent)}

/* 聚焦模式：现代极简、低对比表面与克制交互 */
.stage{display:none}
#focusBtn.on{color:var(--accent);border-color:var(--accent);background:var(--accent-soft)}
html.focus,html.focus body{overflow:hidden}
html.focus .page,html.focus .search{display:none}

html.focus .stage{
  display:block;
  position:fixed;
  left:0;
  right:0;
  top:var(--tb);
  bottom:0;
  z-index:5;
  overflow:hidden;
  background:var(--bg);
  isolation:isolate;
}

/* 极轻微的环境色，不抢网站图标的视觉焦点 */
html.focus .stage::before{
  content:'';
  position:absolute;
  inset:0;
  z-index:-1;
  pointer-events:none;
  background:radial-gradient(
    ellipse at 50% 0%,
    rgba(124,131,255,.055),
    transparent 62%
  );
}

html[data-theme=light].focus .stage::before{
  background:radial-gradient(
    ellipse at 50% 0%,
    rgba(79,70,229,.035),
    transparent 62%
  );
}

.track{
  position:absolute;
  left:0;
  right:0;
  top:0;
  height:100%;
  transition:transform .4s cubic-bezier(.3,.7,.2,1);
}

.fpage{
  position:absolute;
  left:0;
  right:0;
  height:100%;
}

/* 卡片主体：低饱和表面、细边框、弱阴影 */
.fcard{
  position:absolute;
  overflow:hidden;
  display:flex;
  flex-direction:column;
  align-items:center;
  justify-content:center;
  gap:9px;
  padding:8px 7px 10px;
  border-radius:16px;
  text-align:center;
  color:var(--text);

  background:rgba(255,255,255,.78);
  border:1px solid rgba(100,110,135,.15);

  -webkit-backdrop-filter:blur(14px) saturate(135%);
  backdrop-filter:blur(14px) saturate(135%);

  box-shadow:
    inset 0 1px 0 rgba(255,255,255,.9),
    0 2px 4px rgba(20,25,40,.025),
    0 8px 24px -18px rgba(20,25,40,.24);

  transition:
    transform .2s cubic-bezier(.2,.7,.2,1),
    background .2s ease,
    border-color .2s ease,
    box-shadow .2s ease;

  -webkit-tap-highlight-color:transparent;
}

/* 深色主题：石墨灰表面，避免纯黑和厚重反光 */
[data-theme=dark] .fcard{
  background:rgba(30,33,43,.82);
  border-color:rgba(255,255,255,.085);

  box-shadow:
    inset 0 1px 0 rgba(255,255,255,.055),
    0 2px 5px rgba(0,0,0,.10),
    0 10px 26px -20px rgba(0,0,0,.45);
}

/* 悬停：轻微浮起，边缘略微提亮 */
.fcard:hover{
  z-index:2;
  transform:translateY(-2px) scale(1.015);
  background:rgba(255,255,255,.96);
  border-color:rgba(100,110,145,.25);

  box-shadow:
    inset 0 1px 0 rgba(255,255,255,.95),
    0 5px 14px rgba(25,35,60,.055),
    0 14px 28px -20px rgba(25,35,60,.20);
}

[data-theme=dark] .fcard:hover{
  background:rgba(42,46,59,.96);
  border-color:rgba(180,190,255,.24);

  box-shadow:
    inset 0 1px 0 rgba(255,255,255,.075),
    0 5px 16px rgba(0,0,0,.16),
    0 0 0 1px rgba(160,170,255,.035);
}

/* 彻底取消旧版金属扫光和鼠标点光源 */
.fcard::before,
.fcard::after{
  display:none;
}

/* 网站图标：保留图标本身，不加多余装饰 */
.fcard .ico{
  width:var(--ico);
  height:var(--ico);
  flex:none;
  border-radius:calc(var(--ico)*.23);
  background:var(--surface2);
  border:1px solid rgba(100,110,135,.10);
}

[data-theme=dark] .fcard .ico{
  border-color:rgba(255,255,255,.07);
}

.fcard .ico img{
  padding:3px;
}

/* 统一图标形状：满铺方图直接铺满并裁成统一圆角；其余 logo 放进同一块底板，内边距一致 */
.fcard .ico[data-k=full]{background:transparent;border-color:rgba(100,110,135,.16)}
[data-theme=dark] .fcard .ico[data-k=full]{border-color:rgba(255,255,255,.08)}
.fcard .ico[data-k=full] img{padding:0;object-fit:cover}
.fcard .ico[data-k=logo]{background:#fff;border-color:rgba(100,110,135,.16)}
.fcard .ico[data-k=logo] img{padding:17%}
.fcard .ico[data-k=logo][data-tone=light]{background:#262a37;border-color:rgba(255,255,255,.08)}
[data-theme=dark] .fcard .ico[data-k=logo]{background:rgba(255,255,255,.075);border-color:rgba(255,255,255,.08)}
[data-theme=dark] .fcard .ico[data-k=logo][data-tone=dark]{background:#eef0f6;border-color:transparent}
[data-theme=dark] .fcard .ico[data-k=logo][data-tone=light]{background:rgba(255,255,255,.075)}

.fcard .ico-fb{
  font-size:calc(var(--ico)*.45);
}

/* 网站名称：清晰、紧凑，避免过重 */
.fn{
  flex:none;
  max-width:100%;
  font-size:13px;
  font-weight:560;
  /* 固定行高：字号被缩小时，名称区高度不变，所有卡片的图标位置保持一致 */
  height:18px;
  line-height:18px;
  letter-spacing:.005em;
  /* 名称始终单行：名字太长时由脚本缩小字号（最小 9px）来放进卡片，实在放不下才用省略号 */
  display:block;
  white-space:nowrap;
  overflow:hidden;
  text-overflow:ellipsis;
}

/* 页面切换指示点 */
.dots{
  position:absolute;
  right:8px;
  top:50%;
  transform:translateY(-50%);
  display:flex;
  flex-direction:column;
  z-index:6;
}

.dot{
  width:24px;
  height:16px;
  display:flex;
  align-items:center;
  justify-content:center;
  background:none;
  border:0;
  padding:0;
  cursor:pointer;
}

.dot::before{
  content:'';
  width:5px;
  height:5px;
  border-radius:50%;
  background:var(--muted);
  opacity:.42;
  transition:transform .2s,opacity .2s,background .2s;
}

.dot.on::before{
  background:var(--accent);
  opacity:1;
  transform:scale(1.35);
}

/* 触屏设备不使用悬停浮起效果 */
@media(hover:none){
  .fcard:hover{transform:none}
}

/* 尊重系统减少动态效果设置 */
@media(prefers-reduced-motion:reduce){
  .track,.fcard,.dot::before{
    transition:none!important;
  }
}

@media(max-width:860px){
  .page{padding:0 14px}
  .brand .bt{display:none}
  .tb-sp{display:none}
  .kbd{display:none}.search .input{padding-right:12px}
  .layout{display:block;padding-top:0}
  .side{position:sticky;top:var(--tb);z-index:15;flex-direction:row;gap:8px;overflow-x:auto;overflow-y:hidden;max-height:none;padding:8px 14px;margin:0 -14px 6px;background:color-mix(in srgb,var(--bg) 88%,transparent);backdrop-filter:blur(14px);-webkit-backdrop-filter:blur(14px);scrollbar-width:none}
  .side::-webkit-scrollbar{display:none}
  .side-item{flex:none;white-space:nowrap;border:1px solid var(--border);background:var(--surface);padding:6px 12px}
  .side-item .n{display:none}
  .side-item.active{border-color:transparent}
  .sec{scroll-margin-top:calc(var(--tb) + 60px)}
  .grid{grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:8px}
}
@media(max-width:420px){.grid{grid-template-columns:repeat(2,minmax(0,1fr))}.card{padding:9px 10px;gap:10px}}
`;

const HOME_JS = String.raw`
(function(){
var U=window.NavUI,esc=U.esc,hostOf=U.hostOf,norm=U.norm;
var D=window.__DATA__,cats=D.categories,links=D.links;
var $=function(s){return document.querySelector(s)};
var side=$('#side'),main=$('#main'),input=$('#q'),stage=$('#stage'),fbtn=$('#focusBtn');
var q='',active=null,lock=0;
var TOP_N=8,clicks=window.__CLICKS__||{},byId={};
links.forEach(function(l){byId[l.id]=l});
function topLinks(){
  return links.filter(function(l){return clicks[l.id]>0})
    .sort(function(a,b){return clicks[b.id]-clicks[a.id]})
    .slice(0,TOP_N);
}

function visible(l,c){
  if(!q)return true;
  return norm(l.title+' '+l.desc+' '+hostOf(l.url)+' '+c.name).indexOf(norm(q))!==-1;
}
function card(l,mark){
  return '<a class="card'+(mark?' first':'')+'" data-id="'+esc(l.id)+'" href="'+esc(l.url)+'" target="_blank" rel="noopener noreferrer"'+(l.desc?' title="'+esc(l.desc)+'"':'')+'>'+
    U.icon(l)+'<span class="txt"><span class="t">'+esc(l.title)+'</span>'+(l.desc?'<span class="d">'+esc(l.desc)+'</span>':'')+'</span></a>';
}
function render(){
  if(!links.length){
    side.innerHTML='';
    main.innerHTML='<div class="empty">还没有链接。<a href="/admin">去管理页添加</a></div>';
    return;
  }
  var sideH='',mainH='',total=0,marked=false;
  var top=q?[]:topLinks();
  if(top.length){
    total+=top.length;
    sideH+='<a class="side-item" href="#cat-__top" data-cat="__top"><span class="nm">⭐ 常用网站</span><span class="n">'+top.length+'</span></a>';
    mainH+='<section class="sec" id="cat-__top" data-cat="__top"><h2>⭐ 常用网站<span class="cnt">近期常用</span></h2><div class="grid">'+
      top.map(function(l){return card(l,false)}).join('')+'</div></section>';
  }
  cats.forEach(function(c){
    var items=links.filter(function(l){return l.cat===c.id&&visible(l,c)});
    if(!items.length)return;
    total+=items.length;
    sideH+='<a class="side-item" href="#cat-'+esc(c.id)+'" data-cat="'+esc(c.id)+'"><span class="nm">'+esc(c.name)+'</span><span class="n">'+items.length+'</span></a>';
    mainH+='<section class="sec" id="cat-'+esc(c.id)+'" data-cat="'+esc(c.id)+'"><h2>'+esc(c.name)+'<span class="cnt">'+items.length+'</span></h2><div class="grid">'+
      items.map(function(l){var m=q&&!marked;marked=true;return card(l,m)}).join('')+'</div></section>';
  });
  side.innerHTML=sideH;
  main.innerHTML=total?mainH:'<div class="empty">没有匹配的链接</div>';
  fixPad();active=null;spy();
}
/* 底部补足留白，保证最后一个分类也能滚动到顶部（否则点击靠后的分类时页面滚不动） */
function fixPad(){
  var secs=main.querySelectorAll('.sec');
  if(!secs.length){main.style.paddingBottom='';return}
  var last=secs[secs.length-1],foot=document.querySelector('.footer');
  var off=parseFloat(getComputedStyle(last).scrollMarginTop)||72;
  var need=window.innerHeight-off-last.offsetHeight-(foot?foot.offsetHeight+20:0);
  main.style.paddingBottom=Math.max(0,Math.ceil(need))+'px';
}
window.addEventListener('resize',fixPad);
function keepVisible(el){
  if(!el)return;
  if(getComputedStyle(side).flexDirection==='row'){
    side.scrollTo({left:el.offsetLeft-side.clientWidth/2+el.offsetWidth/2,behavior:'smooth'});
  }else{
    var top=el.offsetTop,bot=top+el.offsetHeight;
    if(top<side.scrollTop)side.scrollTop=top-8;
    else if(bot>side.scrollTop+side.clientHeight)side.scrollTop=bot-side.clientHeight+8;
  }
}
function setActive(id){
  if(id===active)return;
  active=id;
  var cur=null;
  side.querySelectorAll('.side-item').forEach(function(a){
    var on=a.getAttribute('data-cat')===id;
    a.classList.toggle('active',on);
    if(on)cur=a;
  });
  keepVisible(cur);
}
function spy(){
  if(Date.now()<lock)return;
  var secs=main.querySelectorAll('.sec');
  if(!secs.length)return;
  var cur=secs[0].getAttribute('data-cat');
  var off=60+24;
  for(var i=0;i<secs.length;i++){
    if(secs[i].getBoundingClientRect().top<=off)cur=secs[i].getAttribute('data-cat');
  }
  if(window.innerHeight+window.scrollY>=document.documentElement.scrollHeight-2)cur=secs[secs.length-1].getAttribute('data-cat');
  setActive(cur);
}
var ticking=false;
window.addEventListener('scroll',function(){
  if(ticking)return;ticking=true;
  requestAnimationFrame(function(){ticking=false;spy()});
},{passive:true});

side.addEventListener('click',function(e){
  var a=e.target.closest('.side-item');if(!a)return;
  e.preventDefault();
  var id=a.getAttribute('data-cat'),sec=document.getElementById('cat-'+id);
  if(!sec)return;
  lock=Date.now()+800;
  setActive(id);
  sec.scrollIntoView({behavior:'smooth',block:'start'});
});
/* 点击统计：先记在本机，每小时汇总上报一次（节省 KV 写入） */
var PEND_KEY='nav:pending',LAST_KEY='nav:lastReport',REPORT_MS=3600000;
var memPend={},memLast=0;
function lsGet(k){try{return localStorage.getItem(k)}catch(e){return null}}
function lsSet(k,v){try{localStorage.setItem(k,v);return true}catch(e){return false}}
function readPend(){
  var raw=lsGet(PEND_KEY);
  if(raw===null)return memPend;
  try{var o=JSON.parse(raw);return o&&typeof o==='object'?o:{}}catch(e){return {}}
}
function writePend(o){if(!lsSet(PEND_KEY,JSON.stringify(o)))memPend=o}
function lastReport(){var v=parseInt(lsGet(LAST_KEY),10);return isNaN(v)?memLast:v}
function setLast(t){memLast=t;lsSet(LAST_KEY,String(t))}
function addPend(o,id,n){o[id]=(o[id]||0)+n}
function flush(force){
  var now=Date.now(),prev=lastReport();
  if(!force&&now-prev<REPORT_MS)return;
  var take=readPend();
  if(!Object.keys(take).length)return;
  writePend({});setLast(now); /* 先清空并记下时间，避免多个标签页重复上报 */
  var ok=false;
  try{
    fetch('/click',{method:'POST',body:JSON.stringify(take),keepalive:true,credentials:'same-origin',headers:{'Content-Type':'application/json'}})
      .then(function(r){if(!r.ok)throw 0})
      .catch(function(){ /* 失败：放回去，下次再报 */
        var cur=readPend();Object.keys(take).forEach(function(k){addPend(cur,k,take[k])});
        writePend(cur);setLast(prev);
      });
    ok=true;
  }catch(e){}
  if(!ok){var cur=readPend();Object.keys(take).forEach(function(k){addPend(cur,k,take[k])});writePend(cur);setLast(prev)}
}
function bump(id){
  if(!id||!byId[id])return;
  clicks[id]=(clicks[id]||0)+1; /* 本机榜单立即生效 */
  var p=readPend();addPend(p,id,1);writePend(p);
  flush(false);
}
/* 把本机尚未上报的点击叠加到服务器给的分数上，保证本机榜单不滞后 */
(function(){var p=readPend();Object.keys(p).forEach(function(k){if(byId[k])clicks[k]=(clicks[k]||0)+p[k]})})();
function track(e){
  if(e.button===2)return;
  var a=e.target.closest('a[data-id]');if(!a)return;
  bump(a.getAttribute('data-id'));
}
main.addEventListener('click',track);
stage.addEventListener('click',track);
stage.addEventListener('auxclick',function(e){if(e.button===1)track(e)});
main.addEventListener('auxclick',function(e){if(e.button===1)track(e)});
flush(false); /* 打开页面时若已满一小时，顺便上报上次没报的 */
setInterval(function(){flush(false)},300000); /* 页面一直开着时，每 5 分钟检查是否满一小时 */
document.addEventListener('visibilitychange',function(){if(document.visibilityState==='hidden')flush(false)});
input.addEventListener('input',function(){q=input.value.trim();render()});
document.addEventListener('keydown',function(e){
  var tag=(document.activeElement&&document.activeElement.tagName)||'';
  if(e.key==='/'&&tag!=='INPUT'&&tag!=='TEXTAREA'){e.preventDefault();if(focusOn())setFocus(false);input.focus();input.select()}
  else if(e.key==='Escape'&&document.activeElement===input){input.value='';q='';render();input.blur()}
  else if(e.key==='Enter'&&document.activeElement===input&&q){
    var first=main.querySelector('.card');
    if(first){
      bump(first.getAttribute('data-id'));
      window.open(first.getAttribute('href'),'_blank','noopener');
    }
  }
});
/* ---------- 聚焦模式 ---------- */
var fIndex=0,fCap=1,fPages=0,fWheel=0,fItems=[],fS=100,fMouse=null,fRaf=0;
function focusOn(){return document.documentElement.classList.contains('focus')}
/* 按分数降序；分数相同保持原有的分类 / 链接顺序 */
function rankedLinks(){
  var order=[];
  cats.forEach(function(c){links.forEach(function(l){if(l.cat===c.id)order.push(l)})});
  return order.map(function(l,i){return {l:l,i:i}})
    .sort(function(a,b){return (clicks[b.l.id]||0)-(clicks[a.l.id]||0)||a.i-b.i})
    .map(function(x){return x.l});
}
function buildFocus(first){
  var list=rankedLinks();
  if(!list.length){stage.innerHTML='<div class="empty">还没有链接。<a href="/admin">去管理页添加</a></div>';return}
  var sw=stage.clientWidth,sh=stage.clientHeight;
  var W=sw-80,H=sh-48,gap=W<520?10:14,base=W<520?96:112;
  var cols=Math.max(1,Math.floor((W+gap)/(base+gap))),rows=Math.max(1,Math.floor((H+gap)/(base+gap)));
  var s=Math.max(56,Math.floor(Math.min((W-(cols-1)*gap)/cols,(H-(rows-1)*gap)/rows,150)));
  var ox=(sw-(cols*s+(cols-1)*gap))/2,oy=(sh-(rows*s+(rows-1)*gap))/2;
  var cap=cols*rows,n=Math.ceil(list.length/cap);
  if(first!=null)fIndex=Math.floor(first/cap); /* 窗口大小变化后，尽量停留在原来看的那几个网站 */
  /* 第一屏：格子按到中心的距离排序（距离相同时从正上方起顺时针），点击最多的放正中心 */
  var cx=(cols-1)/2,cy=(rows-1)/2,spiral=[];
  for(var i=0;i<cap;i++){
    var dx=i%cols-cx,dy=Math.floor(i/cols)-cy;
    spiral.push({i:i,d:Math.round(Math.sqrt(dx*dx+dy*dy)*1e6),a:(Math.atan2(dx,-dy)+2*Math.PI)%(2*Math.PI)});
  }
  spiral.sort(function(a,b){return a.d-b.d||a.a-b.a});
  var h='',meta=[];
  for(var p=0;p<n;p++){
    h+='<div class="fpage" style="top:'+(p*100)+'%">';
    meta[p]=[];
    list.slice(p*cap,(p+1)*cap).forEach(function(l,k){
      var cell=p===0?spiral[k].i:k;
      meta[p].push({cx:ox+(cell%cols)*(s+gap)+s/2,cy:oy+Math.floor(cell/cols)*(s+gap)+s/2});
      h+='<a class="fcard" data-id="'+esc(l.id)+'" href="'+esc(l.url)+'" target="_blank" rel="noopener noreferrer" title="'+esc(l.title)+'" style="width:'+s+'px;height:'+s+'px;left:'+(ox+(cell%cols)*(s+gap))+'px;top:'+(oy+Math.floor(cell/cols)*(s+gap))+'px">'+
        U.icon(l)+'<span class="fn">'+esc(l.title)+'</span></a>';
    });
    h+='</div>';
  }
  var dots='';
  if(n>1)for(var d=0;d<n;d++)dots+='<button class="dot" type="button" data-i="'+d+'" aria-label="第 '+(d+1)+' 屏"></button>';
  stage.style.setProperty('--ico',Math.round(s*.38)+'px');
  stage.innerHTML='<div class="track">'+h+'</div>'+(n>1?'<div class="dots">'+dots+'</div>':'');
  fCap=cap;fPages=n;fS=s;
  fitNames();
  if(document.fonts&&document.fonts.ready)document.fonts.ready.then(fitNames);
  fItems=[];
  var pgEls=stage.querySelectorAll('.fpage');
  for(var q=0;q<n;q++){
    var kids=pgEls[q].children;
    fItems[q]=meta[q].map(function(m,i){m.el=kids[i];return m});
  }
  goTo(Math.min(fIndex,n-1),true);
}
/* 金属高光：扫光随鼠标水平位置移动，鼠标靠近的卡片出现点光源高光（只改光泽，不缩放、不模糊） */
function applyLens(){
  var items=fItems[fIndex];if(!items)return;
  var R=fS*3,sw=stage.clientWidth;
  for(var i=0;i<items.length;i++){
    var m=items[i],el=m.el,li=0;
    if(fMouse){
      var dx=m.cx-fMouse.x,dy=m.cy-fMouse.y,tl=Math.max(0,1-Math.sqrt(dx*dx+dy*dy)/R);li=tl*tl;
      el.style.setProperty('--lx',(fMouse.x-(m.cx-fS/2))+'px');
      el.style.setProperty('--ly',(fMouse.y-(m.cy-fS/2))+'px');
      el.style.setProperty('--sx',(100-fMouse.x/Math.max(1,sw)*100).toFixed(1)+'%');
    }
    el.style.setProperty('--li',li.toFixed(3));
  }
}
function lensSoon(){if(!fRaf)fRaf=requestAnimationFrame(function(){fRaf=0;applyLens()})}
stage.addEventListener('pointermove',function(e){
  if(e.pointerType==='touch')return;
  var r=stage.getBoundingClientRect();fMouse={x:e.clientX-r.left,y:e.clientY-r.top};lensSoon();
});
stage.addEventListener('pointerleave',function(){fMouse=null;lensSoon()});
/* 名称太长就缩小字号，让它在一行内放得下（最小 9px，再长就显示省略号） */
function fitNames(){
  var els=stage.querySelectorAll('.fn');
  for(var i=0;i<els.length;i++){
    var el=els[i];el.style.fontSize='';
    var cw=el.clientWidth,sw=el.scrollWidth;
    if(cw>0&&sw>cw){
      var base=parseFloat(getComputedStyle(el).fontSize)||13;
      el.style.fontSize=Math.max(9,Math.floor(base*cw/sw*2)/2)+'px';
    }
  }
}
function goTo(i,instant){
  i=Math.max(0,Math.min(fPages-1,i));fIndex=i;
  var t=stage.querySelector('.track');
  if(t){
    if(instant){t.style.transition='none'}
    t.style.transform='translateY(-'+(i*100)+'%)';
    if(instant){t.offsetHeight;t.style.transition=''}
  }
  stage.querySelectorAll('.dot').forEach(function(b,k){b.classList.toggle('on',k===i)});
  lensSoon();
}
function setFocus(on){
  document.documentElement.classList.toggle('focus',on);
  fbtn.classList.toggle('on',on);fbtn.setAttribute('aria-pressed',on?'true':'false');
  try{localStorage.setItem('nav:focus',on?'1':'0')}catch(e){}
  if(on){fIndex=0;buildFocus()}else{render()}
}
fbtn.addEventListener('click',function(){setFocus(!focusOn())});
stage.addEventListener('click',function(e){var b=e.target.closest('.dot');if(b)goTo(parseInt(b.getAttribute('data-i'),10))});
stage.addEventListener('wheel',function(e){
  e.preventDefault();
  var now=Date.now();if(now<fWheel||Math.abs(e.deltaY)<8)return;
  fWheel=now+450;goTo(fIndex+(e.deltaY>0?1:-1));
},{passive:false});
var ty=null;
stage.addEventListener('touchstart',function(e){ty=e.touches[0].clientY},{passive:true});
stage.addEventListener('touchend',function(e){
  if(ty===null)return;var dy=e.changedTouches[0].clientY-ty;ty=null;
  if(Math.abs(dy)>50)goTo(fIndex+(dy<0?1:-1));
},{passive:true});
document.addEventListener('keydown',function(e){
  if(!focusOn())return;
  var tag=(document.activeElement&&document.activeElement.tagName)||'';
  if(tag==='INPUT'||tag==='TEXTAREA')return;
  var k=e.key;
  if(k==='ArrowDown'||k==='ArrowRight'||k==='PageDown'){e.preventDefault();goTo(fIndex+1)}
  else if(k==='ArrowUp'||k==='ArrowLeft'||k==='PageUp'){e.preventDefault();goTo(fIndex-1)}
  else if(k==='Home'){e.preventDefault();goTo(0)}
  else if(k==='End'){e.preventDefault();goTo(fPages-1)}
  else if(k==='Escape'){setFocus(false)}
});
var rz;
window.addEventListener('resize',function(){
  clearTimeout(rz);
  rz=setTimeout(function(){if(focusOn())buildFocus(fIndex*fCap)},120);
});

render();
if(focusOn()){fbtn.classList.add('on');fbtn.setAttribute('aria-pressed','true');buildFocus()}
})();`;

function homePage(data, title, authed, clicks) {
    const year = new Date().getFullYear();
    return `<!DOCTYPE html>
<html lang="zh-CN" data-theme="dark">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>${escapeHtml(title)}</title>
${FAVICON_LINK}
${THEME_INIT}
<script>try{if(localStorage.getItem('nav:focus')==='1')document.documentElement.classList.add('focus')}catch(e){}</script>
<style>
${BASE_CSS}
${HOME_CSS}
</style>
</head>
<body>
<header class="topbar"><div class="tb-in">
    <div class="brand"><div class="mark"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2 4 7v10l8 5 8-5V7z"/><path d="M12 22V12M4 7l8 5 8-5"/></svg></div><span class="bt">${escapeHtml(title)}</span></div>
    <label class="search">
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5"/></svg>
      <input class="input" id="q" type="search" placeholder="搜索名称、描述、网址…" autocomplete="off">
      <span class="kbd">/</span>
    </label>
    <span class="tb-sp"></span>
    ${THEME_BTN}
    <button class="icon-btn" id="focusBtn" type="button" aria-label="聚焦模式" aria-pressed="false" title="聚焦模式"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M8 3H5a2 2 0 0 0-2 2v3M21 8V5a2 2 0 0 0-2-2h-3M3 16v3a2 2 0 0 0 2 2h3M16 21h3a2 2 0 0 0 2-2v-3"/><circle cx="12" cy="12" r="3"/></svg></button>
    <a class="icon-btn" href="/admin" title="管理" aria-label="管理"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 6h10M18 6h2M4 12h2M10 12h10M4 18h12M20 18h0"/><circle cx="16" cy="6" r="2"/><circle cx="8" cy="12" r="2"/><circle cx="18" cy="18" r="2"/></svg></a>
    ${authed ? '<a class="icon-btn" href="/logout" title="退出登录" aria-label="退出登录"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><path d="m16 17 5-5-5-5M21 12H9"/></svg></a>' : ''}
  </div></header>

<div class="page">
  <div class="layout">
    <nav class="side" id="side" aria-label="分类"></nav>
    <main class="main" id="main"></main>
  </div>
  <footer class="footer">© ${year} ${escapeHtml(title)}</footer>
</div>
<div class="stage" id="stage" aria-label="聚焦模式"></div>
<script>window.__DATA__=${safeJson(data)};window.__CLICKS__=${safeJson(clicks || {})};</script>
<script>${COMMON_JS}</script>
<script>${HOME_JS}</script>
<script>${THEME_JS}</script>
</body>
</html>`;
}

// ============================================================
//  管理后台：左侧分类，右侧该分类的链接
// ============================================================
const ADMIN_CSS = `
:root{--mw:1100px}
.page{position:relative;z-index:1;max-width:1100px;margin:0 auto;padding:0 20px 60px}
.topbar h1{font-size:18px;font-weight:650;letter-spacing:-.01em;flex:1}
.back{display:inline-flex;align-items:center;gap:6px;color:var(--muted);font-size:14px;flex:none}
.back:hover{color:var(--text)}
.save{font-size:12px;color:var(--faint);min-width:56px;text-align:right}
.save.saving{color:var(--warn)}.save.saved{color:var(--ok)}.save.error{color:var(--bad)}
.amain{display:grid;grid-template-columns:260px minmax(0,1fr);gap:18px;align-items:start;margin-top:8px}
.apanel{min-width:0;background:var(--surface);border:1px solid var(--border);border-radius:16px;padding:14px}
.cats-panel{position:sticky;top:calc(var(--tb) + 8px);max-height:calc(100vh - var(--tb) - 24px);overflow-y:auto}
.ph{display:flex;align-items:center;justify-content:space-between;gap:10px;margin-bottom:10px}
.ph .ttl{font-size:13px;font-weight:600;color:var(--muted)}
.ph h2{font-size:17px;font-weight:650;display:inline-block;margin-right:8px;vertical-align:middle}
.pane-head{display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:12px}
.pane-head .ttlbox{flex:1;min-width:140px;display:flex;align-items:center;gap:8px}
.pane-head h2{font-size:17px;font-weight:650;min-width:0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.pane-head .chip{flex:none}
.rt{min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.r-name .chip{flex:none}
.pane-head .input{width:210px;height:36px}
.hint{color:var(--faint);font-size:12px;margin-top:10px}
.crow{display:flex;align-items:center;gap:6px;padding:8px 6px;border-radius:10px;cursor:pointer;border:1px solid transparent;transition:background .12s}
.crow:hover{background:var(--surface2)}
.crow.active{background:var(--accent-soft);color:var(--accent)}
.crow .cn{flex:1;min-width:0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;font-size:14px;font-weight:500}
.crow .cc{font-size:12px;color:var(--faint)}
.crow .cact{display:none;gap:2px}
.crow:hover .cact{display:flex}
@media(hover:none){.crow .cact{display:flex}}
.crow.over{outline:2px solid var(--accent);outline-offset:-2px;background:var(--accent-soft)}
.grip{color:var(--faint);cursor:grab;user-select:none;font-size:15px;line-height:1;padding:4px 2px;letter-spacing:-2px;flex:none}
.grip.off{opacity:.25;cursor:not-allowed}
.mini{width:26px;height:26px;border-radius:7px;border:none;background:none;color:var(--muted);display:inline-flex;align-items:center;justify-content:center}
.mini:hover{background:var(--surface);color:var(--text)}.mini.danger:hover{color:var(--bad)}
.list{display:flex;flex-direction:column;gap:8px}
.row{display:flex;align-items:center;gap:12px;padding:10px 12px;background:var(--surface);border:1px solid var(--border);border-radius:12px;transition:border-color .15s,opacity .15s}
.row:hover{border-color:var(--border-strong)}
.row.dragging,.crow.dragging{opacity:.4}
.row.over{border-color:var(--accent);box-shadow:0 -2px 0 var(--accent)}
.r-main{flex:1;min-width:0}
.r-name{font-weight:600;font-size:14px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;display:flex;align-items:center;gap:8px}
.r-sub{color:var(--faint);font-size:12px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.r-act{display:flex;gap:6px;flex:none}
.r-act .icon-btn{width:34px;height:34px}
.r-act .icon-btn.danger:hover{color:var(--bad);border-color:var(--bad)}
.empty{text-align:center;color:var(--faint);padding:56px 0;border:1px dashed var(--border);border-radius:12px}

.backdrop{position:fixed;inset:0;z-index:50;background:rgba(0,0,0,.55);backdrop-filter:blur(3px);display:none;align-items:center;justify-content:center;padding:16px}
.backdrop.open{display:flex}
.modal{width:100%;max-width:540px;max-height:92vh;overflow:auto;background:var(--surface);border:1px solid var(--border);border-radius:18px;box-shadow:var(--shadow);animation:pop .18s ease}
@keyframes pop{from{opacity:0;transform:scale(.97) translateY(6px)}to{opacity:1;transform:none}}
.m-head{padding:18px 20px 6px}
.m-head h2{font-size:17px;font-weight:650}
.m-body{padding:10px 20px 6px;display:grid;grid-template-columns:1fr 1fr;gap:14px}
.m-body .full{grid-column:1/-1}
.m-foot{display:flex;justify-content:flex-end;gap:10px;padding:14px 20px 18px}
.f label{display:block;font-size:12px;font-weight:500;color:var(--muted);margin-bottom:6px}
.f .opt-label{color:var(--faint);font-weight:400}
.rel{position:relative}
.ins-btn{position:absolute;right:5px;top:50%;transform:translateY(-50%);width:34px;height:30px;border-radius:8px;border:1px solid var(--border);background:var(--surface2);color:var(--text);font-size:20px;font-weight:700;line-height:1;display:flex;align-items:center;justify-content:center;transition:.15s}
.ins-btn:hover{border-color:var(--accent);color:var(--accent)}
.icon-edit{display:flex;gap:14px;align-items:center;padding:12px;border:1px dashed var(--border-strong);border-radius:12px;transition:.15s}
.icon-edit.drag{border-color:var(--accent);background:var(--accent-soft)}
.big .ico{width:56px;height:56px;border-radius:14px}
.big .ico-fb{font-size:22px}
.ie-actions{display:flex;flex-wrap:wrap;gap:8px;align-items:center}
.ie-actions .hint{flex-basis:100%;margin:0}
.ai-row{display:flex;align-items:center;gap:10px;margin-top:8px}
.ai-row[hidden],#aiBatch[hidden]{display:none}
.ai-row .hint{margin:0}
.toasts{position:fixed;left:50%;bottom:24px;transform:translateX(-50%);z-index:100;display:flex;flex-direction:column;gap:8px;align-items:center}
.toast{padding:10px 16px;border-radius:10px;background:var(--text);color:var(--bg);font-size:14px;box-shadow:var(--shadow);animation:pop .18s ease}
.toast.error{background:var(--bad);color:#fff}
@media(max-width:820px){
  .page{padding:0 14px 60px}
  .amain{grid-template-columns:minmax(0,1fr)}
  .cats-panel{position:static;max-height:none}
  .pane-head .input{width:100%;order:3}
  .m-body{grid-template-columns:minmax(0,1fr)}
}
`;

const ADMIN_JS = String.raw`
(function(){
var U=window.NavUI,esc=U.esc,hostOf=U.hostOf,norm=U.norm;
var $=function(s){return document.querySelector(s)};
var data={categories:[],links:[]},cur=null,q='',editing=null,catEditing=null,formIcon='';
var dragLink=null,dragCat=null;
var SVG_EDIT='<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 20h9"/><path d="M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4z"/></svg>';
var SVG_TRASH='<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 6h18"/><path d="M8 6V4h8v2"/><path d="M19 6l-1 14H6L5 6"/><path d="M10 11v6M14 11v6"/></svg>';

function rid(n){var a=new Uint8Array(n),s='';crypto.getRandomValues(a);for(var i=0;i<n;i++)s+=('0'+a[i].toString(16)).slice(-2);return s}
function toast(msg,type){
  var el=document.createElement('div');el.className='toast'+(type==='error'?' error':'');el.textContent=msg;
  $('#toasts').appendChild(el);setTimeout(function(){el.remove()},type==='error'?4500:2000);
}
function api(method,url,body,raw){
  var opt={method:method,headers:{}};
  if(raw){opt.body=raw.body;opt.headers['Content-Type']=raw.type}
  else if(body){opt.body=JSON.stringify(body);opt.headers['Content-Type']='application/json'}
  return fetch(url,opt).then(function(r){return r.json().catch(function(){return {}}).then(function(d){
    if(!r.ok)throw new Error(d.error||('HTTP '+r.status));return d;
  })});
}
function setSave(st){var el=$('#saveState');el.className='save '+st;el.textContent=st==='saving'?'保存中…':st==='error'?'保存失败':'已保存'}
var chain=Promise.resolve();
function save(){
  setSave('saving');
  var body=JSON.parse(JSON.stringify(data));
  chain=chain.then(function(){return api('PUT','/api/data',body)})
    .then(function(){setSave('saved')})
    .catch(function(e){setSave('error');toast(e.message,'error');return load()});
  return chain;
}
function load(){
  return api('GET','/api/data').then(function(d){
    data=d;
    if(!cur||!data.categories.some(function(c){return c.id===cur}))cur=data.categories[0].id;
    render();
  }).catch(function(e){toast(e.message,'error')});
}

function catOf(id){return data.categories.filter(function(c){return c.id===id})[0]}
function linkOf(id){return data.links.filter(function(l){return l.id===id})[0]}
function countOf(id){return data.links.filter(function(l){return l.cat===id}).length}
function lastIndexOfCat(id){for(var i=data.links.length-1;i>=0;i--)if(data.links[i].cat===id)return i;return -1}
function moveLinkToCat(link,catId){
  data.links.splice(data.links.indexOf(link),1);
  link.cat=catId;
  data.links.splice(lastIndexOfCat(catId)+1,0,link);
}

/* ---------- 渲染 ---------- */
function render(){renderCats();renderLinks()}
function renderCats(){
  $('#cats').innerHTML=data.categories.map(function(c){
    return '<div class="crow'+(c.id===cur&&!q?' active':'')+'" data-id="'+esc(c.id)+'" draggable="true">'+
      '<span class="grip" title="拖动排序">⋮⋮</span><span class="cn">'+esc(c.name)+'</span><span class="cc">'+countOf(c.id)+'</span>'+
      '<span class="cact"><button class="mini" data-act="rename" title="重命名" aria-label="重命名">'+SVG_EDIT+'</button>'+
      (data.categories.length>1?'<button class="mini danger" data-act="delcat" title="删除分类" aria-label="删除分类">'+SVG_TRASH+'</button>':'')+'</span></div>';
  }).join('');
}
function renderLinks(){
  var searching=!!q,nq=norm(q),c=catOf(cur);
  var list=searching
    ?data.links.filter(function(l){var cc=catOf(l.cat);return norm(l.title+' '+l.desc+' '+l.url+' '+(cc?cc.name:'')).indexOf(nq)!==-1})
    :data.links.filter(function(l){return l.cat===cur});
  $('#paneTitle').textContent=searching?'搜索结果':(c?c.name:'');
  $('#paneCount').textContent=list.length+' 个链接';
  if(!list.length){
    $('#links').innerHTML='<div class="empty">'+(searching?'没有匹配的链接':'这个分类下还没有链接')+'</div>';
    return;
  }
  $('#links').innerHTML=list.map(function(l){
    var cc=catOf(l.cat);
    return '<div class="row" data-id="'+esc(l.id)+'" draggable="'+(searching?'false':'true')+'">'+
      '<span class="grip'+(searching?' off':'')+'" title="'+(searching?'搜索时无法排序':'拖动排序，或拖到左侧分类')+'">⋮⋮</span>'+
      U.icon(l)+
      '<div class="r-main"><div class="r-name"><span class="rt">'+esc(l.title)+'</span>'+(searching&&cc?'<span class="chip">'+esc(cc.name)+'</span>':'')+'</div>'+
      '<div class="r-sub">'+esc(l.desc?l.desc+' · ':'')+esc(hostOf(l.url))+'</div></div>'+
      '<div class="r-act"><button class="icon-btn" data-act="edit" title="编辑" aria-label="编辑">'+SVG_EDIT+'</button>'+
      '<button class="icon-btn danger" data-act="del" title="删除" aria-label="删除">'+SVG_TRASH+'</button></div></div>';
  }).join('');
}

/* ---------- 拖拽：链接排序 / 移动分类 / 分类排序 ---------- */
function clearOver(){document.querySelectorAll('.over').forEach(function(x){x.classList.remove('over')})}
function endDrag(){
  dragLink=null;dragCat=null;clearOver();
  document.querySelectorAll('.dragging').forEach(function(x){x.classList.remove('dragging')});
}
function reorder(arr,a,b){
  var ia=arr.indexOf(a),ib=arr.indexOf(b);
  arr.splice(ia,1);
  var nb=arr.indexOf(b);
  arr.splice(ia<ib?nb+1:nb,0,a);
}
var linksEl=$('#links'),catsEl=$('#cats');
linksEl.addEventListener('dragstart',function(e){
  var r=e.target.closest('.row');if(!r||r.getAttribute('draggable')!=='true')return;
  dragLink=r.getAttribute('data-id');r.classList.add('dragging');
  e.dataTransfer.effectAllowed='move';try{e.dataTransfer.setData('text/plain',dragLink)}catch(x){}
});
linksEl.addEventListener('dragover',function(e){
  if(!dragLink)return;e.preventDefault();clearOver();
  var r=e.target.closest('.row');if(r&&r.getAttribute('data-id')!==dragLink)r.classList.add('over');
});
linksEl.addEventListener('drop',function(e){
  if(!dragLink)return;e.preventDefault();
  var r=e.target.closest('.row');
  if(r){
    var a=linkOf(dragLink),b=linkOf(r.getAttribute('data-id'));
    if(a&&b&&a!==b&&a.cat===b.cat){reorder(data.links,a,b);save()}
  }
  endDrag();render();
});
linksEl.addEventListener('dragend',function(){endDrag()});

catsEl.addEventListener('dragstart',function(e){
  var r=e.target.closest('.crow');if(!r)return;
  dragCat=r.getAttribute('data-id');r.classList.add('dragging');
  e.dataTransfer.effectAllowed='move';try{e.dataTransfer.setData('text/plain',dragCat)}catch(x){}
});
catsEl.addEventListener('dragover',function(e){
  if(!dragCat&&!dragLink)return;e.preventDefault();clearOver();
  var r=e.target.closest('.crow');if(r&&r.getAttribute('data-id')!==dragCat)r.classList.add('over');
});
catsEl.addEventListener('drop',function(e){
  e.preventDefault();
  var r=e.target.closest('.crow');
  if(r){
    var to=r.getAttribute('data-id');
    if(dragCat){
      var a=catOf(dragCat),b=catOf(to);
      if(a&&b&&a!==b){reorder(data.categories,a,b);save()}
    }else if(dragLink){
      var l=linkOf(dragLink);
      if(l&&l.cat!==to){moveLinkToCat(l,to);toast('已移动到「'+catOf(to).name+'」');save()}
    }
  }
  endDrag();render();
});
catsEl.addEventListener('dragend',function(){endDrag()});

/* ---------- 分类操作 ---------- */
catsEl.addEventListener('click',function(e){
  var row=e.target.closest('.crow');if(!row)return;
  var id=row.getAttribute('data-id'),b=e.target.closest('[data-act]');
  if(b){
    if(b.getAttribute('data-act')==='rename')openCatModal(id);
    else delCat(id);
    return;
  }
  cur=id;q='';$('#search').value='';render();
});
function delCat(id){
  var c=catOf(id),n=countOf(id);
  if(!c||data.categories.length<2)return;
  if(!confirm(n?'删除分类「'+c.name+'」及其中的 '+n+' 个链接？此操作不可撤销。':'删除分类「'+c.name+'」？'))return;
  data.categories=data.categories.filter(function(x){return x.id!==id});
  data.links=data.links.filter(function(l){return l.cat!==id});
  if(cur===id)cur=data.categories[0].id;
  render();save();toast('已删除分类');
}
function openCatModal(id){
  if(!id&&data.categories.length>=60){toast('分类最多 60 个','error');return}
  catEditing=id||null;
  $('#catTitle').textContent=id?'重命名分类':'新增分类';
  $('#catName').value=id?catOf(id).name:'';
  $('#catModal').classList.add('open');
  setTimeout(function(){var el=$('#catName');el.focus();el.select()},30);
}
function submitCat(){
  var name=$('#catName').value.trim().slice(0,24);
  if(!name){toast('请输入分类名称','error');return}
  var dup=data.categories.some(function(c){return c.id!==catEditing&&c.name.toLowerCase()===name.toLowerCase()});
  if(dup){toast('已有同名分类','error');return}
  if(catEditing){catOf(catEditing).name=name}
  else{var id=rid(3);data.categories.push({id:id,name:name});cur=id;q='';$('#search').value=''}
  $('#catModal').classList.remove('open');
  render();save();
}
$('#addCat').addEventListener('click',function(){openCatModal(null)});
$('#catSave').addEventListener('click',submitCat);
$('#catCancel').addEventListener('click',function(){$('#catModal').classList.remove('open')});
$('#catName').addEventListener('keydown',function(e){if(e.key==='Enter'){e.preventDefault();submitCat()}});

/* ---------- 链接操作 ---------- */
linksEl.addEventListener('click',function(e){
  var b=e.target.closest('[data-act]');if(!b)return;
  var id=b.closest('.row').getAttribute('data-id'),l=linkOf(id);if(!l)return;
  if(b.getAttribute('data-act')==='edit')openForm(id);
  else if(confirm('确认删除「'+l.title+'」？')){
    data.links.splice(data.links.indexOf(l),1);render();save();toast('已删除');
  }
});
$('#addLink').addEventListener('click',function(){openForm(null)});
$('#search').addEventListener('input',function(e){q=e.target.value.trim();render()});

/* ---------- 链接表单 ---------- */
function withScheme(u){u=String(u||'').trim();return u&&!/^[a-z][a-z0-9+.-]*:/i.test(u)?'https://'+u:u}
function updateIconPrev(){
  var t=$('#fTitle').value.trim()||'?',u=withScheme($('#fUrl').value);
  $('#iconPrev').innerHTML=U.icon({title:t,url:u,icon:formIcon});
  $('#iconAuto').disabled=!formIcon;
  $('#iconHint').textContent=formIcon?'已使用上传的图标':'未上传时自动获取网站图标，获取不到则显示首字母；也可把图片拖到这里或直接粘贴';
}
var pv;function schedulePrev(){clearTimeout(pv);pv=setTimeout(updateIconPrev,450)}
$('#fUrl').addEventListener('input',schedulePrev);
$('#fTitle').addEventListener('input',schedulePrev);

function openForm(id){
  editing=id||null;
  var l=id?linkOf(id):null;
  $('#formTitle').textContent=l?'编辑链接':'新增链接';
  $('#fUrl').value=l?l.url:'';
  $('#fTitle').value=l?l.title:'';
  $('#fDesc').value=l?l.desc:'';
  $('#fCat').innerHTML=data.categories.map(function(c){return '<option value="'+esc(c.id)+'">'+esc(c.name)+'</option>'}).join('');
  $('#fCat').value=l?l.cat:cur;
  formIcon=l?l.icon:'';
  updateIconPrev();
  $('#formModal').classList.add('open');
  setTimeout(function(){$(l?'#fTitle':'#fUrl').focus()},30);
}
function submitForm(){
  var url=withScheme($('#fUrl').value),title=$('#fTitle').value.trim(),desc=$('#fDesc').value.trim(),cat=$('#fCat').value;
  try{var p=new URL(url);if(!/^https?:$/.test(p.protocol))throw 0}catch(e){toast('请填写有效的网址','error');$('#fUrl').focus();return}
  if(!title){toast('请填写名称','error');$('#fTitle').focus();return}
  var wasEdit=!!editing;
  if(editing){
    var l=linkOf(editing);
    l.title=title;l.url=url;l.desc=desc;l.icon=formIcon;
    if(l.cat!==cat)moveLinkToCat(l,cat);
  }else{
    data.links.splice(lastIndexOfCat(cat)+1,0,{id:rid(5),title:title,url:url,desc:desc,cat:cat,icon:formIcon});
  }
  cur=cat;q='';$('#search').value='';
  $('#formModal').classList.remove('open');
  render();save();toast(wasEdit?'已更新':'已添加');
}
$('#formSave').addEventListener('click',submitForm);
$('#formCancel').addEventListener('click',function(){$('#formModal').classList.remove('open')});
$('#formModal').addEventListener('keydown',function(e){
  if(e.key==='Enter'&&e.target.tagName==='INPUT'){e.preventDefault();submitForm()}
});

/* 描述框：在光标处插入 " · " */
function insertDot(){
  var el=$('#fDesc'),v=el.value,s=el.selectionStart==null?v.length:el.selectionStart,e=el.selectionEnd==null?s:el.selectionEnd;
  var before=v.slice(0,s),after=v.slice(e);
  var ins=(before===''||/\s$/.test(before)?'':' ')+'·'+(/^\s/.test(after)?'':' ');
  var next=before+ins+after;
  if(el.maxLength>0&&next.length>el.maxLength)return;
  el.value=next;var pos=(before+ins).length;
  el.focus();try{el.setSelectionRange(pos,pos)}catch(x){}
}
$('#insDot').addEventListener('mousedown',function(e){e.preventDefault()});
$('#insDot').addEventListener('click',insertDot);
$('#fDesc').addEventListener('keydown',function(e){if(e.altKey&&(e.key==='.'||e.code==='Period')){e.preventDefault();insertDot()}});

/* ---------- 图标上传：浏览器端缩放为 128px PNG 再上传 ---------- */
function toPng(file,size){
  return new Promise(function(resolve,reject){
    var url=URL.createObjectURL(file),img=new Image();
    img.onload=function(){
      try{
        var c=document.createElement('canvas');c.width=c.height=size;
        var ctx=c.getContext('2d');
        var w=img.naturalWidth||img.width||size,h=img.naturalHeight||img.height||size;
        var s=Math.min(size/w,size/h),dw=w*s,dh=h*s;
        ctx.drawImage(img,(size-dw)/2,(size-dh)/2,dw,dh);
        c.toBlob(function(b){URL.revokeObjectURL(url);b?resolve(b):reject(new Error('图片转换失败'))},'image/png');
      }catch(e){URL.revokeObjectURL(url);reject(e)}
    };
    img.onerror=function(){URL.revokeObjectURL(url);reject(new Error('无法读取这个图片'))};
    img.src=url;
  });
}
function handleFile(file){
  if(!file||String(file.type).indexOf('image/')!==0){toast('请选择图片文件','error');return}
  if(file.size>8*1024*1024){toast('图片不能超过 8MB','error');return}
  $('#iconHint').textContent='处理中…';
  toPng(file,128).then(function(blob){return api('POST','/api/icon',null,{body:blob,type:'image/png'})})
    .then(function(r){formIcon=r.id;updateIconPrev()})
    .catch(function(e){toast(e.message,'error');updateIconPrev()});
}
$('#iconUpload').addEventListener('click',function(){$('#iconFile').click()});
$('#iconFile').addEventListener('change',function(){handleFile(this.files[0]);this.value=''});
$('#iconAuto').addEventListener('click',function(){formIcon='';updateIconPrev()});
var box=$('#iconBox');
box.addEventListener('dragover',function(e){e.preventDefault();box.classList.add('drag')});
box.addEventListener('dragleave',function(){box.classList.remove('drag')});
box.addEventListener('drop',function(e){e.preventDefault();box.classList.remove('drag');if(e.dataTransfer.files&&e.dataTransfer.files[0])handleFile(e.dataTransfer.files[0])});
$('#formModal').addEventListener('paste',function(e){
  var f=e.clipboardData&&e.clipboardData.files;
  if(f&&f.length&&String(f[0].type).indexOf('image/')===0){e.preventDefault();handleFile(f[0])}
});

/* ---------- 弹窗关闭 ---------- */
document.querySelectorAll('.backdrop').forEach(function(b){
  b.addEventListener('mousedown',function(e){if(e.target===b)b.classList.remove('open')});
});
document.addEventListener('keydown',function(e){
  if(e.key==='Escape')document.querySelectorAll('.backdrop.open').forEach(function(b){b.classList.remove('open')});
});

/* ---------- 导入书签（Netscape 书签 HTML：浏览器 / OneNav 导出） ---------- */
var parsedImp=null;
function impMode(){var e=document.querySelector('input[name=impMode]:checked');return e?e.value:'name'}
function urlKey(u){try{var p=new URL(u);return p.protocol+'//'+p.host.toLowerCase()+p.pathname.replace(/\/+$/,'')+p.search}catch(e){return u}}
function folderName(a){
  var dl=a.closest('dl');
  while(dl){
    var dt=dl.parentElement,h=null;
    if(dt&&dt.tagName==='DT'){for(var i=0;i<dt.children.length;i++)if(dt.children[i].tagName==='H3'){h=dt.children[i];break}}
    if(!h&&dl.previousElementSibling&&dl.previousElementSibling.tagName==='H3')h=dl.previousElementSibling;
    if(h&&!h.hasAttribute('personal_toolbar_folder')&&!h.hasAttribute('unfiled_bookmarks_folder')){
      var n=h.textContent.trim();if(n)return n.slice(0,24);
    }
    dl=dl.parentElement?dl.parentElement.closest('dl'):null;
  }
  return '未分类';
}
function hostName(url){
  var h=hostOf(url).toLowerCase().replace(/^www\./,''),l=h.split('.'),n=l[0];
  if(l.length>=2){
    var tld=l[l.length-1],sl=l[l.length-2];
    n=(l.length>=3&&tld.length===2&&/^(com|net|org|gov|edu|co|ac)$/.test(sl))?l[l.length-3]:sl;
  }
  return (n.charAt(0).toUpperCase()+n.slice(1)).slice(0,40);
}
function makeItem(text,url,mode){
  var t=String(text||'').replace(/\s+/g,' ').trim(),desc='';
  var m=t.match(/^(.+?)\s+[-–—|·]\s+(.+)$/);
  if(m){t=m[1].trim();desc=m[2].trim()}
  else if(mode==='desc'&&t){desc=t;t=hostName(url)}
  if(!t)t=hostName(url);
  return {title:t.slice(0,40),url:url,desc:desc.slice(0,80)};
}
function parseBookmarks(html){
  var doc=new DOMParser().parseFromString(html,'text/html');
  var as=doc.querySelectorAll('a[href]'),groups={},order=[],bad=0,total=0,plain=0;
  for(var i=0;i<as.length;i++){
    var href=(as[i].getAttribute('href')||'').trim();
    if(!/^https?:\/\//i.test(href)){bad++;continue}
    var url;try{url=new URL(href).href}catch(e){bad++;continue}
    var text=as[i].textContent||'';
    if(!/\s[-–—|·]\s/.test(text))plain++;
    var f=folderName(as[i]);
    if(!groups[f]){groups[f]=[];order.push(f)}
    groups[f].push({text:text,url:url});total++;
  }
  return {groups:groups,order:order,total:total,bad:bad,plain:plain};
}
function planImport(p,replace,mode){
  var cats=replace?[]:data.categories.slice(),links=replace?[]:data.links;
  var seen={},nLinks=links.length;
  links.forEach(function(l){seen[urlKey(l.url)]=1});
  var plan=[],added=0,dup=0,capped=0,catCount=cats.length;
  p.order.forEach(function(name){
    var ex=cats.filter(function(c){return c.name.toLowerCase()===name.toLowerCase()})[0];
    var items=[];
    p.groups[name].forEach(function(it){
      var k=urlKey(it.url);
      if(seen[k]){dup++;return}
      if(nLinks+items.length+added>=1000){capped++;return}
      seen[k]=1;items.push(makeItem(it.text,it.url,mode));
    });
    if(!items.length)return;
    if(!ex&&catCount>=60){capped+=items.length;return}
    if(!ex)catCount++;
    added+=items.length;
    plan.push({name:name,isNew:!ex,items:items});
  });
  return {plan:plan,added:added,dup:dup,capped:capped};
}
function renderImp(){
  var r=planImport(parsedImp,$('#impReplace').checked,impMode());
  $('#impSum').innerHTML='共识别 <b>'+parsedImp.total+'</b> 个链接，将导入 <b>'+r.added+'</b> 个'+
    (r.dup?'，跳过重复 '+r.dup+' 个':'')+(r.capped?'，超出上限 '+r.capped+' 个未导入':'')+(parsedImp.bad?'，忽略非网页链接 '+parsedImp.bad+' 个':'')+'。';
  $('#impList').innerHTML=r.plan.length?r.plan.map(function(g){
    return '<div style="display:flex;justify-content:space-between;gap:10px;padding:8px 0;border-bottom:1px solid var(--border);font-size:14px"><span style="min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">'+esc(g.name)+(g.isNew?' <span class="chip">新分类</span>':'')+'</span><span style="color:var(--muted);flex:none">'+g.items.length+' 个</span></div>';
  }).join(''):'<div class="empty" style="padding:18px 0">没有可导入的新链接</div>';
  $('#impGo').disabled=!r.added;
  return r;
}
function applyImport(){
  var replace=$('#impReplace').checked,r=planImport(parsedImp,replace,impMode());
  if(!r.added)return;
  if(replace){data.categories=[];data.links=[]}
  r.plan.forEach(function(g){
    var c=data.categories.filter(function(x){return x.name.toLowerCase()===g.name.toLowerCase()})[0];
    if(!c){c={id:rid(3),name:g.name};data.categories.push(c)}
    g.items.forEach(function(it){data.links.push({id:rid(5),title:it.title,url:it.url,desc:it.desc,cat:c.id,icon:''})});
  });
  if(!catOf(cur))cur=data.categories[0].id;
  q='';$('#search').value='';
  $('#impModal').classList.remove('open');
  render();save();toast('已导入 '+r.added+' 个链接');
}
$('#impBtn').addEventListener('click',function(){$('#impFile').click()});
$('#impFile').addEventListener('change',function(){
  var f=this.files&&this.files[0];this.value='';if(!f)return;
  if(f.size>5*1024*1024){toast('文件过大','error');return}
  f.text().then(function(txt){
    parsedImp=parseBookmarks(txt);
    if(!parsedImp.total){toast('没有识别到链接，请确认是书签 HTML 文件','error');return}
    $('#impReplace').checked=false;document.querySelector('input[name=impMode][value=name]').checked=true;$('#impModeBox').style.display=parsedImp.plain?'':'none';renderImp();$('#impModal').classList.add('open');
  }).catch(function(){toast('读取文件失败','error')});
});
$('#impReplace').addEventListener('change',renderImp);
document.querySelectorAll('input[name=impMode]').forEach(function(e){e.addEventListener('change',renderImp)});
$('#impCancel').addEventListener('click',function(){$('#impModal').classList.remove('open')});
$('#impGo').addEventListener('click',applyImport);

/* ---------- AI 生成描述（Workers AI） ---------- */
var AI_ON=document.body.getAttribute('data-ai')==='1';
if(AI_ON){$('#aiRow').hidden=false;$('#aiBatch').hidden=false}
function fullUrl(v){v=String(v||'').trim();return v&&!/^https?:\/\//i.test(v)?'https://'+v:v}
function aiDescribe(url,title){return api('POST','/api/describe',{url:url,title:title||''})}
$('#aiGen').addEventListener('click',function(){
  var url=fullUrl($('#fUrl').value);
  if(!url){toast('请先填写网址','error');return}
  var btn=this,hint=$('#aiHint');btn.disabled=true;btn.textContent='生成中…';hint.textContent='';
  aiDescribe(url,$('#fTitle').value).then(function(r){
    $('#fDesc').value=r.desc;
    if(!$('#fTitle').value.trim()&&r.name)$('#fTitle').value=r.name.slice(0,40);
    hint.textContent=r.guessed?'未能读取网页，仅凭域名推测，请核对':'';
  }).catch(function(e){toast(e.message,'error')})
    .then(function(){btn.disabled=false;btn.textContent='AI 生成描述'});
});
var aiRunning=false;
$('#aiBatch').addEventListener('click',function(){
  if(aiRunning)return;
  var todo=data.links.filter(function(l){return !l.desc}).map(function(l){return l.id});
  if(!todo.length){toast('所有链接都已有描述');return}
  if(!confirm('为 '+todo.length+' 个没有描述的链接生成描述？\n每个链接会抓取网页并调用一次 Workers AI（使用免费额度）。'))return;
  aiRunning=true;
  var btn=this,total=todo.length,done=0,ok=0,fail=0,guess=0,streak=0,lastErr='',i=0,stop=false;
  function tick(){btn.textContent='生成中 '+done+'/'+total}
  function worker(){
    if(stop||i>=todo.length)return Promise.resolve();
    var id=todo[i++],l=linkOf(id);
    if(!l)return worker();
    return aiDescribe(l.url,l.title).then(function(r){
      var x=linkOf(id);if(x&&!x.desc){x.desc=r.desc.slice(0,80);ok++;if(r.guessed)guess++}
      streak=0;
    }).catch(function(e){fail++;streak++;lastErr=e.message;if(streak>=3)stop=true})
      .then(function(){done++;tick();if(ok&&ok%5===0)save();return worker()});
  }
  tick();btn.disabled=true;
  Promise.all([worker(),worker()]).then(function(){
    aiRunning=false;btn.disabled=false;btn.textContent='AI 补全描述';
    if(ok){save();render()}
    var msg='已生成 '+ok+' 个描述'+(guess?'（其中 '+guess+' 个未能读取网页，请核对）':'')+(fail?'，失败 '+fail+' 个':'');
    toast(msg,fail&&!ok?'error':undefined);
    if(fail&&lastErr)setTimeout(function(){toast(lastErr,'error')},300);
  });
});

load();
})();`;

function adminPage(title, aiOn) {
    return `<!DOCTYPE html>
<html lang="zh-CN" data-theme="dark">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>管理 · ${escapeHtml(title)}</title>
${FAVICON_LINK}
${THEME_INIT}
<style>
${BASE_CSS}
${ADMIN_CSS}
</style>
</head>
<body data-ai="${aiOn ? '1' : ''}">
<header class="topbar"><div class="tb-in">
    <a class="back" href="/"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m15 18-6-6 6-6"/></svg>返回</a>
    <h1>管理</h1>
    <span class="save" id="saveState"></span>
    ${THEME_BTN}
    <a class="icon-btn" href="/logout" title="退出登录" aria-label="退出登录"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><path d="m16 17 5-5-5-5M21 12H9"/></svg></a>
  </div></header>

<div class="page">
  <div class="amain">
    <aside class="apanel cats-panel">
      <div class="ph"><span class="ttl">分类</span><span style="display:flex;gap:6px"><button class="btn btn-sm" id="impBtn" type="button" title="导入浏览器 / OneNav 导出的书签 HTML">导入</button><button class="btn btn-sm" id="addCat" type="button">＋ 新增</button></span></div>
      <input type="file" id="impFile" accept=".html,.htm,text/html" hidden>
      <div id="cats"></div>
      <div class="hint">拖动调整分类顺序；把右侧的链接拖到分类上即可移动。</div>
    </aside>
    <section class="apanel">
      <div class="pane-head">
        <div class="ttlbox"><h2 id="paneTitle"></h2><span class="chip" id="paneCount"></span></div>
        <input class="input" id="search" type="search" placeholder="搜索全部链接…" autocomplete="off">
        <button class="btn btn-sm" id="aiBatch" type="button" hidden title="为所有没有描述的链接用 AI 生成一句话描述">AI 补全描述</button>
        <button class="btn btn-primary" id="addLink" type="button">＋ 新增链接</button>
      </div>
      <div class="list" id="links"></div>
    </section>
  </div>
</div>

<!-- 新增/编辑链接 -->
<div class="backdrop" id="formModal">
  <div class="modal" role="dialog" aria-modal="true">
    <div class="m-head"><h2 id="formTitle">新增链接</h2></div>
    <div class="m-body">
      <div class="f full"><label>网址</label>
        <input class="input" id="fUrl" placeholder="https://example.com" autocomplete="off" inputmode="url">
      </div>
      <div class="f"><label>名称</label>
        <input class="input" id="fTitle" maxlength="40" placeholder="如 Excalidraw" autocomplete="off">
      </div>
      <div class="f"><label>分类</label>
        <select class="input" id="fCat"></select>
      </div>
      <div class="f full"><label>描述 <span class="opt-label">（可选）</span></label>
        <div class="rel">
          <input class="input" id="fDesc" placeholder="一句话说明" maxlength="80" autocomplete="off" style="padding-right:48px">
          <button type="button" class="ins-btn" id="insDot" title="在光标处插入分隔符 ·（快捷键 Alt+.）" aria-label="插入分隔符">·</button>
        </div>
        <div class="ai-row" id="aiRow" hidden><button class="btn btn-sm" id="aiGen" type="button">AI 生成描述</button><span class="hint" id="aiHint"></span></div>
      </div>
      <div class="f full"><label>图标</label>
        <div class="icon-edit" id="iconBox">
          <div class="big" id="iconPrev"></div>
          <div class="ie-actions">
            <button class="btn btn-sm" id="iconUpload" type="button">上传图标</button>
            <button class="btn btn-sm" id="iconAuto" type="button">使用网站图标</button>
            <div class="hint" id="iconHint"></div>
          </div>
          <input type="file" id="iconFile" accept="image/*" hidden>
        </div>
      </div>
    </div>
    <div class="m-foot">
      <button class="btn" id="formCancel" type="button">取消</button>
      <button class="btn btn-primary" id="formSave" type="button">保存</button>
    </div>
  </div>
</div>

<!-- 新增/重命名分类 -->
<div class="backdrop" id="catModal">
  <div class="modal" role="dialog" aria-modal="true" style="max-width:380px">
    <div class="m-head"><h2 id="catTitle">新增分类</h2></div>
    <div style="padding:10px 20px 4px"><input class="input" id="catName" maxlength="24" placeholder="如 办公工具" autocomplete="off"></div>
    <div class="m-foot">
      <button class="btn" id="catCancel" type="button">取消</button>
      <button class="btn btn-primary" id="catSave" type="button">保存</button>
    </div>
  </div>
</div>

<!-- 导入书签 -->
<div class="backdrop" id="impModal">
  <div class="modal" role="dialog" aria-modal="true" style="max-width:460px">
    <div class="m-head"><h2>导入书签</h2></div>
    <div style="padding:6px 20px 4px">
      <div id="impSum" style="font-size:14px"></div>
      <div id="impList" style="max-height:40vh;overflow:auto;margin:10px 0;border:1px solid var(--border);border-radius:10px;padding:2px 12px"></div>
      <div id="impModeBox" style="font-size:13px;color:var(--muted);margin-bottom:10px">
        <div style="margin-bottom:4px">没有「名称 - 描述」分隔符的书签文字，用作：</div>
        <label style="display:inline-flex;gap:6px;align-items:center;margin-right:16px;cursor:pointer"><input type="radio" name="impMode" value="name" checked>名称</label>
        <label style="display:inline-flex;gap:6px;align-items:center;cursor:pointer"><input type="radio" name="impMode" value="desc">描述（名称取自域名）</label>
      </div>
      <label style="display:flex;gap:8px;align-items:center;font-size:13px;color:var(--muted);cursor:pointer"><input type="checkbox" id="impReplace">导入前清空现有的分类和链接（替换）</label>
      <div class="hint">文件夹会变成分类，网址相同的链接自动跳过；「名称 - 描述」「名称 · 描述」会自动拆开；图标会自动使用网站图标，之后可再上传替换。</div>
    </div>
    <div class="m-foot">
      <button class="btn" id="impCancel" type="button">取消</button>
      <button class="btn btn-primary" id="impGo" type="button">导入</button>
    </div>
  </div>
</div>

<div class="toasts" id="toasts"></div>
<script>${COMMON_JS}</script>
<script>${ADMIN_JS}</script>
<script>${THEME_JS}</script>
</body>
</html>`;
}
