/**
 * edgy-sync v2: gateway + hosted browser app, in one Cloudflare Worker file.
 *
 * Paste this over the whole Worker code in the Cloudflare editor and click Deploy.
 * Secret needed: PROXY_TOKEN (your passphrase).
 * Optional: a KV namespace bound as THROTTLE (see the notes that came with this file).
 *
 * Routes
 *   /app                  the browser app (public page, but useless without the passphrase)
 *   /?u=<url>             the gateway (needs the passphrase header, or a signed ?k= key
 *                         that the Worker itself puts into pages it rewrites)
 *   /?ping=1              passphrase check used by the login screen
 *   /chat                 Claude chat page (uses the Claude API, needs the ANTHROPIC_API_KEY secret)
 *   /api/chat             its backend (needs the passphrase header)
 *   anything else         404
 *
 * Gateway behaviour
 *  - Fetches the target server-side; blocks localhost / private / metadata addresses and odd
 *    ports, re-checking every redirect hop.
 *  - GET, HEAD and POST (urlencoded, up to 2 MB). Cookies are never stored here: the app keeps
 *    its own jar and sends it in X-Proxy-Jar; the Worker applies it per hop and returns changes
 *    in X-Proxy-Cookies.
 *  - Rewrites HTML so images, CSS, fonts and media go through this Worker (rw=0 disables).
 *    Scripts and inline handlers are stripped unless js=1. Iframes/objects/embeds removed.
 *  - raw=1 returns HTML untouched (the Source view).
 *  - A GET answered with 403 is retried through Jina Reader (pages) or wsrv.nl (images).
 *    Optional secret JINA_API_KEY raises Jina's rate limit.
 *  - Repeated wrong passphrases from one IP are locked out for 15 minutes.
 */

const ENC = new TextEncoder();
const MAX_REDIRECTS = 5;
const MAX_BODY = 2 * 1024 * 1024;
const KEY_TTL_SECONDS = 3600;
const FAIL_LIMIT = 8;
const FAIL_WINDOW = 900; // seconds
const ALLOWED_PORTS = new Set(['', '80', '443', '8080', '8443']);
const UA =
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0';

// Subresources (fonts especially) are loaded cross-origin from the sandboxed page, so GETs
// need this. Preflights are not answered, so other sites cannot send the token header.
const ACAO = { 'Access-Control-Allow-Origin': '*' };

const SECURITY = {
  'Content-Security-Policy': 'sandbox',
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
};

const COPY_HEADERS = ['content-type', 'content-disposition', 'content-range', 'accept-ranges', 'last-modified'];

export default {
  async fetch(request, env) {
    try {
      return await handle(request, env);
    } catch (e) {
      return fail(502, 'Gateway error: ' + ((e && e.message) || e));
    }
  },
};

/* ───────────────────────────── main handler ───────────────────────────── */

async function handle(request, env) {
  const url = new URL(request.url);

  if (url.pathname === '/app' || url.pathname === '/app/') {
    return request.method === 'GET' ? serveApp() : new Response('Method not allowed', { status: 405 });
  }
  if (url.pathname === '/chat' || url.pathname === '/chat/') {
    return request.method === 'GET' ? serveChat() : new Response('Method not allowed', { status: 405 });
  }
  if (url.pathname === '/api/chat') return chatApi(request, url, env);
  if (url.pathname === '/robots.txt') {
    return new Response('User-agent: *\nDisallow: /\n', { headers: { 'Content-Type': 'text/plain' } });
  }
  if (url.pathname !== '/') return new Response('Not found', { status: 404 });

  if (!env.PROXY_TOKEN) return fail(500, 'PROXY_TOKEN is not configured on the Worker.');
  if (!['GET', 'HEAD', 'POST'].includes(request.method)) return fail(405, 'Method not allowed.');

  const rawTarget = url.searchParams.get('u');
  const auth = await authenticate(request, url, env);
  if (auth === 'locked') {
    return fail(429, 'Too many failed attempts. Try again in a few minutes.', { 'Retry-After': String(FAIL_WINDOW) });
  }
  if (auth !== 'ok') return rawTarget ? fail(401, 'Unauthorized.') : new Response('Not found', { status: 404 });
  if (!rawTarget) return new Response('ok', { status: 200, headers: { 'Content-Type': 'text/plain', 'Cache-Control': 'no-store' } });

  const target = parseTarget(rawTarget);
  if (!target) return fail(400, 'Blocked or invalid target URL.');

  let bodyBuf;
  if (request.method === 'POST') {
    const len = Number(request.headers.get('Content-Length') || 0);
    if (len > MAX_BODY) return fail(413, 'Request body too large.');
    bodyBuf = await request.arrayBuffer();
    if (bodyBuf.byteLength > MAX_BODY) return fail(413, 'Request body too large.');
  }

  const opts = {
    js: url.searchParams.get('js') === '1',
    rw: url.searchParams.get('rw') !== '0',
    raw: url.searchParams.get('raw') === '1',
  };

  const jar = parseJar(request.headers.get('X-Proxy-Jar'));
  const ref = request.headers.get('X-Proxy-Referer') || '';
  const up = await fetchUpstream(request, target, bodyBuf, jar, ref);
  const { final, changes } = up;
  let resp = up.resp;
  let via = '';

  // Some sites (BBC, for one) answer every Cloudflare Worker with 403 "Access Denied".
  // For GETs, retry through an outside fetcher: Jina Reader for pages, wsrv.nl for images.
  if (resp.status === 403 && request.method === 'GET') {
    const fb = await fallbackFetch(final, resp, env);
    if (fb) {
      resp = fb.resp;
      via = fb.via;
    }
  }

  const out = new Headers({ ...ACAO, ...SECURITY });
  const packed = packJar(changes);
  if (packed) out.set('X-Proxy-Cookies', packed);
  for (const h of COPY_HEADERS) {
    const v = resp.headers.get(h);
    if (v) out.set(h, v);
  }
  out.set('X-Final-URL', final.href);
  if (via) out.set('X-Proxy-Via', via);

  const ctype = (resp.headers.get('Content-Type') || '').toLowerCase();
  const isHtml = /text\/html|application\/xhtml\+xml/.test(ctype);
  const isCss = ctype.includes('text/css');

  if (request.method === 'HEAD' || [204, 205, 304].includes(resp.status)) {
    return new Response(null, { status: resp.status, headers: out });
  }

  if (isHtml && !opts.raw) {
    const ctx = { origin: url.origin, key: await makeKey(env.PROXY_TOKEN), js: opts.js, rw: opts.rw };
    out.set('Cache-Control', 'no-store');
    return buildRewriter(ctx, final.href).transform(new Response(resp.body, { status: resp.status, headers: out }));
  }

  if (isCss && !opts.raw && opts.rw) {
    const ctx = { origin: url.origin, key: await makeKey(env.PROXY_TOKEN), js: false, rw: true };
    const css = urlTools(ctx, final.href).cssText(await resp.text());
    out.set('Cache-Control', 'private, max-age=600');
    return new Response(css, { status: resp.status, headers: out });
  }

  out.set('Cache-Control', opts.raw || isHtml ? 'no-store' : 'private, max-age=600');
  return new Response(resp.body, { status: resp.status, headers: out });
}

function fail(status, msg, extra) {
  return new Response(msg, {
    status,
    headers: {
      ...ACAO,
      ...(extra || {}),
      'X-Proxy-Error': '1',
      'Content-Type': 'text/plain; charset=utf-8',
      'Cache-Control': 'no-store',
    },
  });
}

/* ─────────────────────────────── upstream ─────────────────────────────── */

async function fetchUpstream(request, target, bodyBuf, jar, ref) {
  let method = request.method;
  let body = bodyBuf;
  let cur = target;
  const work = jar.slice();
  const changes = [];

  const base = new Headers({
    'User-Agent': UA,
    Accept: request.headers.get('Accept') || '*/*',
    'Accept-Language': request.headers.get('Accept-Language') || 'en-GB,en;q=0.9',
  });
  const range = request.headers.get('Range');
  if (range) base.set('Range', range);
  const ct = request.headers.get('Content-Type');

  let refUrl = null;
  if (ref) {
    try {
      const r = new URL(ref);
      if (r.protocol === 'http:' || r.protocol === 'https:') refUrl = r;
    } catch (_) {}
  }

  for (let i = 0; i <= MAX_REDIRECTS; i++) {
    const h = new Headers(base);
    if (body && ct) h.set('Content-Type', ct);
    const ck = cookieHeader(work, cur);
    if (ck) h.set('Cookie', ck);
    if (refUrl) h.set('Referer', refUrl.href);
    if (method === 'POST') h.set('Origin', refUrl ? refUrl.origin : cur.origin);

    const resp = await fetch(cur.href, { method, headers: h, body: body || undefined, redirect: 'manual' });

    for (const sc of setCookies(resp)) {
      const c = parseSetCookie(sc, cur);
      if (c) {
        applyCookie(work, c);
        changes.push(c);
      }
    }

    if ([301, 302, 303, 307, 308].includes(resp.status)) {
      const loc = resp.headers.get('Location');
      if (!loc) return { resp, final: cur, changes };
      let next;
      try {
        next = new URL(loc, cur);
      } catch (_) {
        return { resp, final: cur, changes };
      }
      const checked = parseTarget(next.href);
      if (!checked) throw new Error('Redirect to a blocked address.');
      if (resp.status === 303 || ((resp.status === 301 || resp.status === 302) && method === 'POST')) {
        method = 'GET';
        body = undefined;
      }
      cur = checked;
      continue;
    }
    return { resp, final: cur, changes };
  }
  throw new Error('Too many redirects.');
}

/* ─────────────────────────────── fallback ─────────────────────────────── */

const IMAGE_EXT = /\.(jpe?g|png|gif|webp|avif|bmp|ico|svg)(\?|$)/i;

async function fallbackFetch(final, blocked, env) {
  const ctype = (blocked.headers.get('Content-Type') || '').toLowerCase();
  const looksImage = IMAGE_EXT.test(final.pathname) || ctype.startsWith('image/');
  try {
    if (looksImage) {
      const r = await fetch('https://wsrv.nl/?url=' + encodeURIComponent(final.href), { headers: { 'User-Agent': UA } });
      if (!r.ok || !(r.headers.get('Content-Type') || '').startsWith('image/')) return null;
      return { resp: r, via: 'wsrv' };
    }
    const h = { 'X-Return-Format': 'html', Accept: 'text/html' };
    if (env.JINA_API_KEY) h.Authorization = 'Bearer ' + env.JINA_API_KEY;
    const r = await fetch('https://r.jina.ai/' + final.href, { headers: h });
    if (!r.ok) return null;
    const html = await r.text();
    if (!/<html|<body|<head/i.test(html.slice(0, 2000))) return null;
    return {
      resp: new Response(html, { status: 200, headers: { 'Content-Type': 'text/html; charset=utf-8' } }),
      via: 'jina',
    };
  } catch (_) {
    return null;
  }
}

/* ───────────────────────────── cookie jar ─────────────────────────────
   Cookie shape: { n name, v value, d domain, h 1=host-only, p path, s 1=secure, e expiry ms (0 = session, -1 = delete) } */

const COOKIE_NAME = /^[^\s;=,"\\\x00-\x1f\x7f]+$/;
const COOKIE_VALUE = /^[^\x00-\x1f\x7f;]*$/;

function setCookies(resp) {
  if (typeof resp.headers.getSetCookie === 'function') return resp.headers.getSetCookie();
  const v = resp.headers.get('Set-Cookie');
  return v ? [v] : [];
}

function parseSetCookie(str, url) {
  const parts = str.split(';');
  const eq = parts[0].indexOf('=');
  if (eq < 1) return null;
  const n = parts[0].slice(0, eq).trim();
  const v = parts[0].slice(eq + 1).trim();
  if (!COOKIE_NAME.test(n) || !COOKIE_VALUE.test(v)) return null;
  const host = url.hostname.toLowerCase();
  const slash = url.pathname.lastIndexOf('/');
  const c = { n, v, d: host, h: 1, p: slash > 0 ? url.pathname.slice(0, slash) : '/', s: 0, e: 0 };
  let maxAge = null;
  let expires = null;
  for (const raw of parts.slice(1)) {
    const j = raw.indexOf('=');
    const k = (j < 0 ? raw : raw.slice(0, j)).trim().toLowerCase();
    const val = j < 0 ? '' : raw.slice(j + 1).trim();
    if (k === 'domain' && val) {
      const d = val.replace(/^\./, '').toLowerCase();
      if (!d.includes('.') || !(host === d || host.endsWith('.' + d))) return null;
      c.d = d;
      c.h = 0;
    } else if (k === 'path' && val.startsWith('/')) {
      c.p = val;
    } else if (k === 'secure') {
      c.s = 1;
    } else if (k === 'max-age') {
      const m = parseInt(val, 10);
      if (!isNaN(m)) maxAge = m;
    } else if (k === 'expires') {
      const t = Date.parse(val);
      if (!isNaN(t)) expires = t;
    }
  }
  if (maxAge !== null) c.e = maxAge <= 0 ? -1 : Date.now() + maxAge * 1000;
  else if (expires !== null) c.e = expires <= Date.now() ? -1 : expires;
  return c;
}

function applyCookie(list, c) {
  const i = list.findIndex((x) => x.n === c.n && x.d === c.d && x.p === c.p);
  if (i >= 0) list.splice(i, 1);
  if (c.e !== -1) list.push(c);
}

function pathMatch(req, p) {
  return req === p || (req.startsWith(p) && (p.endsWith('/') || req.charAt(p.length) === '/'));
}

function cookieHeader(list, url) {
  const host = url.hostname.toLowerCase();
  const now = Date.now();
  const https = url.protocol === 'https:';
  return list
    .filter(
      (c) =>
        (!c.e || c.e > now) &&
        (c.h ? host === c.d : host === c.d || host.endsWith('.' + c.d)) &&
        (!c.s || https) &&
        pathMatch(url.pathname, c.p)
    )
    .sort((a, b) => b.p.length - a.p.length)
    .map((c) => c.n + '=' + c.v)
    .join('; ');
}

function parseJar(h) {
  if (!h) return [];
  try {
    const a = JSON.parse(atob(h));
    if (!Array.isArray(a)) return [];
    return a
      .slice(0, 400)
      .filter(
        (c) =>
          c &&
          typeof c.n === 'string' &&
          typeof c.v === 'string' &&
          typeof c.d === 'string' &&
          typeof c.p === 'string' &&
          COOKIE_NAME.test(c.n) &&
          COOKIE_VALUE.test(c.v)
      )
      .map((c) => ({ n: c.n, v: c.v, d: c.d.toLowerCase(), h: c.h ? 1 : 0, p: c.p, s: c.s ? 1 : 0, e: Number(c.e) || 0 }));
  } catch (_) {
    return [];
  }
}

function packJar(list) {
  const a = list.slice();
  while (a.length) {
    const s = JSON.stringify(a).replace(/[\u007f-\uffff]/g, (ch) => '\\u' + ('0000' + ch.charCodeAt(0).toString(16)).slice(-4));
    if (s.length <= 6000) return btoa(s);
    a.pop();
  }
  return '';
}

/* ───────────────────────────── target checks ──────────────────────────── */

function parseTarget(raw) {
  let t;
  try {
    t = new URL(raw);
  } catch (_) {
    return null;
  }
  if (t.protocol !== 'http:' && t.protocol !== 'https:') return null;
  if (t.username || t.password) return null;
  if (!ALLOWED_PORTS.has(t.port)) return null;
  if (isBlockedHost(t.hostname)) return null;
  return t;
}

function isBlockedHost(host) {
  const h = host.toLowerCase().replace(/\.$/, '');
  if (!h) return true;
  if (h.startsWith('[')) return isBlockedV6(h.slice(1, -1));
  if (/^\d+\.\d+\.\d+\.\d+$/.test(h)) return isPrivateV4(h);
  if (!h.includes('.')) return true;
  const bad = ['.localhost', '.local', '.internal', '.lan', '.home.arpa', '.corp', '.intranet'];
  return h === 'localhost' || bad.some((s) => h.endsWith(s));
}

function isPrivateV4(h) {
  const [a, b] = h.split('.').map(Number);
  return (
    a === 0 ||
    a === 10 ||
    a === 127 ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 0) ||
    (a === 192 && b === 168) ||
    (a === 198 && (b === 18 || b === 19)) ||
    a >= 224
  );
}

function isBlockedV6(a) {
  a = a.toLowerCase();
  if (a === '::' || a === '::1') return true;
  if (!/^[23][0-9a-f]{0,3}:/.test(a)) return true;
  return a.startsWith('2002:') || a.startsWith('2001:0:') || a.startsWith('2001:db8');
}

/* ─────────────────────── auth and failed-attempt lockout ─────────────────────── */

async function sha(s) {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', ENC.encode(s)));
}

async function safeEqual(a, b) {
  const [ha, hb] = await Promise.all([sha(a), sha(b)]);
  let d = 0;
  for (let i = 0; i < ha.length; i++) d |= ha[i] ^ hb[i];
  return d === 0;
}

async function hmacHex(secret, msg) {
  const key = await crypto.subtle.importKey('raw', ENC.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, ENC.encode(msg));
  return [...new Uint8Array(sig)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

async function makeKey(secret) {
  const exp = Math.floor(Date.now() / 1000) + KEY_TTL_SECONDS;
  return exp + '.' + (await hmacHex(secret, 'k' + exp));
}

async function checkKey(k, secret) {
  const [exp, sig] = k.split('.');
  if (!/^\d+$/.test(exp || '') || !sig) return false;
  if (Number(exp) < Date.now() / 1000) return false;
  return safeEqual(sig, await hmacHex(secret, 'k' + exp));
}

// Per-isolate memory is always used. If a KV namespace named THROTTLE is bound, it is used
// as well, so the lockout survives restarts and is shared between Cloudflare locations.
const memFails = new Map();

async function failCount(env, ip) {
  const now = Date.now();
  let n = 0;
  const m = memFails.get(ip);
  if (m && m.reset > now) n = m.n;
  else if (m) memFails.delete(ip);
  if (env.THROTTLE) {
    try {
      n = Math.max(n, Number(await env.THROTTLE.get('f:' + ip)) || 0);
    } catch (_) {}
  }
  return n;
}

async function addFail(env, ip) {
  const now = Date.now();
  const m = memFails.get(ip);
  const n = (m && m.reset > now ? m.n : 0) + 1;
  if (memFails.size > 1000) memFails.clear();
  memFails.set(ip, { n, reset: now + FAIL_WINDOW * 1000 });
  if (env.THROTTLE) {
    try {
      const cur = Number(await env.THROTTLE.get('f:' + ip)) || 0;
      await env.THROTTLE.put('f:' + ip, String(cur + 1), { expirationTtl: FAIL_WINDOW });
    } catch (_) {}
  }
}

async function authenticate(request, url, env) {
  const hdr = request.headers.get('X-Proxy-Token');
  if (hdr) {
    const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
    if ((await failCount(env, ip)) >= FAIL_LIMIT) return 'locked';
    if (await safeEqual(hdr, env.PROXY_TOKEN)) return 'ok';
    await addFail(env, ip);
    return 'bad';
  }
  const k = url.searchParams.get('k');
  if (k && request.method !== 'POST' && (await checkKey(k, env.PROXY_TOKEN))) return 'ok';
  return 'bad';
}

/* ───────────────────────── HTML / CSS rewriting ───────────────────────── */

function urlTools(ctx, initialBase) {
  let base = initialBase;

  const skip = (v) => !v || /^\s*(data:|blob:|javascript:|mailto:|tel:|about:|#)/i.test(v);

  const resolve = (v) => {
    try {
      const a = new URL(v.trim(), base);
      return /^https?:$/.test(a.protocol) ? a.href : null;
    } catch (_) {
      return null;
    }
  };

  const absOnly = (v) => (skip(v) ? v : resolve(v) || v);

  const px = (v) => {
    if (skip(v)) return v;
    const a = resolve(v);
    if (!a) return v;
    return ctx.rw ? ctx.origin + '/?u=' + encodeURIComponent(a) + '&k=' + ctx.key : a;
  };

  const srcset = (s) =>
    s
      .split(',')
      .map((part) => {
        const bits = part.trim().split(/\s+/);
        if (!bits[0]) return '';
        bits[0] = px(bits[0]);
        return bits.join(' ');
      })
      .filter(Boolean)
      .join(', ');

  const cssText = (css) =>
    css
      .replace(/url\(\s*(?:"([^"]*)"|'([^']*)'|([^)"'\s]*))\s*\)/gi, (m, a, b, c) => {
        const v = a ?? b ?? c ?? '';
        return skip(v) ? m : 'url("' + px(v) + '")';
      })
      .replace(/@import\s+(?:"([^"]*)"|'([^']*)')/gi, (m, a, b) => '@import "' + px(a ?? b ?? '') + '"');

  return { px, absOnly, srcset, cssText, setBase: (b) => (base = b) };
}

function buildRewriter(ctx, finalUrl) {
  const t = urlTools(ctx, finalUrl);
  let styleBuf = '';

  const media = {
    element(el) {
      const src = el.getAttribute('src');
      const lazy = el.getAttribute('data-src');
      if (lazy && (!src || /^data:/i.test(src))) el.setAttribute('src', t.px(lazy));
      else if (src) el.setAttribute('src', t.px(src));

      const poster = el.getAttribute('poster');
      if (poster) el.setAttribute('poster', t.px(poster));

      const ss = el.getAttribute('srcset');
      const dss = el.getAttribute('data-srcset');
      if (dss) el.setAttribute('srcset', t.srcset(dss));
      else if (ss) el.setAttribute('srcset', t.srcset(ss));

      el.removeAttribute('integrity');
    },
  };

  return new HTMLRewriter()
    .on('base', {
      element(el) {
        const h = el.getAttribute('href');
        if (h) {
          try {
            t.setBase(new URL(h, finalUrl).href);
          } catch (_) {}
        }
        el.remove();
      },
    })
    .on('meta', {
      element(el) {
        const he = (el.getAttribute('http-equiv') || '').toLowerCase();
        if (he === 'refresh' || he === 'content-security-policy') el.remove();
      },
    })
    .on('iframe, frame, object, embed, applet', {
      element(el) {
        el.remove();
      },
    })
    .on('img, source, video, audio, track', media)
    .on('link', {
      element(el) {
        const rel = (el.getAttribute('rel') || '').toLowerCase();
        const href = el.getAttribute('href');
        el.removeAttribute('integrity');
        el.removeAttribute('crossorigin');
        if (!href || /preload|prefetch|preconnect|dns-prefetch|manifest/.test(rel)) {
          el.remove();
        } else if (/stylesheet|icon/.test(rel)) {
          el.setAttribute('href', t.px(href));
        } else {
          el.setAttribute('href', t.absOnly(href));
        }
      },
    })
    .on('script', {
      element(el) {
        if (!ctx.js) {
          el.remove();
          return;
        }
        const s = el.getAttribute('src');
        if (s) el.setAttribute('src', t.px(s));
        el.removeAttribute('integrity');
        el.removeAttribute('crossorigin');
      },
    })
    .on('a, area', {
      element(el) {
        const h = el.getAttribute('href');
        if (h) el.setAttribute('href', t.absOnly(h));
        el.removeAttribute('target');
        el.removeAttribute('ping');
      },
    })
    .on('form', {
      element(el) {
        const a = el.getAttribute('action');
        if (a) el.setAttribute('action', t.absOnly(a));
        el.removeAttribute('target');
      },
    })
    .on('style', {
      text(chunk) {
        styleBuf += chunk.text;
        if (chunk.lastInTextNode) {
          chunk.replace(t.cssText(styleBuf), { html: true });
          styleBuf = '';
        } else {
          chunk.remove();
        }
      },
    })
    .on('*', {
      element(el) {
        if (!ctx.js) {
          for (const [name] of [...el.attributes]) {
            if (name.length > 2 && name.startsWith('on')) el.removeAttribute(name);
          }
        }
        const st = el.getAttribute('style');
        if (st && st.includes('url(')) el.setAttribute('style', t.cssText(st));
      },
    });
}

/* ═══════════════════════════════════════════════════════════════════════════
   THE APP (served at /app)
   appMain() below is real browser code. The Worker serialises it into the page with
   toString(), so it must stay self-contained and must never contain a closing script tag.
═══════════════════════════════════════════════════════════════════════════ */

const APP_CSS = `
*{box-sizing:border-box}
html,body{height:100%;margin:0;background:#121216;color:#e2e2e6;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
.hidden{display:none!important}
button,input,select{font:inherit}
#login{height:100%;display:flex;align-items:center;justify-content:center}
#loginform{width:320px;max-width:90vw;display:flex;flex-direction:column;gap:12px;background:#18181f;border:1px solid #2d2d38;border-radius:12px;padding:24px}
#loginform h1{margin:0 0 4px;font-size:18px;font-weight:600}
#pw{background:#0d0d12;border:1px solid #2d2d38;border-radius:8px;color:#f4f4f8;padding:10px;font-size:14px;outline:none}
#pw:focus{border-color:#3b82f6;box-shadow:0 0 0 2px rgba(59,130,246,.2)}
.chk{display:flex;align-items:center;gap:6px;font-size:12px;color:#c4c4d0;cursor:pointer;white-space:nowrap}
.chk input{margin:0;cursor:pointer}
.go{background:#3b82f6;border:none;border-radius:6px;color:#fff;padding:8px 14px;font-size:13px;font-weight:600;cursor:pointer;flex-shrink:0}
.go:hover{background:#2563eb}
#loginmsg{margin:0;min-height:16px;font-size:12px;color:#f59e0b}
#app{display:flex;flex-direction:column;height:100vh}
header{background:#18181f;border-bottom:1px solid #292934;flex-shrink:0}
.tabstrip{display:flex;align-items:center;padding:6px 10px 0;gap:4px;background:#14141a;overflow-x:auto;scrollbar-width:none}
.tabstrip::-webkit-scrollbar{display:none}
#tabs{display:flex;gap:4px}
.tab{display:flex;align-items:center;gap:6px;padding:6px 12px;border-radius:8px 8px 0 0;background:#1e1e26;border:1px solid #2d2d38;border-bottom:none;color:#9292a0;font-size:12px;cursor:pointer;max-width:200px;min-width:100px}
.tab:hover{background:#262632;color:#e2e2e6}
.tab.active{background:#18181f;color:#fff;font-weight:500}
.tab-title{white-space:nowrap;overflow:hidden;text-overflow:ellipsis;flex:1}
.tab-close{border:none;background:transparent;color:#9292a0;cursor:pointer;font-size:12px;line-height:1;padding:2px 4px;border-radius:4px}
.tab-close:hover{background:rgba(255,255,255,.15);color:#ff5555}
#addtab{background:transparent;border:none;color:#9292a0;cursor:pointer;padding:4px 8px;border-radius:6px;font-size:14px}
#addtab:hover{background:#252530;color:#fff}
.spacer{flex:1}
.link{background:transparent;border:1px solid #2d2d38;border-radius:6px;color:#c4c4d0;font-size:12px;padding:3px 10px;cursor:pointer;white-space:nowrap;margin-bottom:2px}
.link:hover{border-color:#3b82f6;color:#fff}
.toolbar{display:flex;align-items:center;gap:8px;padding:8px 12px}
.nav{background:transparent;border:1px solid #2d2d38;border-radius:6px;color:#c4c4d0;width:30px;height:30px;display:flex;align-items:center;justify-content:center;cursor:pointer;flex-shrink:0;font-size:15px}
.nav:hover:not(:disabled){background:#252532;border-color:#3b82f6;color:#fff}
.nav:disabled{opacity:.35;cursor:not-allowed}
.urlbar{flex:1;display:flex;align-items:center;background:#0d0d12;border:1px solid #2d2d38;border-radius:8px;padding:0 10px;min-width:120px}
.urlbar:focus-within{border-color:#3b82f6;box-shadow:0 0 0 2px rgba(59,130,246,.2)}
#url{flex:1;background:transparent;border:none;outline:none;color:#f4f4f8;font-size:13px;padding:7px 0;width:100%}
#mode{background:#1e1e26;border:1px solid #2d2d38;border-radius:6px;color:#c4c4d0;font-size:12px;padding:5px 8px;outline:none;cursor:pointer}
main{flex:1;min-height:0;display:flex;flex-direction:column;background:#fff}
#frame{flex:1;width:100%;border:0;background:#fff}
#text{flex:1;overflow:auto;padding:20px;background:#0d0d12;color:#c9d1d9;font-family:monospace;font-size:12.5px;line-height:1.5;white-space:pre-wrap;word-break:break-all}
footer{height:24px;background:#14141a;border-top:1px solid #22222b;display:flex;align-items:center;padding:0 10px;font-size:11px;color:#7c7c8a}
#status{white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
@media (max-width:640px){.tab{min-width:70px}#mode{max-width:96px}}
`;

const APP_BODY = `
<div id="login">
  <form id="loginform" autocomplete="off">
    <h1>Browser</h1>
    <input id="pw" type="password" placeholder="Passphrase" autocomplete="current-password" autofocus>
    <div style="display:flex;align-items:center;justify-content:space-between;gap:10px">
      <label class="chk"><input type="checkbox" id="remember"> Remember on this device</label>
      <button class="go" type="submit">Unlock</button>
    </div>
    <p id="loginmsg"></p>
  </form>
</div>
<div id="app" class="hidden">
  <header>
    <div class="tabstrip">
      <div id="tabs"></div>
      <button id="addtab" type="button" title="New tab">+</button>
      <div class="spacer"></div>
      <button class="link" id="openchat" type="button">Claude</button>
      <button class="link" id="clearck" type="button">Clear cookies</button>
      <button class="link" id="popout" type="button">Pop out</button>
      <button class="link" id="lock" type="button">Lock</button>
    </div>
    <form class="toolbar" id="bar" autocomplete="off">
      <button class="nav" id="back" type="button" title="Back">&#8592;</button>
      <button class="nav" id="fwd" type="button" title="Forward">&#8594;</button>
      <button class="nav" id="reload" type="button" title="Reload">&#8635;</button>
      <div class="urlbar"><input id="url" type="text" placeholder="Type a web address or search" spellcheck="false" autocapitalize="off"></div>
      <select id="mode" title="View mode">
        <option value="browse">Browse</option>
        <option value="js">Browse + scripts</option>
        <option value="plain">Plain (no rewrite)</option>
        <option value="source">Source</option>
        <option value="text">Text only</option>
      </select>
      <button class="go" type="submit">Go</button>
    </form>
  </header>
  <main>
    <iframe id="frame" sandbox="allow-scripts allow-forms" title="Page"></iframe>
    <pre id="text" class="hidden"></pre>
  </main>
  <footer><span id="status">Ready</span><span class="spacer"></span><span id="ck"></span></footer>
</div>
`;

/* ───────────────────────── the browser app (client side) ───────────────────────── */

function appMain() {
  var $ = function (id) {
    return document.getElementById(id);
  };
  var TOK = 'pp_tok';
  var token = '';
  var JARKEY = 'pp_jar';
  var tabs = [];
  var cur = null;
  var persist = false;
  var jar = [];

  // Script injected into every rendered page: sends link clicks and form submits to the app.
  var FRAME_JS = [
    '(function(){',
    'var B=window.__B||"";',
    'function send(m){parent.postMessage(m,"*");}',
    'document.addEventListener("click",function(e){',
    ' if(e.defaultPrevented||e.button>1)return;',
    ' var a=e.target&&e.target.closest?e.target.closest("a[href],area[href]"):null;',
    ' if(!a)return;',
    ' var h=a.getAttribute("href")||"";',
    ' if(!h||h.charAt(0)==="#"||/^\\s*javascript:/i.test(h))return;',
    ' e.preventDefault();',
    ' if(/^(mailto|tel):/i.test(h))return;',
    ' send({t:"nav",u:a.href,nt:!!(e.ctrlKey||e.metaKey||e.button===1)});',
    '},true);',
    'document.addEventListener("submit",function(e){',
    ' var f=e.target;e.preventDefault();',
    ' var p=new URLSearchParams();',
    ' new FormData(f).forEach(function(v,k){if(typeof v==="string")p.append(k,v);});',
    ' var s=e.submitter;if(s&&s.name)p.append(s.name,s.value);',
    ' var u=f.getAttribute("action")?f.action:B;',
    ' if((f.getAttribute("method")||"get").toLowerCase()==="post"){send({t:"form",u:u,b:p.toString()});}',
    ' else{try{var x=new URL(u);x.search=p.toString();send({t:"nav",u:x.href});}catch(_){}}',
    '},true);',
    '})();',
  ].join('\n');

  /* storage helpers (never throw) */
  function sget(k) {
    try {
      return sessionStorage.getItem(k) || localStorage.getItem(k) || '';
    } catch (e) {
      return '';
    }
  }
  function sset(k, v, persist) {
    try {
      sessionStorage.setItem(k, v);
      if (persist) localStorage.setItem(k, v);
      else localStorage.removeItem(k);
    } catch (e) {}
  }
  function sdel(k) {
    try {
      sessionStorage.removeItem(k);
      localStorage.removeItem(k);
    } catch (e) {}
  }

  function status(s) {
    $('status').textContent = s;
  }

  /* ───────── cookie jar (kept here, sent to the gateway with each request) ───────── */

  function jarLoad() {
    try {
      var a = JSON.parse(sget(JARKEY) || '[]');
      jar = Array.isArray(a) ? a : [];
    } catch (e) {
      jar = [];
    }
    jarCount();
  }
  function jarSave() {
    sset(JARKEY, JSON.stringify(jar), persist);
    jarCount();
  }
  function jarCount() {
    $('ck').textContent = jar.length ? jar.length + (jar.length === 1 ? ' cookie' : ' cookies') : '';
  }
  function jarClear() {
    jar = [];
    sdel(JARKEY);
    jarCount();
  }
  function jarMatches(c, host) {
    return c.h ? host === c.d : host === c.d || host.endsWith('.' + c.d);
  }
  function b64json(a) {
    return btoa(
      JSON.stringify(a).replace(/[\u007f-\uffff]/g, function (ch) {
        return '\\u' + ('0000' + ch.charCodeAt(0).toString(16)).slice(-4);
      })
    );
  }
  function jarHeader(url) {
    var now = Date.now();
    jar = jar.filter(function (c) {
      return !c.e || c.e > now;
    });
    if (!jar.length) return '';
    var h = b64json(jar);
    if (h.length > 12000) {
      var host = hostOf(url);
      h = b64json(
        jar.filter(function (c) {
          return jarMatches(c, host);
        })
      );
    }
    return h.length > 12000 ? '' : h;
  }
  function jarMerge(h) {
    if (!h) return;
    try {
      JSON.parse(atob(h)).forEach(function (c) {
        jar = jar.filter(function (x) {
          return !(x.n === c.n && x.d === c.d && x.p === c.p);
        });
        if (c.e !== -1) jar.push(c);
      });
      if (jar.length > 400) jar = jar.slice(-400);
      jarSave();
    } catch (e) {}
  }

  /* ───────── login ───────── */

  async function tryLogin(pw, remember, auto) {
    var msg = $('loginmsg');
    msg.textContent = 'Checking...';
    try {
      var r = await fetch('/?ping=1', { headers: { 'X-Proxy-Token': pw }, cache: 'no-store' });
      if (r.status === 429) {
        msg.textContent = 'Too many wrong attempts. Try again in a few minutes.';
        return false;
      }
      if (r.ok && (await r.text()) === 'ok') {
        token = pw;
        persist = !!remember;
        sset(TOK, pw, remember);
        jarLoad();
        msg.textContent = '';
        $('pw').value = '';
        showApp();
        return true;
      }
      if (auto) sdel(TOK);
      msg.textContent = auto ? '' : 'Wrong passphrase.';
    } catch (e) {
      msg.textContent = 'Could not reach the gateway.';
    }
    return false;
  }

  function showApp() {
    $('login').classList.add('hidden');
    $('app').classList.remove('hidden');
    if (!tabs.length) newTab();
  }

  function lock(message) {
    token = '';
    sdel(TOK);
    jarClear();
    tabs = [];
    cur = null;
    $('frame').srcdoc = '';
    $('app').classList.add('hidden');
    $('login').classList.remove('hidden');
    $('loginmsg').textContent = message || '';
    $('pw').focus();
  }

  /* ───────── helpers ───────── */

  function gw(target, mode) {
    var q = '/?u=' + encodeURIComponent(target);
    if (mode === 'js') q += '&js=1';
    else if (mode === 'plain') q += '&rw=0';
    else if (mode === 'source') q += '&raw=1';
    return q;
  }

  function normalise(v) {
    v = (v || '').trim();
    if (!v) return '';
    if (/^https?:\/\//i.test(v)) return v;
    if (!/\s/.test(v) && /^[^\/?#]+\.[a-z]{2,}([\/?#].*)?$/i.test(v)) return 'https://' + v;
    return 'https://html.duckduckgo.com/html/?q=' + encodeURIComponent(v);
  }

  function hostOf(u) {
    try {
      return new URL(u).hostname;
    } catch (e) {
      return u;
    }
  }

  function escHtml(s) {
    return String(s).replace(/[&<>"]/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c];
    });
  }

  var BLANK =
    '<body style="margin:0;height:100vh;display:flex;align-items:center;justify-content:center;background:#fff;color:#8a8a98;font:14px -apple-system,Segoe UI,sans-serif">Type a web address or search above.</body>';

  /* ───────── tabs ───────── */

  function newTab(url) {
    var t = { title: 'New tab', hist: [], i: -1, mode: cur ? cur.mode : 'browse', rid: 0 };
    tabs.push(t);
    activate(t);
    if (url) go(url);
    else $('url').focus();
    return t;
  }

  function closeTab(t) {
    var idx = tabs.indexOf(t);
    if (idx < 0) return;
    t.rid++;
    tabs.splice(idx, 1);
    if (!tabs.length) {
      cur = null;
      newTab();
      return;
    }
    if (cur === t) activate(tabs[Math.min(idx, tabs.length - 1)]);
    else renderTabs();
  }

  function activate(t) {
    cur = t;
    renderTabs();
    $('mode').value = t.mode;
    syncBar();
    render(t);
  }

  function renderTabs() {
    var box = $('tabs');
    box.textContent = '';
    tabs.forEach(function (t) {
      var d = document.createElement('div');
      d.className = 'tab' + (t === cur ? ' active' : '');
      var s = document.createElement('span');
      s.className = 'tab-title';
      s.textContent = t.title || 'New tab';
      var x = document.createElement('button');
      x.type = 'button';
      x.className = 'tab-close';
      x.title = 'Close tab';
      x.textContent = '✕';
      d.appendChild(s);
      d.appendChild(x);
      d.addEventListener('click', function () {
        activate(t);
      });
      x.addEventListener('click', function (ev) {
        ev.stopPropagation();
        closeTab(t);
      });
      box.appendChild(d);
    });
  }

  function syncBar() {
    if (!cur) return;
    var e = cur.hist[cur.i];
    $('url').value = e ? e.final || e.url : '';
    $('back').disabled = cur.i <= 0;
    $('fwd').disabled = cur.i >= cur.hist.length - 1;
  }

  /* ───────── navigation ───────── */

  function go(url, body, ref) {
    if (!cur) return;
    var t = cur;
    var u = normalise(url);
    if (!u) return;
    t.hist = t.hist.slice(0, t.i + 1);
    t.hist.push({ url: u, body: body == null ? null : body, ref: ref || '', content: null });
    t.i = t.hist.length - 1;
    load(t, t.hist[t.i]);
  }

  function step(d) {
    if (!cur) return;
    var n = cur.i + d;
    if (n < 0 || n >= cur.hist.length) return;
    cur.i = n;
    var e = cur.hist[n];
    var fresh = e.content && e.mode === cur.mode && Date.now() - e.at < 40 * 60 * 1000;
    if (fresh) {
      syncBar();
      cur.title = e.title || hostOf(e.url);
      renderTabs();
      render(cur);
    } else {
      load(cur, e);
    }
  }

  async function load(t, entry) {
    var rid = ++t.rid;
    var mode = t.mode;
    if (t === cur) {
      $('url').value = entry.url;
      status('Loading...');
      $('back').disabled = t.i <= 0;
      $('fwd').disabled = t.i >= t.hist.length - 1;
    }
    var content;
    var title = '';
    try {
      var init = { headers: { 'X-Proxy-Token': token }, cache: 'no-store' };
      var jh = jarHeader(entry.url);
      if (jh) init.headers['X-Proxy-Jar'] = jh;
      if (entry.ref) init.headers['X-Proxy-Referer'] = entry.ref;
      if (entry.body != null) {
        init.method = 'POST';
        init.headers['Content-Type'] = 'application/x-www-form-urlencoded';
        init.body = entry.body;
      }
      var r = await fetch(gw(entry.url, mode), init);
      if (rid !== t.rid) return;
      if (r.status === 401) {
        lock('The gateway rejected the passphrase.');
        return;
      }
      jarMerge(r.headers.get('X-Proxy-Cookies'));
      if (r.headers.get('X-Proxy-Error')) {
        content = { kind: 'text', text: 'Error ' + r.status + ': ' + (await r.text()) };
      } else {
        entry.final = r.headers.get('X-Final-URL') || entry.url;
        var ct = (r.headers.get('Content-Type') || '').toLowerCase();
        var isHtml = /text\/html|application\/xhtml/.test(ct);
        if (isHtml && mode !== 'source') {
          var html = await r.text();
          var doc = new DOMParser().parseFromString(html, 'text/html');
          title = (doc.title || '').trim();
          if (mode === 'text') {
            doc.querySelectorAll('script,style,noscript,template').forEach(function (n) {
              n.remove();
            });
            var txt = (doc.body ? doc.body.textContent : '').replace(/[ \t]+\n/g, '\n').replace(/\n\s*\n\s*\n+/g, '\n\n').trim();
            content = { kind: 'text', text: txt || '(no text found)' };
          } else {
            content = { kind: 'html', html: html };
          }
        } else if (/^image\//.test(ct)) {
          content = { kind: 'image', url: URL.createObjectURL(await r.blob()) };
        } else if (isHtml || /^text\/|json|xml|javascript/.test(ct) || !ct) {
          content = { kind: 'text', text: await r.text() };
        } else {
          var name = (entry.final || entry.url).split('?')[0].split('/').pop() || 'download';
          content = { kind: 'file', url: URL.createObjectURL(await r.blob()), name: name };
        }
        var via = r.headers.get('X-Proxy-Via');
        status(r.status + ' · ' + hostOf(entry.final) + (via ? ' · via fallback (' + via + ')' : ''));
      }
    } catch (e) {
      if (rid !== t.rid) return;
      content = { kind: 'text', text: 'Could not reach the gateway.\n' + ((e && e.message) || e) };
      status('Failed');
    }
    entry.content = content;
    entry.mode = mode;
    entry.at = Date.now();
    entry.title = title || hostOf(entry.final || entry.url);
    t.title = entry.title;
    renderTabs();
    if (t === cur) {
      syncBar();
      render(t);
    }
  }

  function render(t) {
    var frame = $('frame');
    var text = $('text');
    var e = t.hist[t.i];
    var c = e && e.content;
    frame.classList.add('hidden');
    text.classList.add('hidden');
    if (!c) {
      frame.srcdoc = BLANK;
      frame.classList.remove('hidden');
      if (!e) status('Ready');
      return;
    }
    if (c.kind === 'html') {
      var inject =
        '<scr' + 'ipt>window.__B=' + JSON.stringify(e.final || e.url).replace(/</g, '\\u003c') + ';' + FRAME_JS + '</scr' + 'ipt>';
      frame.srcdoc = c.html + inject;
      frame.classList.remove('hidden');
    } else if (c.kind === 'image') {
      frame.srcdoc =
        '<body style="margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#0d0d12"><img style="max-width:100%;max-height:100vh" src="' +
        escHtml(c.url) +
        '">';
      frame.classList.remove('hidden');
    } else if (c.kind === 'file') {
      text.textContent = 'Downloading ' + c.name + ' ...';
      text.classList.remove('hidden');
      var a = document.createElement('a');
      a.href = c.url;
      a.download = c.name;
      document.body.appendChild(a);
      a.click();
      a.remove();
    } else {
      text.textContent = c.text;
      text.scrollTop = 0;
      text.classList.remove('hidden');
    }
  }

  /* ───────── events ───────── */

  $('loginform').addEventListener('submit', function (ev) {
    ev.preventDefault();
    var pw = $('pw').value;
    if (pw) tryLogin(pw, $('remember').checked, false);
  });

  $('bar').addEventListener('submit', function (ev) {
    ev.preventDefault();
    go($('url').value);
  });
  $('back').addEventListener('click', function () {
    step(-1);
  });
  $('fwd').addEventListener('click', function () {
    step(1);
  });
  $('reload').addEventListener('click', function () {
    if (!cur) return;
    var e = cur.hist[cur.i];
    if (e) load(cur, e);
  });
  $('addtab').addEventListener('click', function () {
    newTab();
  });
  $('lock').addEventListener('click', function () {
    lock('');
  });
  $('openchat').addEventListener('click', function () {
    window.open('/chat', '_blank');
  });
  $('clearck').addEventListener('click', function () {
    jarClear();
    status('Cookies cleared');
  });
  $('popout').addEventListener('click', function () {
    window.open(location.href, '_blank', 'popup=yes,width=1200,height=800');
  });
  $('mode').addEventListener('change', function () {
    if (!cur) return;
    cur.mode = $('mode').value;
    var e = cur.hist[cur.i];
    if (e) load(cur, e);
  });

  window.addEventListener('message', function (ev) {
    if (!cur || ev.source !== $('frame').contentWindow) return;
    var m = ev.data;
    if (!m || typeof m !== 'object' || typeof m.u !== 'string' || !/^https?:\/\//i.test(m.u)) return;
    var ce = cur.hist[cur.i];
    var from = ce ? ce.final || ce.url : '';
    if (m.t === 'nav') {
      if (m.nt) {
        newTab();
        go(m.u, null, from);
      } else go(m.u, null, from);
    } else if (m.t === 'form' && typeof m.b === 'string') {
      go(m.u, m.b, from);
    }
  });

  var saved = sget(TOK);
  if (saved) {
    var inLocal = false;
    try {
      inLocal = !!localStorage.getItem(TOK);
    } catch (e) {}
    tryLogin(saved, inLocal, true);
  }
}

const PAGE_CSP =
  // Pages are shown in a srcdoc iframe, which inherits this policy, so it has to allow
  // the Worker's own images/fonts/styles/scripts (for js=1) and inline content.
  "default-src 'none'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; " +
  "img-src 'self' data: blob:; font-src 'self' data:; media-src 'self' data: blob:; " +
  "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'";

function servePage(title, css, body, main) {
  const page =
    '<!doctype html><html lang="en"><head><meta charset="utf-8">' +
    '<meta name="viewport" content="width=device-width,initial-scale=1">' +
    '<meta name="robots" content="noindex,nofollow"><title>' + title + '</title>' +
    '<style>' + css + '</style></head><body>' + body +
    '<scr' + 'ipt>var __name=function(f){return f};(' + main.toString() + ')();</scr' + 'ipt>' +
    '</body></html>';
  return new Response(page, {
    headers: {
      'Content-Type': 'text/html; charset=utf-8',
      'Cache-Control': 'no-store',
      'X-Robots-Tag': 'noindex',
      'X-Content-Type-Options': 'nosniff',
      'Referrer-Policy': 'no-referrer',
      'Content-Security-Policy': PAGE_CSP,
    },
  });
}

function serveApp() {
  return servePage('Browser', APP_CSS, APP_BODY, appMain);
}

/* ═══════════════════════════════════════════════════════════════════════════
   CLAUDE CHAT (served at /chat)
   Talks to the Claude API through /api/chat with the key held in the ANTHROPIC_API_KEY
   secret. This is API access, separate from a claude.ai account and its chat history.
═══════════════════════════════════════════════════════════════════════════ */

const CHAT_MODEL = /^claude-[a-z0-9.-]{3,60}$/;

async function chatApi(request, url, env) {
  if (request.method !== 'POST') return fail(405, 'Method not allowed.');
  if (!env.PROXY_TOKEN) return fail(500, 'PROXY_TOKEN is not configured on the Worker.');
  const auth = await authenticate(request, url, env);
  if (auth === 'locked') {
    return fail(429, 'Too many failed attempts. Try again in a few minutes.', { 'Retry-After': String(FAIL_WINDOW) });
  }
  if (auth !== 'ok') return fail(401, 'Unauthorized.');
  if (!env.ANTHROPIC_API_KEY) return fail(500, 'ANTHROPIC_API_KEY is not configured on the Worker.');

  const raw = await request.text();
  if (raw.length > MAX_BODY) return fail(413, 'Conversation too large. Start a new chat.');
  let j;
  try {
    j = JSON.parse(raw);
  } catch (_) {
    return fail(400, 'Bad request.');
  }
  const model = typeof j.model === 'string' && CHAT_MODEL.test(j.model) ? j.model : '';
  const messages = (Array.isArray(j.messages) ? j.messages : [])
    .filter((m) => m && (m.role === 'user' || m.role === 'assistant') && typeof m.content === 'string' && m.content)
    .map((m) => ({ role: m.role, content: m.content }));
  if (!model || !messages.length) return fail(400, 'Bad request.');

  const up = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: {
      'x-api-key': env.ANTHROPIC_API_KEY,
      'anthropic-version': '2023-06-01',
      'content-type': 'application/json',
    },
    body: JSON.stringify({ model, max_tokens: 4096, stream: true, messages }),
  });
  if (!up.ok) {
    let msg = await up.text();
    try {
      msg = JSON.parse(msg).error.message;
    } catch (_) {}
    return fail(up.status, 'Claude API: ' + msg);
  }
  return new Response(up.body, {
    headers: { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' },
  });
}

const CHAT_CSS = `
*{box-sizing:border-box}
html,body{height:100%;margin:0;background:#121216;color:#e2e2e6;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
.hidden{display:none!important}
button,textarea,select{font:inherit}
#chat{display:flex;flex-direction:column;height:100vh;max-width:860px;margin:0 auto}
#top{display:flex;align-items:center;gap:8px;padding:10px 12px;border-bottom:1px solid #292934}
#top h1{margin:0;font-size:15px;font-weight:600;flex:1}
#model,.btn{background:#1e1e26;border:1px solid #2d2d38;border-radius:6px;color:#c4c4d0;font-size:12px;padding:5px 8px;cursor:pointer}
.btn:hover{border-color:#3b82f6;color:#fff}
#log{flex:1;overflow-y:auto;padding:16px 12px;display:flex;flex-direction:column;gap:10px}
.msg{max-width:88%;padding:10px 12px;border-radius:10px;font-size:14px;line-height:1.5;white-space:pre-wrap;overflow-wrap:anywhere}
.msg.user{align-self:flex-end;background:#2563eb;color:#fff}
.msg.assistant{align-self:flex-start;background:#1e1e26;border:1px solid #2d2d38}
.msg.err{align-self:flex-start;background:#3a1d1d;border:1px solid #6b2a2a;color:#fca5a5}
#send{display:flex;gap:8px;padding:10px 12px;border-top:1px solid #292934}
#in{flex:1;min-height:44px;max-height:200px;resize:vertical;background:#0d0d12;border:1px solid #2d2d38;border-radius:8px;color:#f4f4f8;padding:10px;font-size:14px;outline:none}
#in:focus{border-color:#3b82f6}
.go{background:#3b82f6;border:none;border-radius:8px;color:#fff;padding:0 16px;font-size:13px;font-weight:600;cursor:pointer}
.go:disabled{opacity:.5;cursor:default}
#need{padding:40px 20px;text-align:center;color:#c4c4d0;font-size:14px}
#need a{color:#60a5fa}
`;

const CHAT_BODY = `
<div id="need" class="hidden">Unlock the browser first: <a href="/app">open /app</a>, enter your passphrase, then come back here.</div>
<div id="chat">
  <div id="top">
    <h1>Claude</h1>
    <select id="model" title="Model">
      <option value="claude-sonnet-5-5">Sonnet 5.5</option>
      <option value="claude-opus-5-5">Opus 5.5</option>
      <option value="claude-haiku-5-5">Haiku 5.5</option>
    </select>
    <button class="btn" id="new" type="button">New chat</button>
  </div>
  <div id="log"></div>
  <form id="send">
    <textarea id="in" placeholder="Message Claude (Enter to send, Shift+Enter for a new line)"></textarea>
    <button class="go" id="gobtn" type="submit">Send</button>
  </form>
</div>
`;

function chatMain() {
  var $ = function (id) {
    return document.getElementById(id);
  };
  var token = '';
  var msgs = [];
  var busy = false;
  try {
    token = sessionStorage.getItem('pp_tok') || localStorage.getItem('pp_tok') || '';
  } catch (e) {}
  if (!token) {
    $('need').classList.remove('hidden');
    $('chat').classList.add('hidden');
    return;
  }
  try {
    var a = JSON.parse(sessionStorage.getItem('pp_chat') || '[]');
    if (Array.isArray(a)) msgs = a;
    var sm = sessionStorage.getItem('pp_model');
    if (sm) $('model').value = sm;
  } catch (e) {}

  function save() {
    try {
      sessionStorage.setItem('pp_chat', JSON.stringify(msgs));
    } catch (e) {}
  }
  function add(role, text) {
    var d = document.createElement('div');
    d.className = 'msg ' + role;
    d.textContent = text;
    $('log').appendChild(d);
    $('log').scrollTop = $('log').scrollHeight;
    return d;
  }
  msgs.forEach(function (m) {
    add(m.role, m.content);
  });

  async function send() {
    if (busy) return;
    var t = $('in').value.trim();
    if (!t) return;
    busy = true;
    $('gobtn').disabled = true;
    $('in').value = '';
    msgs.push({ role: 'user', content: t });
    add('user', t);
    var el = add('assistant', '...');
    var out = '';
    try {
      var r = await fetch('/api/chat', {
        method: 'POST',
        headers: { 'X-Proxy-Token': token, 'Content-Type': 'application/json' },
        body: JSON.stringify({ model: $('model').value, messages: msgs }),
      });
      if (!r.ok || !r.body) throw new Error((await r.text()) || 'HTTP ' + r.status);
      var rd = r.body.getReader();
      var dec = new TextDecoder();
      var buf = '';
      for (;;) {
        var x = await rd.read();
        if (x.done) break;
        buf += dec.decode(x.value, { stream: true });
        var lines = buf.split('\n');
        buf = lines.pop();
        lines.forEach(function (l) {
          if (l.indexOf('data:') !== 0) return;
          try {
            var j = JSON.parse(l.slice(5));
            if (j.type === 'content_block_delta' && j.delta && j.delta.text) out += j.delta.text;
            else if (j.type === 'error') out += '\n[error: ' + ((j.error && j.error.message) || 'unknown') + ']';
          } catch (e) {}
        });
        el.textContent = out || '...';
        $('log').scrollTop = $('log').scrollHeight;
      }
      if (!out) throw new Error('Empty reply.');
      msgs.push({ role: 'assistant', content: out });
      save();
    } catch (e) {
      msgs.pop();
      el.className = 'msg err';
      el.textContent = 'Error: ' + ((e && e.message) || e);
      $('in').value = t;
    }
    busy = false;
    $('gobtn').disabled = false;
    $('in').focus();
  }

  $('send').addEventListener('submit', function (ev) {
    ev.preventDefault();
    send();
  });
  $('in').addEventListener('keydown', function (ev) {
    if (ev.key === 'Enter' && !ev.shiftKey) {
      ev.preventDefault();
      send();
    }
  });
  $('new').addEventListener('click', function () {
    if (busy) return;
    msgs = [];
    save();
    $('log').textContent = '';
  });
  $('model').addEventListener('change', function () {
    try {
      sessionStorage.setItem('pp_model', $('model').value);
    } catch (e) {}
  });
  $('in').focus();
}

function serveChat() {
  return servePage('Claude', CHAT_CSS, CHAT_BODY, chatMain);
}
