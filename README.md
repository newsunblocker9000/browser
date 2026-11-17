# browser

Private web gateway plus a hosted browser app, in one Cloudflare Worker (`worker.js`).

- `/app` the browser app (tabs, address bar, view modes, passphrase login)
- `/?u=<url>` the gateway (needs the `X-Proxy-Token` header, or the signed `?k=` key the Worker adds to pages it rewrites)
- `/?ping=1` passphrase check
- `/chat` Claude chat page using the Claude API (unlock at `/app` first). Needs a second secret, `ANTHROPIC_API_KEY`, from console.anthropic.com. This is API access billed per use, separate from a claude.ai account.

## Fallback for blocked sites

Some sites (BBC News, for one) return 403 "Access Denied" to anything coming from a Cloudflare Worker. When that happens on a GET, the gateway retries through Jina Reader (`r.jina.ai`) for pages and `wsrv.nl` for images. The status bar shows "via fallback" when this kicks in. Jina's free tier is rate-limited; an optional `JINA_API_KEY` secret raises it.

## Setup

1. Cloudflare dashboard: Workers & Pages, Create, import this repo. Name the Worker `browser` (must match `name` in `wrangler.jsonc`). Build command: none. Deploy command: `npx wrangler deploy`.
2. Worker, Settings, Variables and Secrets: add a secret called `PROXY_TOKEN` (your passphrase).
3. Optional: create a KV namespace and bind it as `THROTTLE` (see the comment in `wrangler.jsonc`) so the failed-login lockout is shared across locations.
4. Open `https://browser.<your-subdomain>.workers.dev/app`.

Keep `worker.js` unminified: the app code is serialised into the page with `toString()`.
