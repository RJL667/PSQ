# Web-host proxy setup — `phishield.com/scanner-info`

**For: Phishield's hosting / web team**
**Prepared by: SML Consulting (Phishield UMA scanner architecture)**
**Required by: Tuesday 2026-05-19 (alongside WordPress → HTML conversion)**

---

## What's being requested

The Phishield cyber-risk scanner identifies itself in every outbound HTTP request with the header:

```
User-Agent: Phishield-Scanner/1.0 (+https://phishield.com/scanner-info)
```

When a security team at a scanned target investigates the source of scanner traffic, they will visit that URL to verify the scanner is legitimate. **That URL must return a working page on `phishield.com`.** Currently it would 404.

The page content is hosted on Phishield's Render service at `https://phishield-scanner.onrender.com/scanner-info` — see what it looks like there for reference.

There are three viable ways to make `phishield.com/scanner-info` return this page. **Option A** is the simplest and is the recommended path given the upcoming WordPress → HTML conversion. Options B and C are alternatives.

---

## DNS context (already confirmed)

- `phishield.com` is on **Hetzner DNS** (`ns.second-ns.com`, `ns1.your-server.de`, `ns3.second-ns.de`)
- No Cloudflare, no Vercel, no edge-proxy layer currently in front of the site

This means the proxy / page must be served at the **web server level** on whatever hosts phishield.com.

---

## Option A — Static copy on the new HTML site (recommended)

Since the WordPress site is being converted to static HTML this week, the simplest approach is to include the `scanner-info` page as a static file in the new site.

### Step 1 — Add the file

Place this HTML at `/scanner-info` (or `/scanner-info/index.html`) in the new static site:

> Download the current canonical version from:
> https://phishield-scanner.onrender.com/scanner-info
> (save the rendered HTML as `scanner-info.html` and include it in the deploy)

Alternative: use the source template directly from the GitHub repo:
> https://github.com/brafter12345-cmyk/PSQ/blob/master/security_scanner/templates/scanner_info.html
> (this file is Jinja2-templated — for static use, just take it as plain HTML; there are no template variables in it)

### Step 2 — Verify

After deployment, run from any machine:

```bash
curl -sI https://phishield.com/scanner-info
```

Expected: `HTTP/2 200` with `Content-Type: text/html` and a body containing "Phishield Scanner — Public Identity".

Also test in a browser — the page should render and the address bar should stay on `phishield.com/scanner-info`.

### Trade-off

This is a **static snapshot**. If the scanner's IP ranges, request profile, or contact details change in future, the static copy must be manually re-synced. In practice this content changes ~once per year, so manual sync is reasonable. If you prefer a single source of truth, see Option B.

---

## Option B — nginx reverse-proxy (if the new site is on a Hetzner VM with nginx)

Cleanest single-source-of-truth answer. Requires whatever web server hosts phishield.com to support nginx-style reverse-proxy directives.

In the phishield.com server's nginx configuration (typically `/etc/nginx/sites-available/phishield.com` or similar), add a `location` block:

```nginx
location = /scanner-info {
    proxy_pass https://phishield-scanner.onrender.com/scanner-info;
    proxy_set_header Host phishield-scanner.onrender.com;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_ssl_server_name on;
    proxy_ssl_verify off;
    proxy_redirect off;

    # Cache at the edge for 10 minutes — scanner-info changes rarely
    proxy_cache_valid 200 10m;
    add_header Cache-Control "public, max-age=600";
}
```

Reload nginx after applying: `sudo nginx -t && sudo systemctl reload nginx`

### Apache equivalent (if it's Apache, not nginx)

```apache
<Location "/scanner-info">
    ProxyPass "https://phishield-scanner.onrender.com/scanner-info"
    ProxyPassReverse "https://phishield-scanner.onrender.com/scanner-info"
    Header set Cache-Control "public, max-age=600"
</Location>
```

`mod_proxy` and `mod_proxy_http` must be enabled.

---

## Option C — Add Cloudflare as a CDN layer (future-looking)

If Phishield is considering moving phishield.com to Cloudflare anyway (for DDoS protection, CDN, WAF, etc.), this becomes the cleanest answer long-term:

1. Add phishield.com as a site in Cloudflare (free tier is fine)
2. Update nameservers at the registrar from Hetzner → Cloudflare
3. Set up a Cloudflare Worker (the JavaScript from the earlier draft of this document) to reverse-proxy `/scanner-info` → Render

This adds CDN, edge caching, DDoS protection, and gives Phishield other capabilities (WAF rules, bot management, analytics) — but it's a bigger DNS migration than the scanner-info URL alone justifies. **Don't do this just for the scanner-info page.** If you're moving to Cloudflare for other reasons, scanner-info comes along for free.

---

## What NOT to do

- **Do not** use a 301 / 302 redirect to `phishield-scanner.onrender.com` — that changes the visible URL and undermines the security-team trust the whole exercise is trying to build.
- **Do not** modify the Render origin — `phishield-scanner.onrender.com/scanner-info` is the canonical source.
- **Do not** cache longer than 10 minutes — gives Phishield room to update the page if details change.

---

## After implementation

Confirm to SML Consulting that `phishield.com/scanner-info` returns the page. We will then update the scanner's User-Agent constant in `http_client.py` to point at the canonical URL (currently pointing directly at the Render service as a placeholder).

---

## Recommended path

For Tuesday's WordPress → HTML cut-over, **Option A (static copy)** is the smallest delta and least risk. Add `scanner-info.html` to the new static deploy alongside the other pages. Total work: ~5 minutes.

If you want to do this once and never touch it again, **Option B (nginx reverse-proxy)** is the right long-term answer.

---

## Questions / escalation

- Technical owner (Phishield UMA): Sarel Lessing
- Scanner architecture: SML Consulting
- Reference: SCN-025 in the Phishield Scanner Gap Analysis v10 document
