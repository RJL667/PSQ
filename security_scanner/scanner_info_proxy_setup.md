# Cloudflare proxy setup — `phishield.com/scanner-info`

**For: Phishield's hosting / web team**
**Prepared by: SML Consulting (Phishield UMA scanner architecture)**
**Required by: Tuesday 2026-05-19 (alongside WordPress → HTML conversion)**

---

## What's being requested

A reverse-proxy rule on the `phishield.com` Cloudflare zone so that requests to:

```
https://phishield.com/scanner-info
```

are served by the Render-hosted scanner service at:

```
https://phishield-scanner.onrender.com/scanner-info
```

The end user's browser address bar should still read `phishield.com/scanner-info` — the proxy must be **transparent** (no 302 redirect that changes the visible URL).

---

## Why

Phishield's cyber-risk scanner identifies itself in every outbound HTTP request with the header:

```
User-Agent: Phishield-Scanner/1.0 (+https://phishield.com/scanner-info)
```

When a security team at a scanned target investigates the source of scanner traffic, they will visit that URL to verify the scanner is legitimate. The page they need to see is hosted on the scanner's own Render service, but the URL must be on the `phishield.com` brand domain to be trusted (security teams treat `*.onrender.com` URLs with suspicion).

This is the standard pattern used by every commercial passive scanner — Bitsight, SecurityScorecard, Coalition, CFC, Black Kite, RiskRecon all expose their scanner-identity page on their own brand domain via a reverse-proxy to the scanner backend.

---

## Recommended approach: Cloudflare Worker

The cleanest option in Cloudflare's free tier. Single small JavaScript function. URL stays canonical, response is identical to the Render origin.

### Step 1 — Create the Worker

1. Cloudflare dashboard → **Workers & Pages** → **Create Application** → **Create Worker**
2. Name the worker `phishield-scanner-info-proxy`
3. Paste the code below (this is the entire worker):

```javascript
export default {
  async fetch(request) {
    const url = new URL(request.url);

    // Only proxy /scanner-info (and any sub-paths if needed later)
    if (!url.pathname.startsWith("/scanner-info")) {
      return new Response("Not found", { status: 404 });
    }

    // Rewrite the host to point at the Render scanner backend
    const upstream = new URL(request.url);
    upstream.hostname = "phishield-scanner.onrender.com";
    upstream.port = "";  // Render uses 443 (HTTPS default)
    upstream.protocol = "https:";

    // Forward the request as-is. Strip the Cloudflare CF-* headers
    // since they could confuse the upstream Flask app.
    const headers = new Headers(request.headers);
    headers.set("Host", "phishield-scanner.onrender.com");
    headers.delete("cf-connecting-ip");
    headers.delete("cf-ipcountry");
    headers.delete("cf-ray");
    headers.delete("cf-visitor");

    const upstreamResponse = await fetch(upstream.toString(), {
      method: request.method,
      headers: headers,
      body: request.method === "GET" || request.method === "HEAD"
        ? undefined : request.body,
      redirect: "manual",
    });

    // Return upstream response verbatim. Cache for 10 minutes at the
    // edge so we don't hammer Render for every visitor — the page
    // is static enough that 10 min staleness is fine.
    const responseHeaders = new Headers(upstreamResponse.headers);
    responseHeaders.set("Cache-Control", "public, max-age=600");

    return new Response(upstreamResponse.body, {
      status: upstreamResponse.status,
      statusText: upstreamResponse.statusText,
      headers: responseHeaders,
    });
  }
};
```

4. Click **Save and Deploy**

### Step 2 — Bind the Worker to the route

1. Still inside the Worker's page → **Triggers** tab → **Routes** → **Add Route**
2. Route: `phishield.com/scanner-info*`
3. Zone: `phishield.com`
4. Click **Save**

### Step 3 — Verify

After ~30 seconds for propagation, run from any machine:

```bash
curl -sI https://phishield.com/scanner-info
```

Expected response: `HTTP/2 200` with `Content-Type: text/html` and a body containing "Phishield Scanner — Public Identity".

Also test in a browser — the address bar should stay on `phishield.com/scanner-info` (NOT redirect to onrender.com).

---

## Alternative: simple redirect (if Workers is not preferred)

If for any reason a Worker isn't viable on the current Cloudflare plan, a **Bulk Redirect** is a working fallback. The visible URL will change to `phishield-scanner.onrender.com/scanner-info` in the browser, which is less ideal but still functional.

1. Cloudflare dashboard → **Rules** → **Redirect Rules** → **Create Rule**
2. Rule name: `Scanner info redirect`
3. When incoming requests match: URL Full URL equals `https://phishield.com/scanner-info`
4. Then: Static — Type 301 (Moved Permanently), URL `https://phishield-scanner.onrender.com/scanner-info`, preserve query string

The Worker option is preferred. Use the redirect only if Worker setup is blocked for any reason.

---

## What NOT to do

- **Do not** use a 302 / 301 redirect if the Worker option is available — the canonical URL must remain visible.
- **Do not** modify the Render origin server in any way — `phishield-scanner.onrender.com` is managed separately and serves the canonical content.
- **Do not** cache the response longer than 10 minutes — the scanner-info page may be updated periodically with new IP ranges or contact details.

---

## After implementation

Confirm to SML Consulting that the Worker route is live, then we will update the scanner's User-Agent header to point at the canonical `https://phishield.com/scanner-info` URL (currently it points at the direct Render URL as a placeholder).

---

## Questions / escalation

- Technical owner (Phishield UMA): Sarel Lessing
- Scanner architecture: SML Consulting
- Reference: SCN-025 in the Phishield Scanner Gap Analysis v10 document
