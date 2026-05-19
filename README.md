# RealScan

**An external web-posture scanner on Cloudflare Workers.**

Paste a domain, get a graded report: HTTPS/HSTS, security headers,
SPF/DMARC/DNSSEC/CAA, origin-bypass subdomains, and secrets exposed in
client-delivered code. Shareable, expiring report links.

🔗 **Live:** *(deployed URL)*

> Sibling of [Sentinel](https://github.com/samuelmonteirotf/sentinel) —
> same edge stack, same honesty rule.

---

## The honesty rule

A Worker **cannot** do a raw TLS handshake against an arbitrary host or
truly discover an origin behind a CDN. So RealScan doesn't pretend to.
It only reports what is genuinely verifiable from a Worker:

| Check | How |
|---|---|
| HTTPS reachable · HTTP→HTTPS redirect | real fetches |
| HSTS (with `max-age` quality) | response header |
| CSP · X-Content-Type-Options · clickjacking · Referrer-Policy · Permissions-Policy | response headers |
| Tech/version disclosure · cookie flags · mixed content | headers + parsed HTML |
| SPF · DMARC (with policy) · DNSSEC · CAA | DNS-over-HTTPS (1.1.1.1) |
| Origin-bypass subdomains | resolves `origin/direct/cpanel/...` and flags non-CDN addresses (heuristic, labelled as such) |
| Exposed secrets | regex over the HTML + first-party scripts (AWS/Google/Stripe/Slack/GitHub/private keys), redacted |

Score starts at 100; findings subtract by severity → letter grade A–F.

## Not an attack proxy

A scanner that fetches user-supplied URLs is an SSRF vector by default.
`ssrf.js` enforces: http/https + default ports only, no IP literals,
and **the host is resolved and rejected if any address is
private/reserved** (RFC1918, loopback, link-local incl.
`169.254.169.254`, CGNAT, ULA, IPv4-mapped v6). Scans are rate-limited
per client IP via a Durable Object.

## Architecture

```
 POST /api/scan ─▶ SSRF guard ─▶ ScanLimiter DO (per IP)
                                      │
                                      ▼
                                  scan.js  (isolated checks, DoH, capped fetches)
                                      │
                                      ▼
                          Reports DO  ──▶ /r/:id (shareable)  +  /api/stats (live)
```

Each check is wrapped independently — a failing probe degrades to
"could not determine" instead of breaking the report. Report rendering
HTML-escapes everything that came from the scanned site.

## Run it

```bash
npm install
wrangler deploy
```

No secrets, no paid APIs, no build step.

## Roadmap

- [ ] Certificate Transparency lookup (issuer / expiry from CT logs)
- [ ] DKIM check when a selector is provided
- [ ] PDF export of the report
- [ ] Scheduled re-scan + diff (regression alerts)

## License

MIT
