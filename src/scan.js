// The scan engine. Every check below is something a Cloudflare Worker can
// genuinely verify. Things a Worker CANNOT do (full TLS handshake
// inspection, true origin discovery) are deliberately NOT claimed.
//
// Each check is isolated: if one fails, it degrades to "could not
// determine" instead of breaking the report.

import { doh, txt, resolveIps } from "./dns.js";

const SEV_COST = { high: 20, medium: 10, low: 4, info: 0, pass: 0 };

async function readCapped(res, maxBytes = 600_000) {
  const reader = res.body && res.body.getReader();
  if (!reader) return "";
  const chunks = [];
  let total = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.length;
    chunks.push(value);
    if (total >= maxBytes) {
      await reader.cancel();
      break;
    }
  }
  return new TextDecoder().decode(
    chunks.reduce((acc, c) => {
      const m = new Uint8Array(acc.length + c.length);
      m.set(acc);
      m.set(c, acc.length);
      return m;
    }, new Uint8Array())
  );
}

function tfetch(url, opts, ms) {
  return fetch(url, { ...opts, signal: AbortSignal.timeout(ms) });
}

const SECRET_RULES = [
  { re: /AKIA[0-9A-Z]{16}/g, name: "AWS access key id", sev: "high" },
  { re: /AIza[0-9A-Za-z\-_]{35}/g, name: "Google API key", sev: "medium" },
  { re: /sk_live_[0-9a-zA-Z]{16,}/g, name: "Stripe live secret key", sev: "high" },
  { re: /xox[baprs]-[0-9A-Za-z-]{10,}/g, name: "Slack token", sev: "high" },
  { re: /gh[pousr]_[0-9A-Za-z]{36}/g, name: "GitHub token", sev: "high" },
  { re: /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/g, name: "private key", sev: "high" },
  { re: /pk_live_[0-9a-zA-Z]{16,}/g, name: "Stripe publishable key (expected public)", sev: "info" },
];

function redact(s) {
  return s.length <= 10 ? "***" : s.slice(0, 4) + "…" + s.slice(-4);
}

function scanSecrets(text, source, findings) {
  for (const rule of SECRET_RULES) {
    const seen = new Set();
    let m;
    rule.re.lastIndex = 0;
    while ((m = rule.re.exec(text)) && seen.size < 3) {
      if (seen.has(m[0])) continue;
      seen.add(m[0]);
      findings.push({
        sev: rule.sev,
        title: `${rule.name} found in ${source}`,
        detail: `Matched \`${redact(m[0])}\`. Client-delivered code is public — rotate anything sensitive and serve it from the backend.`,
      });
    }
  }
}

export async function runScan(url, host, env) {
  const timeout = parseInt(env.FETCH_TIMEOUT_MS || "8000", 10);
  const maxScripts = parseInt(env.MAX_SCRIPTS || "6", 10);
  const findings = [];
  const meta = { host, scheme: url.protocol.replace(":", "") };
  const add = (sev, title, detail) => findings.push({ sev, title, detail });

  // --- 1. Fetch the page over HTTPS --------------------------------------
  let res, html = "", finalUrl = url.href;
  try {
    res = await tfetch("https://" + host + url.pathname, { redirect: "follow" }, timeout);
    finalUrl = res.url;
    html = await readCapped(res);
  } catch (e) {
    add("high", "Site not reachable over HTTPS", `\`https://${host}\` did not respond (${e.name}).`);
    return finalize(findings, meta, host);
  }
  const H = res.headers;
  const header = (n) => H.get(n) || "";

  // --- 2. HTTP -> HTTPS redirect -----------------------------------------
  try {
    const r = await tfetch("http://" + host + "/", { redirect: "manual" }, timeout);
    const loc = r.headers.get("location") || "";
    if (r.status >= 300 && r.status < 400 && /^https:/i.test(loc))
      add("pass", "HTTP redirects to HTTPS", `\`${r.status}\` → ${loc}`);
    else
      add("medium", "No forced HTTPS redirect", `Plain \`http://${host}\` returned ${r.status} without redirecting to HTTPS.`);
  } catch {
    add("info", "HTTP redirect check inconclusive", "Could not probe the plain-HTTP endpoint.");
  }

  // --- 3. HSTS -----------------------------------------------------------
  const hsts = header("strict-transport-security");
  if (hsts) {
    const max = parseInt((hsts.match(/max-age=(\d+)/i) || [])[1] || "0", 10);
    if (max >= 15552000)
      add("pass", "HSTS enabled", `\`${hsts}\``);
    else
      add("low", "HSTS max-age is short", `\`${hsts}\` — recommend ≥ 15552000 (180d).`);
  } else {
    add("medium", "No HSTS header", "Add `Strict-Transport-Security` to prevent SSL-strip downgrade.");
  }

  // --- 4. Security headers ----------------------------------------------
  const csp = header("content-security-policy");
  if (csp) add("pass", "Content-Security-Policy present", `\`${csp.slice(0, 120)}${csp.length > 120 ? "…" : ""}\``);
  else add("medium", "No Content-Security-Policy", "Strongest mitigation against XSS / injection is absent.");

  if (/nosniff/i.test(header("x-content-type-options"))) add("pass", "X-Content-Type-Options: nosniff", "MIME-sniffing disabled.");
  else add("low", "Missing X-Content-Type-Options", "Set `nosniff`.");

  const xfo = header("x-frame-options");
  if (xfo || /frame-ancestors/i.test(csp)) add("pass", "Clickjacking protection present", xfo ? `X-Frame-Options: ${xfo}` : "via CSP frame-ancestors");
  else add("medium", "No clickjacking protection", "No `X-Frame-Options` and no CSP `frame-ancestors`.");

  if (header("referrer-policy")) add("pass", "Referrer-Policy set", `\`${header("referrer-policy")}\``);
  else add("low", "No Referrer-Policy", "Referrer may leak to third parties.");

  if (header("permissions-policy")) add("pass", "Permissions-Policy set", "Browser features are constrained.");
  else add("info", "No Permissions-Policy", "Optional, but recommended to lock down camera/mic/geo.");

  // --- 5. Tech / version disclosure --------------------------------------
  for (const h of ["server", "x-powered-by", "x-aspnet-version", "x-generator"]) {
    const v = header(h);
    if (v && !/^cloudflare$/i.test(v))
      add("low", `Tech disclosed via \`${h}\``, `\`${v}\` — reveals stack/version to attackers.`);
  }

  // --- 6. Cookie flags ---------------------------------------------------
  const sc = H.get("set-cookie");
  if (sc) {
    const issues = [];
    if (!/;\s*secure/i.test(sc)) issues.push("no Secure");
    if (!/;\s*httponly/i.test(sc)) issues.push("no HttpOnly");
    if (!/;\s*samesite/i.test(sc)) issues.push("no SameSite");
    if (issues.length) add("medium", "Cookie set without hardening", issues.join(", ") + ".");
    else add("pass", "Cookies hardened", "Secure + HttpOnly + SameSite present.");
  }

  // --- 7. Mixed content --------------------------------------------------
  if (finalUrl.startsWith("https://")) {
    const mixed = (html.match(/(?:src|href)=["']http:\/\/[^"']+/gi) || [])
      .filter((s) => !/http:\/\/(www\.)?w3\.org/i.test(s));
    if (mixed.length)
      add("medium", "Mixed content", `${mixed.length} resource(s) loaded over plain HTTP on an HTTPS page.`);
    else add("pass", "No mixed content", "All page resources are HTTPS.");
  }

  // --- 8. Email / DNS posture -------------------------------------------
  const spf = (await txt(host)).find((t) => /^v=spf1/i.test(t));
  spf ? add("pass", "SPF record present", `\`${spf.slice(0, 90)}\``)
      : add("medium", "No SPF record", "Spoofed mail from your domain won't be rejected.");

  const dmarc = (await txt("_dmarc." + host)).find((t) => /^v=DMARC1/i.test(t));
  if (dmarc) {
    const p = (dmarc.match(/p=(\w+)/i) || [])[1] || "none";
    p === "none" ? add("low", "DMARC policy is p=none", "Monitoring only — no enforcement.")
                  : add("pass", `DMARC enforced (p=${p})`, `\`${dmarc.slice(0, 90)}\``);
  } else add("medium", "No DMARC record", "No protection against domain spoofing.");

  try {
    const z = await doh(host, "A");
    z.ad ? add("pass", "DNSSEC validated", "Answer carried the authenticated-data flag.")
         : add("info", "DNSSEC not detected", "Resolver did not return an authenticated answer.");
  } catch { add("info", "DNSSEC check inconclusive", ""); }

  try {
    const caa = await doh(host, "CAA");
    (caa.answers || []).some((a) => a.type === 257)
      ? add("pass", "CAA record present", "Certificate issuance is restricted.")
      : add("low", "No CAA record", "Any CA can issue certs for this domain.");
  } catch {}

  // --- 9. Origin-exposure heuristic --------------------------------------
  const behindCf = /cloudflare/i.test(header("server")) || !!H.get("cf-ray");
  meta.behindCdn = behindCf;
  if (behindCf) {
    const apexIps = new Set(await resolveIps(host));
    const exposed = [];
    for (const sub of ["origin", "direct", "cpanel", "webmail", "ftp", "mail", "dev", "staging"]) {
      const ips = await resolveIps(sub + "." + host);
      if (ips.length && ips.some((ip) => !apexIps.has(ip))) exposed.push(sub + "." + host);
    }
    if (exposed.length)
      add("medium", "Possible origin exposure behind the CDN",
        `These names resolve to non-CDN addresses and may bypass Cloudflare: ${exposed.join(", ")}. Verify they don't serve the origin directly.`);
    else
      add("pass", "No obvious origin-bypass subdomains", "Common direct-origin names did not resolve outside the CDN.");
  }

  // --- 10. Exposed secrets in delivered code -----------------------------
  scanSecrets(html, "the HTML", findings);
  const scripts = [...html.matchAll(/<script[^>]+src=["']([^"']+)["']/gi)]
    .map((m) => m[1])
    .filter((s) => !/^https?:\/\//i.test(s) || s.includes(host))
    .slice(0, maxScripts);
  for (const s of scripts) {
    try {
      const abs = new URL(s, finalUrl).href;
      const jr = await tfetch(abs, {}, timeout);
      scanSecrets(await readCapped(jr, 400_000), "`" + s.split("/").pop() + "`", findings);
    } catch {}
  }
  if (!findings.some((f) => /found in/.test(f.title)))
    add("pass", "No high-confidence secrets in client code", `Scanned the HTML + ${scripts.length} first-party script(s).`);

  return finalize(findings, meta, host);
}

function finalize(findings, meta, host) {
  let score = 100;
  for (const f of findings) score -= SEV_COST[f.sev] || 0;
  score = Math.max(0, score);
  const grade =
    score >= 90 ? "A" : score >= 75 ? "B" : score >= 60 ? "C" : score >= 40 ? "D" : "F";
  const order = { high: 0, medium: 1, low: 2, info: 3, pass: 4 };
  findings.sort((a, b) => order[a.sev] - order[b.sev]);
  return {
    host,
    scannedAt: new Date().toISOString(),
    grade,
    score,
    counts: findings.reduce((c, f) => ((c[f.sev] = (c[f.sev] || 0) + 1), c), {}),
    meta,
    findings,
  };
}
