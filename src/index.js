// RealScan — external web-posture scanner on Cloudflare Workers.
//
//   GET  /                landing + scan form + live grade stats
//   POST /api/scan        { url } -> runs the scan, returns a report id
//   GET  /api/report?id=  stored report JSON (CORS, for the portfolio)
//   GET  /r/:id           shareable rendered report
//   GET  /api/stats       aggregate counters (CORS)

import { validateTarget } from "./ssrf.js";
import { runScan } from "./scan.js";
import { renderLanding, renderReport } from "./dashboard.js";

export { Reports } from "./reports.js";
export { ScanLimiter } from "./limiter.js";

const J = (o, s = 200, cors = false) =>
  new Response(JSON.stringify(o), {
    status: s,
    headers: {
      "content-type": "application/json",
      "cache-control": "no-store",
      ...(cors ? { "access-control-allow-origin": "*" } : {}),
    },
  });

const HTML = (h) =>
  new Response(h, { headers: { "content-type": "text/html; charset=utf-8" } });

function shortId() {
  const b = new Uint8Array(6);
  crypto.getRandomValues(b);
  return [...b].map((x) => x.toString(36).padStart(2, "0")).join("").slice(0, 8);
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const reports = env.REPORTS.get(env.REPORTS.idFromName("global"));

    if (url.pathname === "/" || url.pathname === "")
      return HTML(renderLanding(url.host));

    if (url.pathname === "/api/stats") {
      const r = await reports.fetch("https://do/stats");
      return new Response(await r.text(), {
        headers: {
          "content-type": "application/json",
          "cache-control": "no-store",
          "access-control-allow-origin": "*",
        },
      });
    }

    if (url.pathname === "/api/report") {
      const r = await reports.fetch("https://do/get?id=" + encodeURIComponent(url.searchParams.get("id") || ""));
      return new Response(await r.text(), {
        status: r.status,
        headers: { "content-type": "application/json", "access-control-allow-origin": "*" },
      });
    }

    if (url.pathname.startsWith("/r/")) {
      const id = url.pathname.slice(3);
      const r = await reports.fetch("https://do/get?id=" + encodeURIComponent(id));
      if (!r.ok) return HTML(renderLanding(url.host, "Report not found or expired."));
      return HTML(renderReport(await r.json(), url.host, id));
    }

    if (url.pathname === "/api/scan" && request.method === "POST") {
      let input;
      try {
        input = (await request.json()).url;
      } catch {
        return J({ error: "Send JSON { url }." }, 400, true);
      }
      if (!input || typeof input !== "string")
        return J({ error: "Missing url." }, 400, true);

      // Abuse control before doing any outbound work.
      const ip = request.headers.get("cf-connecting-ip") || "anon";
      const lim = env.SCAN_LIMITER.get(env.SCAN_LIMITER.idFromName(ip));
      const lr = await lim.fetch("https://do/", {
        method: "POST",
        body: JSON.stringify({
          limit: parseInt(env.SCAN_LIMIT || "8", 10),
          windowMs: parseInt(env.SCAN_WINDOW_MS || "600000", 10),
        }),
      });
      const { limited, retryAfter } = await lr.json();
      if (limited)
        return J({ error: `Rate limited. Try again in ${retryAfter}s.` }, 429, true);

      const v = await validateTarget(input);
      if (!v.ok) return J({ error: v.error }, 400, true);

      let report;
      try {
        report = await runScan(v.url, v.host, env);
      } catch (e) {
        return J({ error: "Scan failed: " + e.name }, 502, true);
      }

      const id = shortId();
      ctx.waitUntil(
        reports.fetch("https://do/save", {
          method: "POST",
          body: JSON.stringify({ id, report }),
        })
      );
      return J({ id, path: "/r/" + id, report }, 200, true);
    }

    return new Response("Not found", { status: 404 });
  },
};
