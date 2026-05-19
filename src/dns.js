// DNS-over-HTTPS via Cloudflare 1.1.1.1 (JSON API).
// One small helper used by both the SSRF guard and the scan engine.

const DOH = "https://cloudflare-dns.com/dns-query";

export async function doh(name, type, timeoutMs = 6000) {
  const u = new URL(DOH);
  u.searchParams.set("name", name);
  u.searchParams.set("type", type);
  const r = await fetch(u, {
    headers: { accept: "application/dns-json" },
    signal: AbortSignal.timeout(timeoutMs),
  });
  if (!r.ok) throw new Error("DoH " + r.status);
  const j = await r.json();
  return {
    status: j.Status, // 0 = NOERROR
    ad: !!j.AD, // DNSSEC-validated answer
    answers: (j.Answer || []).map((a) => ({ type: a.type, data: a.data })),
  };
}

// Collect every A/AAAA address a hostname resolves to.
export async function resolveIps(host) {
  const ips = [];
  for (const t of ["A", "AAAA"]) {
    try {
      const res = await doh(host, t);
      for (const a of res.answers) {
        if ((t === "A" && a.type === 1) || (t === "AAAA" && a.type === 28)) {
          ips.push(a.data);
        }
      }
    } catch {
      /* one family failing is fine */
    }
  }
  return ips;
}

// TXT records, with the surrounding quotes/whitespace normalised.
export async function txt(name) {
  try {
    const res = await doh(name, "TXT");
    return res.answers
      .filter((a) => a.type === 16)
      .map((a) => a.data.replace(/^"|"$/g, "").replace(/"\s+"/g, ""));
  } catch {
    return [];
  }
}
