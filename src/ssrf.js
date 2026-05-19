// SSRF guard. A public scanner that fetches arbitrary user-supplied URLs
// is an attack proxy unless every target is validated. Rules:
//
//   * http/https only, default ports only
//   * no IP literals (force a real hostname)
//   * resolve the host and reject if ANY address is private/reserved
//
// This is the most security-sensitive file in the project.

import { resolveIps } from "./dns.js";

function ipv4Private(ip) {
  const p = ip.split(".").map(Number);
  if (p.length !== 4 || p.some((n) => Number.isNaN(n) || n < 0 || n > 255))
    return true; // malformed -> treat as unsafe
  const [a, b] = p;
  return (
    a === 0 ||
    a === 10 ||
    a === 127 ||
    (a === 169 && b === 254) || // link-local + cloud metadata 169.254.169.254
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    (a === 100 && b >= 64 && b <= 127) || // CGNAT
    a >= 224 // multicast / reserved
  );
}

function ipv6Unsafe(ip) {
  const x = ip.toLowerCase();
  return (
    x === "::1" ||
    x === "::" ||
    x.startsWith("fe80") || // link-local
    x.startsWith("fc") ||
    x.startsWith("fd") || // unique-local
    x.startsWith("::ffff:") // IPv4-mapped -> could smuggle a private v4
  );
}

export async function validateTarget(input) {
  let url;
  try {
    url = new URL(/^https?:\/\//i.test(input) ? input : "https://" + input);
  } catch {
    return { ok: false, error: "Not a valid URL." };
  }

  if (url.protocol !== "https:" && url.protocol !== "http:")
    return { ok: false, error: "Only http/https is supported." };
  if (url.port && url.port !== "80" && url.port !== "443")
    return { ok: false, error: "Only default ports (80/443) are allowed." };

  const host = url.hostname.toLowerCase();
  if (
    host === "localhost" ||
    host.endsWith(".localhost") ||
    host.endsWith(".internal") ||
    host.endsWith(".local")
  )
    return { ok: false, error: "Internal hostnames are blocked." };

  // Reject raw IP literals — we want a resolvable public name.
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.includes(":"))
    return { ok: false, error: "Use a hostname, not an IP address." };

  const ips = await resolveIps(host);
  if (ips.length === 0)
    return { ok: false, error: "Host does not resolve." };
  for (const ip of ips) {
    const bad = ip.includes(":") ? ipv6Unsafe(ip) : ipv4Private(ip);
    if (bad)
      return { ok: false, error: "Host resolves to a private/reserved address." };
  }

  return { ok: true, url, host, ips };
}
