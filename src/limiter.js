// Per-client scan rate limiter. A scanner makes outbound requests on
// behalf of whoever calls it — so the budget here is about not letting
// RealScan be used to hammer third parties, not about UX.

export class ScanLimiter {
  constructor(state) {
    this.state = state;
  }

  async fetch(request) {
    const { limit, windowMs } = await request.json();
    const now = Date.now();
    const cutoff = now - windowMs;

    let hits = (await this.state.storage.get("hits")) || [];
    hits = hits.filter((t) => t > cutoff);

    if (hits.length >= limit) {
      const retryAfter = Math.ceil((hits[0] + windowMs - now) / 1000);
      return Response.json({ limited: true, retryAfter });
    }
    hits.push(now);
    await this.state.storage.put("hits", hits);
    return Response.json({ limited: false, remaining: limit - hits.length });
  }
}
