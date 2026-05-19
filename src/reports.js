// Stores shareable reports by short id and keeps aggregate counters
// (grade distribution + total scans) for the landing page and the
// portfolio's live embed. Same honest-metrics rule as Sentinel: these
// numbers only ever reflect scans that actually ran.

const TTL_MS = 30 * 24 * 60 * 60 * 1000;

export class Reports {
  constructor(state) {
    this.state = state;
  }

  async fetch(request) {
    const url = new URL(request.url);

    if (url.pathname === "/save" && request.method === "POST") {
      const { id, report } = await request.json();
      await this.state.storage.put("r:" + id, { report, exp: Date.now() + TTL_MS });

      const t =
        (await this.state.storage.get("totals")) ||
        { total: 0, grades: { A: 0, B: 0, C: 0, D: 0, F: 0 }, since: Date.now() };
      t.total++;
      t.grades[report.grade] = (t.grades[report.grade] || 0) + 1;
      await this.state.storage.put("totals", t);
      return new Response("ok");
    }

    if (url.pathname === "/get") {
      const rec = await this.state.storage.get("r:" + url.searchParams.get("id"));
      if (!rec || rec.exp < Date.now())
        return new Response("not found", { status: 404 });
      return Response.json(rec.report);
    }

    // /stats
    const t =
      (await this.state.storage.get("totals")) ||
      { total: 0, grades: { A: 0, B: 0, C: 0, D: 0, F: 0 }, since: Date.now() };
    return Response.json(t);
  }
}
