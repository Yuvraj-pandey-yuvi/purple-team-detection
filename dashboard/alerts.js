/* Shared alert list + detail view for the main page and the alerts page. All text via textContent. */
(function () {
  "use strict";
  const el = (t, c, x) => { const e = document.createElement(t); if (c) e.className = c; if (x !== undefined && x !== null) e.textContent = x; return e; };
  const fmt = n => Number(n || 0).toLocaleString("en-US");
  const when = iso => iso ? iso.slice(0, 16).replace("T", " ") + " UTC" : "";
  const css = `.al{border-top:1px solid #172033}.al:first-child{border-top:0}
.al>.hd{display:flex;gap:12px;align-items:flex-start;padding:11px 6px;cursor:pointer}.al>.hd:hover,.al>.hd:focus-visible{background:#131c2c;outline:none}
.al .tx{flex:1;min-width:0}.al .ds{overflow-wrap:anywhere}.al .mt{color:#8b98ad;font-size:12px;margin-top:2px}.al .cv{color:#8b98ad;transition:transform .15s}.al.open .cv{transform:rotate(90deg)}
.al .dt{display:none;margin:0 6px 12px;padding:14px;background:#0c121d;border:1px solid #1c2636;border-radius:10px}.al.open .dt{display:block}
.dg{display:grid;grid-template-columns:150px 1fr;gap:6px 14px;font-size:13px}.dg b{color:#8b98ad;font-weight:600}.dg span{overflow-wrap:anywhere;font-family:ui-monospace,Menlo,monospace}
.dt h4{margin:14px 0 6px;font-size:11px;letter-spacing:.12em;text-transform:uppercase;color:#8b98ad}.dt pre{margin:0;padding:10px;background:#080c14;border-radius:8px;overflow:auto;white-space:pre-wrap;overflow-wrap:anywhere;font-size:12px}
.pg{display:flex;gap:12px;align-items:center;justify-content:space-between;padding:12px 6px 0;color:#8b98ad;font-size:13px}.pg button,.btn{background:#16203a;color:#e6eaf2;border:1px solid #2a3556;border-radius:8px;padding:6px 14px;cursor:pointer;font:inherit;text-decoration:none}.pg button:disabled{opacity:.4;cursor:default}
.sev{font-size:10px;font-weight:700;padding:2px 7px;border-radius:5px;letter-spacing:.06em;flex:none;margin-top:2px}.CRITICAL{background:#5b1325;color:#ff8fa5}.HIGH{background:#5a3207;color:#ffc069}.MEDIUM{background:#4a3f0a;color:#ffe27a}.LOW,.INFO{background:#16314a;color:#8ecbff}
@media(max-width:600px){.dg{grid-template-columns:1fr}}`;
  document.head.append(el("style", "", css));

  async function getJSON(path) {
    const r = await fetch(path, { cache: "no-store" });
    if (!r.ok) throw new Error("HTTP " + r.status);
    return r.json();
  }

  function detail(d) {
    const box = el("div"), g = el("div", "dg");
    [["Alert ID", d.id], ["Rule", d.rule_id], ["ATT&CK technique", d.technique], ["Severity", d.severity], ["Log source", d.log_source],
     ["Time", when(d.timestamp)], ["First seen", when(d.first_seen)], ["Last seen", when(d.last_seen)], ["Source IP", d.source_ip],
     ["Username", d.username], ["Audit uid", d.auid], ["Dedup key", d.dedup_key]]
      .filter(r => r[1] !== null && r[1] !== undefined && r[1] !== "").forEach(r => g.append(el("b", "", r[0]), el("span", "", r[1])));
    box.append(g, el("h4", "", "Description"), el("pre", "", d.description));
    const keys = Object.keys(d.extra || {});
    if (keys.length) { box.append(el("h4", "", "Extra fields")); const x = el("div", "dg"); keys.forEach(k => x.append(el("b", "", k), el("span", "", d.extra[k]))); box.append(x); }
    box.append(el("h4", "", "Raw log"), el("pre", "", d.raw_log || (d.raw_log_note ? "Raw log " + d.raw_log_note : "No raw log stored for this alert")));
    return box;
  }

  function row(a) {
    const r = el("div", "al"), h = el("div", "hd"), t = el("div", "tx"), m = el("div", "mt");
    h.setAttribute("role", "button"); h.tabIndex = 0; h.setAttribute("aria-expanded", "false");
    t.append(el("div", "ds", a.description));
    m.textContent = [a.rule_id, a.log_source, a.source_ip, when(a.ts)].filter(Boolean).join("  ·  ");
    t.append(m); h.append(el("span", "sev " + a.severity, a.severity), t, el("span", "cv", "▸"));
    const d = el("div", "dt"); r.append(h, d);
    const toggle = async () => {
      const open = r.classList.toggle("open"); h.setAttribute("aria-expanded", String(open));
      if (open && !d.firstChild) {
        d.textContent = "Loading…";
        try { d.textContent = ""; d.append(detail(await getJSON("/api/alerts/" + encodeURIComponent(a.id)))); }
        catch (e) { d.textContent = "Could not load detail (" + e.message + ")"; }
      }
    };
    h.addEventListener("click", toggle);
    h.addEventListener("keydown", e => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); toggle(); } });
    return r;
  }

  /* load(root, params, {onPage}) -> fetches /api/alerts?params, renders rows (+pager when onPage given) */
  async function load(root, params, opts) {
    opts = opts || {};
    root.textContent = "Loading alerts…";
    let data;
    try { data = await getJSON("/api/alerts?" + new URLSearchParams(params)); }
    catch (e) { root.textContent = "Alerts are not available right now (" + e.message + ")."; return null; }
    root.textContent = "";
    if (!data.items.length) root.append(el("div", "mt", "No alerts in this period."));
    data.items.forEach(a => root.append(row(a)));
    if (opts.onPage) {
      const first = (data.page - 1) * data.per_page + 1, p = el("div", "pg"), prev = el("button", "", "← Previous"), next = el("button", "", "Next →");
      prev.disabled = data.page <= 1; next.disabled = data.page >= data.pages;
      prev.onclick = () => opts.onPage(data.page - 1); next.onclick = () => opts.onPage(data.page + 1);
      p.append(el("span", "", data.total ? "Showing " + fmt(first) + "–" + fmt(first + data.items.length - 1) + " of " + fmt(data.total) : ""), el("span", "", "Page " + data.page + " of " + data.pages), prev, next);
      root.append(p);
    }
    return data;
  }
  window.AlertsUI = { load, getJSON, fmt, when };
})();
