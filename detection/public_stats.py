# detection/public_stats.py
"""
Per-day honeypot statistics for the dashboard's date picker, plus the key findings and the
"who attacked when" data.

The engine builds public_stats.db (one JSON row per UTC day plus an 'all' row). The read-only
dashboard pod fetches ONE row per request, so it never touches the live honeypot database.
Same safety pattern as the other public files: atomic swap, skipped when nothing changed,
attacker-controlled text flattened/capped (via public_attackers), URLs defanged.
"""
import hashlib
import json
import os
import re
import sqlite3
from collections import Counter, defaultdict
from datetime import date, datetime, timedelta, timezone

from detection import public_alerts, public_attackers as pat

SCHEMA_VERSION = "1"
TOP_ATTACKERS, TOP_LIST, MAP_CAP, CAMPAIGN_ROWS = 15, 8, 600, 8
MAP_SSH_RESERVE = 150            # map slots kept for SSH scanners: they have no honeypot sessions, so they sort last
_DAY = re.compile(r"^(all|\d{4}-\d{2}-\d{2})$")


class _Scope:
    def __init__(self):
        self.ips, self.attempts, self.users, self.pwds, self.cmds = Counter(), Counter(), Counter(), Counter(), Counter()
        self.hours = [0] * 24
        self.cmd_sessions = 0

    def add(self, other: "_Scope"):
        self.ips.update(other.ips); self.attempts.update(other.attempts); self.users.update(other.users)
        self.pwds.update(other.pwds); self.cmds.update(other.cmds); self.cmd_sessions += other.cmd_sessions
        self.hours = [a + b for a, b in zip(self.hours, other.hours)]


def _load(connection) -> dict[str, _Scope]:
    days: dict[str, _Scope] = defaultdict(_Scope)
    day = "substr(s.start_time, 1, 10)"
    for d, ip, n in connection.execute(f"SELECT {day}, s.src_ip, COUNT(*) FROM sessions s WHERE s.start_time IS NOT NULL GROUP BY 1, 2"):
        days[d].ips[ip] = n
    for d, h, n in connection.execute(f"SELECT {day}, substr(s.start_time, 12, 2), COUNT(*) FROM sessions s WHERE s.start_time IS NOT NULL GROUP BY 1, 2"):
        if h.isdigit() and int(h) < 24:
            days[d].hours[int(h)] = n
    joins = "FROM {t} x JOIN sessions s ON s.session_id = x.session_id WHERE s.start_time IS NOT NULL GROUP BY 1, 2"
    for d, ip, n in connection.execute(f"SELECT {day}, s.src_ip, COUNT(*) " + joins.format(t="session_logins")):
        days[d].attempts[ip] = n
    for d, v, n in connection.execute(f"SELECT {day}, x.username, COUNT(*) " + joins.format(t="session_logins")):
        days[d].users[v] = n
    for d, v, n in connection.execute(f"SELECT {day}, x.password, COUNT(*) " + joins.format(t="session_logins")):
        days[d].pwds[v] = n
    for d, v, n in connection.execute(f"SELECT {day}, x.command_text, COUNT(*) " + joins.format(t="session_commands")):
        days[d].cmds[v] = n
    for d, n in connection.execute(f"SELECT {day}, COUNT(DISTINCT x.session_id) " + "FROM session_commands x JOIN sessions s ON s.session_id = x.session_id WHERE s.start_time IS NOT NULL GROUP BY 1"):
        days[d].cmd_sessions = n
    return days


def _place(geo, ip):
    return geo.get(ip) or {}


def assemble(day: str, sc: _Scope, geo: dict, by_ip: dict) -> dict:
    """One scope (a day or all time). by_ip maps ip -> [public alerts, SSH alerts] for that scope, so
    attackers that only the detections saw (for example SSH brute force on the real server) show up too."""
    total = sum(sc.ips.values())
    countries, networks, located = {}, {}, 0
    for ip, n in sc.ips.items():                      # honeypot statistics count sessions only
        p = _place(geo, ip)
        if "lat" in p:
            located += n
            c = countries.setdefault(p.get("cc") or "??", {"cc": p.get("cc") or "??", "country": p.get("country") or "Unknown", "sessions": 0, "attackers": 0})
            c["sessions"] += n; c["attackers"] += 1
            k = p.get("org") or "Unknown network"
            w = networks.setdefault(k, {"network": k, "sessions": 0, "attackers": 0})
            w["sessions"] += n; w["attackers"] += 1
    counts = lambda ip: by_ip.get(ip, [0, 0])
    kind = lambda ip: "both" if sc.ips.get(ip) and counts(ip)[1] else ("ssh" if not sc.ips.get(ip) else "honeypot")
    order = sorted(set(sc.ips) | set(by_ip), key=lambda ip: (-sc.ips.get(ip, 0), -counts(ip)[0], ip))
    ssh_only = [ip for ip in order if ip not in sc.ips][:3]                     # always leave room for a few of them
    shown = [ip for ip in order if ip not in ssh_only][:TOP_ATTACKERS - len(ssh_only)] + ssh_only
    attackers, points = [], []
    for ip in shown:
        p = _place(geo, ip)
        attackers.append({"ip": pat.flat(ip, 45), "sessions": sc.ips.get(ip, 0), "alerts": counts(ip)[0], "attempts": sc.attempts.get(ip, 0),
                          "kind": kind(ip), "cc": p.get("cc"), "country": p.get("country"), "network": p.get("org") or None})
    mappable = [ip for ip in order if "lat" in _place(geo, ip)]
    ssh_pins = [ip for ip in mappable if ip not in sc.ips][:MAP_SSH_RESERVE]       # reserved: the cap must never hide them
    on_map = ssh_pins + [ip for ip in mappable if ip in sc.ips][:MAP_CAP - len(ssh_pins)]
    for ip in on_map:
        p = _place(geo, ip)
        points.append({"ip": pat.flat(ip, 45), "lat": round(p["lat"], 2), "lon": round(p["lon"], 2), "sessions": sc.ips.get(ip, 0),
                       "alerts": counts(ip)[0], "cc": p.get("cc"), "kind": kind(ip)})
    top = lambda d: sorted(d.values(), key=lambda x: -x["sessions"])[:10]
    cmd_total = sum(sc.cmds.values())
    return {
        "day": day, "sessions": total, "attackers_count": len(sc.ips), "attempts": sum(sc.attempts.values()),
        "ssh_scanners": sum(1 for ip in by_ip if ip not in sc.ips), "alerts": sum(v[0] for v in by_ip.values()),
        "attackers": attackers, "countries": top(countries), "networks": top(networks), "map": points, "map_total": len(mappable),
        "located_sessions": located, "hours": sc.hours,
        "usernames": [{"value": pat.flat(v, 40), "count": n} for v, n in sc.users.most_common(TOP_LIST)],
        "passwords": [{"value": pat.flat(v, 40), "count": n} for v, n in sc.pwds.most_common(TOP_LIST)],
        "commands": {"total": cmd_total, "distinct": len(sc.cmds), "sessions_with_commands": sc.cmd_sessions, "sessions_total": total,
                     "top": [{"value": pat.display_command(v), "count": n, "meaning": pat.meaning_of(v)} for v, n in sc.cmds.most_common(TOP_LIST)],
                     "other": cmd_total - sum(n for _, n in sc.cmds.most_common(TOP_LIST))},
    }


def alert_scopes(alerts) -> dict:
    """day -> ip -> [public alerts, SSH (auth_log) alerts] for public alerts that carry a source IP."""
    out: dict = defaultdict(dict)
    for a in alerts:
        if not a.source_ip or not public_alerts.is_public(a):
            continue
        rec = out[public_alerts.event_moment(a).date().isoformat()].setdefault(a.source_ip, [0, 0])
        rec[0] += 1
        rec[1] += 1 if public_alerts._enum(a.log_source) == "auth_log" else 0
    return out


def findings(allscope: _Scope) -> list[dict]:
    total = sum(allscope.ips.values())
    if not total:
        return []
    out = []
    top3 = sum(n for _, n in allscope.ips.most_common(3))
    out.append({"stat": f"{round(100 * top3 / total)}%", "text": "of all honeypot sessions came from just three IP addresses."})
    cmd_total = sum(allscope.cmds.values())
    if cmd_total:
        share = allscope.cmds.most_common(1)[0][1] / cmd_total
        with_cmd = allscope.cmd_sessions / total
        out.append({"stat": f"{round(100 * share)}%", "text": f"of the commands typed were the same one-line check, and {round(100 * with_cmd)}% of sessions ran a command at all. That looks like automation, not people."})
    logins = sum(allscope.users.values())
    if logins:
        out.append({"stat": f"{round(100 * allscope.users.get('root', 0) / logins)}%", "text": "of login attempts used the username “root”."})
    return out


def campaigns(days: dict[str, _Scope], geo: dict) -> dict:
    """Top attackers' activity per day across the whole period (for the 'who attacked when' chart)."""
    if not days:
        return {"days": [], "rows": []}
    first, last = date.fromisoformat(min(days)), date.fromisoformat(max(days))
    span = [(first + timedelta(days=i)).isoformat() for i in range((last - first).days + 1)]
    totals = Counter()
    for sc in days.values():
        totals.update(sc.ips)
    rows = []
    for ip, _ in totals.most_common(CAMPAIGN_ROWS):
        p = _place(geo, ip)
        rows.append({"ip": pat.flat(ip, 45), "cc": p.get("cc"), "network": p.get("org") or None, "total": totals[ip],
                     "counts": [days[d].ips.get(ip, 0) if d in days else 0 for d in span]})
    return {"days": span, "rows": rows}


def build(cowrie_db: str, geo: dict, out_path: str, now=None, alerts=()) -> dict:
    connection = pat._ro(cowrie_db)
    try:
        days = _load(connection)
    finally:
        connection.close()
    by_day = alert_scopes(alerts)
    for d in by_day:
        days[d]                                                   # a day with alerts but no honeypot visit still gets a row
    allscope = _Scope()
    for sc in days.values():
        allscope.add(sc)
    merged: dict = {}
    for m in by_day.values():
        for ip, (n, ssh) in m.items():
            rec = merged.setdefault(ip, [0, 0]); rec[0] += n; rec[1] += ssh
    rows = {"all": assemble("all", allscope, geo, merged)}
    for d, sc in days.items():
        rows[d] = assemble(d, sc, geo, by_day.get(d, {}))
    payload = {k: json.dumps(v, separators=(",", ":")) for k, v in rows.items()}
    fingerprint = hashlib.sha1((SCHEMA_VERSION + "|" + "|".join(k + payload[k] for k in sorted(payload))).encode()).hexdigest()
    try:
        c = sqlite3.connect(f"file:{out_path}?mode=ro", uri=True)
        current = c.execute("SELECT value FROM meta WHERE key='fingerprint'").fetchone()
        c.close()
        unchanged = bool(current and current[0] == fingerprint)
    except sqlite3.Error:
        unchanged = False
    if not unchanged:
        temp = out_path + ".tmp"
        if os.path.exists(temp):
            os.remove(temp)
        c = sqlite3.connect(temp)
        try:
            c.executescript("CREATE TABLE stats (day TEXT PRIMARY KEY, data TEXT NOT NULL); CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);")
            c.executemany("INSERT INTO stats VALUES (?, ?)", payload.items())
            c.execute("INSERT INTO meta VALUES ('fingerprint', ?)", (fingerprint,))
            c.commit()
        finally:
            c.close()
        os.replace(temp, out_path)
    stat_days = sorted(({"day": d, "sessions": sum(sc.ips.values()), "alerts": sum(v[0] for v in by_day.get(d, {}).values())} for d, sc in days.items()),
                       key=lambda x: x["day"], reverse=True)
    return {"stat_days": stat_days, "findings": findings(allscope), "campaigns": campaigns(days, geo)}


def get(db_path: str, day: str):
    if not _DAY.match(str(day)):
        return None
    c = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=5)
    try:
        row = c.execute("SELECT data FROM stats WHERE day = ?", (day,)).fetchone()
    finally:
        c.close()
    return json.loads(row[0]) if row else None
