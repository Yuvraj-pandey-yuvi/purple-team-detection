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

from detection import public_attackers as pat

SCHEMA_VERSION = "1"
TOP_ATTACKERS, TOP_LIST, MAP_CAP, CAMPAIGN_ROWS = 15, 8, 600, 8
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


def assemble(day: str, sc: _Scope, geo: dict) -> dict:
    total = sum(sc.ips.values())
    attackers, countries, networks, points, located = [], {}, {}, [], 0
    for rank, (ip, n) in enumerate(sc.ips.most_common()):
        p = _place(geo, ip)
        if rank < TOP_ATTACKERS:
            attackers.append({"ip": pat.flat(ip, 45), "sessions": n, "attempts": sc.attempts.get(ip, 0), "cc": p.get("cc"),
                              "country": p.get("country"), "network": p.get("org") or None})
        if "lat" in p:
            located += n
            if len(points) < MAP_CAP:
                points.append({"ip": pat.flat(ip, 45), "lat": round(p["lat"], 2), "lon": round(p["lon"], 2), "sessions": n, "cc": p.get("cc")})
            c = countries.setdefault(p.get("cc") or "??", {"cc": p.get("cc") or "??", "country": p.get("country") or "Unknown", "sessions": 0, "attackers": 0})
            c["sessions"] += n; c["attackers"] += 1
            k = p.get("org") or "Unknown network"
            w = networks.setdefault(k, {"network": k, "sessions": 0, "attackers": 0})
            w["sessions"] += n; w["attackers"] += 1
    top = lambda d: sorted(d.values(), key=lambda x: -x["sessions"])[:10]
    cmd_total = sum(sc.cmds.values())
    return {
        "day": day, "sessions": total, "attackers_count": len(sc.ips), "attempts": sum(sc.attempts.values()),
        "attackers": attackers, "countries": top(countries), "networks": top(networks), "map": points,
        "located_sessions": located, "hours": sc.hours,
        "usernames": [{"value": pat.flat(v, 40), "count": n} for v, n in sc.users.most_common(TOP_LIST)],
        "passwords": [{"value": pat.flat(v, 40), "count": n} for v, n in sc.pwds.most_common(TOP_LIST)],
        "commands": {"total": cmd_total, "distinct": len(sc.cmds), "sessions_with_commands": sc.cmd_sessions, "sessions_total": total,
                     "top": [{"value": pat.display_command(v), "count": n, "meaning": pat.meaning_of(v)} for v, n in sc.cmds.most_common(TOP_LIST)],
                     "other": cmd_total - sum(n for _, n in sc.cmds.most_common(TOP_LIST))},
    }


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


def build(cowrie_db: str, geo: dict, out_path: str, now=None) -> dict:
    connection = pat._ro(cowrie_db)
    try:
        days = _load(connection)
    finally:
        connection.close()
    allscope = _Scope()
    for sc in days.values():
        allscope.add(sc)
    rows = {"all": assemble("all", allscope, geo)}
    for d, sc in days.items():
        rows[d] = assemble(d, sc, geo)
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
    stat_days = sorted(({"day": d, "sessions": sum(sc.ips.values())} for d, sc in days.items()), key=lambda x: x["day"], reverse=True)
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
