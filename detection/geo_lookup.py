# detection/geo_lookup.py
"""
Attacker geolocation, done ONCE per IP on the server and cached on disk.

WHY here and not in the browser: the old dashboard called http://ip-api.com from every
visitor's browser. That breaks under HTTPS (mixed content), hits a per-visitor rate
limit, and repeats every lookup for every viewer. Here the engine looks each IP up
once, over HTTPS, and the page only draws what is already in the summary file.

Failure design: the free service has no uptime guarantee and its limits are stated
inconsistently, so a failed or rate-limited lookup only means "this IP has no pin yet".
Nothing else breaks, and the IP is retried on a later cycle.
"""
import ipaddress
import json
import os
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone

API_URL = "https://ipwho.is/{ip}?fields=success,message,latitude,longitude,city,country,country_code"
RETRY_AFTER = timedelta(hours=1)      # do not hammer an IP whose lookup failed
MAX_NEW_PER_CYCLE = 20               # stays far below the free daily limit
TIMEOUT_SECONDS = 4


class RateLimited(Exception):
    """The service answered 429: stop looking things up for this cycle."""


def is_public_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def fetch_ipwho(ip: str) -> dict | None:
    """One HTTPS lookup. Returns a clean dict or None. Raises RateLimited on HTTP 429."""
    try:
        with urllib.request.urlopen(API_URL.format(ip=ip), timeout=TIMEOUT_SECONDS) as response:
            data = json.load(response)
    except urllib.error.HTTPError as error:
        if error.code == 429:
            raise RateLimited() from error
        return None
    except (urllib.error.URLError, TimeoutError, ValueError, OSError):
        return None
    if not data.get("success"):
        return None
    try:
        return {
            "lat": float(data["latitude"]), "lon": float(data["longitude"]),
            "city": str(data.get("city") or "")[:60],
            "country": str(data.get("country") or "")[:60],
            "cc": str(data.get("country_code") or "")[:2],
        }
    except (KeyError, TypeError, ValueError):
        return None


def load_cache(path: str) -> dict:
    try:
        with open(path) as f:
            cache = json.load(f)
        return cache if isinstance(cache, dict) else {}
    except (FileNotFoundError, ValueError):
        return {}


def save_cache(path: str, cache: dict) -> None:
    temp_path = path + ".tmp"
    with open(temp_path, "w") as f:
        json.dump(cache, f)
        f.flush()
        os.fsync(f.fileno())
    os.replace(temp_path, path)


def enrich(ips, cache_path: str, fetch=fetch_ipwho, max_new: int = MAX_NEW_PER_CYCLE,
           now: datetime | None = None) -> dict:
    """Return {ip: {lat, lon, city, country, cc}} for every IP we know a location for.

    New IPs are looked up (at most max_new per call), good answers are cached forever,
    failures are remembered with a time so they are retried only after RETRY_AFTER.
    """
    now = now or datetime.now(timezone.utc)
    cache = load_cache(cache_path)
    looked_up = 0
    changed = False

    for ip in ips:
        if not is_public_ip(ip):
            continue
        entry = cache.get(ip)
        if entry and "lat" in entry:
            continue                                   # already located: never ask again
        if entry and "failed_at" in entry:
            failed_at = datetime.fromisoformat(entry["failed_at"])
            if now - failed_at < RETRY_AFTER:
                continue
        if looked_up >= max_new:
            break
        looked_up += 1
        try:
            result = fetch(ip)
        except RateLimited:
            break                                      # stop for this cycle, keep what we have
        cache[ip] = result if result else {"failed_at": now.isoformat()}
        changed = True

    if changed:
        save_cache(cache_path, cache)
    return {ip: entry for ip, entry in cache.items() if "lat" in entry}
