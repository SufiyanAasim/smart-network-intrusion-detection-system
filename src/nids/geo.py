"""IP classification and optional GeoIP resolution.

Stdlib-only classification (private / public / loopback / reserved) always
works. Full geographic resolution (country + lat/long) is optional: it needs
the `geoip2` package AND a MaxMind GeoLite2-City `.mmdb` database, whose path
is given via the GEOIP_DB_PATH environment variable. Without those, callers
still get the category breakdown and a clear reason the map is unavailable.

Kept free of Streamlit imports so it can be unit tested directly.
"""

import ipaddress
import os

GEOIP_DB_ENV = "GEOIP_DB_PATH"


def classify_ip(ip):
    """Return a coarse category for an IP string.

    One of: "private", "loopback", "reserved", "public", or "invalid".
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "invalid"

    if addr.is_loopback:
        return "loopback"
    if addr.is_private:
        return "private"
    if addr.is_reserved or addr.is_link_local or addr.is_multicast or addr.is_unspecified:
        return "reserved"
    return "public"


def categorize_ips(ips):
    """Return {category: count} for an iterable of IP strings."""
    counts = {}
    for ip in ips:
        category = classify_ip(ip)
        counts[category] = counts.get(category, 0) + 1
    return counts


def geoip_db_path():
    """Return the configured MaxMind DB path, or None if unset/missing."""
    path = os.environ.get(GEOIP_DB_ENV)
    if path and os.path.exists(path):
        return path
    return None


def geoip_available():
    """True only if both the geoip2 package and a readable DB are present."""
    if geoip_db_path() is None:
        return False
    try:
        import geoip2.database  # noqa: F401
    except ImportError:
        return False
    return True


def resolve_locations(ips, db_path=None):
    """Resolve public IPs to {ip, country, latitude, longitude} dicts.

    Private/loopback/reserved/invalid IPs are skipped (they have no
    meaningful geographic location). Returns an empty list if GeoIP isn't
    available. Never raises on individual lookup failures — those IPs are
    just omitted.
    """
    path = db_path or geoip_db_path()
    if path is None:
        return []
    try:
        import geoip2.database
    except ImportError:
        return []

    results = []
    with geoip2.database.Reader(path) as reader:
        for ip in ips:
            if classify_ip(ip) != "public":
                continue
            try:
                response = reader.city(ip)
            except Exception:
                continue
            if response.location.latitude is None:
                continue
            results.append({
                "ip": ip,
                "country": response.country.name,
                "latitude": response.location.latitude,
                "longitude": response.location.longitude,
            })
    return results
