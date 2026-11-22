#!/usr/bin/env python3
"""
IP Geolocation Tracker
Resolves IP addresses to geographic and network data using multiple
providers with fallback support.
"""

import json
import sys
import urllib.request
from dataclasses import dataclass
from typing import Optional

IP_API_URL = "http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query"
IPINFO_URL = "https://ipinfo.io/{ip}/json"


@dataclass
class GeoResult:
    ip: str
    country: str
    country_code: str
    region: str
    city: str
    zip_code: str
    lat: float
    lon: float
    timezone: str
    isp: str
    org: str
    asn: str
    raw: dict


def fetch_ipapi(ip: str) -> Optional[dict]:
    """Fetch from ip-api.com (free, no key)."""
    try:
        url = IP_API_URL.format(ip=ip)
        with urllib.request.urlopen(url, timeout=10) as r:
            data = json.loads(r.read().decode())
            if data.get("status") == "success":
                return data
    except Exception:
        pass
    return None


def fetch_ipinfo(ip: str) -> Optional[dict]:
    """Fetch from ipinfo.io (fallback)."""
    try:
        url = IPINFO_URL.format(ip=ip)
        req = urllib.request.Request(url, headers={"User-Agent": "GeoLookup/1.0"})
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.loads(r.read().decode())
    except Exception:
        pass
    return None


def geolocate(ip: str) -> GeoResult:
    """Resolve IP to geolocation. Tries ip-api first, then ipinfo."""
    ip = ip.strip()
    data = fetch_ipapi(ip)
    if not data:
        data = fetch_ipinfo(ip)
    if not data:
        raise ValueError(f"Could not resolve {ip}")

    # Normalize ip-api format
    if "query" in data:
        return GeoResult(
            ip=data.get("query", ip),
            country=data.get("country", ""),
            country_code=data.get("countryCode", ""),
            region=data.get("regionName", data.get("region", "")),
            city=data.get("city", ""),
            zip_code=data.get("zip", ""),
            lat=float(data.get("lat", 0)),
            lon=float(data.get("lon", 0)),
            timezone=data.get("timezone", ""),
            isp=data.get("isp", ""),
            org=data.get("org", ""),
            asn=data.get("as", ""),
            raw=data,
        )

    # ipinfo format
    loc = data.get("loc", "0,0").split(",")
    return GeoResult(
        ip=data.get("ip", ip),
        country=data.get("country", ""),
        country_code=data.get("country", ""),
        region=data.get("region", ""),
        city=data.get("city", ""),
        zip_code=data.get("postal", ""),
        lat=float(loc[0]) if len(loc) > 0 else 0,
        lon=float(loc[1]) if len(loc) > 1 else 0,
        timezone=data.get("timezone", ""),
        isp=data.get("org", data.get("isp", "")),
        org=data.get("org", ""),
        asn=data.get("org", ""),
        raw=data,
    )


def main():
    import argparse
    parser = argparse.ArgumentParser(description="IP geolocation lookup")
    parser.add_argument("ip", nargs="*")
    parser.add_argument("-j", "--json", action="store_true")
    args = parser.parse_args()

    ips = args.ip if args.ip else [input("IP: ").strip()]

    for ip in ips:
        try:
            r = geolocate(ip)
            if args.json:
                print(json.dumps(r.raw, indent=2))
            else:
                print("=" * 45)
                print(f"IP:        {r.ip}")
                print(f"Location:  {r.city}, {r.region} {r.country_code}")
                print(f"Country:   {r.country}")
                print(f"Coords:    {r.lat}, {r.lon}")
                print(f"Timezone:  {r.timezone}")
                print(f"ISP:       {r.isp}")
                print(f"Org:       {r.org}")
                print(f"ASN:       {r.asn}")
                print("=" * 45)
        except Exception as e:
            print(f"Error ({ip}): {e}")


if __name__ == "__main__":
    main()
