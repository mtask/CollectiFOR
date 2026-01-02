import requests
import sys

def fetch(ip_address, api_key):
    """
    Fetch IP information from ipinfo.io for a single IP address.
    Returns a dict with IP details or empty dict if error.
    """
    if not api_key:
        return {}

    url = f"https://ipinfo.io/{ip_address}/json?token={api_key}"
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        data = response.json()
        return {
            "ip": data.get("ip"),
            "hostname": data.get("hostname"),
            "city": data.get("city"),
            "region": data.get("region"),
            "country": data.get("country"),
            "loc": data.get("loc"),  # lat,long
            "org": data.get("org"),
            "postal": data.get("postal"),
            "timezone": data.get("timezone"),
            "readme": data.get("readme"),
        }
    except requests.RequestException:
        return {}

