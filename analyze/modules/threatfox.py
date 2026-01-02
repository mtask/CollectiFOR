import sys
import ipaddress
import requests
import json
from datetime import datetime
from pathlib import Path

path = Path(__file__).parent.absolute()
sys.path.append(f"{path}/../")


def fetch(search_term, api_key):
    """
    Search IoCs from abuse.ch - ThreatFox
    """
    if not api_key:
        return []
    if not api_key:
        return []
    headers = {
        "Auth-Key": api_key
    }
    data = {
        'query': 'search_ioc',
        'search_term': search_term
    }
    r = requests.post('https://threatfox-api.abuse.ch/api/v1/', data=json.dumps(data), headers=headers)
    if r.status_code != 200:
        print(f"Threatfox api returned {repr(r.text)} with status code {r.status_code}")
        return []
    return r.json()

if __name__=="__main__":
    print(json.dumps(fetch(sys.argv[1], sys.argv[2]), indent=2))
