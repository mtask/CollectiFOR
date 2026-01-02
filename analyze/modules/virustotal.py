import sys
import requests
from pathlib import Path

path = Path(__file__).parent.absolute()
sys.path.append(f"{path}/../")

def fetch(data, type, api_key):
    if not api_key:
        return {"error": "Missing virustotal API key"}
    if type == "filehash":
        url = f"https://www.virustotal.com/api/v3/files/{data}"
    elif type == "domain":
        url = f"https://www.virustotal.com/api/v3/domains/{data}"
    elif type == "ip":
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{data}"
    else:
        return {"error": "Unknown API call"}
    headers = {"accept": "application/json", "x-apikey": api_key}
    return requests.get(url, headers=headers).json()

def fetch_filehash(value, api_key):
    try:
        return(fetch(value, "filehash", api_key))
    except requests.RequestException as e:
        return {"error": f"Request error: {str(e)}"}
    except Exception as e:
        return {"error": f"Unexpected error: {str(e)}"}

def fetch_url(value, api_key):
    try:
        return(fetch(value, "url", api_key))
    except requests.RequestException as e:
        return {"error": f"Request error: {str(e)}"}
    except Exception as e:
        return {"error": f"Unexpected error: {str(e)}"}

def fetch_domain(value, api_key):
    try:
        return(fetch(value, "domain", api_key))
    except requests.RequestException as e:
        return {"error": f"Request error: {str(e)}"}
    except Exception as e:
        return {"error": f"Unexpected error: {str(e)}"}

def fetch_ip(value, api_key):
    try:
        return(fetch(value, "ip", api_key))
    except requests.RequestException as e:
        return {"error": f"Request error: {str(e)}"}
    except Exception as e:
        return {"error": f"Unexpected error: {str(e)}"}

if __name__=="__main__":
    fetch(sys.argv[1])
