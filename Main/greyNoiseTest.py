import requests
from dotenv import load_dotenv
import os

# Load keys from env
load_dotenv()

GREYNOISE_API_KEY = os.getenv("GREYNOISE_API_KEY")
API_URL = "https://api.greynoise.io/v3/community/"

HEADERS = {
    "Accept": "application/json",
    "key": GREYNOISE_API_KEY
}

# Example list of IPs (replace with your own)
ip_list = [
    "45.143.220.53",
    "198.51.100.23",
    "103.21.244.0"
]

def check_ip(ip):
    response = requests.get(API_URL + ip, headers=HEADERS)
    if response.status_code == 200:
        data = response.json()
        print(f"\n IP: {ip}")
        print(f"   Classification: {data['classification']}")
        print(f"   Name: {data.get('name', 'N/A')}")
        print(f"   Tags: {', '.join(data.get('tags', []))}")
    elif response.status_code == 404:
        print(f"\n  IP: {ip} – Not seen on GreyNoise")
    else:
        print(f"\n  Error checking {ip}: {response.status_code}")

# Loop through and check each IP
for ip in ip_list:
    check_ip(ip)