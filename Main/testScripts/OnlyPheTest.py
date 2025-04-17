import requests
from dotenv import load_dotenv
import os

# Load keys from env
load_dotenv()

ONLYPHE_API_KEY = os.getenv("ONLYPHE_API_KEY")
API_URL = "https://ipinfo.io/"

# The IP you want to query
ip = "8.8.8.8"

# Endpoint: summary for an IP address
url = f"{API_URL}/summary/ip/{ip}"

# HTTP headers with API key
headers = {
    "Authorization": f"apikey {ONLYPHE_API_KEY}"
}

# Make the request
response = requests.get(url, headers=headers)

# Handle the response
if response.status_code == 200:
    data = response.json()
    print(f"\nSummary for IP: {ip}")
    print("Results count:", data.get("count", 0))
    for key, value in data.items():
        if isinstance(value, list):
            print(f"\n{key.title()}:")
            for item in value[:3]:  # show a few items if list is long
                print("  ", item)
        elif key != "results":
            print(f"{key.title()}: {value}")
else:
    print(f"Failed to fetch data: {response.status_code}")
    print("Response:", response.text)