import requests
from dotenv import load_dotenv
import os

# Load keys from env
load_dotenv()

IPINFO_API_KEY = os.getenv("IPINFO_API_KEY")
API_URL = "https://ipinfo.io/"

# Example IP address to query
ip_address = '8.8.8.8'  # You can change this to any IP you want to query

# Construct the URL for the API request
url = f'{API_URL}{ip_address}/json?token={IPINFO_API_KEY}'

# Make the GET request to the IPinfo API
response = requests.get(url)

# Check if the request was successful
if response.status_code == 200:
    data = response.json()
    
    print(f"Information for IP: {ip_address}")
    print(f"IP Address: {data.get('ip', 'N/A')}")
    print(f"Hostname: {data.get('hostname', 'N/A')}")
    print(f"City: {data.get('city', 'N/A')}")
    print(f"Region: {data.get('region', 'N/A')}")
    print(f"Country: {data.get('country', 'N/A')}")
    print(f"Location: {data.get('loc', 'N/A')}")
    print(f"Organization: {data.get('org', 'N/A')}")
    print(f"ASN: {data.get('asn', {}).get('asn', 'N/A')}")
    print(f"Carrier: {data.get('carrier', 'N/A')}")
    print(f"VPN/Proxy?: {data.get('privacy', {}).get('vpn', 'N/A')}")

else:
    print(f"Failed to retrieve data for IP {ip_address}. Status code: {response.status_code}")