import shodan
import requests
from dotenv import load_dotenv
import os

# Load the .env file
load_dotenv()

#apikey = os.getenv('apikey')


# Function takes deviceType, country tag, and a port
# Returns a dictionary of all found matches
# IP: {ip}
# HTTP Banner
# Date found
# Server type
# Web location
# Length of request
# Type of request
# For getting all the internet facing devices
def shodanFunc(deviceType, country=None, port=None):
    SHODAN_API_KEY=os.getenv('SHODAN_API_KEY')
    api = shodan.Shodan(SHODAN_API_KEY)
    try:

        # Search Shodan
        results = api.search(deviceType)

        ipList = []

        print(type(results))
        print(results.keys())
        
        print('Results found: {}'.format(results['total']))
        
        for result in results['matches']:
                print('IP: {}'.format(result['ip_str']))
                print(result['data'])
                print('')
                ipList.append(result['ip_str'])
        

        return ipList
    
    except shodan.APIError as e:
        print('Error: {}'.format(e))

# Accepts a list of IP strings
# Returns tagged IPs with some more information
# For threat information
def greyNoiseFunc(ipList):
    print(ipList)

    # Load the key and prepare the greynoise webpage
    GREYNOISE_API_KEY = os.getenv("GREYNOISE_API_KEY")
    API_URL = "https://api.greynoise.io/v3/community/"

    # Allow the webpage to accept the API key
    HEADERS = {
        "Accept": "application/json",
        "key": GREYNOISE_API_KEY
    }

    # This will send the ip to greyNoise
    def check_ip(singleIP):
        
        # Send the request
        response = requests.get(API_URL + singleIP, headers=HEADERS)
        if response.status_code == 200:

            # Collect the json
            data = response.json()

            # Send the json for parsing
            collectedData = collectFlat(data)
            return collectedData
        
        # If the request fails
        elif response.status_code == 404:
            print(f"\n IP: {singleIP} - Not seen on GreyNoise")

        # 429: Credits exceeded
        else:
            print(f"\n Error checking {singleIP}: {response.status_code}")
    
    for ip in ipList:
        check_ip(ip)

# Takes a list of IP addresses
# Returns a dictionary of
# More information than Shodan
# Ip, Hostname, City, Region, Country, Lat/Long, Organization, ASN, Carrier, and VPN/Proxy
def ipInfo(ipAddressList):
    IPINFO_API_KEY = os.getenv("IPINFO_API_KEY")
    API_URL = "https://ipinfo.io/"
    
    
    for ipAddress in ipAddressList:

        # Construct the URL for the API request
        url = f'{API_URL}{ipAddress}/json?token={IPINFO_API_KEY}'

        # Make the GET request to the IPinfo API
        response = requests.get(url)

        # Check if the request was successful
        if response.status_code == 200:
            data = response.json()

            collectData = collectFlat(data)
            return collectData

        else:
            print(f"Failed to retrieve data for IP {ipAddress}. Status code: {response.status_code}")

            return None

# Takes a list of IPs 
# Enriches the IP data
# Returns a json
def onyPheTest(ipAddressList):
    ONLYPHE_API_KEY = os.getenv("ONLYPHE_API_KEY")
    API_URL = "https://www.onyphe.io/api/v2"

    for ip in ipAddressList:

        # Request summary/ip from OnyPheTest
        url = f"{API_URL}/summary/ip/{ip}"
        headers = {
            "Authorization": f"apikey {ONLYPHE_API_KEY}"
        }

        # Attempt to get a reponse from the API
        try:
            response = requests.get(url, headers=headers)

            # If the IP does not contain an app/json then we process it as needed
            if "application/json" not in response.headers.get("Content-Type", ""):
                print(f"[!] Unexpected content type for IP {ip}: {response.headers.get('Content-Type')}")
                print("Response text:", response.text)
                continue

            # Collect the response and print
            response.raise_for_status()
            data = response.json()

            print(f"\n=== Summary for IP: {ip} ===")
            collectedData = collectFlat(data)

            return collectedData

        except requests.exceptions.RequestException as e:
            print(f"Request failed for IP {ip}: {e}")
        except ValueError as e:
            print(f"Failed to parse JSON for IP {ip}: {e}")

# Recursive function to parse complex json dictionaries
def collectFlat(data, prefix=''):
    result = {}
    
    if isinstance(data, dict):
        for key, value in data.items():
            new_prefix = f"{prefix}{key}."
            result.update(collectFlat(value, new_prefix))
    elif isinstance(data, list):
        for i, item in enumerate(data[:3]):  # show first 3 items
            result.update(collectFlat(item, f"{prefix}[{i}]."))
    else:
        result[prefix[:-1]] = data  # remove trailing dot or bracket

    return result

# Runs the Shodan Func against an 'apache' option, this now is a dictionary of lots of data
# IP: {ip}
# HTTP Banner
# Date found
# Server type
# Web location
# Length of request
# Type of request
#shodanResults = shodanFunc('apache')
#shodanResults = ['173.247.248.238', '66.96.149.32', '87.236.102.131', '8.8.8.8']
shodanResults = ['8.8.8.8']

# finds threats with greyNoise
threatIP = greyNoiseFunc(shodanResults)
for keys in threatIP.keys():
    print(keys)

# Enriches with ipInfo
#ipInfoResults = ipInfo(shodanResults)
#for keys in ipInfoResults.keys():
#    print(keys)

''' Desired keys from onyPhe:
        results.[0].domain.[0]
        results.[0].host.[0]
        results.[0].hostname.[0]
        results.[0].ip
        results.[0].issuer.commonname
        results.[0].issuer.country
        results.[0].issuer.organization'
        results.[0].fingerprint.md5
        results.[0].fingerprint.sha1
        results.[0].fingerprint.sha256'''
#enrichedIP = onyPheTest(shodanResults)
#for keys in enrichedIP.keys():
#    print(keys)



