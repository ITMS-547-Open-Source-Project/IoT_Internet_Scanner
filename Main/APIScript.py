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
# Returns an enriched dataset of those IPs
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
        
        response = requests.get(API_URL + singleIP, headers=HEADERS)
        if response.status_code == 200:
            data = response.json()
            print(f"\n IP: {ip}")
            print(f"   Classification: {data['classification']}")
            print(f"   Name: {data.get('name', 'N/A')}")
            print(f"   Tags: {', '.join(data.get('tags', []))}")
        elif response.status_code == 404:
            print(f"\n IP: {singleIP} - Not seen on GreyNoise")
        else:
            print(f"\n Error checking {singleIP}: {response.status_code}")
    
    for ip in ipList:
        check_ip(ip)

# Runs the Shodan Func against an 'apache' option, this now is a dictionary of lots of data
#shodanResults = shodanFunc('apache')
shodanResults = ['173.247.248.238', '66.96.149.32', '87.236.102.131', '8.8.8.8']

# Runs the GreyNoiseFunction with the shodanResults ipList
greyNoiseFunc(shodanResults)



