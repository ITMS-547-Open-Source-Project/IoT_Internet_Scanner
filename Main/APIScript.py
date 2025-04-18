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

    HEADERS = {
        "Accept": "application/json",
        "key": GREYNOISE_API_KEY
    }

    # Placeholder for results
    results = {}

    def check_ip(singleIP):
        response = requests.get(API_URL + singleIP, headers=HEADERS)
        if response.status_code == 200:
            data = response.json()
            collectedData = collectFlat(data)  # Assuming you have this defined
            return collectedData
        elif response.status_code == 404:
            print(f"\n IP: {singleIP} - Not seen on GreyNoise")
            return None
        else:
            print(f"\n Error checking {singleIP}: {response.status_code}")
            return None

    # Iterate and collect results
    for ip in ipList:
        result = check_ip(ip)
        if result is not None:
            results[ip] = result

    return results

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
#greyNoiseResults = greyNoiseFunc(shodanResults)
greyNoiseResults = {'8.8.8.8': {'ip': '8.8.8.8', 'noise': False, 'riot': True, 'classification': 'benign', 'name': 'Google Public DNS', 'link': 'https://viz.greynoise.io/ip/8.8.8.8', 'last_seen': '2025-04-18', 'message': 'Success'}}
print(greyNoiseResults)
try:
    for keys in greyNoiseResults.keys():
        ipData = greyNoiseResults[keys]
        for key in ipData.keys():
            print(key)
except AttributeError as e:
    print(e)

# Enriches with ipInfo
#ipInfoResults = ipInfo(shodanResults)
ipInfoResults = {'ip': '8.8.8.8', 'hostname': 'dns.google', 'city': 'Mountain View', 'region': 'California', 'country': 'US', 'loc': '38.0088,-122.1175', 'org': 'AS15169 Google LLC', 'postal': '94043', 'timezone': 'America/Los_Angeles', 'anycast': True}
print(ipInfoResults)
for keys in ipInfoResults.keys():
    print(keys)

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
enrichedIP={'count': 30, 'error': 0, 'max_page': 1, 'myip': '104.194.118.53', 'page': 1, 'page_size': 30, 'results.[0].@category': 'ctl', 'results.[0].@timestamp': '2025-04-18T21:12:27.000Z', 'results.[0].basicconstraints.[0]': 'critical', 'results.[0].ca': 'false', 'results.[0].domain.[0]': '200250.xyz', 'results.[0].extkeyusage.[0]': 'serverAuth', 'results.[0].fingerprint.md5': 'a7f23a0b3b02f1fc3f92368e7adae9d2', 'results.[0].fingerprint.sha1': 'bedda102f4368cd243b3da28f61f42e4c99c35c1', 'results.[0].fingerprint.sha256': 'f14fea23240711e03d213f96e2cf7bdb7cb58d1076e7e6ebd9e27e8b7f1f1564', 'results.[0].hostname': '200250.xyz', 'results.[0].ip': '8.8.8.8', 'results.[0].issuer.commonname': 'WE1', 'results.[0].issuer.country': 'US', 'results.[0].issuer.organization': 'Google Trust Services', 'results.[0].keyusage.[0]': 'critical', 'results.[0].keyusage.[1]': 'digitalSignature', 'results.[0].publickey.algorithm': 'id-ecPublicKey', 'results.[0].seen_date': '2025-04-18', 'results.[0].serial': 'bc:05:be:0a:14:2e:ef:71:0d:6d:11:54:ff:0f:4b:47', 'results.[0].signature.algorithm': 'ecdsa-with-SHA256', 'results.[0].source': 'googlexenon2025h2log', 'results.[0].subject.altname.[0]': '*.200250.xyz', 'results.[0].subject.altname.[1]': '200250.xyz', 'results.[0].subject.commonname': '200250.xyz', 'results.[0].tag': '<enterprise field>: tag', 'results.[0].tld.[0]': 'xyz', 'results.[0].validity.notafter': '2025-07-17T21:09:54.000Z', 'results.[0].validity.notbefore': '2025-04-18T20:11:08.000Z', 'results.[0].version': 'v3', 'results.[0].wildcard': 'true', 'results.[1].@category': 'ctl', 'results.[1].@timestamp': '2025-04-18T21:12:07.000Z', 'results.[1].basicconstraints.[0]': 'critical', 'results.[1].ca': 'false', 'results.[1].domain.[0]': 'dade-pardazan.com', 'results.[1].extkeyusage.[0]': 'serverAuth', 'results.[1].extkeyusage.[1]': 'clientAuth', 'results.[1].fingerprint.md5': 'b5a3c19fb827bf8a520eef17cae99c0c', 'results.[1].fingerprint.sha1': '42770805c09955ab0a65b96db921ee21224d5aaa', 'results.[1].fingerprint.sha256': '7db851fee74460e1841104e11681dcdaeb81c29da2c3dbceede219a33e62b6d1', 'results.[1].host.[0]': 'vdi', 'results.[1].hostname.[0]': 'vdi.dade-pardazan.com', 'results.[1].ip': '8.8.8.8', 'results.[1].issuer.commonname': 'R11', 'results.[1].issuer.country': 'US', 'results.[1].issuer.organization': "Let's Encrypt", 'results.[1].keyusage.[0]': 'critical', 'results.[1].keyusage.[1]': 'digitalSignature', 'results.[1].keyusage.[2]': 'keyEncipherment', 'results.[1].publickey.algorithm': 'rsaEncryption', 'results.[1].publickey.exponent': 65537, 'results.[1].publickey.length': 2048, 'results.[1].seen_date': '2025-04-18', 'results.[1].serial': '06:36:08:db:1b:86:ea:dc:f0:01:29:3c:4c:06:3c:43:a0:9e', 'results.[1].signature.algorithm': 'sha256WithRSAEncryption', 'results.[1].source': 'digicertyeti2025log', 'results.[1].subject.altname.[0]': 'vdi.dade-pardazan.com', 'results.[1].subject.commonname': 'vdi.dade-pardazan.com', 'results.[1].tag': '<enterprise field>: tag', 'results.[1].tld.[0]': 'com', 'results.[1].validity.notafter': '2025-07-17T07:35:42.000Z', 'results.[1].validity.notbefore': '2025-04-18T07:35:43.000Z', 'results.[1].version': 'v3', 'results.[1].wildcard': 'false', 'results.[2].@category': 'ctl', 'results.[2].@timestamp': '2025-04-18T21:09:21.000Z', 'results.[2].basicconstraints.[0]': 'critical', 'results.[2].ca': 'false', 'results.[2].domain.[0]': 'uq.edu.au', 'results.[2].extkeyusage.[0]': 'serverAuth', 'results.[2].extkeyusage.[1]': 'clientAuth', 'results.[2].fingerprint.md5': '7ac4788803997b791a7a2c3280d33a42', 'results.[2].fingerprint.sha1': 'b20b334c6f29b7d0b0f8f74b1f640a84c4e0921e', 'results.[2].fingerprint.sha256': '462e67cf73f5ce902038c2f40379f8e2cb9c641bc75252ded7975dcd8bab7129', 'results.[2].host.[0]': 'test-acme-prod', 'results.[2].hostname.[0]': 'test-acme-prod.im-prod.aws.uq.edu.au', 'results.[2].ip': '8.8.8.8', 'results.[2].issuer.commonname': 'ZeroSSL ECC Domain Secure Site CA', 'results.[2].issuer.country': 'AT', 'results.[2].issuer.organization': 'ZeroSSL', 'results.[2].keyusage.[0]': 'critical', 'results.[2].keyusage.[1]': 'digitalSignature', 'results.[2].publickey.algorithm': 'id-ecPublicKey', 'results.[2].seen_date': '2025-04-18', 'results.[2].serial': 'c7:6f:ec:08:a9:05:fa:42:3c:46:46:58:fb:87:12:b2', 'results.[2].signature.algorithm': 'ecdsa-with-SHA384', 'results.[2].source': 'letsencryptoak2025h2', 'results.[2].subdomains.[0]': 'aws.uq.edu.au', 'results.[2].subdomains.[1]': 'im-prod.aws.uq.edu.au', 'results.[2].subject.altname.[0]': 'test-acme-prod.im-prod.aws.uq.edu.au', 'results.[2].subject.commonname': 'test-acme-prod.im-prod.aws.uq.edu.au', 'results.[2].tag': '<enterprise field>: tag', 'results.[2].tld.[0]': 'edu.au', 'results.[2].validity.notafter': '2025-07-17T23:59:59.000Z', 'results.[2].validity.notbefore': '2025-04-18T00:00:00.000Z', 'results.[2].version': 'v3', 'results.[2].wildcard': 'false', 'status': 'ok', 'text': 'Success', 'took': 0.444, 'total': 35334}
print(enrichedIP)
for keys in enrichedIP.keys():
    print(keys)



