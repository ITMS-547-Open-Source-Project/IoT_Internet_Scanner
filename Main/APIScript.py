import shodan
import requests
from dotenv import load_dotenv
import os

# Load the .env file
load_dotenv()

#apikey = os.getenv('apikey')


# Function takes deviceType, country tag, and a port
# Returns a dictionary of all found matches
# org, os, port, hostnames, products
# For getting all the internet facing devices
def shodanFunc(device_type: str, limit: int = 5):
    """
    Searches Shodan for devices matching the given type and returns a list of device info dictionaries.

    Parameters:
        device_type (str): The search term (e.g., 'webcam', 'router')
        api_key (str): Your Shodan API key
        limit (int): Maximum number of results to return (default: 10)

    Returns:
        List[Dict]: List of dictionaries containing device info
    """
    SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")
    api = shodan.Shodan(SHODAN_API_KEY)
    devices = []

    try:
        results = api.search(device_type)
        matches = results['matches'][:limit]

        for result in matches:
            device = {
                'ip': result.get('ip_str'),
                'organization': result.get('org'),
                'os': result.get('os'),
                'port': result.get('port'),
                'hostnames': result.get('hostnames'),
                'product': result.get('product')
            }
            devices.append(device)

    except shodan.APIError as e:
        print(f"Shodan API Error: {e}")

    return devices

# Accepts a list of IP strings
# Returns a nested dictionary where the IP is the key
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
            collectedData = collectFlat(data)
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
# Returns a nested dictionary where the key is the IP
# More information than Shodan
# Ip, Hostname, City, Region, Country, Lat/Long, Organization, ASN, Carrier, and VPN/Proxy
def ipInfo(ipAddressList):
    IPINFO_API_KEY = os.getenv("IPINFO_API_KEY")
    API_URL = "https://ipinfo.io/"

    results = {}

    def check_ip(singleIP):
        # Construct the URL for the API request
        url = f'{API_URL}{singleIP}/json?token={IPINFO_API_KEY}'

        # Make the GET request to the IPinfo API
        response = requests.get(url)

        # Check if the request was successful
        if response.status_code == 200:
            data = response.json()
            collectData = collectFlat(data)
            return collectData
        else:
            print(f"Failed to retrieve data for IP {singleIP}. Status code: {response.status_code}")
            return None
    
    for ip in ipAddressList:
        result = check_ip(ip)
        if result is not None:
            results[ip] = result
    
    return results
    
# Takes a list of IPs 
# Enriches the IP data
# Returns a json
def onyPheTest(ipAddressList):
    ONLYPHE_API_KEY = os.getenv("ONLYPHE_API_KEY")
    API_URL = "https://www.onyphe.io/api/v2"

    results = {}

    def check_ip(ip):
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

            # Collect the response and print
            response.raise_for_status()
            data = response.json()

            collectedData = collectFlat(data)

            return collectedData

        except requests.exceptions.RequestException as e:
            print(f"Request failed for IP {ip}: {e}")
        except ValueError as e:
            print(f"Failed to parse JSON for IP {ip}: {e}")
        
    for ip in ipAddressList:
        result = check_ip(ip)
        if result is not None:
            results[ip] = result
    
    return results

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
shodanResults = [{'ip': '8.8.8.8', 'organization': 'CSL Computer Service Langenbach GmbH', 'os': None, 'port': 80, 'hostnames': ['vault.ceramtec.com'], 'product': 'Apache httpd'}, {'ip': '1.1.1.1', 'organization': 'DigitalOcean, LLC', 'os': None, 'port': 80, 'hostnames': ['omega.host.webbedfeet.uk'], 'product': 'Apache httpd'}, {'ip': '69.22.188.41', 'organization': 'PhotoShelter, Inc.', 'os': None, 'port': 443, 'hostnames': ['photoshelter.com', 'le2.nyc.bitshelter.com'], 'product': None}, {'ip': '143.244.72.12', 'organization': 'YRC Inc.', 'os': None, 'port': 443, 'hostnames': ['citrix.yrcw.com'], 'product': None}, {'ip': '66.96.163.133', 'organization': 'Newfold Digital, Inc.', 'os': None, 'port': 443, 'hostnames': ['133.163.96.66.static.eigbox.net', 'bizland.com'], 'product': None}]
ipList = [ip['ip'] for ip in shodanResults]

# finds threats with greyNoise
#greyNoiseResults = greyNoiseFunc(ipList)
greyNoiseResults = {'8.8.8.8': {'ip': '8.8.8.8', 'noise': False, 'riot': True, 'classification': 'benign', 'name': 'Google Public DNS', 'link': 'https://viz.greynoise.io/ip/8.8.8.8', 'last_seen': '2025-04-18', 'message': 'Success'}, '1.1.1.1': {'ip': '1.1.1.1', 'noise': False, 'riot': True, 'classification': 'benign', 'name': 'Cloudflare Public DNS', 'link': 'https://viz.greynoise.io/ip/1.1.1.1', 'last_seen': '2025-04-18', 'message': 'Success'}}
#print(greyNoiseResults)
#try:
 #   for keys in greyNoiseResults.keys():
 #       ipData = greyNoiseResults[keys]
#        for key in ipData.keys():
#            print(key)
#except AttributeError as e:
#    print(e)

# Enriches with ipInfo
#ipInfoResults = ipInfo(ipList)
ipInfoResults = {'8.8.8.8': {'ip': '8.8.8.8', 'hostname': 'dns.google', 'city': 'Mountain View', 'region': 'California', 'country': 'US', 'loc': '38.0088,-122.1175', 'org': 'AS15169 Google LLC', 'postal': '94043', 'timezone': 'America/Los_Angeles', 'anycast': True}, '1.1.1.1': {'ip': '1.1.1.1', 'hostname': 'one.one.one.one', 'city': 'Brisbane', 'region': 'Queensland', 'country': 'AU', 'loc': '-27.4816,153.0175', 'org': 'AS13335 Cloudflare, Inc.', 'postal': '4101', 'timezone': 'Australia/Brisbane', 'anycast': True}, '58.220.219.247': {'ip': '58.220.219.247', 'city': 'Shanghai', 'region': 'Shanghai', 'country': 'CN', 'loc': '31.2222,121.4581', 'org': 'AS4134 CHINANET-BACKBONE', 'postal': '200000', 'timezone': 'Asia/Shanghai'}}
#print(ipInfoResults)
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
#onyPHEResults = onyPheTest(ipList)
onyPHEResults={'8.8.8.8': {'count': 30, 'error': 0, 'max_page': 1, 'myip': '104.194.118.53', 'page': 1, 'page_size': 30, 'results.[0].@category': 'ctl', 'results.[0].@timestamp': '2025-04-18T22:10:19.000Z', 'results.[0].basicconstraints.[0]': 'critical', 'results.[0].ca': 'false', 'results.[0].domain.[0]': 'uq.edu.au', 'results.[0].extkeyusage.[0]': 'serverAuth', 'results.[0].extkeyusage.[1]': 'clientAuth', 'results.[0].fingerprint.md5': '2f96dd3cd52d629337127b26c143eeee', 'results.[0].fingerprint.sha1': 'b6e8f8fa4e9b8917aaab4276625ac12ebd1b7d82', 'results.[0].fingerprint.sha256': '9d5b06233574eefa4efde7db09d7f3c2b5f4a472f213423f49cfab8226113991', 'results.[0].host.[0]': 'test-acme-prod', 'results.[0].hostname.[0]': 'test-acme-prod.im-prod.aws.uq.edu.au', 'results.[0].ip': '8.8.8.8', 'results.[0].issuer.commonname': 'ZeroSSL ECC Domain Secure Site CA', 'results.[0].issuer.country': 'AT', 'results.[0].issuer.organization': 'ZeroSSL', 'results.[0].keyusage.[0]': 'critical', 'results.[0].keyusage.[1]': 'digitalSignature', 'results.[0].publickey.algorithm': 'id-ecPublicKey', 'results.[0].seen_date': '2025-04-18', 'results.[0].serial': 'c6:0e:d7:d2:32:67:32:cd:e2:65:51:6d:92:a4:b7:5f', 'results.[0].signature.algorithm': 'ecdsa-with-SHA384', 'results.[0].source': 'letsencryptoak2025h2', 'results.[0].subdomains.[0]': 'aws.uq.edu.au', 'results.[0].subdomains.[1]': 'im-prod.aws.uq.edu.au', 'results.[0].subject.altname.[0]': 'test-acme-prod.im-prod.aws.uq.edu.au', 'results.[0].subject.commonname': 'test-acme-prod.im-prod.aws.uq.edu.au', 'results.[0].tag': '<enterprise field>: tag', 'results.[0].tld.[0]': 'edu.au', 'results.[0].validity.notafter': '2025-07-17T23:59:59.000Z', 'results.[0].validity.notbefore': '2025-04-18T00:00:00.000Z', 'results.[0].version': 'v3', 'results.[0].wildcard': 'false', 'results.[1].@category': 'ctl', 'results.[1].@timestamp': '2025-04-18T22:06:48.000Z', 'results.[1].basicconstraints.[0]': 'critical', 'results.[1].ca': 'false', 'results.[1].domain.[0]': 'kkkmkm.com', 'results.[1].extkeyusage.[0]': 'serverAuth', 'results.[1].fingerprint.md5': '387aa67fe094278d003517ebbf390bca', 'results.[1].fingerprint.sha1': '4163fb3116337f9e6d0c3dbcd2b939846e67f08a', 'results.[1].fingerprint.sha256': '84be525a9b7652d0d034f9a070b99ffa0b7d87ee1263efd6e17855f15f5f4394', 'results.[1].hostname': 'kkkmkm.com', 'results.[1].ip': '8.8.8.8', 'results.[1].issuer.commonname': 'WE1', 'results.[1].issuer.country': 'US', 'results.[1].issuer.organization': 'Google Trust Services', 'results.[1].keyusage.[0]': 'critical', 'results.[1].keyusage.[1]': 'digitalSignature', 'results.[1].publickey.algorithm': 'id-ecPublicKey', 'results.[1].seen_date': '2025-04-18', 'results.[1].serial': 'df:07:d1:1b:fa:6e:30:8e:13:01:ba:37:37:ee:4a:c2', 'results.[1].signature.algorithm': 'ecdsa-with-SHA256', 'results.[1].source': 'digicertsphinx2025h2log', 'results.[1].subject.altname.[0]': '*.kkkmkm.com', 'results.[1].subject.altname.[1]': 'kkkmkm.com', 'results.[1].subject.commonname': 'kkkmkm.com', 'results.[1].tag': '<enterprise field>: tag', 'results.[1].tld.[0]': 'com', 'results.[1].validity.notafter': '2025-07-17T22:04:22.000Z', 'results.[1].validity.notbefore': '2025-04-18T21:06:42.000Z', 'results.[1].version': 'v3', 'results.[1].wildcard': 'true', 'results.[2].@category': 'ctl', 'results.[2].@timestamp': '2025-04-18T21:56:04.000Z', 'results.[2].basicconstraints.[0]': 'critical', 'results.[2].ca': 'false', 'results.[2].domain.[0]': 'go1.games', 'results.[2].extkeyusage.[0]': 'serverAuth', 'results.[2].extkeyusage.[1]': 'clientAuth', 'results.[2].fingerprint.md5': 'e881be83e49fc4ab86df0231361ec2bc', 'results.[2].fingerprint.sha1': '174c2daa14900f0a0257250efa722842eff9bfe7', 'results.[2].fingerprint.sha256': '68f9e069aa8958c27ca2f0a513dd5463daa1475890b7b5f9a7afea84646a2708', 'results.[2].hostname': 'go1.games', 'results.[2].ip': '8.8.8.8', 'results.[2].issuer.commonname': 'E5', 'results.[2].issuer.country': 'US', 'results.[2].issuer.organization': "Let's Encrypt", 'results.[2].keyusage.[0]': 'critical', 'results.[2].keyusage.[1]': 'digitalSignature', 'results.[2].publickey.algorithm': 'id-ecPublicKey', 'results.[2].seen_date': '2025-04-18', 'results.[2].serial': '05:ad:e7:8f:3f:e1:43:ad:86:de:fa:7a:b2:11:67:8d:d6:04', 'results.[2].signature.algorithm': 'ecdsa-with-SHA384', 'results.[2].source': 'cloudflarenimbus2025', 'results.[2].subject.altname.[0]': 'go1.games', 'results.[2].subject.altname.[1]': '*.go1.games', 'results.[2].subject.commonname': 'go1.games', 'results.[2].tag': '<enterprise field>: tag', 'results.[2].tld.[0]': 'games', 'results.[2].validity.notafter': '2025-07-11T19:20:28.000Z', 'results.[2].validity.notbefore': '2025-04-12T19:20:29.000Z', 'results.[2].version': 'v3', 'results.[2].wildcard': 'true', 'status': 'ok', 'text': 'Success', 'took': 0.205, 'total': 35350}, '1.1.1.1': {'count': 30, 'error': 0, 'max_page': 1, 'myip': '104.194.118.53', 'page': 1, 'page_size': 30, 'results.[0].@category': 'ctl', 'results.[0].@timestamp': '2025-04-18T21:53:45.000Z', 'results.[0].basicconstraints.[0]': 'critical', 'results.[0].ca': 'false', 'results.[0].domain.[0]': 'mcp-app.com', 'results.[0].domain.[1]': 'theranest.com', 'results.[0].domain.[2]': 'webaba-app.com', 'results.[0].extkeyusage.[0]': 'serverAuth', 'results.[0].extkeyusage.[1]': 'clientAuth', 'results.[0].fingerprint.md5': 'b3ef04c6fc615e247169bad4ce8a0e9e', 'results.[0].fingerprint.sha1': '94f7e76678d9eadb1b9e8823307bb43327790080', 'results.[0].fingerprint.sha256': '8d48334303aba3aa8a616844115e5243dec0273c13249c60454e88e7a41f5ad1', 'results.[0].host.[0]': 'do344527', 'results.[0].hostname.[0]': 'do344527.dev.mcp-app.com', 'results.[0].hostname.[1]': 'do344527.dev.theranest.com', 'results.[0].hostname.[2]': 'do344527.dev.webaba-app.com', 'results.[0].ip.[0]': '1.1.1.1', 'results.[0].ip.[1]': '255.255.255.255', 'results.[0].issuer.commonname': 'ZeroSSL RSA Domain Secure Site CA', 'results.[0].issuer.country': 'AT', 'results.[0].issuer.organization': 'ZeroSSL', 'results.[0].keyusage.[0]': 'critical', 'results.[0].keyusage.[1]': 'digitalSignature', 'results.[0].keyusage.[2]': 'keyEncipherment', 'results.[0].publickey.algorithm': 'rsaEncryption', 'results.[0].publickey.exponent': 65537, 'results.[0].publickey.length': 2048, 'results.[0].seen_date': '2025-04-18', 'results.[0].serial': '55:27:70:e6:28:b2:d0:f3:38:eb:7f:70:19:8c:1e:a1', 'results.[0].signature.algorithm': 'sha384WithRSAEncryption', 'results.[0].source': 'googlexenon2025h2log', 'results.[0].subdomains.[0]': 'dev.mcp-app.com', 'results.[0].subdomains.[1]': 'dev.theranest.com', 'results.[0].subdomains.[2]': 'dev.webaba-app.com', 'results.[0].subject.altname.[0]': '*.do344527.dev.theranest.com', 'results.[0].subject.altname.[1]': '*.do344527.dev.mcp-app.com', 'results.[0].subject.altname.[2]': '*.do344527.dev.webaba-app.com', 'results.[0].subject.commonname': '*.do344527.dev.theranest.com', 'results.[0].tag': '<enterprise field>: tag', 'results.[0].tld.[0]': 'com', 'results.[0].validity.notafter': '2025-07-17T23:59:59.000Z', 'results.[0].validity.notbefore': '2025-04-18T00:00:00.000Z', 'results.[0].version': 'v3', 'results.[0].wildcard': 'true', 'results.[1].@category': 'ctl', 'results.[1].@timestamp': '2025-04-18T21:52:49.000Z', 'results.[1].basicconstraints.[0]': 'critical', 'results.[1].ca': 'false', 'results.[1].domain.[0]': 'mcp-app.com', 'results.[1].domain.[1]': 'theranest.com', 'results.[1].domain.[2]': 'webaba-app.com', 'results.[1].extkeyusage.[0]': 'serverAuth', 'results.[1].extkeyusage.[1]': 'clientAuth', 'results.[1].fingerprint.md5': '76f5102d6fca2364f97b7dd9180f082d', 'results.[1].fingerprint.sha1': 'd05bd7ac22ce6f365fdeb03088958d2b04aab176', 'results.[1].fingerprint.sha256': '473f046815cd120c46fc224fd8929c36303aa2fcbaa0602cf0399b1a845da8cf', 'results.[1].host.[0]': 'do344527', 'results.[1].hostname.[0]': 'do344527.dev.mcp-app.com', 'results.[1].hostname.[1]': 'do344527.dev.theranest.com', 'results.[1].hostname.[2]': 'do344527.dev.webaba-app.com', 'results.[1].ip.[0]': '1.1.1.1', 'results.[1].ip.[1]': '255.255.255.255', 'results.[1].issuer.commonname': 'ZeroSSL RSA Domain Secure Site CA', 'results.[1].issuer.country': 'AT', 'results.[1].issuer.organization': 'ZeroSSL', 'results.[1].keyusage.[0]': 'critical', 'results.[1].keyusage.[1]': 'digitalSignature', 'results.[1].keyusage.[2]': 'keyEncipherment', 'results.[1].publickey.algorithm': 'rsaEncryption', 'results.[1].publickey.exponent': 65537, 'results.[1].publickey.length': 2048, 'results.[1].seen_date': '2025-04-18', 'results.[1].serial': '55:27:70:e6:28:b2:d0:f3:38:eb:7f:70:19:8c:1e:a1', 'results.[1].signature.algorithm': 'sha384WithRSAEncryption', 'results.[1].source': 'letsencryptoak2025h2', 'results.[1].subdomains.[0]': 'dev.mcp-app.com', 'results.[1].subdomains.[1]': 'dev.theranest.com', 'results.[1].subdomains.[2]': 'dev.webaba-app.com', 'results.[1].subject.altname.[0]': '*.do344527.dev.theranest.com', 'results.[1].subject.altname.[1]': '*.do344527.dev.mcp-app.com', 'results.[1].subject.altname.[2]': '*.do344527.dev.webaba-app.com', 'results.[1].subject.commonname': '*.do344527.dev.theranest.com', 'results.[1].tag': '<enterprise field>: tag', 'results.[1].tld.[0]': 'com', 'results.[1].validity.notafter': '2025-07-17T23:59:59.000Z', 'results.[1].validity.notbefore': '2025-04-18T00:00:00.000Z', 'results.[1].version': 'v3', 'results.[1].wildcard': 'true', 'results.[2].@category': 'ctl', 'results.[2].@timestamp': '2025-04-18T21:52:49.000Z', 'results.[2].basicconstraints.[0]': 'critical', 'results.[2].ca': 'false', 'results.[2].domain.[0]': 'mcp-app.com', 'results.[2].domain.[1]': 'theranest.com', 'results.[2].domain.[2]': 'webaba-app.com', 'results.[2].extkeyusage.[0]': 'serverAuth', 'results.[2].extkeyusage.[1]': 'clientAuth', 'results.[2].fingerprint.md5': 'b3ef04c6fc615e247169bad4ce8a0e9e', 'results.[2].fingerprint.sha1': '94f7e76678d9eadb1b9e8823307bb43327790080', 'results.[2].fingerprint.sha256': '8d48334303aba3aa8a616844115e5243dec0273c13249c60454e88e7a41f5ad1', 'results.[2].host.[0]': 'do344527', 'results.[2].hostname.[0]': 'do344527.dev.mcp-app.com', 'results.[2].hostname.[1]': 'do344527.dev.theranest.com', 'results.[2].hostname.[2]': 'do344527.dev.webaba-app.com', 'results.[2].ip.[0]': '255.255.255.255', 'results.[2].ip.[1]': '1.1.1.1', 'results.[2].issuer.commonname': 'ZeroSSL RSA Domain Secure Site CA', 'results.[2].issuer.country': 'AT', 'results.[2].issuer.organization': 'ZeroSSL', 'results.[2].keyusage.[0]': 'critical', 'results.[2].keyusage.[1]': 'digitalSignature', 'results.[2].keyusage.[2]': 'keyEncipherment', 'results.[2].publickey.algorithm': 'rsaEncryption', 'results.[2].publickey.exponent': 65537, 'results.[2].publickey.length': 2048, 'results.[2].seen_date': '2025-04-18', 'results.[2].serial': '55:27:70:e6:28:b2:d0:f3:38:eb:7f:70:19:8c:1e:a1', 'results.[2].signature.algorithm': 'sha384WithRSAEncryption', 'results.[2].source': 'letsencryptoak2025h2', 'results.[2].subdomains.[0]': 'dev.mcp-app.com', 'results.[2].subdomains.[1]': 'dev.theranest.com', 'results.[2].subdomains.[2]': 'dev.webaba-app.com', 'results.[2].subject.altname.[0]': '*.do344527.dev.webaba-app.com', 'results.[2].subject.altname.[1]': '*.do344527.dev.mcp-app.com', 'results.[2].subject.altname.[2]': '*.do344527.dev.theranest.com', 'results.[2].subject.commonname': '*.do344527.dev.theranest.com', 'results.[2].tag': '<enterprise field>: tag', 'results.[2].tld.[0]': 'com', 'results.[2].validity.notafter': '2025-07-17T23:59:59.000Z', 'results.[2].validity.notbefore': '2025-04-18T00:00:00.000Z', 'results.[2].version': 'v3', 'results.[2].wildcard': 'true', 'status': 'ok', 'text': 'Success', 'took': 0.389, 'total': 51080}, '58.220.219.247': {'count': 0, 'error': 0, 'max_page': 1, 'myip': '104.194.118.53', 'page': 1, 'page_size': 0, 'status': 'ok', 'text': 'Success', 'took': 0.063, 'total': 0}}
#print(onyPHEResults)
wantedIP = ["results.[0].domain.[0]",
        "results.[0].host.[0]",
        "results.[0].hostname.[0]",
        "results.[0].ip",
        "results.[0].issuer.commonname",
        "results.[0].issuer.country",
        "results.[0].issuer.organization",
        "results.[0].fingerprint.md5",
        "results.[0].fingerprint.sha1",
        "results.[0].fingerprint.sha256"]
wantedKeys = []
for keys in onyPHEResults.keys():
    wantedIP.append(keys)

# Subset containing only wantedKeys and wantedIP using dictionary comprehension
onyPHERClean = {
    ip: { subkey: topKey[subkey] for subkey in wantedIP if subkey in topKey }
    for ip, topKey in onyPHEResults.items()
}

# Process the Data from the APIs, clean it, gain some statistics, and process it into a .csv and send it to the GUI
#greyNoiseResults
#ipInfoResults
#onyPHERClean
for key in onyPHERClean.keys():
    print(f"\n===onyPhe Data: {key}===")
    for key, value in onyPHERClean[key].items():
        print(f"{key}:{value}")

for key in greyNoiseResults.keys():
    print(f"\n===Grey Noise Results: {key}===")
    for key, value in greyNoiseResults[key].items():
        print(f"{key}:{value}")

for key in ipInfoResults.keys():
    print(f"\n===IP Info Results: {key}===")
    for key, value in ipInfoResults[key].items():
        print(f"{key}:{value}")

for ip in shodanResults:
    print(f"\n==Shodan Results: {ip['ip']}")
    for key, value in ip.items():
        print(f"{key}:{value}")

print("\n===onyPhe Keys===")
for key in onyPHERClean['8.8.8.8'].keys():
    print(key)

print("\n===Grey Nois Keys===")
for key in greyNoiseResults['8.8.8.8'].keys():
    print(key)
    
print("\n===IP Info Keys===")
for key in ipInfoResults['8.8.8.8'].keys():
    print(key)

print("\n===Shodan Keys===")
for key in shodanResults[0].keys():
    print(key)

keys_to_extract = ["ip", "results.[0].issuer.commname", "results.[0].issuer.country", "results.[0].issuer.organization",
                   "results.[0].fingerprint.md5","results.[0].fingerprint.sha1", "results.[0].fingerprint.sha256",
                   "noise", "riot", "classification", "hostname", "city", "region", "country", "loc", "org",
                   "organization", "os", "port", "hostnames", "product"]

sources = [onyPHERClean, greyNoiseResults, ipInfoResults]

combinedData = {}

# Combine the data into one dictionary
for entry in shodanResults:
    _id = entry["ip"]
    combined = {}

    for key in keys_to_extract:
        #Try from shodanResults
        if key in entry:
            combined[key] = entry[key]
            continue
        
        # Then try from the other sources
        for dictionary in sources:
            if _id in dictionary and key in dictionary[_id]:
                combined[key] = dictionary[_id][key]
                break
    
    combinedData[_id] = combined

for key in combinedData.keys():
    print(f"\n==={key} Data===")
    for keys, values in combinedData[key].items():
        print(f"{keys}:{values}")

'''Combine the data to return these things:
onhyPHE:
results.[0].issuer.commname
results.[0].issuer.country
results.[0].issuer.organization
results.[0].fingerprint.md5
results.[0].fingerprint.sha1
results.[0].fingerprint.sha256

GreyNoise:
noise
riot - potentially filter out all noise
classification

IpInfo:
hostname
city
region
country
loc
org

Shodan:
ip
organization
os
port
hostnames
product
'''





