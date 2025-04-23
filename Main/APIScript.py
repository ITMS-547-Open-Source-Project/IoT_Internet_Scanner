#    Template and Processing for our GUI
#    Copyright (C) 2025 Kaleb Austgen

#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.

#    This program is distributed in the hope that it will be useful,s
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.

#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <https://www.gnu.org/licenses/>.

import shodan
import requests
import pandas as pd
import streamlit as st
import csv
from dotenv import load_dotenv
import os
import logging
import ipaddress

# Load the .env file
load_dotenv()

# Logging
logging.basicConfig(
    filename='terminalOutput.log',
    level=logging.INFO,
    format='%(asctime)s - %(message)s',
)

# Function takes deviceType, country tag, and a port
# Returns a dictionary of all found matches
# org, os, port, hostnames, products
# For getting all the internet facing devices
def _shodanFunc(query: str) -> list[dict]:
    """
    Searches Shodan for devices matching the given type and returns a list of device info dictionaries.

    Parameters:
        query (str): The search term (e.g., 'webcam', 'router')
        api_key (str): Your Shodan API key
        limit (int): Maximum number of results to return (default: 10)

    Returns:
        List[Dict]: List of dictionaries containing device info
    """
    SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")
    api = shodan.Shodan(SHODAN_API_KEY)
    devices = []

    try:
        try:
            ipaddress.ip_address(query)
            isIP = True
        except ValueError:
            isIP = False
        
        # If the user input an IP address
        if isIP:
            result = api.host(query)
            for service in result['data']:
                device = {
                    'ip': result.get('ip_str'),
                    'organization': result.get('org', 'N/A'),
                    'os': result.get('os', 'N/A'),
                    'port': service.get('port', 'N/A'),
                    'hostnames': result.get('hostnames', 'N/A'),
                    'product': service.get('product', 'N/A')
                }
                devices.append(device)
        else:
            
            results = api.search(query)

            # Raise error if improper input
            if not query or not isinstance(query, str) or query.strip() == "":
                raise ValueError("Device type must be a non-empty string")
            
            matches = results['matches']

            for result in matches:
                device = {
                    'ip': result.get('ip_str'),
                    'organization': result.get('org', 'N/A'),
                    'os': result.get('os', 'N/A'),
                    'port': result.get('port', 'N/A'),
                    'hostnames': result.get('hostnames', 'N/A'),
                    'product': result.get('product', 'N/A')
                }
                devices.append(device)
                print("Device found and added to dict")
                logging.info("Device found and added to dict")

    except shodan.APIError as e:
        print(f"Shodan API Error: {e}")
        logging.info(f"Shodan API Error: {e}")

    return devices

# Accepts a list of IP strings
# Returns a nested dictionary where the IP is the key
# For threat information
def _greyNoiseFunc(ipList) -> dict:
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
            logging.info(f"\n IP: {singleIP} - Not seen on GreyNoise")
            return None
        else:
            print(f"\n Error checking {singleIP}: {response.status_code}")
            logging.info(f"\n Error checking {singleIP}: {response.status_code}")
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
def _ipInfo(ipAddressList) -> dict:
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
            logging.info(f"Failed to retrieve data for IP {singleIP}. Status code: {response.status_code}")
            return None
    
    for ip in ipAddressList:
        result = check_ip(ip)
        if result is not None:
            results[ip] = result
    
    return results
    
# Takes a list of IPs 
# Enriches the IP data
def _onyPheTest(ipAddressList) -> dict:
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
                logging.info(f"[!] Unexpected content type for IP {ip}: {response.headers.get('Content-Type')}\nResponse text: {response.text}")

            # Collect the response and print
            response.raise_for_status()
            data = response.json()

            collectedData = collectFlat(data)

            return collectedData

        except requests.exceptions.RequestException as e:
            print(f"Request failed for IP {ip}: {e}")
            logging.info(f"Request failed for IP {ip}: {e}")
        except ValueError as e:
            print(f"Failed to parse JSON for IP {ip}: {e}")
            logging.info(f"Failed to parse JSON for IP {ip}: {e}")
        
    for ip in ipAddressList:
        result = check_ip(ip)
        if result is not None:
            results[ip] = result
    
    return results

# Recursive function to parse complex json dictionaries
def collectFlat(data, prefix='') -> dict:
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

# Write to CSV
def csvWrite(data) -> csv:
    # Extract all fieldnames from one of the inner dictionaries
    fieldnames = ['ID'] + list(next(iter(data.values())).keys())

    with open('IoTScanner_Data.csv', 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for key, inner_dict in data.items():
            row = {'ID': key}
            row.update(inner_dict)
            writer.writerow(row)

# The following functions are all for creating and retrieving dictionaries

# This will retrieve and enrich the requested data
def combineAndGetAPIData(deviceType) -> dict[dict]:

    # Call ShodanAPI
    shodanResults = _shodanFunc(deviceType)
    ipList = [ip['ip'] for ip in shodanResults] # Create a list of found IP addresses

    # Call GreyNoiseAPI
    greyNoiseResults = _greyNoiseFunc(ipList)

    # Call IpInfoAPI
    ipInfoResults = _ipInfo(ipList)

    # Call OnyPheAPI
    onyPheResults = _onyPheTest(ipList)
    
    # Next, we combine all three APIs into a comprehensive dataset

    # The specific information that is wanted so we can display it to the user, list of subkeys
    keysToExtract = ["ip", "results.[0].issuer.commname", "results.[0].issuer.country", "results.[0].issuer.organization",
                    "results.[0].fingerprint.md5","results.[0].fingerprint.sha1", "results.[0].fingerprint.sha256",
                    "noise", "riot", "classification", "hostname", "city", "region", "country", "loc", "org",
                    "organization", "os", "port", "hostnames", "product"]
    
    sources = [greyNoiseResults, ipInfoResults, onyPheResults]

    combinedData = {}

    for entry in shodanResults:
        _id = entry["ip"]
        combined = {}
    
        for key in keysToExtract:

            # First try Shodan
            if key in entry:
                combined[key] = entry[key]
                continue
            
            # Then try from other sources
            for dictionary in sources:
                if _id in dictionary and key in dictionary[_id]:
                    combined[key] = dictionary[_id][key]
                    break
        
        combinedData[_id] = combined

    return combinedData

# The following functions are used to retrieve specific data from the combined Dict

# Open ports and how many of each
def getPortCount(combinedData) -> dict:

    # Create a dict of ports and count them
    portCount = {}
    for key in combinedData.keys():
        if 'port' in combinedData[key]:
            port = combinedData[key]['port']
            if port not in portCount:
                portCount[port] = 1
            else:
                portCount[port] += 1
        else:
            continue
    
    return portCount   

# Types of Operating Systems and how many
def getOS(combinedData) -> dict:
    # Create a dict of OS types and count them
    osCount = {}
    for key in combinedData.keys():
        if 'os' in combinedData[key]:
            operatingsystem = combinedData[key]['os']
            if operatingsystem not in osCount:
                osCount[operatingsystem] = 1
            else:
                osCount[operatingsystem] += 1
        else:
            continue

    return osCount

# Product names
def getProducts(combinedData) -> dict:
    # Create a dict of product names and their count
    productCount = {}
    for key in combinedData.keys():
        if 'product' in combinedData[key]:
            product = combinedData[key]['os']
            if product not in productCount:
                productCount[product] = 1
            else:
                productCount[product] += 1

    return productCount

# Benign or not
def getClassification(combinedData) -> dict:
    # Create a dict of classification
    classificationDict = {}
    for key in combinedData.keys():
        print(key)
        if 'classification' in combinedData[key]:
            classification = combinedData[key]['classification']
            print(classification)
            if classification not in classificationDict:
                classificationDict[classification] = 1
                print(classificationDict[classification])
            else:
                classificationDict[classification] += 1
                print(classificationDict[classification])
    
    return classificationDict

# Organizations
def getOrganizations(combinedData) -> list:
    orgList = []
    for key in combinedData.keys():
        if 'organization' in combinedData[key]:
            orgList.append(combinedData[key]['organization'])
    return orgList
            

# Locations of each device
def getLocation(combinedData) -> pd.DataFrame:

    locationList = []
    for key in combinedData.keys():
        if 'loc' in combinedData[key]:
            location = combinedData[key]["loc"]
            tempLocList = [float(coordinates) for coordinates in location.split(",")]
            locationList.append(tempLocList)
        else:
            continue

    locationDataFrame = pd.DataFrame(
        [[lat, lon] for lat, lon in locationList],
        columns=["lat", "lon"])
    
    return locationDataFrame

# Build DataFrame from data
def getTableData(combinedData) -> pd.DataFrame:

    dataTable = pd.DataFrame.from_dict(combinedData, orient='index').reset_index()
    dataTable = dataTable.rename(columns={'index': 'ip'})
    # Remove one of the "os" columns
    dataTable = dataTable.loc[:, ~dataTable.columns.duplicated()]

    return dataTable