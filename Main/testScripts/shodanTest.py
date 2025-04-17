import shodan
from dotenv import load_dotenv
import os

# Load keys from env
load_dotenv()

SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")

#api = shodan.Shodan(SHODAN_API_KEY)
api = shodan.Shodan(SHODAN_API_KEY)
# Wrap the request in a try/ except block to catch errors
try:
        # Search Shodan
        results = api.search('apache')

        # Show the results
        print('Results found: {}'.format(results['total']))
        for result in results['matches']:
                print('IP: {}'.format(result['ip_str']))
                print(result['data'])
                print('')
except shodan.APIError as e:
        print('Error: {}'.format(e))