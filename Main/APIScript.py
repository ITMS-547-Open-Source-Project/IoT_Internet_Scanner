import shodan
from dotenv import load_dotenv
import os

# Load the .env file
load_dotenv()

#apikey = os.getenv('apikey')
SHODAN_API_KEY=os.getenv('SHODAN_API_KEY')

# Function takes deviceType, country tag, and a port
def shodanFunc(deviceType, country=None, port=None):
    try:

        # Search Shodan
        results = api.search(deviceType)

