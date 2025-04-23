# IoT_Internet_Scanner
Main repository for our IoT scanner

Welcome to the IoT Internet Scanner! (Better name pending)

This tool pulls from several different APIs, Shodan, IPInfo, OnyPhe, and Greynoise and combines the data into something meaningful

It is useful if you are attempting to discover any exposed devices on your network, and very useful for OSINT as all this information is available online.

It provides some helpful graphics all on a locally run web app, maybe I'll make it into a product one day

How to Use:
Simply clone the repository, get your four API keys and put them in a .env like this:
SHODAN_API_KEY=<yourkeyhere>
GREYNOISE_API_KEY=<yourkeyhere>
ONLYPHE_API_KEY=<yourkeyhere>
IPINFO_API_KEY=<yourkeyhere>

Then while in the "Main" directory, run this in a terminal: streamlit run '.\GuiDisplay.py'

Then you are good to go and you can start conducting OSINT on any possible device type on the internet!