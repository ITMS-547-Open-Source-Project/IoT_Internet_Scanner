#    Template for our GUI
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

import streamlit as st
import pandas as pd
import random
import time
 
# Dummy function to simulate querying public APIs
def query_threat_info(device_type, country, port):
    # In a real implementation, you would call your API handlers here.
    # For now, we simulate the delay and results.
    time.sleep(1)  # Simulate network/API delay
    results = {
        "device_count": random.randint(100, 5000),
        "top_ports": [80, 23, 554],
        "risk_score": random.randint(0, 100),
        "ip_geolocation_data": pd.DataFrame({
            "lat": [random.uniform(-90, 90) for _ in range(10)],
            "lon": [random.uniform(-180, 180) for _ in range(10)]
        })
    }
    return results
 
# Title and description for the application
st.title("IoT Threat Mapper (Ethical Version)")
st.markdown("""
This tool allows you to explore publicly available data about exposed IoT devices without performing any unauthorized scanning.
Enter the device type and filtering criteria, and the system will display risk indicators based on open data sources.
""")
 
# Create a form for user input
with st.form("iot_threat_mapper_form"):
    device_type = st.text_input("IoT Device Type", "Camera")
    country = st.text_input("Country (ISO code or name)", "US")
    port = st.text_input("Optional: Specific Port", "")
    submitted = st.form_submit_button("Search Devices")
    if submitted:
        with st.spinner("Querying public data..."):
            results = query_threat_info(device_type, country, port)
        st.subheader("Scan Results")
        st.write(f"**Total Exposed '{device_type}' Devices in {country}:** {results['device_count']}")
        st.write("**Common Open Ports:**", results["top_ports"])
        st.write(f"**Risk Score:** {results['risk_score']} / 100")
        st.subheader("Device Geolocations")
        st.markdown("The map below shows random sample locations of these devices. In your actual application, these would come from IP geolocation lookups of the data collected.")
        st.map(results["ip_geolocation_data"])
        st.info("Note: This is a demo template using dummy data. Integrate real API calls for production use!")