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
import APIScript as api

# Title and description for the application
st.title("IoT Threat Mapper (Ethical Version)")
st.markdown("""
This tool allows you to explore publicly available data about exposed IoT devices without performing any unauthorized scanning.
Enter the device type and filtering criteria, and the system will display risk indicators based on open data sources.
""")
 
# Create a form for user input
with st.form("iot_threat_mapper_form"):
    deviceType = st.text_input("IoT Device Type", "apache")
    submitted = st.form_submit_button("Search Devices")
    if submitted:
        with st.spinner("Querying public data..."):
            data = api.combineAndGetAPIData(deviceType)
            portCount = api.getPortCount(data)
            osCount = api.getOS(data)
            location = api.getLocation(data)
        st.subheader("Scan Results")
        st.write(f"**Total Exposed '{deviceType}': {len(data)}")
        st.write("**Common Open Ports:**", portCount)
        st.write("**Found Operating Systems:**", osCount)
        st.subheader("Device Geolocations")
        st.markdown("The map shows the geographic location of these devices.")
        st.map(location)
        st.info("Note: This tool is in pre-alpha development")