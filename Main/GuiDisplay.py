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

# Session state to track form submission
if "form_submitted" not in st.session_state:
    st.session_state.form_submitted = False

# Handle form submission
def handleSubmit():
    st.session_state.form_submitted = True

# Tell Streamlit to use wide layout
st.set_page_config(layout="wide")

with st.container():
    # Title and description for the application
    st.title("IoT Threat Mapper (Ethical Version)")
    st.markdown("""
    This tool allows you to explore publicly available data about exposed IoT devices without performing any unauthorized scanning.
    Enter the device type and filtering criteria, and the system will display risk indicators based on open data sources.
    """)

# BEFORE submit: show full-width form
if not st.session_state.form_submitted:
    with st.form("iot_threat_mapper_form"):
        st.session_state.deviceType = st.text_input("IoT Device Type", "apache")
        submitted = st.form_submit_button("Search Devices", on_click=handleSubmit)

# AFTER submit: split into two columns
else:
 
    col1, col2 = st.columns(2)

    with col1:
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
                    orgList = api.getOrganizations(data)
                    deviceType = 'apache'
                   #data, portCount, osCount, location, orgList= api.tempReturnData()
                   #api.csvWrite(data)
                    dataTable = api.getTableData(data)
    
    with col2:
        st.subheader("Device Geolocations")
        st.markdown("The map shows the geographic location of these devices.")
        st.map(location)
        
    with st.container():
        st.subheader("Scan Results")
        col1, col2, col3 = st.columns(3)
        with col1:
            st.subheader("Exposed Organizations:")
            for org in orgList:
                st.write(org)
        with col2:
            st.subheader("Found Open Ports")
            for key, value in portCount.items():
                if isinstance(value, list):
                    value = ", ".join(str(v) for v in value)
                st.write(f"{key}: {value}")
        with col3:
            st.subheader("Found Operating Systems")
            for key, value in osCount.items():
                if isinstance(value, list):
                    value = ", ".join(str(v) for v in value)
                st.write(f"{key}: {value}")
    # Expander for collapsible table
    with st.expander("Click to show table"):
        st.dataframe(dataTable)
    
    st.info("Note: This tool is in pre-alpha development")