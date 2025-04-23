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

# Run this tool in your web browser with ~$ streamlit run '.\GuiDisplay.py'


import streamlit as st
import subprocess
import time
import threading
import os
import ProcessingScripts as pro
import APIScript as api

# Session state to track form submission
if "form_submitted" not in st.session_state:
    st.session_state.form_submitted = False

# Session state to track thread
if "logThreadStarted" not in st.session_state:
    st.session_state.logThreadStarted = False

# Handle form submission
def handleSubmit():
    st.session_state.form_submitted = True

# Overwrites the log
logFile = "terminalOutput.log"
if os.path.exists(logFile):
    with open(logFile, "w") as f:
        pass # truncate

# Tell Streamlit to use wide layout
st.set_page_config(layout="wide")

with st.container():
    # Title and description for the application
    st.title("IoT Threat Mapper (Ethical Version)")
    st.markdown("""
    This tool allows you to explore publicly available data about exposed IoT devices without performing any unauthorized scanning.
    Enter the device type and filtering criteria, and the system will display risk indicators based on open data sources.
    """)

# BEFORE submit: show full-width form:
with st.form("iot_threat_mapper_form"):
    
    st.session_state.deviceType = st.text_input("IoT Device Type", "apache")
    submitted = st.form_submit_button("Search for any device")
    if submitted:
        with st.spinner("Querying public data..."):

            # Get all the data from the APIs
            data = api.combineAndGetAPIData(st.session_state.deviceType)
            portCount = api.getPortCount(data)
            osCount = api.getOS(data)
            location = api.getLocation(data)
            orgList = api.getOrganizations(data)
            classificationData = api.getClassification(data)
            dataTable = api.getTableData(data)

            # Store data into session_state
            st.session_state.update({
                "form_submitted": True,
                "data": data,
                "portCount": portCount,
                "osCount": osCount,
                "location": location,
                "orgList": orgList,
                "classificationData": classificationData,
                "dataTable": dataTable,
            })
            
# If form is already submitted, render results
if st.session_state.get("form_submitted", False):
    
    with st.container():
        st.subheader("Scan Results")
        col1, col2, col3 = st.columns(3)

        # Org drop down
        with col1:
            st.subheader("Exposed Organizations:")
            with st.expander("Click to see organizations"):
                for org in st.session_state.orgList:
                    st.write(org)
        
        # Port drop down
        with col2:
            st.subheader("Found Open Ports")
            with st.expander("Click to see open ports"):
                for key, value in st.session_state.portCount.items():
                    if isinstance(value, list):
                        value = ", ".join(str(v) for v in value)
                    st.write(f"{key}: {value}")

        # OS drop down
        with col3:
            st.subheader("Found Operating Systems")
            with st.expander("Found operating systems"):
                for key, value in st.session_state.osCount.items():
                    if isinstance(value, list):
                        value = ", ".join(str(v) for v in value)
                    st.write(f"{key}: {value}")

    # Expander for collapsible table
    with st.expander("Click to show table"):
        st.dataframe(st.session_state.dataTable)
    
    with st.container():

        # Analysis/Graphs/Maps 
        st.subheader("Analysis")
        col1, col2, col3 = st.columns(3)

        # Port Pie Chart
        with col1:
            st.subheader("Open Ports Distribution")
            pro.makePortPieChart(st.session_state.portCount)
        
        # Geographic Map
        with col2:
            st.subheader("Device Geolocations")
            st.markdown("The map shows the geographic location of these devices.")
            st.map(st.session_state.location)
        
        # Classification Graph
        with col3:
            st.subheader("Classification Distribution")
            pro.makeClassificationPieChart(st.session_state.classificationData)
            print(st.session_state.classificationData)
        
    
    st.info("Note: This tool is in alpha development")