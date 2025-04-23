#    Analysis and Graphing Functions
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

import plotly.express as px
import streamlit as st
import APIScript as api

# Takes a dictionary and makes it into a pie chart
def makePortPieChart(portTotals) -> px.pie:
    labels = [f"Port {port}" for port in portTotals]
    values = list(portTotals.values())

    px.defaults.template = "plotly_dark" # use dark mode

    fig = px.pie(
        names=labels,
        values=values,
        title="Open Ports",
        color=labels
    )

    # Streamlit embed
    st.plotly_chart(fig, use_container_width=True)

def makeClassificationPieChart(classificationData):
    labels = [f"{data}" for data in classificationData]
    values = list(classificationData.values())

    px.defaults.template = "plotly_dark" # use dark mode

    fig = px.pie(
        names=labels,
        values=values,
        title="Classification",
        color=labels
    )

    # Streamlit embed
    st.plotly_chart(fig, use_container_width=True)


