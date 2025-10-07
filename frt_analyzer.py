import streamlit as st
import xml.etree.ElementTree as ET
import pandas as pd
from io import StringIO

st.title("IIS Failed Request Tracing Analyzer")
st.write("Upload your FRT XML file (e.g., fr000022.xml) to analyze.")

# File uploader
uploaded_file = st.file_uploader("Choose an XML file", type="xml")

if uploaded_file is not None:
    try:
        # Read and parse XML
        xml_content = StringIO(uploaded_file.getvalue().decode("utf-8"))
        tree = ET.parse(xml_content)
        root = tree.getroot()
        
        if root.tag != "failedRequest":
            st.error("Invalid FRT XML: Missing <failedRequest> root tag.")
        else:
            # Extract summary
            url = root.get("url", "N/A")
            status_code = root.get("statusCode", "N/A")
            sub_status_code = root.get("subStatusCode", "N/A")
            time_taken = root.get("timeTaken", "N/A")
            
            # Extract verb (from data nodes)
            verb = "N/A"
            for data in root.iter("data"):
                if data.find("name") is not None and data.find("name").text == "VERB":
                    verb = data.find("value").text if data.find("value") is not None else "N/A"
                    break
            
            # Extract events for timeline
            events = []
            for i, event in enumerate(root.iter("event")):
                event_name = event.find("name").text if event.find("name") is not None else "Unknown"
                reason = event.get("reason", "")
                # Handle time attribute safely
                time_ms = event.get("time", None)
                try:
                    time_ms = int(float(time_ms)) if time_ms else i * 10  # Fallback to index-based time
                except (ValueError, TypeError):
                    st.warning(f"Invalid time value '{time_ms}' for event {event_name}, using {i * 10} ms")
                    time_ms = i * 10  # Fallback to sequential time
                provider = event.find("providerName").text if event.find("providerName") is not None else ""
                events.append({
                    "Time (ms)": time_ms,
                    "Event Name": event_name,
                    "Provider": provider,
                    "Reason": reason
                })
            
            # Create DataFrame for timeline
            df = pd.DataFrame(events)
            if not df.empty:
                df = df.sort_values("Time (ms)")
            
            # Root cause detection
            root_cause = "Unknown"
            if status_code == "404":
                root_cause = "File Not Found (Check physical path)"
            elif status_code == "500":
                root_cause = "Server Error (Review modules/logs)"
            
            # Display summary
            st.subheader("Request Summary")
            col1, col2, col3, col4 = st.columns(4)
            col1.metric("URL", url)
            col2.metric("Status Code", f"{status_code}.{sub_status_code}")
            col3.metric("Time Taken", f"{time_taken} ms")
            col4.metric("Root Cause", root_cause)
            
            # Display timeline
            st.subheader("Event Timeline")
            if not df.empty:
                st.dataframe(df, use_container_width=True)
            else:
                st.warning("No events found in the XML file.")
            
            # Insights
            st.subheader("Insights")
            st.write(f"- Total Events: {len(events)}")
            st.write(f"- Recommendation: For {root_cause}, inspect the error in the timeline (e.g., FILE_CACHE_ACCESS_END with code 0x80070002).")
            
            # Download processed data
            if not df.empty:
                csv = df.to_csv(index=False).encode("utf-8")
                st.download_button("Download Timeline as CSV", csv, "frt_timeline.csv", "text/csv")
    
    except ET.ParseError as e:
        st.error(f"XML parsing error: {e}")
    except Exception as e:
        st.error(f"Error processing file: {e}")
else:
    st.info("👆 Upload a file to get started!")
