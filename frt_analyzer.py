import streamlit as st
import xml.etree.ElementTree as ET
import pandas as pd
from io import BytesIO, StringIO
from lxml import etree
import os

st.title("IIS Failed Request Tracing Analyzer with freb.xsl")
st.write("Upload your FRT XML file (e.g., fr000031.xml) to view the report using freb.xsl or parse events directly.")

# File uploader for XML
uploaded_xml = st.file_uploader("Choose an FRT XML file", type="xml")

# Option to choose rendering method
render_option = st.radio("Select rendering method:", ["Use freb.xsl (HTML Report)", "Parse Events Directly (Table View)"])

# Load freb.xsl from the repo
xsl_path = "freb.xsl"
if not os.path.exists(xsl_path):
    st.error("freb.xsl not found in the repository. Please upload it or use the Parse Events Directly option.")
    xsl_bytes = None
else:
    with open(xsl_path, "rb") as f:  # Read as bytes
        xsl_bytes = f.read()

if uploaded_xml is not None:
    try:
        if render_option == "Use freb.xsl (HTML Report)" and xsl_bytes:
            # Use bytes for lxml parsing
            xml_bytes = uploaded_xml.getvalue()  # Raw bytes of XML
            xml_doc = etree.parse(BytesIO(xml_bytes))
            xsl_doc = etree.parse(BytesIO(xsl_bytes))  # Use bytes for XSL
            transform = etree.XSLT(xsl_doc)
            html_result = transform(xml_doc)
            
            # Render HTML in Streamlit
            st.subheader("Transformed HTML Report (via freb.xsl)")
            st.components.v1.html(str(html_result), height=600, scrolling=True)
            
            # Debug: Check for events using lxml
            event_nodes = xml_doc.xpath("//iis:event", namespaces={"iis": "http://schemas.microsoft.com/win/2004/08/events/trace"})
            st.write(f"Debug: Found {len(event_nodes)} event nodes in XML")
            if len(event_nodes) == 0:
                st.warning("No <event> tags found. Check XML structure or IIS tracing settings.")
                st.write("Debug: First few tags in XML:")
                for child in xml_doc.getroot()[:5]:
                    st.write(f"- {child.tag}")
        
        elif render_option == "Parse Events Directly (Table View)":
            # Parse XML with ElementTree (for fallback)
            xml_content = StringIO(uploaded_xml.getvalue().decode("utf-8"))
            tree = ET.parse(xml_content)
            root = tree.getroot()
            
            if root.tag != "failedRequest" and not root.tag.endswith("}failedRequest"):
                st.error("Invalid FRT XML: Missing or unrecognized <failedRequest> root tag.")
                st.write(f"Root tag found: {root.tag}")
            else:
                # Extract summary
                url = root.get("url", "N/A")
                status_code = root.get("statusCode", "N/A")
                sub_status_code = root.get("subStatusCode", "N/A")
                time_taken = root.get("timeTaken", "N/A")
                
                # Extract verb
                verb = "N/A"
                for data in root.iterfind(".//{http://schemas.microsoft.com/win/2004/08/events/trace}data") or root.iter("data"):
                    if data.find("name") is not None and data.find("name").text == "VERB":
                        verb = data.find("value").text if data.find("value") is not None else "N/A"
                        break
                
                # Extract events
                events = []
                ns = {"iis": "http://schemas.microsoft.com/win/2004/08/events/trace"}
                event_nodes = list(root.iterfind(".//{http://schemas.microsoft.com/win/2004/08/events/trace}event")) or list(root.iter("event"))
                st.write(f"Debug: Found {len(event_nodes)} event nodes")
                
                for i, event in enumerate(event_nodes):
                    event_name = event.find("name", ns) or event.find("name")
                    event_name = event_name.text if event_name is not None else "Unknown"
                    reason = event.get("reason", "")
                    time_ms = event.get("time", None)
                    try:
                        time_ms = int(float(time_ms)) if time_ms else i * 10
                    except (ValueError, TypeError):
                        st.warning(f"Invalid time value '{time_ms}' for event {event_name}, using {i * 10} ms")
                        time_ms = i * 10
                    provider = event.find("providerName", ns) or event.find("providerName")
                    provider = provider.text if provider is not None else ""
                    events.append({
                        "Time (ms)": time_ms,
                        "Event Name": event_name,
                        "Provider": provider,
                        "Reason": reason
                    })
                
                # Create DataFrame
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
                    st.warning("No events found in the XML file. Check if <event> tags exist or use freb.xsl option.")
                    st.write("Debug: First few tags in XML:")
                    for child in root[:5]:
                        st.write(f"- {child.tag}")
                
                # Insights
                st.subheader("Insights")
                st.write(f"- Total Events: {len(events)}")
                st.write(f"- Recommendation: For {root_cause}, inspect the error in the timeline (e.g., FILE_CACHE_ACCESS_END with code 0x80070002).")
                
                # Download CSV
                if not df.empty:
                    csv = df.to_csv(index=False).encode("utf-8")
                    st.download_button("Download Timeline as CSV", csv, "frt_timeline.csv", "text/csv")
    
    except etree.ParseError as e:
        st.error(f"XML/XSL parsing error: {e}")
        st.write("Debug: Check if freb.xsl or XML file has a valid XML declaration and structure.")
    except Exception as e:
        st.error(f"Error processing file: {e}")
        st.write("Debug: An unexpected error occurred. Please share the XML structure or error details.")
else:
    st.info("👆 Upload an FRT XML file to get started!")
