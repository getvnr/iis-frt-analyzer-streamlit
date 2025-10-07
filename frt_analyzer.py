import streamlit as st
import xml.etree.ElementTree as ET
import pandas as pd
from io import BytesIO, StringIO
from lxml import etree
import os

# Inject custom CSS for full-screen layout
st.markdown(
    """
<style>
/* Existing styles remain */
html, body {
    height: 100%;
    margin: 0;
    padding: 0;
    overflow: hidden;
}
.main .block-container {
    padding: 0;
    max-width: 100%;
    height: 100vh;
}
iframe[title="st.components.v1.html"] {
    width: 100%;
    height: 100vh;
    border: none;
    position: absolute;
    top: 0;
    left: 0;
}
/* Existing styles for fullscreen-mode and others */
</style>
    """,
    unsafe_allow_html=True
)

# Initialize session state for full-screen mode
if "fullscreen" not in st.session_state:
    st.session_state.fullscreen = False

# Toggle full-screen mode
if not st.session_state.fullscreen:
    st.title("IIS Failed Request Tracing Analyzer with freb.xsl")
    st.write("Upload your FRT XML file (e.g., fr000031.xml) to view the full-screen Request Diagnostics report.")
    
    # File uploader for XML
    uploaded_xml = st.file_uploader("Choose an FRT XML file", type="xml")
    
    # Option to choose rendering method
    render_option = st.radio("Select rendering method:", ["Use freb.xsl (HTML Report)", "Parse Events Directly (Table View)"])
    
    # Button to enter full-screen mode
    if st.button("Enter Full-Screen Mode (HTML Report Only)"):
        st.session_state.fullscreen = True
        st.rerun()

# Load freb.xsl from the repo
xsl_path = "freb.xsl"
if not os.path.exists(xsl_path):
    st.error("freb.xsl not found in the repository. Please upload it or use the Parse Events Directly option.")
    xsl_bytes = None
else:
    with open(xsl_path, "rb") as f:
        xsl_bytes = f.read()

# Apply fullscreen class if enabled
if st.session_state.fullscreen:
    st.markdown('<div class="fullscreen-mode">', unsafe_allow_html=True)

if uploaded_xml is not None:
    try:
        if render_option == "Use freb.xsl (HTML Report)" and xsl_bytes:
            # Use bytes for lxml parsing
            xml_bytes = uploaded_xml.getvalue()
            xml_doc = etree.parse(BytesIO(xml_bytes))
            xsl_doc = etree.parse(BytesIO(xsl_bytes))
            transform = etree.XSLT(xsl_doc)
            html_result = transform(xml_doc)
            
            # Render HTML in Streamlit
            st.subheader("Request Diagnostics (via freb.xsl)")
            st.components.v1.html(str(html_result), height=1000, scrolling=True)
            
            # Debug: Check for events using lxml
            if not st.session_state.fullscreen:
                event_nodes = xml_doc.xpath("//iis:event", namespaces={"iis": "http://schemas.microsoft.com/win/2004/08/events/trace"})
                st.write(f"Debug: Found {len(event_nodes)} event nodes in XML")
                if len(event_nodes) == 0:
                    st.warning("No <event> tags found. Check XML structure or IIS tracing settings.")
                    st.write("Debug: First few tags in XML:")
                    for child in xml_doc.getroot()[:5]:
                        st.write(f"- {child.tag}")
        
        elif render_option == "Parse Events Directly (Table View)":
            # Parse XML with ElementTree
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
                site = root.get("siteId", "N/A")
                process = root.get("processId", "N/A")
                app_pool = root.get("appPoolId", "N/A")
                authentication = root.get("authentication", "N/A")
                user = root.get("userName", "N/A")
                activity_id = root.get("activityId", "N/A")
                verb = "N/A"
                for data in root.iterfind(".//{http://schemas.microsoft.com/win/2004/08/events/trace}data") or root.iter("data"):
                    if data.find("name") is not None and data.find("name").text == "VERB":
                        verb = data.find("value").text if data.find("value") is not None else "N/A"
                        break
                
                # Extract events
                events = []
                ns = {"iis": "http://schemas.microsoft.com/win/2004/08/events/trace"}
                event_nodes = list(root.iterfind(".//{http://schemas.microsoft.com/win/2004/08/events/trace}event")) or list(root.iter("event"))
                
                if not st.session_state.fullscreen:
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
                if not st.session_state.fullscreen:
                    st.subheader("Request Summary")
                    col1, col2, col3, col4 = st.columns(4)
                    col1.metric("URL", url)
                    col2.metric("Status Code", f"{status_code}.{sub_status_code}")
                    col3.metric("Time Taken", f"{time_taken} ms")
                    col4.metric("Root Cause", root_cause)
                    col1.metric("Site", site)
                    col2.metric("Process", process)
                    col3.metric("App Pool", app_pool)
                    col4.metric("Authentication", authentication)
                    col1.metric("User", user)
                    col2.metric("Activity ID", activity_id)
                    col3.metric("Verb", verb)
                
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
    if st.session_state.fullscreen:
        st.error("Please upload an XML file to view the full-screen report.")
        if st.button("Exit Full-Screen Mode"):
            st.session_state.fullscreen = False
            st.rerun()
    else:
        st.info("👆 Upload an FRT XML file to get started!")

if st.session_state.fullscreen:
    st.markdown('</div>', unsafe_allow_html=True)
