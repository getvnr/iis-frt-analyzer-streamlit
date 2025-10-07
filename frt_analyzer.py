import streamlit as st
import xml.etree.ElementTree as ET
import pandas as pd
from io import BytesIO, StringIO
from lxml import etree
import os

# Inject custom CSS and JavaScript for full-screen layout
st.markdown(
    """
    <style>
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
    .fullscreen-mode .stApp {
        margin: 0;
        padding: 0;
    }
    .fullscreen-mode .stFileUploader,
    .fullscreen-mode .stRadio,
    .fullscreen-mode .stCheckbox,
    .fullscreen-mode .stMarkdown,
    .fullscreen-mode .stButton {
        display: none;
    }
    header, footer {
        visibility: hidden;
    }
    </style>
    <script>
    function makeFullScreen() {
        var elem = document.querySelector('iframe[title="st.components.v1.html"]');
        if (elem && elem.requestFullscreen) {
            elem.requestFullscreen();
        } else if (elem && elem.webkitRequestFullscreen) {
            elem.webkitRequestFullscreen();
        } else if (elem && elem.msRequestFullscreen) {
            elem.msRequestFullscreen();
        }
    }
    window.addEventListener('load', makeFullScreen);
    </script>
    """,
    unsafe_allow_html=True
)

# Initialize session state
if "fullscreen" not in st.session_state:
    st.session_state.fullscreen = False

# Main UI
if not st.session_state.fullscreen:
    st.title("IIS Failed Request Tracing Analyzer")
    st.write("Upload your FRT XML file (e.g., fr000031.xml) to analyze request diagnostics.")

    uploaded_xml = st.file_uploader("Choose an FRT XML file", type="xml")
    render_option = st.radio("Select rendering method:", ["Use freb.xsl (HTML Report)", "Parse Events Directly (Table View)"])

    if st.button("Enter Full-Screen Mode (HTML Report Only)"):
        if uploaded_xml and render_option == "Use freb.xsl (HTML Report)":
            st.session_state.fullscreen = True
            st.rerun()
        else:
            st.warning("Please upload an XML file and select 'Use freb.xsl (HTML Report)' to enter full-screen mode.")

# Load freb.xsl
xsl_path = "freb.xsl"
xsl_bytes = None
if os.path.exists(xsl_path):
    with open(xsl_path, "rb") as f:
        xsl_bytes = f.read()
else:
    st.error("freb.xsl not found. Please upload it or use the Parse Events Directly option.")

# Full-screen mode
if st.session_state.fullscreen:
    st.markdown('<div class="fullscreen-mode">', unsafe_allow_html=True)
    if uploaded_xml and xsl_bytes and render_option == "Use freb.xsl (HTML Report)":
        try:
            xml_bytes = uploaded_xml.getvalue()
            xml_doc = etree.parse(BytesIO(xml_bytes))
            xsl_doc = etree.parse(BytesIO(xsl_bytes))
            transform = etree.XSLT(xsl_doc)
            html_result = transform(xml_doc)
            st.components.v1.html(f'<div onload="makeFullScreen()">{str(html_result)}</div>', height=1000, scrolling=True)
        except MemoryError:
            st.error("Memory error occurred. Please use a smaller XML file or increase server resources.")
            if st.button("Exit Full-Screen Mode"):
                st.session_state.fullscreen = False
                st.rerun()
        except etree.ParseError as e:
            st.error(f"XML/XSL parsing error: {e}")
        except Exception as e:
            st.error(f"Error processing file: {e}")
    else:
        st.error("Invalid state for full-screen mode. Please upload an XML file and select 'Use freb.xsl (HTML Report)'.")
        if st.button("Exit Full-Screen Mode"):
            st.session_state.fullscreen = False
            st.rerun()
    st.markdown('</div>', unsafe_allow_html=True)

# Non-full-screen processing
if uploaded_xml and not st.session_state.fullscreen:
    try:
        if render_option == "Parse Events Directly (Table View)":
            xml_content = StringIO(uploaded_xml.getvalue().decode("utf-8"))
            tree = ET.parse(xml_content)
            root = tree.getroot()

            if root.tag not in ["failedRequest", "{http://schemas.microsoft.com/win/2004/08/events/trace}failedRequest"]:
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
                verb = next((data.find("value").text for data in root.iterfind(".//{http://schemas.microsoft.com/win/2004/08/events/trace}data") 
                            if data.find("name") is not None and data.find("name").text == "VERB" and data.find("value") is not None), "N/A")

                # Extract events
                events = []
                ns = {"iis": "http://schemas.microsoft.com/win/2004/08/events/trace"}
                event_nodes = list(root.iterfind(".//{http://schemas.microsoft.com/win/2004/08/events/trace}event")) or list(root.iter("event"))

                for i, event in enumerate(event_nodes):
                    event_name = (event.find("name", ns) or event.find("name")).text if (event.find("name", ns) or event.find("name")) is not None else "Unknown"
                    reason = event.get("reason", "")
                    time_ms = event.get("time", None)
                    time_ms = int(float(time_ms)) if time_ms else i * 10
                    provider = (event.find("providerName", ns) or event.find("providerName")).text if (event.find("providerName", ns) or event.find("providerName")) is not None else ""
                    events.append({"Time (ms)": time_ms, "Event Name": event_name, "Provider": provider, "Reason": reason})

                # Create DataFrame
                df = pd.DataFrame(events).sort_values("Time (ms)") if events else pd.DataFrame()

                # Root cause detection
                root_cause = "Unknown"
                if status_code == "404":
                    root_cause = "File Not Found (Check physical path)"
                elif status_code == "500":
                    root_cause = "Server Error (Review modules/logs)"

                # Display summary
                st.subheader("Request Summary")
                cols = st.columns(4)
                cols[0].metric("URL", url)
                cols[1].metric("Status Code", f"{status_code}.{sub_status_code}")
                cols[2].metric("Time Taken", f"{time_taken} ms")
                cols[3].metric("Root Cause", root_cause)
                cols[0].metric("Site", site)
                cols[1].metric("Process", process)
                cols[2].metric("App Pool", app_pool)
                cols[3].metric("Authentication", authentication)
                cols[0].metric("User", user)
                cols[1].metric("Activity ID", activity_id)
                cols[2].metric("Verb", verb)

                # Display timeline
                st.subheader("Event Timeline")
                if not df.empty:
                    st.dataframe(df, use_container_width=True)
                else:
                    st.warning("No events found in the XML file.")

                # Insights
                st.subheader("Insights")
                st.write(f"- Total Events: {len(events)}")
                st.write(f"- Recommendation: For {root_cause}, inspect the error in the timeline.")

                # Download CSV
                if not df.empty:
                    csv = df.to_csv(index=False).encode("utf-8")
                    st.download_button("Download Timeline as CSV", csv, "frt_timeline.csv", "text/csv")

    except etree.ParseError as e:
        st.error(f"XML parsing error: {e}")
    except Exception as e:
        st.error(f"Unexpected error: {e}")
else:
    if not st.session_state.fullscreen:
        st.info("👆 Upload an FRT XML file to get started!")
