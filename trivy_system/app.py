import streamlit as st
import json
import pandas as pd
import plotly.express as px
import subprocess
import asyncio
import os
from streamlit_oauth import OAuth2Component

st.set_page_config(page_title="Trivy Scan Visualizer", layout="wide")

# --- Authentication ---
CLIENT_ID = "trivy-client"
CLIENT_SECRET = ""
AUTHORIZE_URL = "http://localhost:8001/realms/trivy-realm/protocol/openid-connect/auth"
TOKEN_URL = "http://localhost:8001/realms/trivy-realm/protocol/openid-connect/token"
REVOKE_TOKEN_URL = "http://localhost:8001/realms/trivy-realm/protocol/openid-connect/logout"

oauth2 = OAuth2Component(CLIENT_ID, CLIENT_SECRET, AUTHORIZE_URL, TOKEN_URL, TOKEN_URL, REVOKE_TOKEN_URL)

if 'token' not in st.session_state or st.session_state.token is None:
    result = oauth2.authorize_button(
        name="Login with Keycloak",
        icon="https://www.keycloak.org/resources/images/keycloak_logo_480x108.png",
        redirect_uri="http://localhost:8501",
        scope="openid email profile",
        key="keycloak",
    )
    
    if result:
        st.session_state.token = result
        st.rerun()
    else:
        st.warning("Please log in to access the Trivy Scan Visualizer.")
        st.stop()

logout_url = f"{REVOKE_TOKEN_URL}?post_logout_redirect_uri=http://localhost:8501&client_id={CLIENT_ID}"
if st.sidebar.button("Logout"):
    # Clear local session state
    if 'token' in st.session_state:
        del st.session_state.token
    # Redirect to Keycloak logout
    st.markdown(f'<meta http-equiv="refresh" content="0;url={logout_url}">', unsafe_allow_html=True)
    st.stop()

token = st.session_state.get('token')
if token:
    # streamlit-oauth returns the token nested in a 'token' key in some versions/configurations
    access_token = token.get('access_token') or token.get('token', {}).get('access_token')
    
    if not access_token:
        st.error("Login failed: No access token received.")
        if st.button("Reset Login"):
            del st.session_state.token
            st.rerun()

st.title("🛡️ Trivy Scan Visualizer")

# --- Sidebar Controls ---
st.sidebar.header("Scan Configuration")

scan_mode = st.sidebar.radio("Mode", ["Run New Scan", "Upload Existing JSON"])

vulns = []

if scan_mode == "Run New Scan":
    # List directories in the dedicated scan folder
    base_path = "/trivy_scan"
    
    # Ensure the directory exists (it should be mounted)
    if not os.path.exists(base_path):
        st.error(f"Scan directory '{base_path}' not found. Please ensure it is mounted.")
        target_dir = None
    else:
        try:
            # List subdirectories and files
            items = [d for d in os.listdir(base_path)]
            items.sort()
            
            options = items + ["Custom Path..."]
            
            selected_option = st.sidebar.selectbox("Select Target (in /trivy_scan)", options)
            
            if selected_option == "Custom Path...":
                target_dir = st.sidebar.text_input("Enter Custom Path", value=base_path)
            else:
                target_dir = os.path.join(base_path, selected_option)
                st.sidebar.info(f"Selected: {target_dir}")

        except Exception as e:
            st.sidebar.error(f"Error listing directories: {e}")
            target_dir = st.sidebar.text_input("Target Directory", value=base_path)

    if target_dir and st.sidebar.button("Run Trivy Scan"):
        with st.spinner(f"Scanning {target_dir}..."):
            try:
                # Run Trivy command
                output_file = "scan_results.json"
                cmd = [
                    "trivy", "fs", 
                    "--format", "json", 
                    "--output", output_file, 
                    target_dir
                ]
                result = subprocess.run(cmd, capture_output=True, text=True)
                
                if result.returncode == 0:
                    st.success("Scan completed successfully!")
                    # Load the generated file
                    if os.path.exists(output_file):
                        with open(output_file, "r") as f:
                            data = json.load(f)
                else:
                    st.error("Trivy scan failed.")
                    st.code(result.stderr)
                    data = None
            except Exception as e:
                st.error(f"An error occurred: {e}")
                data = None
    else:
        # Try to load previous result if exists
        if os.path.exists("scan_results.json"):
            try:
                with open("scan_results.json", "r") as f:
                    data = json.load(f)
            except:
                data = None
        else:
            data = None

else: # Upload Mode
    uploaded_file = st.sidebar.file_uploader("Upload Trivy JSON output", type=["json"])
    if uploaded_file is not None:
        data = json.load(uploaded_file)
    else:
        data = None

# --- Data Parsing & Visualization ---

def parse_trivy_json(data):
    vulnerabilities = []
    if data and 'Results' in data:
        for result in data['Results']:
            target = result.get('Target', 'Unknown')
            if 'Vulnerabilities' in result:
                for vuln in result['Vulnerabilities']:
                    vuln['Target'] = target
                    vulnerabilities.append(vuln)
    return vulnerabilities

if data:
    vulns = parse_trivy_json(data)
    
    if not vulns:
        st.info("No vulnerabilities found in the scan results.")
    else:
        df = pd.DataFrame(vulns)
        
        # --- Filters ---
        st.sidebar.header("Filters")
        
        # Severity Filter
        if 'Severity' in df.columns:
            all_severities = df['Severity'].unique().tolist()
            selected_severities = st.sidebar.multiselect(
                "Select Severity", 
                options=all_severities, 
                default=all_severities
            )
            df = df[df['Severity'].isin(selected_severities)]
        
        # Search Filter
        search_query = st.sidebar.text_input("Search (PkgName, ID, Title)")
        if search_query:
            mask = df.apply(lambda x: x.astype(str).str.contains(search_query, case=False).any(), axis=1)
            df = df[mask]

        # --- Dashboard ---
        
        # Color Map
        severity_colors = {
            'CRITICAL': '#FF8080',
            'HIGH': '#FFB366',
            'MEDIUM': '#FFFF80',
            'LOW': '#80B3FF',
            'UNKNOWN': '#C0C0C0'
        }

        # Metrics
        col1, col2, col3 = st.columns(3)
        col1.metric("Total Vulnerabilities", len(df))
        if 'Severity' in df.columns:
            col2.metric("Critical", len(df[df['Severity'] == 'CRITICAL']))
            col3.metric("High", len(df[df['Severity'] == 'HIGH']))

        # Charts
        col_chart1, col_chart2 = st.columns(2)
        
        with col_chart1:
            st.subheader("Severity Distribution")
            if not df.empty and 'Severity' in df.columns:
                fig_severity = px.pie(
                    df, 
                    names='Severity', 
                    title='Vulnerabilities by Severity', 
                    hole=0.4,
                    color='Severity',
                    color_discrete_map=severity_colors
                )
                st.plotly_chart(fig_severity, width="stretch")
        
        with col_chart2:
            st.subheader("Top Affected Packages")
            if not df.empty and 'PkgName' in df.columns:
                top_pkgs = df['PkgName'].value_counts().head(10).reset_index()
                top_pkgs.columns = ['PkgName', 'Count']
                fig_pkgs = px.bar(top_pkgs, x='Count', y='PkgName', orientation='h', title='Top 10 Vulnerable Packages')
                fig_pkgs.update_layout(yaxis={'categoryorder':'total ascending'})
                st.plotly_chart(fig_pkgs, width="stretch")

        # Data Table
        st.subheader("Detailed Vulnerabilities")
        
        # Select columns to display
        display_cols = ['VulnerabilityID', 'PkgName', 'InstalledVersion', 'FixedVersion', 'Severity', 'Title', 'Target']
        # Ensure columns exist
        display_cols = [c for c in display_cols if c in df.columns]
        
        # Function to color Severity column
        def color_severity(val):
            color = severity_colors.get(val, 'white')
            # Use background color for better visibility, with black text
            return f'background-color: {color}; color: black'

        st.dataframe(
            df[display_cols].style.map(color_severity, subset=['Severity']), 
            width="stretch"
        )

else:
    if scan_mode == "Run New Scan":
        st.info("Enter a target directory and click 'Run Trivy Scan' to start.")
    else:
        st.info("Upload a JSON file to visualize results.")
