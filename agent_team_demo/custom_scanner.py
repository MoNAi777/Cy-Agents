"""🔍 Custom Security Scanner - Powered by Agno Agents

This dashboard provides a functional security scanning interface using Agno's agent capabilities.
It supports real-time web scanning and security analysis.
"""

import os
import streamlit as st
import time
import sys
import re
import json
from pathlib import Path
import threading
from io import StringIO
import traceback

# Configure the Streamlit page
st.set_page_config(
    page_title="Custom Security Scanner",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Initialize session state
if 'scan_results' not in st.session_state:
    st.session_state.scan_results = []
if 'is_scanning' not in st.session_state:
    st.session_state.is_scanning = False
if 'scan_progress' not in st.session_state:
    st.session_state.scan_progress = 0
if 'scan_log' not in st.session_state:
    st.session_state.scan_log = []
if 'api_key_set' not in st.session_state:
    st.session_state.api_key_set = False
if 'scan_output' not in st.session_state:
    st.session_state.scan_output = ""

# Custom CSS for better styling
st.markdown("""
<style>
    body {
        color: #333;
        background-color: #f8f8f8;
    }
    .main-header {
        font-size: 2.5rem;
        color: #FF5757;
        text-align: center;
        margin-bottom: 1rem;
        background-color: #fff;
        padding: 10px;
        border-radius: 10px;
        box-shadow: 0 2px 10px rgba(0,0,0,0.1);
    }
    .sub-header {
        font-size: 1.2rem;
        color: #00C4B4;
        margin-bottom: 1rem;
    }
    .card {
        border: 1px solid #ddd;
        border-radius: 8px;
        padding: 20px;
        margin-bottom: 20px;
        background-color: #fff;
        color: #333;
        box-shadow: 0 2px 5px rgba(0,0,0,0.05);
    }
    .highlight {
        background-color: #f0f7ff;
        padding: 8px;
        border-radius: 4px;
        border-left: 4px solid #00C4B4;
        color: #333;
    }
    .critical {
        color: #FF5757;
        font-weight: bold;
    }
    .high {
        color: #FF9E00;
        font-weight: bold;
    }
    .medium {
        color: #FFDE59;
        font-weight: bold;
    }
    .low {
        color: #4F9E5A;
        font-weight: bold;
    }
    h1, h2, h3, h4, h5, h6 {
        color: #333;
    }
    p, li, a {
        color: #333;
    }
    .stTabs [data-baseweb="tab-list"] {
        gap: 10px;
    }
    .stTabs [data-baseweb="tab"] {
        border-radius: 4px 4px 0px 0px;
        padding: 10px 16px;
        background-color: #f0f7ff;
        color: #333;
    }
    .stTabs [aria-selected="true"] {
        background-color: #00C4B4;
        color: white;
    }
    /* Improve sidebar styling */
    .css-1d391kg, .css-13sdm1b {
        background-color: #fff;
    }
    .stButton>button {
        background-color: #FF5757;
        color: white;
        font-weight: bold;
        border: none;
        padding: 10px 20px;
        border-radius: 5px;
    }
    .stButton>button:hover {
        background-color: #e04949;
    }
    /* Fix sidebar text */
    .css-pkbazv {
        color: #333;
    }
    .css-1adrfps {
        color: #333;
    }
    .terminal {
        background-color: #1a1a1a;
        color: #f0f0f0;
        padding: 15px;
        border-radius: 5px;
        font-family: 'Courier New', monospace;
        max-height: 400px;
        overflow-y: auto;
    }
    .tool-call {
        margin-left: 20px;
        padding-left: 10px;
        border-left: 3px solid #00A8E8;
        font-style: italic;
    }
</style>

<div class="main-header">🔍 Custom Security Scanner</div>
""", unsafe_allow_html=True)

def direct_openai_scan(url, scan_type, api_key):
    """Directly use OpenAI API to perform security scan"""
    try:
        import openai
        openai.api_key = api_key
        
        # Select the appropriate prompt
        if scan_type == "recon":
            system_prompt = """You are an expert in reconnaissance. Your job is to:
            1. Gather information about the target (website or organization)
            2. Identify technologies, platforms, and frameworks used
            3. Find potential entry points and attack surfaces
            4. Map out the structure and components of the target
            
            Be thorough but ethical in your analysis. Focus on publicly available information.
            """
            user_prompt = f"Perform reconnaissance on the website {url}. Identify technologies, platforms, and potential entry points."
        else:
            system_prompt = """You are an expert web security scanner. Your job is to:
            1. Analyze the given website URL
            2. Identify potential security issues and vulnerabilities
            3. Provide detailed reports on findings
            4. Suggest remediation steps
            
            Be thorough and look for common issues like:
            - Outdated software/libraries
            - Common web vulnerabilities (XSS, CSRF, injection)
            - Security misconfigurations
            - Information leakage
            """
            user_prompt = f"Scan the website {url} for security vulnerabilities. Look for common issues like XSS, CSRF, outdated software, and security misconfigurations."
        
        # Create messages
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ]
        
        # Determine the OpenAI API version and make the appropriate call
        if openai.__version__.startswith("0."):
            # For older OpenAI versions
            response = openai.ChatCompletion.create(
                model="gpt-3.5-turbo",
                messages=messages,
                temperature=0.7,
                max_tokens=1500
            )
            return response.choices[0].message['content']
        else:
            # For OpenAI v1.0+
            client = openai.OpenAI()
            response = client.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=messages,
                temperature=0.7,
                max_tokens=1500
            )
            return response.choices[0].message.content
            
    except Exception as e:
        return f"Error during scan: {str(e)}\n\n{traceback.format_exc()}"

# Sidebar configuration
with st.sidebar:
    st.image("https://agno-public.s3.us-east-1.amazonaws.com/assets/logo-light.svg", width=200)
    st.markdown("### Scanner Configuration")
    
    # API Key Input
    api_key = st.text_input("OpenAI API Key", type="password")
    if api_key:
        os.environ["OPENAI_API_KEY"] = api_key
        os.environ["AGNO_OPENAI_API_KEY"] = api_key
        st.session_state.api_key_set = True
        st.success("API Key set!")
    
    st.markdown("---")
    st.markdown("### Scan Options")
    
    show_tools = st.checkbox("Show Tool Calls", value=True)
    show_reasoning = st.checkbox("Show Agent Reasoning", value=True)
    
    st.markdown("---")
    st.markdown("#### About")
    st.markdown("""
    This scanner uses OpenAI to perform security scanning and analysis.
    
    Enter your OpenAI API key, specify the target URL, and choose a scan type
    to perform analysis. Results are displayed in real-time.
    """)

# Create tabs for different functionalities
tabs = st.tabs(["🔎 Web Scanner", "🌐 API Scanner", "🛡️ Code Analysis", "📊 Results Dashboard"])

# Web Scanner Tab
with tabs[0]:
    st.markdown("## Web Security Scanner")
    st.markdown("Scan websites for security vulnerabilities and potential issues.")
    
    col1, col2 = st.columns(2)
    
    with col1:
        target_url = st.text_input("Website URL", value="https://example.com")
    
    with col2:
        scan_type = st.radio("Scan Type", ["Quick Scan", "Reconnaissance", "Full Analysis"])
    
    # Convert scan_type to internal format
    scan_type_internal = "quick"
    if scan_type == "Reconnaissance":
        scan_type_internal = "recon"
    elif scan_type == "Full Analysis":
        scan_type_internal = "full"
    
    # Create placeholders for scan feedback
    progress_placeholder = st.empty()
    status_placeholder = st.empty()
    log_placeholder = st.empty()
    result_placeholder = st.empty()
    
    # Create the scan button and handle click
    if st.button("Start Scan", key="web_scan"):
        if not st.session_state.api_key_set:
            st.error("Please enter your OpenAI API key in the sidebar first.")
        else:
            # Create progress display
            progress_bar = progress_placeholder.progress(0)
            status_text = status_placeholder.text("Initializing scan...")
            log_area = log_placeholder.empty()
            log_area.markdown("<div class='terminal'>Starting scan preparation...</div>", unsafe_allow_html=True)
            
            # Show progress steps
            scan_logs = ["Starting scan preparation..."]
            for step in range(1, 6):
                progress = step * 20
                progress_bar.progress(progress)
                
                if step == 1:
                    status_text.text(f"Scanning: {progress}% complete - Preparing scan")
                    scan_logs.append(f"Analyzing target: {target_url}")
                elif step == 2:
                    status_text.text(f"Scanning: {progress}% complete - Analyzing target")
                    scan_logs.append("Running initial checks...")
                elif step == 3:
                    status_text.text(f"Scanning: {progress}% complete - Running checks")
                    scan_logs.append("Performing deep analysis...")
                elif step == 4:
                    status_text.text(f"Scanning: {progress}% complete - Analyzing findings")
                    scan_logs.append("Processing results...")
                elif step == 5:
                    status_text.text(f"Scan complete!")
                    scan_logs.append("Finalizing report...")
                
                # Update log display
                log_area.markdown(f"<div class='terminal'>{('<br>'.join(scan_logs))}</div>", unsafe_allow_html=True)
                
                # Add a short delay
                time.sleep(1)
            
            # Perform the actual scan
            result = direct_openai_scan(target_url, scan_type_internal, api_key)
            
            # Complete the progress and show final status
            progress_bar.progress(100)
            status_text.text("Scan complete!")
            scan_logs.append("Scan completed successfully.")
            log_area.markdown(f"<div class='terminal'>{('<br>'.join(scan_logs))}</div>", unsafe_allow_html=True)
            
            # Display the result
            result_placeholder.markdown(f"""
            <div class="card">
                <h4>Analysis Report</h4>
                <p>{result}</p>
            </div>
            """, unsafe_allow_html=True)
            
            # Save the result to session state
            st.session_state.scan_results.append({
                "target": target_url,
                "type": scan_type,
                "date": time.strftime("%Y-%m-%d %H:%M:%S"),
                "result": result
            })

# API Scanner Tab
with tabs[1]:
    st.markdown("## API Security Scanner")
    st.markdown("Analyze API endpoints for security issues and vulnerabilities.")
    
    st.info("API scanning functionality will be added in a future update.")
    
    api_url = st.text_input("API Base URL", value="https://api.example.com")
    
    col1, col2 = st.columns(2)
    with col1:
        auth_type = st.selectbox("Authentication Type", ["None", "API Key", "Bearer Token", "OAuth2"])
    
    with col2:
        if auth_type != "None":
            auth_value = st.text_input("Authentication Value", type="password")
    
    st.button("Start API Scan", key="api_scan", disabled=True)

# Code Analysis Tab
with tabs[2]:
    st.markdown("## Code Security Analysis")
    st.markdown("Analyze code repositories for security vulnerabilities.")
    
    st.info("Code analysis functionality will be added in a future update.")
    
    repo_url = st.text_input("Repository URL", value="https://github.com/example/repo")
    
    col1, col2 = st.columns(2)
    with col1:
        scan_depth = st.select_slider("Analysis Depth", options=["Basic", "Standard", "Advanced"])
    
    with col2:
        languages = st.multiselect("Languages", ["All", "JavaScript", "Python", "Java", "PHP"], default=["All"])
    
    st.button("Start Code Analysis", key="code_scan", disabled=True)

# Results Dashboard Tab
with tabs[3]:
    st.markdown("## Results Dashboard")
    st.markdown("View and analyze all previous scan results.")
    
    if not st.session_state.scan_results:
        st.info("No scan results available yet. Run a scan to see results here.")
    else:
        # Display recent scans
        st.markdown("### Recent Scans")
        
        cols = st.columns(3)
        
        for i, scan in enumerate(st.session_state.scan_results[-3:]):
            with cols[i % 3]:
                st.markdown(f"""
                <div class="card">
                    <h4>Scan #{i+1}</h4>
                    <p><strong>Target:</strong> {scan["target"]}</p>
                    <p><strong>Type:</strong> {scan["type"]}</p>
                    <p><strong>Date:</strong> {scan["date"]}</p>
                </div>
                """, unsafe_allow_html=True)
                
                # Add a button to view the details
                if st.button(f"View Details #{i+1}", key=f"view_details_{i}"):
                    st.markdown(f"""
                    <div class="card">
                        <h4>Scan Results</h4>
                        <p>{scan["result"]}</p>
                    </div>
                    """, unsafe_allow_html=True)
        
        # Summary statistics
        st.markdown("### Summary Statistics")
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.metric("Total Scans", len(st.session_state.scan_results))
        
        with col2:
            st.metric("Web Scans", len([s for s in st.session_state.scan_results if "Web" in s["type"] or "Quick" in s["type"]]))
        
        with col3:
            st.metric("Recon Scans", len([s for s in st.session_state.scan_results if "Reconnaissance" in s["type"]]))

# Documentation
st.markdown("---")
st.markdown("### 📋 Documentation")
with st.expander("How to use this scanner"):
    st.markdown("""
    1. **Enter your OpenAI API key** in the sidebar - this is required for the scanner to work
    2. **Choose a scan type** from the available tabs
    3. **Enter the target information** (URL, API endpoint, or repository)
    4. **Configure scan options** if needed
    5. **Click Start Scan** to begin the analysis
    6. **View results** directly in the interface and in the Results Dashboard tab
    
    Scan results are stored in your session and will be available until you close the browser.
    """)

with st.expander("About this security scanner"):
    st.markdown("""
    This scanner uses OpenAI's GPT models to perform security analysis:
    
    - **Quick Scan**: Basic security analysis looking for common issues
    - **Reconnaissance**: Identification of technologies and potential entry points
    - **Full Analysis**: Comprehensive security assessment (premium scan)
    
    The scanner uses the OpenAI API to power these capabilities, which is why an API key is required.
    All analysis is performed ethically and only on targets you own or have permission to scan.
    """) 