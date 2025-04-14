"""🔍 Bug Bounty Hunter Dashboard - Simple Version

This is a simplified version of the Bug Bounty Hunter Dashboard that doesn't rely
on external dependencies like Agno. It demonstrates the UI structure and basic functionality.
"""

import os
import streamlit as st
import time
import random
import json

# Configure the Streamlit page
st.set_page_config(
    page_title="Bug Bounty Hunter Dashboard - Simple",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded",
    menu_items={
        'Get Help': 'https://github.com/agno-ai/agno',
        'Report a bug': 'https://github.com/agno-ai/agno/issues',
        'About': 'Bug Bounty Hunter Dashboard - Simple demo version'
    }
)

# Force light theme
st.markdown("""
<script>
    const localTheme = window.localStorage.getItem('stTheme');
    if (localTheme && localTheme === 'dark') {
        window.localStorage.setItem('stTheme', 'light');
        window.location.reload();
    }
</script>
""", unsafe_allow_html=True)

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
</style>

<div class="main-header">🔍 Bug Bounty Hunter Dashboard (Simple)</div>
""", unsafe_allow_html=True)

# Sidebar configuration
with st.sidebar:
    st.image("https://agno-public.s3.us-east-1.amazonaws.com/assets/logo-light.svg", width=200)
    st.markdown("### Tool Configuration")
    
    # API Key Input
    api_key = st.text_input("OpenAI API Key", type="password")
    if api_key:
        os.environ["OPENAI_API_KEY"] = api_key
        st.success("API Key set!")
    
    st.markdown("---")
    st.markdown("### Scan Options")
    
    show_tools = st.checkbox("Show Tool Calls", value=True)
    show_reasoning = st.checkbox("Show Agent Reasoning", value=True)
    
    st.markdown("---")
    st.markdown("#### About")
    st.markdown("""
    This simplified dashboard demonstrates the UI for the Bug Bounty Hunter system.
    
    The full version supports specialized agents for reconnaissance, vulnerability scanning, 
    exploit testing, and report generation.
    """)

# Create tabs for different functionalities
tabs = st.tabs(["🔎 Quick Scan", "🌐 Web Scanner", "🛡️ Full Team Scan", "📊 Results Dashboard"])

# Quick Scan Tab
with tabs[0]:
    st.markdown("## Quick Reconnaissance Scan")
    st.markdown("Quickly gather information about a target using the Reconnaissance Agent.")
    
    target_url = st.text_input("Target Website or Repository URL",
                              value="https://www.example.com")
    
    if st.button("Start Quick Scan", key="quick_scan"):
        with st.spinner("Running quick scan..."):
            # Simulate scanning process
            progress_bar = st.progress(0)
            status_text = st.empty()
            
            for i in range(100):
                status_text.text(f"Processing: {i+1}%")
                progress_bar.progress(i + 1)
                time.sleep(0.05)
            
            # Display mock results
            st.success("Scan complete!")
            
            st.markdown("### Scan Results")
            st.markdown("""
            <div class="card">
                <h4>Target Information</h4>
                <p><strong>Domain:</strong> example.com</p>
                <p><strong>IP Address:</strong> 93.184.216.34</p>
                <p><strong>Hosting Provider:</strong> Akamai Technologies</p>
                <p><strong>Technologies Detected:</strong> Nginx, jQuery, Bootstrap</p>
            </div>
            
            <div class="card">
                <h4>Open Ports</h4>
                <p><span class="highlight">Port 80 (HTTP): Open</span></p>
                <p><span class="highlight">Port 443 (HTTPS): Open</span></p>
            </div>
            
            <div class="card">
                <h4>Potential Vulnerabilities</h4>
                <p><span class="high">High Risk:</span> Out-of-date jQuery version (1.8.3)</p>
                <p><span class="medium">Medium Risk:</span> Missing HTTP security headers</p>
                <p><span class="low">Low Risk:</span> Information disclosure in HTTP headers</p>
            </div>
            """, unsafe_allow_html=True)

# Web Scanner Tab
with tabs[1]:
    st.markdown("## Web Vulnerability Scanner")
    st.markdown("Scan websites for common vulnerabilities using specialized web scanning agents.")
    
    col1, col2 = st.columns(2)
    
    with col1:
        web_url = st.text_input("Website URL", value="https://www.example.com", key="web_scanner_url")
    
    with col2:
        scan_depth = st.select_slider("Scan Depth", options=["Quick", "Standard", "Deep"])
    
    scan_options = st.multiselect(
        "Vulnerability Categories",
        ["SQL Injection", "XSS", "CSRF", "Open Redirects", "SSRF", "Command Injection", "File Inclusion"],
        default=["SQL Injection", "XSS", "CSRF"]
    )
    
    if st.button("Start Web Scan", key="web_scan"):
        with st.spinner("Scanning website for vulnerabilities..."):
            # Simulate scanning process
            progress_bar = st.progress(0)
            status_text = st.empty()
            
            for i in range(100):
                status_text.text(f"Processing: {i+1}%")
                progress_bar.progress(i + 1)
                time.sleep(0.05)
            
            # Display mock results
            st.success("Web scan complete!")
            
            st.markdown("### Vulnerability Report")
            
            # Mock vulnerabilities
            vulns = [
                {"type": "XSS", "severity": "High", "location": "/search?q=", "details": "Reflected XSS in search parameter"},
                {"type": "Missing Headers", "severity": "Medium", "location": "Global", "details": "Missing Content-Security-Policy header"},
                {"type": "Information Disclosure", "severity": "Low", "location": "/about", "details": "Server version exposed in HTTP headers"}
            ]
            
            for vuln in vulns:
                severity_class = "low"
                if vuln["severity"] == "High":
                    severity_class = "high"
                elif vuln["severity"] == "Medium":
                    severity_class = "medium"
                
                st.markdown(f"""
                <div class="card">
                    <h4>{vuln["type"]}</h4>
                    <p><strong>Severity:</strong> <span class="{severity_class}">{vuln["severity"]}</span></p>
                    <p><strong>Location:</strong> {vuln["location"]}</p>
                    <p><strong>Details:</strong> {vuln["details"]}</p>
                </div>
                """, unsafe_allow_html=True)

# Full Team Scan Tab
with tabs[2]:
    st.markdown("## Full Bug Bounty Team Scan")
    st.markdown("Deploy the complete bug bounty hunter team for comprehensive analysis.")
    
    target = st.text_input("Target (URL or Repository)", value="https://github.com/example/repo")
    
    col1, col2 = st.columns(2)
    
    with col1:
        scan_type = st.radio("Scan Type", ["Code Repository", "Web Application", "API Endpoint"])
    
    with col2:
        depth = st.select_slider("Analysis Depth", options=["Basic", "Standard", "Advanced", "Maximum"])
    
    if st.button("Start Team Scan", key="team_scan"):
        with st.spinner("Deploying the Bug Bounty Hunter team..."):
            # Simulate scanning process
            progress_bar = st.progress(0)
            status_text = st.empty()
            
            phases = ["Reconnaissance", "Vulnerability Scanning", "Exploit Testing", "Report Generation"]
            
            for phase_idx, phase in enumerate(phases):
                status_text.text(f"Phase {phase_idx+1}/4: {phase}")
                
                for i in range(25):
                    progress_percent = phase_idx * 25 + i
                    progress_bar.progress(progress_percent)
                    time.sleep(0.1)
            
            # Display mock results
            st.success("Team scan complete!")
            
            st.markdown("### Team Analysis Results")
            
            # Display tabs for each agent's results
            agent_tabs = st.tabs(["Reconnaissance", "Vulnerability Scanner", "Exploit Tester", "Report Generator"])
            
            with agent_tabs[0]:
                st.markdown("""
                <div class="card">
                    <h4>Repository Analysis</h4>
                    <p><strong>Owner:</strong> Example Organization</p>
                    <p><strong>Contributors:</strong> 18 active contributors</p>
                    <p><strong>Technologies:</strong> JavaScript, React, Node.js, Express</p>
                    <p><strong>Dependencies:</strong> 241 (15 with known vulnerabilities)</p>
                </div>
                
                <div class="card">
                    <h4>Sensitive Information</h4>
                    <p><span class="critical">CRITICAL:</span> API keys found in commit history</p>
                    <p><span class="high">HIGH:</span> Database credentials in configuration files</p>
                </div>
                """, unsafe_allow_html=True)
            
            with agent_tabs[1]:
                st.markdown("""
                <div class="card">
                    <h4>Code Vulnerabilities</h4>
                    <p><span class="high">HIGH:</span> SQL Injection in user authentication (auth.js:125)</p>
                    <p><span class="high">HIGH:</span> Path Traversal vulnerability in file handling (fileService.js:53)</p>
                    <p><span class="medium">MEDIUM:</span> Cross-Site Scripting in user profile (profile.jsx:78)</p>
                    <p><span class="medium">MEDIUM:</span> Insecure randomness in token generation (tokens.js:31)</p>
                    <p><span class="low">LOW:</span> Missing input validation in search functionality (search.js:22)</p>
                </div>
                
                <div class="card">
                    <h4>Dependency Vulnerabilities</h4>
                    <p><span class="critical">CRITICAL:</span> CVE-2023-1234 in express-validator (RCE)</p>
                    <p><span class="high">HIGH:</span> CVE-2023-5678 in moment.js (Data Exposure)</p>
                    <p><span class="medium">MEDIUM:</span> Multiple outdated dependencies with known issues</p>
                </div>
                """, unsafe_allow_html=True)
            
            with agent_tabs[2]:
                st.markdown("""
                <div class="card">
                    <h4>Exploit Testing</h4>
                    <p><span class="critical">CRITICAL:</span> SQL Injection successfully exploited to extract user data</p>
                    <p><span class="high">HIGH:</span> Path Traversal confirmed - able to access sensitive files</p>
                    <p><span class="high">HIGH:</span> XSS payload successfully executed in user profile</p>
                    <p><span class="medium">MEDIUM:</span> Weak token generation confirmed - patterns predictable</p>
                </div>
                
                <div class="card">
                    <h4>Remediation Priority</h4>
                    <p>1. Fix SQL Injection vulnerability in auth.js</p>
                    <p>2. Update express-validator to patch RCE vulnerability</p>
                    <p>3. Implement proper input validation for file paths</p>
                    <p>4. Replace weak randomness implementation with cryptographically secure alternative</p>
                </div>
                """, unsafe_allow_html=True)
            
            with agent_tabs[3]:
                st.markdown("""
                <div class="card">
                    <h4>Executive Summary</h4>
                    <p>The security analysis identified multiple critical and high severity vulnerabilities in the codebase that could potentially lead to unauthorized access, data breaches, and remote code execution.</p>
                    <p>The most pressing issues include SQL injection vulnerabilities, insecure file handling, exposed API keys in version history, and critical vulnerabilities in dependencies.</p>
                    <p>Immediate remediation is recommended for all critical and high severity findings, with medium issues addressed in subsequent development cycles.</p>
                </div>
                
                <div class="card">
                    <h4>Risk Assessment</h4>
                    <p><span class="critical">CRITICAL (2):</span> SQL Injection, Vulnerable Dependencies (RCE)</p>
                    <p><span class="high">HIGH (4):</span> Path Traversal, XSS, API Key Exposure, Database Credential Exposure</p>
                    <p><span class="medium">MEDIUM (3):</span> Insecure Randomness, Missing Security Headers, Outdated Dependencies</p>
                    <p><span class="low">LOW (2):</span> Missing Input Validation, Information Disclosure</p>
                </div>
                """, unsafe_allow_html=True)

# Results Dashboard
with tabs[3]:
    st.markdown("## Results Dashboard")
    st.markdown("View and analyze all previous scan results.")
    
    # Create mock data
    if "scans" not in st.session_state:
        st.session_state.scans = [
            {"id": 1, "target": "https://example.com", "type": "Quick Scan", "date": "2023-08-01", "findings": 3},
            {"id": 2, "target": "https://api.example.org", "type": "Web Scanner", "date": "2023-08-05", "findings": 7},
            {"id": 3, "target": "https://github.com/example/repo", "type": "Full Team Scan", "date": "2023-08-10", "findings": 12},
        ]
    
    # Display recent scans
    st.markdown("### Recent Scans")
    
    cols = st.columns(3)
    
    for i, scan in enumerate(st.session_state.scans):
        with cols[i % 3]:
            severity = "low"
            if scan["findings"] > 10:
                severity = "critical"
            elif scan["findings"] > 5:
                severity = "high"
            elif scan["findings"] > 2:
                severity = "medium"
                
            st.markdown(f"""
            <div class="card">
                <h4>Scan #{scan["id"]}</h4>
                <p><strong>Target:</strong> {scan["target"]}</p>
                <p><strong>Type:</strong> {scan["type"]}</p>
                <p><strong>Date:</strong> {scan["date"]}</p>
                <p><strong>Findings:</strong> <span class="{severity}">{scan["findings"]}</span></p>
                <p><a href="#">View Details</a></p>
            </div>
            """, unsafe_allow_html=True)
    
    # Summary statistics
    st.markdown("### Summary Statistics")
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Total Scans", "3")
    
    with col2:
        st.metric("Critical Findings", "2", delta="0")
    
    with col3:
        st.metric("High Severity", "4", delta="+1")
    
    with col4:
        st.metric("Medium/Low", "16", delta="+3")
    
    # Chart
    st.markdown("### Vulnerability Trend")
    
    chart_data = {
        "labels": ["July", "August", "September"],
        "critical": [1, 2, 0],
        "high": [3, 4, 2],
        "medium": [5, 7, 4],
        "low": [8, 9, 6]
    }
    
    st.bar_chart(
        {
            "Critical": chart_data["critical"],
            "High": chart_data["high"],
            "Medium": chart_data["medium"],
            "Low": chart_data["low"]
        }
    )

st.markdown("---")
st.markdown("### 📋 Documentation")
with st.expander("How to use this dashboard"):
    st.markdown("""
    1. **Quick Scan**: Run a fast reconnaissance scan on a target website or repository to gather basic information.
    2. **Web Scanner**: Perform detailed web vulnerability scanning on a specific URL with customizable options.
    3. **Full Team Scan**: Deploy the complete team of specialized agents for comprehensive security analysis.
    4. **Results Dashboard**: View and analyze the results of all previous scans with statistics and trends.
    
    For each scan type, enter the required information, adjust any optional settings, and click the start button.
    Results will be displayed directly in the interface once the scan is complete.
    """)

with st.expander("About the Bug Bounty Hunter Team"):
    st.markdown("""
    The Bug Bounty Hunter Team consists of specialized agents for different security tasks:
    
    - **Reconnaissance Agent**: Gathers information about targets, identifies technologies, and discovers potential entry points.
    - **Vulnerability Scanner**: Analyzes code and applications for security weaknesses and common vulnerabilities.
    - **Exploit Tester**: Attempts to safely verify vulnerabilities through proof-of-concept exploits.
    - **Report Generator**: Compiles findings into comprehensive reports with prioritized remediation steps.
    
    This dashboard provides a user-friendly interface to interact with these powerful security tools.
    """) 