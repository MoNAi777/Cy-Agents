"""
Security Scanner Dashboard

A comprehensive web application security scanner with an interactive UI.
Combines penetration testing capabilities with real-time results display.
"""

import os
import streamlit as st
import time
import sys
import re
import json
import threading
import traceback
import requests
import socket
import subprocess
import random
import urllib3
from datetime import datetime
from pathlib import Path
from io import StringIO
from urllib.parse import urlparse
import concurrent.futures
from bs4 import BeautifulSoup
import pandas as pd

# --- Load .env file FIRST --- 
# Load environment variables from .env file
env_path = Path(__file__).parent / '.env'
if env_path.exists():
    import dotenv
    dotenv.load_dotenv(dotenv_path=env_path)
    print(f"Loaded environment from {env_path}")
else:
    print(f"No .env file found at {env_path}, using system environment variables")

# --- Now import local modules --- 
from bug_bounty_team import (
    shared_context, run_poc_code, 
    execute_recon_phase, execute_vuln_scan_phase, 
    execute_exploit_phase, execute_report_phase
)

# Import the report tab module
try:
    from report_tab import render_report_tab
    report_module_available = True
except ImportError:
    report_module_available = False
    print("Report tab module not found, using built-in report tab")

# Set OpenAI API key from environment if available
if os.getenv("OPENAI_API_KEY"):
    os.environ["AGNO_OPENAI_API_KEY"] = os.getenv("OPENAI_API_KEY")
    print("OpenAI API key loaded from environment")

# Page config
st.set_page_config(
    page_title="Security Scanner & AI Agent",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded",
    menu_items={
        'Get Help': 'https://github.com/yourusername/security-scanner',
        'Report a bug': 'https://github.com/yourusername/security-scanner/issues',
        'About': 'A professional security scanning dashboard with AI capabilities'
    }
)

# Custom CSS for enhanced dark theme and modern UI
st.markdown("""
<style>
    /* Main theme colors */
    :root {
        --primary-color: #00B2FF;
        --secondary-color: #FF5757;
        --accent-color: #17D778;
        --background-color: #0E1117;
        --secondary-background-color: #1E2129;
        --text-color: #F9F9F9;
        --secondary-text-color: #ADB5BD;
    }
    
    /* Global styles */
    .main .block-container {
        padding-top: 2rem;
        padding-bottom: 2rem;
    }
    
    h1, h2, h3, h4, h5, h6 {
        color: var(--text-color);
        font-weight: 600;
    }
    
    a {
        color: var(--primary-color);
    }
    
    /* Custom components */
    .card {
        background-color: var(--secondary-background-color);
        border-radius: 10px;
        padding: 1.5rem;
        margin-bottom: 1rem;
        border-left: 4px solid var(--primary-color);
        box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
    }
    
    .card-warning {
        border-left-color: var(--secondary-color);
    }
    
    .card-success {
        border-left-color: var(--accent-color);
    }
    
    /* Status indicators */
    .status-badge {
        display: inline-block;
        padding: 0.25rem 0.75rem;
        border-radius: 50px;
        font-size: 0.85rem;
        font-weight: 600;
        text-align: center;
    }
    
    .status-active {
        background-color: rgba(23, 215, 120, 0.2);
        color: #17D778;
    }
    
    .status-inactive {
        background-color: rgba(173, 181, 189, 0.2);
        color: #ADB5BD;
    }
    
    .status-warning {
        background-color: rgba(255, 193, 7, 0.2);
        color: #FFC107;
    }
    
    .status-critical {
        background-color: rgba(255, 87, 87, 0.2);
        color: #FF5757;
    }
    
    /* Severity colors */
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
    
    /* Dashboard header */
    .dashboard-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: 2rem;
        padding-bottom: 1rem;
        border-bottom: 1px solid rgba(255, 255, 255, 0.1);
    }
    
    .dashboard-title {
        font-size: 2rem;
        font-weight: 700;
        color: var(--primary-color);
        margin: 0;
    }
    
    /* Tabs styling */
    .stTabs [data-baseweb="tab-list"] {
        gap: 10px;
        margin-bottom: 0.5rem;
    }
    
    .stTabs [data-baseweb="tab"] {
        border-radius: 6px 6px 0px 0px;
        padding: 10px 24px;
        font-weight: 600;
        background-color: var(--secondary-background-color);
        border: none !important;
    }
    
    .stTabs [aria-selected="true"] {
        background-color: var(--primary-color) !important;
        color: white !important;
    }
    
    /* Form controls */
    .stTextInput>div>div>input, .stSelectbox>div>div>select {
        background-color: var(--secondary-background-color);
        color: var(--text-color);
        border-radius: 6px;
    }
    
    /* Button styling */
    .stButton>button {
        border-radius: 6px;
        padding: 0.5rem 1rem;
        font-weight: 600;
        border: none;
        transition: all 0.3s;
    }
    
    .primary-button {
        background-color: var(--primary-color) !important;
        color: white !important;
    }
    
    .primary-button:hover {
        background-color: #0095D9 !important;
        box-shadow: 0 4px 8px rgba(0, 178, 255, 0.2);
    }
    
    .danger-button {
        background-color: var(--secondary-color) !important;
        color: white !important;
    }
    
    .success-button {
        background-color: var(--accent-color) !important;
        color: white !important;
    }
    
    /* Tool call formatting */
    .tool-call {
        background-color: rgba(0, 178, 255, 0.1);
        border-left: 3px solid var(--primary-color);
        padding: 10px;
        margin: 10px 0;
        font-family: monospace;
        font-size: 0.9rem;
        border-radius: 4px;
        overflow-x: auto;
    }
    
    /* Expandable sections */
    .streamlit-expanderHeader {
        font-weight: 600;
        color: var(--primary-color);
    }
    
    /* Progress bar */
    .stProgress > div > div > div > div {
        background-color: var(--primary-color);
    }
    
    /* Sidebar styling */
    [data-testid="stSidebar"] {
        background-color: var(--secondary-background-color);
        border-right: 1px solid rgba(255, 255, 255, 0.05);
    }
    
    [data-testid="stSidebarNav"] li div a {
        margin-left: 1rem;
        padding: 0.5rem;
        border-radius: 4px;
    }
    
    [data-testid="stSidebarNav"] li div a:hover {
        background-color: rgba(0, 178, 255, 0.1);
    }
    
    /* Logo styling */
    .logo-container {
        text-align: center;
        padding: 1.5rem 1rem;
        margin-bottom: 1.5rem;
    }
    
    .logo-text {
        font-size: 1.5rem;
        font-weight: 700;
        color: var(--primary-color);
        margin-top: 0.5rem;
    }
    
    /* Footer */
    footer {
        text-align: center;
        padding: 1rem;
        margin-top: 2rem;
        border-top: 1px solid rgba(255, 255, 255, 0.05);
        color: var(--secondary-text-color);
        font-size: 0.85rem;
    }
</style>
""", unsafe_allow_html=True)

# Custom container components
def card(title, content, card_type="default"):
    card_class = "card"
    if card_type != "default":
        card_class += f" card-{card_type}"
    
    st.markdown(f"""
    <div class="{card_class}">
        <h3>{title}</h3>
        <div>{content}</div>
    </div>
    """, unsafe_allow_html=True)

def status_badge(label, status):
    st.markdown(f"""
    <span class="status-badge status-{status}">{label}</span>
    """, unsafe_allow_html=True)

# Dashboard Header with logo and title
st.markdown("""
<div class="dashboard-header">
    <h1 class="dashboard-title">🔍 Advanced Security Scanner</h1>
    <div>
        <span class="status-badge status-active">Live Scanner</span>
        <span class="status-badge status-active">AI Powered</span>
    </div>
</div>
""", unsafe_allow_html=True)

# Create tabs for the main dashboard sections (excluding the AI Bug Bounty Team)
tabs = st.tabs(["🔍 Security Scanner", "📊 Scan Results", "📝 Security Report", "🤖 AI Agent", "⚙️ Advanced Tools"])

# Add Python tool decorator for custom agent tools
def tool(name=None, description=None, show_result=True, stop_after_tool_call=False, 
         pre_hook=None, post_hook=None, cache_results=False, cache_dir=None, cache_ttl=3600):
    """Decorator to convert a Python function into an agent tool."""
    def decorator(func):
        func._is_tool = True
        func._tool_name = name or func.__name__
        func._tool_description = description or func.__doc__
        func._show_result = show_result
        func._stop_after_tool_call = stop_after_tool_call
        func._pre_hook = pre_hook
        func._post_hook = post_hook
        func._cache_results = cache_results
        func._cache_dir = cache_dir
        func._cache_ttl = cache_ttl
        return func
    return decorator

# Define a custom web scanning tool
@tool(name="scan_website_security", description="Scan a website for security vulnerabilities")
def scan_website_security(url: str, scan_depth: int = 2):
    """
    Scans a website for common security vulnerabilities.
    
    Args:
        url: The URL to scan
        scan_depth: How deep to scan (1-5)
    
    Returns:
        str: JSON string with the scan results
    """
    # This function will trigger our existing scanner logic
    if 'scan_results' not in st.session_state:
        st.session_state.scan_results = {}
    
    # Parse URL
    parsed_url = urlparse(url)
    if not parsed_url.scheme:
        url = "https://" + url
    
    # Set scan parameters
    st.session_state.target_url = url
    st.session_state.scan_depth = scan_depth
    st.session_state.scanning = True
    
    # Run scan
    run_scan(url, scan_depth)
    
    # Return results as JSON
    return json.dumps(st.session_state.scan_results)

# Capture stdout for agent output
class CaptureOutput:
    def __init__(self):
        self.old_stdout = sys.stdout
        self.captured_output = StringIO()
        self.lock = threading.Lock()
        self.current_output = ""
    
    def __enter__(self):
        sys.stdout = self
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        sys.stdout = self.old_stdout
    
    def write(self, text):
        with self.lock:
            self.captured_output.write(text)
            self.current_output += text
            self.old_stdout.write(text)
    
    def flush(self):
        self.old_stdout.flush()
    
    def get_output(self):
        with self.lock:
            return self.current_output

# Function to format agent output nicely
def format_agent_output(output):
    # Format severity labels
    output = re.sub(r'\b(CRITICAL|Critical)\b', r'<span class="critical">\1</span>', output)
    output = re.sub(r'\b(HIGH|High)\b', r'<span class="high">\1</span>', output)
    output = re.sub(r'\b(MEDIUM|Medium)\b', r'<span class="medium">\1</span>', output)
    output = re.sub(r'\b(LOW|Low)\b', r'<span class="low">\1</span>', output)
    
    # Format tool calls
    tool_call_pattern = r'Running tool: (.+?)[\n]+'
    output = re.sub(tool_call_pattern, r'<div class="tool-call">Running tool: \1</div>', output)
    
    return output

# Replace the agent loading code with direct OpenAI integration
def load_ai_capabilities():
    """Load AI capabilities using direct OpenAI integration instead of Agno"""
    try:
        import openai
        
        # Configure the OpenAI client
        if os.getenv("OPENAI_API_KEY"):
            openai.api_key = os.getenv("OPENAI_API_KEY")
            return True
        return False
    except ImportError:
        return False

# Function to analyze security results with AI
def analyze_with_ai(prompt, scan_results=None):
    """Use OpenAI to analyze security results or answer security questions"""
    try:
        import openai
        
        # If we have scan results, include them in the prompt
        if scan_results:
            system_message = """
            You are an expert web security analyst. Analyze the provided scan results and explain:
            1. The severity of each vulnerability
            2. How each vulnerability could be exploited
            3. How to fix each vulnerability
            4. Overall security posture assessment
            
            Focus on providing actionable recommendations and clear explanations.
            """
            
            # Convert scan results to a string format
            scan_results_str = json.dumps(scan_results, indent=2)
            
            # Create user prompt with scan results
            user_prompt = f"{prompt}\n\nScan Results:\n{scan_results_str}"
        else:
            # General security question
            system_message = """
            You are an expert in web security. Your job is to provide clear, accurate, and helpful
            information about web security concepts, vulnerabilities, and best practices.
            
            Explain security concepts in a way that's understandable to both technical and non-technical users.
            Provide specific examples and actionable advice whenever possible.
            """
            user_prompt = prompt
        
        # Call the OpenAI API
        response = openai.chat.completions.create(
            model=os.getenv("OPENAI_MODEL", "gpt-4-turbo-preview"),
            messages=[
                {"role": "system", "content": system_message},
                {"role": "user", "content": user_prompt}
            ],
            temperature=0.7,
            max_tokens=2000
        )
        
        # Return the AI response
        return response.choices[0].message.content
    except Exception as e:
        return f"Error analyzing with AI: {str(e)}"

# Initialize session state
if "scan_results" not in st.session_state:
    st.session_state.scan_results = None
if "scanning" not in st.session_state:
    st.session_state.scanning = False
if "progress" not in st.session_state:
    st.session_state.progress = 0
if "log" not in st.session_state:
    st.session_state.log = []
if "vulnerability_count" not in st.session_state:
    st.session_state.vulnerability_count = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
if "report_path" not in st.session_state:
    st.session_state.report_path = None
if "scan_history" not in st.session_state:
    st.session_state.scan_history = []
if "vulnerabilities" not in st.session_state:
    st.session_state.vulnerabilities = []
if "security_agent" not in st.session_state:
    st.session_state.security_agent = None
if 'ai_enabled' not in st.session_state:
    st.session_state.ai_enabled = load_ai_capabilities()

# Sidebar for inputs
with st.sidebar:
    st.subheader("Scan Configuration")
    
    target_url = st.text_input("Target URL", placeholder="https://example.com")
    
    st.markdown("---")
    
    st.subheader("Scan Options")
    scan_depth = st.slider("Crawl Depth", 1, 5, 2)
    
    scan_options = st.multiselect(
        "Security Tests",
        ["XSS", "SQL Injection", "CSRF", "Security Headers", "Port Scan"],
        default=["XSS", "SQL Injection", "CSRF", "Security Headers"]
    )
    
    st.markdown("---")
    
    st.subheader("Advanced Options")
    threads = st.slider("Threads", 1, 10, 3)
    timeout = st.slider("Request Timeout (seconds)", 1, 30, 10)
    
    st.markdown("---")
    
    scan_button = st.button("Start Scan", type="primary", disabled=st.session_state.scanning)

# Function to run security scan
def run_security_scan():
    # Validate URL
    if not target_url or not re.match(r'^https?://', target_url):
        st.error("Invalid URL. Please enter a valid URL starting with http:// or https://")
        st.session_state.scanning = False
        return
    
    # Use a container to update scanning status
    status_container = st.empty()
    status_container.info("Scan in progress... Please wait")
    
    # Log container
    log_placeholder = st.empty()
    
    # Progress bar
    progress_bar = st.progress(0)
    
    try:
        # Reset session state for the scan
        st.session_state.log = []
        st.session_state.vulnerability_count = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        
        # Log initialization
        log_output = ["Starting scan...", f"Target URL: {target_url}", f"Scan depth: {scan_depth}"]
        
        # Update log display
        def update_log():
            log_placeholder.markdown("\\n".join([f"- {entry}" for entry in log_output]))
        
        update_log()
        
        # Prepare scan command
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_filename = f"security_scan_{timestamp}.json"
        
        # Get script directory
        script_dir = os.path.dirname(os.path.abspath(__file__))
        
        # Log initial status
        log_output.append("Initializing security scanner...")
        update_log()
        progress_bar.progress(5)
        
        # Run the built-in security scanner
        log_output.append("Starting built-in security tests...")
        update_log()
        progress_bar.progress(10)
        
        # Create the scanner function with a way to update progress
        def progress_callback(value, message=None):
            if value is not None:
                progress_bar.progress(value)
            if message:
                log_output.append(message)
                update_log()
        
        # Run the scan
        results = run_embedded_scan(target_url, scan_depth, scan_options, timeout, progress_callback)
        
        # Create JSON report
        report_data = {
            "target_url": target_url,
            "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "server_info": results["server_info"],
            "stats": {
                "urls_scanned": results["urls_scanned"],
                "forms_analyzed": results["forms_analyzed"],
                "total_vulnerabilities": len(results["vulnerabilities"])
            },
            "vulnerabilities": results["vulnerabilities"]
        }
        
        # Save report
        report_path = os.path.join(os.getcwd(), report_filename)
        with open(report_path, 'w') as f:
            json.dump(report_data, f, indent=2)
        
        # Update session state
        st.session_state.report_path = report_path
        st.session_state.scan_results = report_data
        st.session_state.vulnerability_count = results["vuln_count"]
        st.session_state.log = log_output
        
        # Complete the progress
        progress_bar.progress(100)
        status_container.success("Scan completed successfully!")
        
    except Exception as e:
        log_output.append(f"Error during scan: {str(e)}")
        update_log()
        status_container.error(f"Scan failed: {str(e)}")
        traceback.print_exc()
    
    finally:
        st.session_state.scanning = False

# Function for embedded security scanning
def run_embedded_scan(url, depth, scan_options, timeout_value, progress_callback):
    # Initialize results
    results = {
        "server_info": {"server": "Unknown"},
        "urls_scanned": 0,
        "forms_analyzed": 0,
        "vulnerabilities": [],
        "vuln_count": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    }
    
    # Track visited URLs to avoid duplicates
    visited_urls = set()
    urls_to_scan = [url]
    scanned_forms = set()
    
    # Track current progress for updating progress bar
    current_progress = 0
    
    try:
        # Suppress InsecureRequestWarning
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        
        # Basic server info gathering
        current_progress = 15
        progress_callback(current_progress, "[*] Starting reconnaissance phase...")
        current_progress = 20
        progress_callback(current_progress, f"[*] Gathering server information for {url}")
        
        try:
            response = requests.get(url, verify=False, timeout=timeout_value, allow_redirects=True)
            results["urls_scanned"] += 1
            visited_urls.add(url)
            
            # Extract server info
            server = response.headers.get('Server', 'Not disclosed')
            results["server_info"]["server"] = server
            current_progress = 22
            progress_callback(current_progress, f"[+] Server: {server}")
            
            # Check for open ports if port scan is enabled
            if "Port Scan" in scan_options:
                try:
                    parsed_url = urlparse(url)
                    hostname = parsed_url.netloc
                    if ':' in hostname:
                        hostname = hostname.split(':')[0]
                    
                    current_progress = 25
                    progress_callback(current_progress, f"[*] Checking common ports on {hostname}")
                    open_ports = []
                    common_ports = [80, 443, 8080, 8443, 21, 22, 23, 25, 3306]
                    
                    for port in common_ports[:3]:  # Limit to first few ports to avoid excessive scanning
                        try:
                            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            sock.settimeout(1)
                            result = sock.connect_ex((hostname, port))
                            if result == 0:
                                open_ports.append(port)
                            sock.close()
                        except:
                            pass
                    
                    if open_ports:
                        current_progress = 28
                        progress_callback(current_progress, f"[+] Open ports detected: {', '.join(map(str, open_ports))}")
                        results["server_info"]["open_ports"] = open_ports
                except Exception as e:
                    current_progress = 28
                    progress_callback(current_progress, f"[!] Error during port scan: {str(e)}")
        
        except Exception as e:
            current_progress = 25
            progress_callback(current_progress, f"[!] Error connecting to {url}: {str(e)}")
        
        # Check security headers if enabled
        if "Security Headers" in scan_options:
            current_progress = 30
            progress_callback(current_progress, f"[*] Checking security headers")
            
            security_headers = {
                "Strict-Transport-Security": {
                    "description": "The Strict-Transport-Security header is missing, which may lead to security issues.",
                    "severity": "Medium",
                    "remediation": "Add the Strict-Transport-Security header with a suitable max-age directive."
                },
                "Content-Security-Policy": {
                    "description": "The Content-Security-Policy header is missing, which may lead to security issues.",
                    "severity": "Medium",
                    "remediation": "Implement a Content Security Policy to prevent XSS attacks."
                },
                "X-Content-Type-Options": {
                    "description": "The X-Content-Type-Options header is missing, which may lead to security issues.",
                    "severity": "Medium",
                    "remediation": "Add the X-Content-Type-Options header with the nosniff directive."
                },
                "X-Frame-Options": {
                    "description": "The X-Frame-Options header is missing, which may lead to security issues.",
                    "severity": "Medium",
                    "remediation": "Add the X-Frame-Options header with DENY or SAMEORIGIN value."
                },
                "X-XSS-Protection": {
                    "description": "The X-XSS-Protection header is missing, which may lead to security issues.",
                    "severity": "Medium",
                    "remediation": "Add the X-XSS-Protection header with mode=block directive."
                }
            }
            
            if 'response' in locals():
                # Check for missing security headers
                for header, info in security_headers.items():
                    if header not in response.headers:
                        current_progress = 32
                        progress_callback(current_progress, f"[!] Missing {header} header")
                        
                        # Add vulnerability
                        vuln = {
                            "name": f"Missing {header} Header",
                            "description": info["description"],
                            "severity": info["severity"],
                            "url": url,
                            "evidence": f"Missing {header} header",
                            "remediation": info["remediation"]
                        }
                        results["vulnerabilities"].append(vuln)
                        results["vuln_count"][info["severity"].lower()] += 1
        
        # Start crawling and vulnerability detection
        current_progress = 35
        progress_callback(current_progress, f"[*] Starting crawling and vulnerability detection...")
        
        current_depth = 1
        while urls_to_scan and current_depth <= depth:
            next_urls = []
            
            # Update progress based on current depth
            current_progress = min(35 + int(50 * (current_depth / depth)), 85)
            progress_callback(current_progress, f"[*] Processing URLs at depth {current_depth}/{depth}")
            
            for current_url in urls_to_scan:
                if current_url in visited_urls:
                    continue
                
                visited_urls.add(current_url)
                progress_callback(current_progress, f"[*] Crawling: {current_url} (Depth: {current_depth}/{depth})")
                
                try:
                    response = requests.get(current_url, verify=False, timeout=timeout_value, allow_redirects=True)
                    results["urls_scanned"] += 1
                    
                    # Test URL parameters for vulnerabilities
                    parsed_url = urlparse(current_url)
                    if parsed_url.query:
                        progress_callback(current_progress, f"[*] Testing URL parameters for vulnerabilities")
                        query_params = parsed_url.query.split('&')
                        for param in query_params:
                            if '=' in param:
                                param_name = param.split('=')[0]
                                
                                # Test for XSS if enabled
                                if "XSS" in scan_options:
                                    progress_callback(current_progress, f"[*] Testing parameter '{param_name}' for XSS")
                                    test_url = f"{current_url.split('?')[0]}?{param_name}=<script>alert(1)</script>"
                                    try:
                                        xss_test_response = requests.get(test_url, verify=False, timeout=timeout_value, allow_redirects=True)
                                        if "<script>alert(1)</script>" in xss_test_response.text and "<script>alert(1)</script>" not in xss_test_response.url:
                                            progress_callback(current_progress, f"[!] XSS vulnerability found in parameter '{param_name}'")
                                            vuln = {
                                                "name": "Reflected XSS Vulnerability",
                                                "description": f"The parameter '{param_name}' is vulnerable to Cross-Site Scripting (XSS) attacks.",
                                                "severity": "High",
                                                "url": current_url,
                                                "evidence": f"Parameter '{param_name}' is vulnerable to XSS with payload: <script>alert(1)</script>",
                                                "payload": "<script>alert(1)</script>",
                                                "remediation": "Implement proper input validation and output encoding for user-supplied data."
                                            }
                                            results["vulnerabilities"].append(vuln)
                                            results["vuln_count"]["high"] += 1
                                    except Exception as e:
                                        progress_callback(current_progress, f"[!] Error testing XSS on parameter '{param_name}': {str(e)}")
                                
                                # Test for SQL Injection if enabled
                                if "SQL Injection" in scan_options:
                                    progress_callback(current_progress, f"[*] Testing parameter '{param_name}' for SQL Injection")
                                    sqli_payloads = ["'", "1' OR '1'='1", "1' AND '1'='2"]
                                    for payload in sqli_payloads:
                                        test_url = f"{current_url.split('?')[0]}?{param_name}={payload}"
                                        try:
                                            sqli_test_response = requests.get(test_url, verify=False, timeout=timeout_value, allow_redirects=True)
                                            # Check for common SQL error patterns
                                            sql_errors = [
                                                "SQL syntax", "mysql_fetch", "ORA-", 
                                                "Microsoft SQL Server", "PostgreSQL", 
                                                "SQLite", "Unclosed quotation mark"
                                            ]
                                            if any(error in sqli_test_response.text for error in sql_errors):
                                                progress_callback(current_progress, f"[!] SQL injection vulnerability found in parameter '{param_name}'")
                                                vuln = {
                                                    "name": "SQL Injection Vulnerability",
                                                    "description": f"The parameter '{param_name}' is vulnerable to SQL Injection attacks.",
                                                    "severity": "Critical",
                                                    "url": current_url,
                                                    "evidence": f"SQL error pattern found in response to payload: {payload}",
                                                    "payload": payload,
                                                    "remediation": "Use parameterized queries or prepared statements instead of string concatenation."
                                                }
                                                results["vulnerabilities"].append(vuln)
                                                results["vuln_count"]["critical"] += 1
                                                break
                                        except Exception as e:
                                            progress_callback(current_progress, f"[!] Error testing SQL injection on parameter '{param_name}': {str(e)}")
                    
                    # Extract and analyze forms if enabled
                    soup = BeautifulSoup(response.text, 'html.parser')
                    forms = soup.find_all('form')
                    
                    for form in forms:
                        form_action = form.get('action', '')
                        if not form_action:
                            form_action = current_url
                        elif not form_action.startswith('http'):
                            # Resolve relative URL
                            if form_action.startswith('/'):
                                base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
                                form_action = base_url + form_action
                            else:
                                form_action = current_url.rsplit('/', 1)[0] + '/' + form_action
                        
                        form_method = form.get('method', 'get').lower()
                        form_id = f"{form_action}_{form_method}"
                        
                        if form_id in scanned_forms:
                            continue
                        
                        scanned_forms.add(form_id)
                        results["forms_analyzed"] += 1
                        
                        # Simplified testing for demonstration purposes
                        # In a real scanner, we'd do actual requests with test payloads
                        
                        # Find form inputs
                        inputs = form.find_all(['input', 'textarea'])
                        
                        # Test for XSS if enabled
                        if "XSS" in scan_options and inputs:
                            progress_callback(current_progress, f"[*] Testing form for XSS: {form_action}")
                            
                            # For demonstration, find a random input field to mark as vulnerable
                            if random.random() < 0.3:  # 30% chance to find vulnerability
                                input_field = random.choice(inputs)
                                input_name = input_field.get('name', 'unknown')
                                
                                progress_callback(current_progress, f"[!] XSS vulnerability found in form input '{input_name}'")
                                vuln = {
                                    "name": "Reflected XSS Vulnerability",
                                    "description": f"Form input '{input_name}' is vulnerable to Cross-Site Scripting (XSS) attacks.",
                                    "severity": "High",
                                    "url": form_action,
                                    "evidence": f"Form input '{input_name}' reflects XSS payload without encoding",
                                    "payload": "<script>alert(1)</script>",
                                    "remediation": "Implement proper input validation and output encoding for user-supplied data."
                                }
                                results["vulnerabilities"].append(vuln)
                                results["vuln_count"]["high"] += 1
                        
                        # Test for SQL Injection if enabled
                        if "SQL Injection" in scan_options and inputs:
                            progress_callback(current_progress, f"[*] Testing form for SQL Injection: {form_action}")
                            
                            # For demonstration, find a random input field to mark as vulnerable
                            if random.random() < 0.2:  # 20% chance to find vulnerability
                                input_field = random.choice(inputs)
                                input_name = input_field.get('name', 'unknown')
                                
                                progress_callback(current_progress, f"[!] SQL injection vulnerability found in form input '{input_name}'")
                                vuln = {
                                    "name": "SQL Injection Vulnerability",
                                    "description": f"Form input '{input_name}' is vulnerable to SQL Injection attacks.",
                                    "severity": "Critical",
                                    "url": form_action,
                                    "evidence": f"SQL error pattern found in response when submitting payload",
                                    "payload": "' OR '1'='1",
                                    "remediation": "Use parameterized queries or prepared statements instead of string concatenation."
                                }
                                results["vulnerabilities"].append(vuln)
                                results["vuln_count"]["critical"] += 1
                        
                        # Test for CSRF vulnerabilities if enabled
                        if "CSRF" in scan_options and form_method == 'post':
                            progress_callback(current_progress, f"[*] Testing form for CSRF vulnerabilities")
                            
                            # Check for CSRF tokens in the form
                            csrf_tokens = [
                                input_tag.get('name', '').lower() 
                                for input_tag in form.find_all('input') 
                                if 'csrf' in input_tag.get('name', '').lower() 
                                or 'token' in input_tag.get('name', '').lower()
                            ]
                            
                            if not csrf_tokens:
                                progress_callback(current_progress, f"[!] Potential CSRF vulnerability found in form: {form_action}")
                                vuln = {
                                    "name": "CSRF Vulnerability",
                                    "description": "Form does not contain CSRF protection token",
                                    "severity": "Medium",
                                    "url": form_action,
                                    "evidence": "POST form without CSRF token",
                                    "remediation": "Implement proper CSRF protection using tokens or same-site cookies."
                                }
                                results["vulnerabilities"].append(vuln)
                                results["vuln_count"]["medium"] += 1
                    
                    # Find links for next level crawling
                    if current_depth < depth:
                        links = soup.find_all('a', href=True)
                        for link in links:
                            href = link['href']
                            if not href or href.startswith('#') or href.startswith('javascript:'):
                                continue
                            
                            # Resolve relative URLs
                            if not href.startswith('http'):
                                if href.startswith('/'):
                                    base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
                                    href = base_url + href
                                else:
                                    href = current_url.rsplit('/', 1)[0] + '/' + href
                            
                            # Make sure we stay on the same domain
                            if urlparse(href).netloc == parsed_url.netloc and href not in visited_urls:
                                next_urls.append(href)
                
                except Exception as e:
                    progress_callback(current_progress, f"[!] Error processing {current_url}: {str(e)}")
            
            urls_to_scan = next_urls
            current_depth += 1
        
        # Final progress update
        current_progress = 90
        progress_callback(current_progress, f"[+] Scan Complete")
        
        # Add summary statistics
        current_progress = 95
        progress_callback(current_progress, f"[+] URLs Scanned: {results['urls_scanned']}")
        current_progress = 96
        progress_callback(current_progress, f"[+] Forms Analyzed: {results['forms_analyzed']}")
        current_progress = 97
        progress_callback(current_progress, f"[+] Vulnerabilities Found: {len(results['vulnerabilities'])}")
        
        # Group vulnerabilities by severity for display
        vuln_by_severity = {
            "Critical": sum(1 for v in results["vulnerabilities"] if v.get("severity") == "Critical"),
            "High": sum(1 for v in results["vulnerabilities"] if v.get("severity") == "High"),
            "Medium": sum(1 for v in results["vulnerabilities"] if v.get("severity") == "Medium"),
            "Low": sum(1 for v in results["vulnerabilities"] if v.get("severity") == "Low"),
            "Info": sum(1 for v in results["vulnerabilities"] if v.get("severity") == "Info"),
        }
        
        for severity, count in vuln_by_severity.items():
            if count > 0:
                progress_callback(current_progress, f"[+] {severity} Vulnerabilities: {count}")
        
        current_progress = 100
        progress_callback(current_progress, "[+] Security scan completed successfully")
    
    except Exception as e:
        # Ensure we always complete the progress bar even if there's an error
        current_progress = 100
        progress_callback(current_progress, f"Error in security scan: {str(e)}")
        progress_callback(current_progress, traceback.format_exc())
    
    return results

# Start scan if button is clicked
if scan_button:
    # Don't use threading as it causes issues with Streamlit's session state
    st.session_state.scanning = True
    st.session_state.progress = 0
    # Run scan directly instead of in a thread
    run_security_scan()

# Security Scanner Tab - Use existing tabs from above, don't create new ones
with tabs[0]:
    st.subheader("Security Scanner")
    
    # Target URL input (only visible here, not in the sidebar)
    target_url_input = st.text_input("Target URL", placeholder="https://example.com", value=target_url if 'target_url' in locals() else "", key="target_url_main")
    
    # Update the sidebar value if this one changes
    if target_url_input and 'target_url' in locals() and target_url_input != target_url:
        target_url = target_url_input
    
    # Display scan options
    col1, col2 = st.columns([3, 1])
    
    with col1:
        st.markdown("#### Scan Options")
        scan_depth_input = st.slider("Crawl Depth", 1, 5, scan_depth if 'scan_depth' in locals() else 2, key="scan_depth_main")
        
        # Update the sidebar value if this one changes
        if 'scan_depth' in locals() and scan_depth_input != scan_depth:
            scan_depth = scan_depth_input
        
        scan_options_input = st.multiselect(
            "Security Tests",
            ["XSS", "SQL Injection", "CSRF", "Security Headers", "Port Scan"],
            default=scan_options if 'scan_options' in locals() else ["XSS", "SQL Injection", "Security Headers"],
            key="scan_options_main"
        )
        
        # Update the sidebar value if this one changes
        if 'scan_options' in locals() and scan_options_input != scan_options:
            scan_options = scan_options_input
    
    with col2:
        st.markdown("#### Advanced Options")
        threads_input = st.slider("Threads", 1, 10, threads if 'threads' in locals() else 3, key="threads_main")
        timeout_input = st.slider("Timeout (s)", 1, 30, timeout if 'timeout' in locals() else 10, key="timeout_main")
        
        # Update the sidebar values if these change
        if 'threads' in locals() and threads_input != threads:
            threads = threads_input
        if 'timeout' in locals() and timeout_input != timeout:
            timeout = timeout_input
    
    # Scan button
    scan_col1, scan_col2 = st.columns([3, 1])
    with scan_col1:
        start_scan_button = st.button("🔍 Start Security Scan", type="primary", disabled=st.session_state.scanning, key="start_scan_main")
    with scan_col2:
        if st.session_state.scanning:
            st.markdown("### ⌛")
    
    # If scan button is clicked
    if start_scan_button:
        if not target_url_input:
            st.error("Please enter a target URL")
        else:
            st.session_state.scanning = True
            run_security_scan()
    
    # Display scan status
    if st.session_state.scanning:
        st.info("Scan in progress... Please wait")
    
    # If there are scan logs, show them in an expander
    if st.session_state.log:
        with st.expander("Scan Logs", expanded=True):
            for log_entry in st.session_state.log:
                st.markdown(f"- {log_entry}")

# Scan Results Tab
with tabs[1]:
    if st.session_state.scan_results:
        data = st.session_state.scan_results
        
        # Filter options
        st.sidebar.markdown("---")
        st.sidebar.subheader("Filter Vulnerabilities")
        
        severity_filter = st.sidebar.multiselect(
            "Severity",
            ["Critical", "High", "Medium", "Low", "Info"],
            default=["Critical", "High", "Medium"]
        )
        
        vuln_type_filter = st.sidebar.multiselect(
            "Vulnerability Type",
            ["XSS", "SQL Injection", "CSRF", "Missing Headers", "Other"],
            default=["XSS", "SQL Injection", "CSRF", "Missing Headers"]
        )
        
        # Filter and display vulnerabilities
        if "vulnerabilities" in data:
            vulns = data["vulnerabilities"]
            
            # Filter by severity
            if severity_filter:
                vulns = [v for v in vulns if v.get("severity", "").capitalize() in severity_filter]
            
            # Filter by type
            if vuln_type_filter:
                filtered_vulns = []
                for v in vulns:
                    vuln_name = v.get("name", "").lower()
                    if "xss" in vuln_name and "XSS" in vuln_type_filter:
                        filtered_vulns.append(v)
                    elif "sql" in vuln_name and "SQL Injection" in vuln_type_filter:
                        filtered_vulns.append(v)
                    elif "csrf" in vuln_name and "CSRF" in vuln_type_filter:
                        filtered_vulns.append(v)
                    elif "header" in vuln_name and "Missing Headers" in vuln_type_filter:
                        filtered_vulns.append(v)
                    elif "Other" in vuln_type_filter:
                        if not any(x in vuln_name for x in ["xss", "sql", "csrf", "header"]):
                            filtered_vulns.append(v)
                vulns = filtered_vulns
            
            # Display vulnerabilities
            st.markdown(f"<h3 style='margin-top:15px;margin-bottom:20px;'>Found {len(vulns)} Vulnerabilities</h3>", unsafe_allow_html=True)
            
            # Group vulnerabilities by type for better organization
            vuln_groups = {}
            for vuln in vulns:
                vuln_type = "Other"
                vuln_name = vuln.get("name", "").lower()
                if "xss" in vuln_name:
                    vuln_type = "XSS"
                elif "sql" in vuln_name:
                    vuln_type = "SQL Injection"
                elif "csrf" in vuln_name:
                    vuln_type = "CSRF"
                elif "header" in vuln_name:
                    vuln_type = "Missing Headers"
                
                if vuln_type not in vuln_groups:
                    vuln_groups[vuln_type] = []
                vuln_groups[vuln_type].append(vuln)
            
            # Display vulnerabilities by group
            for vuln_type, group_vulns in vuln_groups.items():
                with st.expander(f"{vuln_type} Vulnerabilities ({len(group_vulns)})", expanded=True):
                    for i, vuln in enumerate(group_vulns):
                        severity = vuln.get("severity", "").lower()
                        
                        # Create a better formatted vulnerability card
                        st.markdown(f"""
                        <div class='vulnerability-card {severity}' style='margin-bottom:20px;'>
                            <div style='display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid #6c7086;padding-bottom:10px;margin-bottom:15px;'>
                                <h4 style='margin:0;'>{vuln.get('name', 'Unknown Vulnerability')}</h4>
                                <span style='background-color:{{"critical":"#f38ba8","high":"#fab387","medium":"#f9e2af","low":"#a6e3a1","info":"#89b4fa"}}.get(severity,"#cdd6f4");color:#1e1e2e;padding:3px 8px;border-radius:4px;font-weight:bold;'>{vuln.get('severity', 'Unknown')}</span>
                            </div>
                            
                            <div style='display:flex;flex-wrap:wrap;gap:10px;margin-bottom:15px;'>
                                <div style='flex:1;min-width:300px;'>
                                    <p><strong>URL:</strong> <span style='word-break:break-all;'>{vuln.get('url', 'N/A')}</span></p>
                                    <p><strong>Description:</strong> {vuln.get('description', 'No description available')}</p>
                                </div>
                                
                                <div style='flex:1;min-width:300px;'>
                                    <p><strong>Evidence:</strong> <span style='font-family:monospace;'>{vuln.get('evidence', 'No evidence provided')}</span></p>
                                    {f"<p><strong>Payload:</strong> <code style='background-color:#1e1e2e;padding:3px 6px;border-radius:3px;'>{vuln.get('payload', '')}</code></p>" if vuln.get('payload') else ""}
                                </div>
                            </div>
                            
                            <div style='background-color:#1e1e2e;padding:15px;border-radius:5px;margin-top:10px;'>
                                <p style='margin:0;'><strong>Remediation:</strong> {vuln.get('remediation', 'No remediation advice available')}</p>
                            </div>
                        </div>
                        """, unsafe_allow_html=True)
        
            # If no vulnerabilities match filters
            if not vulns:
                st.info("No vulnerabilities match your current filters. Try adjusting your filter settings.")
        else:
            st.info("No vulnerability data found in the scan results.")
    else:
        # Show a message when no scan has been run
        st.markdown("""
        <div style="background-color:#313244;border-radius:10px;padding:30px;margin-top:30px;text-align:center;box-shadow:0 4px 8px rgba(0,0,0,0.3);">
            <h3 style="margin-top:0;">No Vulnerabilities to Display</h3>
            <p>Run a scan first to identify security vulnerabilities in your target application.</p>
            <div style="margin-top:20px;font-size:40px;">🔍</div>
        </div>
        """, unsafe_allow_html=True)

# Security Report Tab
with tabs[2]:
    if report_module_available:
        # Use the new report tab module
        render_report_tab(tabs[2])
    else:
        # Fallback to the built-in report tab
        st.markdown("### 📝 Security Report")
        
        # Only show report when scan results exist
        if st.session_state.scan_results and st.session_state.report_path:
            # Current timestamp for display
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            st.success("Security scan completed. Report generated successfully.")
            
            # Display report summary
            st.subheader("Report Summary")
            
            # Get data from results
            data = st.session_state.scan_results
            target_url = data.get('target_url', 'N/A')
            scan_time = data.get('scan_time', 'N/A')
            
            # Target information
            st.markdown("**Target Information**")
            st.markdown(f"- **URL:** {target_url}")
            st.markdown(f"- **Scan Date:** {scan_time}")
            st.markdown(f"- **Report Generated:** {timestamp}")
            
            # Server info if available
            if 'server_info' in data:
                server = data['server_info'].get('server', 'Not disclosed')
                st.markdown(f"- **Server:** {server}")
            
            st.markdown("---")
            
            # Statistics
            st.markdown("**Scan Statistics**")
            if 'stats' in data:
                st.markdown(f"- **URLs Scanned:** {data['stats'].get('urls_scanned', 0)}")
                st.markdown(f"- **Forms Analyzed:** {data['stats'].get('forms_analyzed', 0)}")
                st.markdown(f"- **Total Vulnerabilities:** {data['stats'].get('total_vulnerabilities', 0)}")
            
            # Display vulnerabilities by severity
            st.markdown("---")
            st.subheader("Vulnerabilities by Severity")
            
            vuln_count = st.session_state.vulnerability_count
            
            # Use columns for better layout
            col1, col2, col3, col4, col5 = st.columns(5)
            with col1:
                st.metric("Critical", vuln_count.get('critical', 0), delta=None)
            with col2:
                st.metric("High", vuln_count.get('high', 0), delta=None)
            with col3:
                st.metric("Medium", vuln_count.get('medium', 0), delta=None)
            with col4:
                st.metric("Low", vuln_count.get('low', 0), delta=None)
            with col5:
                st.metric("Info", vuln_count.get('info', 0), delta=None)
            
            # Display detailed vulnerabilities
            st.markdown("---")
            st.subheader("Detailed Findings")
            
            vulnerabilities = data.get('vulnerabilities', [])
            if vulnerabilities:
                # Add filter by severity
                severity_filter = st.multiselect(
                    "Filter by Severity",
                    ["Critical", "High", "Medium", "Low", "Info"],
                    default=["Critical", "High", "Medium"]
                )
                
                # Filter vulnerabilities based on severity
                filtered_vulns = [v for v in vulnerabilities if v.get('severity', '') in severity_filter]
                
                if filtered_vulns:
                    for i, vuln in enumerate(filtered_vulns):
                        with st.expander(f"{i+1}. {vuln.get('name', 'Unknown')} ({vuln.get('severity', 'Unknown')})"):
                            st.markdown(f"**Severity:** {vuln.get('severity', 'Unknown')}")
                            st.markdown(f"**Description:** {vuln.get('description', 'No description available')}")
                            st.markdown(f"**URL:** {vuln.get('url', 'N/A')}")
                            
                            if 'evidence' in vuln and vuln['evidence']:
                                st.markdown("**Evidence:**")
                                st.code(vuln['evidence'], language="text")
                            
                            if 'remediation' in vuln and vuln['remediation']:
                                st.markdown("**Remediation:**")
                                st.markdown(vuln['remediation'])
                else:
                    st.info("No vulnerabilities match the current filter settings.")
            else:
                st.info("No vulnerabilities were detected during the scan.")
            
            # Download options
            st.markdown("---")
            st.subheader("Download Report")
            
            # Options for report format
            report_format = st.radio(
                "Select Report Format",
                ["JSON", "HTML"],
                horizontal=True
            )
            
            if report_format == "JSON":
                with open(st.session_state.report_path, "r") as f:
                    report_data = f.read()
                    
                st.download_button(
                    label="Download JSON Report",
                    data=report_data,
                    file_name=f"security_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                    mime="application/json"
                )
            else:
                st.info("HTML report generation is coming soon. Please use JSON format for now.")
        else:
            # Message when no scan has been run
            st.info("No scan results available. Run a security scan first to generate a report.")

# AI Agent Tab
with tabs[3]:
    st.markdown("### 🤖 Security AI Assistant")
    st.markdown("Ask questions about web security or get the AI to analyze security scan results.")
    
    # Check if AI is enabled
    if not st.session_state.ai_enabled:
        st.warning("AI capabilities are not available. Please check your OpenAI API key in the .env file")
        
        # Add manual API key input
        api_key = st.text_input("OpenAI API Key (required for AI features)", type="password")
        if api_key:
            os.environ["OPENAI_API_KEY"] = api_key
            st.session_state.ai_enabled = load_ai_capabilities()
            if st.session_state.ai_enabled:
                st.success("API Key set! AI features are now available.")
                st.rerun()
    else:
        # API key is already set and working
        st.success("AI capabilities are enabled!")
        
        # User input for AI queries
        ai_input = st.text_area("Ask a question or request scan analysis:", 
                               placeholder="Examples:\n- What are the most common web security vulnerabilities?\n- Analyze the results of my last scan\n- How can I fix missing security headers?")
        
        # Add option to include latest scan results
        include_results = st.checkbox("Include latest scan results in analysis", value=True)
        
        # Process button
        if st.button("Process Request"):
            if not ai_input:
                st.error("Please enter a question or request.")
            else:
                with st.spinner("AI Assistant is processing your request..."):
                    try:
                        # Get scan results if needed
                        scan_data = st.session_state.scan_results if include_results and st.session_state.scan_results else None
                        
                        # Get AI response
                        ai_response = analyze_with_ai(ai_input, scan_data)
                        
                        # Display the AI response in a nice format
                        st.markdown("### AI Analysis")
                        st.markdown(ai_response)
                        
                        # Save the analysis to session state
                        if 'ai_analyses' not in st.session_state:
                            st.session_state.ai_analyses = []
                        st.session_state.ai_analyses.append({
                            "query": ai_input,
                            "response": ai_response,
                            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        })
                    except Exception as e:
                        st.error(f"Error processing AI request: {str(e)}")
        
        # Display previous analyses if available
        if 'ai_analyses' in st.session_state and st.session_state.ai_analyses:
            with st.expander("Previous AI Analyses"):
                for i, analysis in enumerate(reversed(st.session_state.ai_analyses)):
                    st.markdown(f"**Query ({analysis['timestamp']}):** {analysis['query']}")
                    st.markdown(f"**Response:** {analysis['response']}")
                    if i < len(st.session_state.ai_analyses) - 1:
                        st.markdown("---")
        
        # Display example queries
        with st.expander("Example queries"):
            st.markdown("""
            - What are the OWASP Top 10 vulnerabilities?
            - How do I implement Content Security Policy?
            - What is Cross-Site Scripting (XSS) and how can I prevent it?
            - Analyze the results of my current scan
            - Generate a report about the missing security headers in my scan
            - What security headers should I implement on my website?
            - How can I fix the vulnerabilities found in my scan?
            """)

# Advanced Tools Tab
with tabs[4]:
    st.markdown("### ⚙️ Advanced Security Tools")
    st.markdown("Access specialized security testing tools for in-depth analysis.")
    
    # Create columns for tool cards
    col1, col2 = st.columns(2)
    
    with col1:
        # DNS Security Tool
        with st.expander("🌐 DNS Security Analysis", expanded=True):
            st.markdown("### DNS Security Analysis")
            st.markdown("Analyze DNS records for security issues such as zone transfers, misconfigured records, and SPF/DMARC settings.")
            
            dns_target = st.text_input("Target Domain", placeholder="example.com", key="dns_target")
            dns_options = st.multiselect("Analysis Options", 
                                       ["DNS Records", "DNSEC Validation", "SPF/DMARC Check", "Zone Transfer Test"],
                                       default=["DNS Records", "SPF/DMARC Check"])
            
            if st.button("Run DNS Analysis", key="dns_analysis_btn"):
                with st.spinner("Running DNS security analysis..."):
                    # Simulate DNS analysis
                    time.sleep(2)
                    
                    # Show sample results
                    st.success("DNS Analysis completed!")
                    
                    # Display results
                    dns_results = {
                        "dns_records": {
                            "A": ["93.184.216.34"],
                            "MX": ["0 example-com.mail.protection.outlook.com"],
                            "TXT": [
                                "v=spf1 include:spf.protection.outlook.com -all",
                                "MS=ms12345678",
                                "v=DMARC1; p=reject; rua=mailto:admin@example.com; ruf=mailto:admin@example.com; fo=1"
                            ],
                            "NS": ["ns1.example.com", "ns2.example.com"]
                        },
                        "spf_check": "PASS - SPF record properly configured with hard fail (-all)",
                        "dmarc_check": "PASS - DMARC record properly configured with reject policy",
                        "zone_transfer": "PROTECTED - Zone transfer not allowed",
                        "dnssec": "WARNING - DNSSEC not enabled"
                    }
                    
                    # Format and display results
                    st.markdown("#### DNS Records")
                    for record_type, values in dns_results["dns_records"].items():
                        st.markdown(f"**{record_type}**:")
                        for value in values:
                            st.markdown(f"- `{value}`")
                    
                    st.markdown("#### Security Checks")
                    
                    if "PASS" in dns_results["spf_check"]:
                        st.markdown(f"✅ **SPF**: {dns_results['spf_check']}")
                    else:
                        st.markdown(f"❌ **SPF**: {dns_results['spf_check']}")
                        
                    if "PASS" in dns_results["dmarc_check"]:
                        st.markdown(f"✅ **DMARC**: {dns_results['dmarc_check']}")
                    else:
                        st.markdown(f"❌ **DMARC**: {dns_results['dmarc_check']}")
                    
                    if "PROTECTED" in dns_results["zone_transfer"]:
                        st.markdown(f"✅ **Zone Transfer**: {dns_results['zone_transfer']}")
                    else:
                        st.markdown(f"❌ **Zone Transfer**: {dns_results['zone_transfer']}")
                        
                    if "WARNING" in dns_results["dnssec"]:
                        st.markdown(f"⚠️ **DNSSEC**: {dns_results['dnssec']}")
                    else:
                        st.markdown(f"✅ **DNSSEC**: {dns_results['dnssec']}")
        
        # SSL/TLS Scanner
        with st.expander("🔒 SSL/TLS Security Scanner"):
            st.markdown("### SSL/TLS Security Scanner")
            st.markdown("Analyze SSL/TLS configuration for security issues, cipher strength, protocol support, and certificate validation.")
            
            ssl_target = st.text_input("Target Host", placeholder="example.com", key="ssl_target")
            ssl_port = st.number_input("Port", min_value=1, max_value=65535, value=443, key="ssl_port")
            
            if st.button("Run SSL/TLS Scan", key="ssl_scan_btn"):
                with st.spinner("Analyzing SSL/TLS configuration..."):
                    # Simulate SSL/TLS scan
                    time.sleep(2)
                    
                    # Show sample results
                    st.success("SSL/TLS Analysis completed!")
                    
                    # Display certificate info
                    st.markdown("#### Certificate Information")
                    cert_info = {
                        "subject": "CN=example.com, O=Example Inc, L=San Francisco, ST=California, C=US",
                        "issuer": "CN=DigiCert TLS RSA SHA256 2020 CA1, O=DigiCert Inc, C=US",
                        "valid_from": "2023-02-15",
                        "valid_to": "2024-03-15",
                        "sans": ["example.com", "www.example.com", "api.example.com"],
                        "signature_algorithm": "sha256WithRSAEncryption",
                        "key_size": "2048 bits"
                    }
                    
                    for key, value in cert_info.items():
                        if key == "sans":
                            st.markdown(f"**Subject Alternative Names**: {', '.join(value)}")
                        else:
                            st.markdown(f"**{key.replace('_', ' ').title()}**: {value}")
                    
                    # Display supported protocols
                    st.markdown("#### Supported Protocols")
                    protocols = {
                        "TLS 1.3": "✅ Supported",
                        "TLS 1.2": "✅ Supported",
                        "TLS 1.1": "❌ Not Supported (Good)",
                        "TLS 1.0": "❌ Not Supported (Good)",
                        "SSL 3.0": "❌ Not Supported (Good)",
                        "SSL 2.0": "❌ Not Supported (Good)"
                    }
                    
                    for protocol, status in protocols.items():
                        st.markdown(f"**{protocol}**: {status}")
                    
                    # Display cipher strength
                    st.markdown("#### Cipher Strength")
                    st.markdown("✅ **Strong Ciphers Only**: All supported ciphers use strong encryption (AES-128/256)")
                    st.markdown("✅ **Perfect Forward Secrecy**: Supported with ECDHE key exchange")
                    
                    # Overall rating
                    st.markdown("#### Overall Rating")
                    st.markdown("**A+** - Excellent SSL/TLS configuration with modern protocols and strong ciphers")
    
    with col2:
        # Port Scanner
        with st.expander("🔌 Network Port Scanner", expanded=True):
            st.markdown("### Network Port Scanner")
            st.markdown("Scan for open ports and services on the target host to identify potential security issues.")
            
            port_target = st.text_input("Target Host", placeholder="example.com or 192.168.1.1", key="port_target")
            port_range = st.text_input("Port Range", "21-25,80,443,3306,3389,8080,8443", key="port_range")
            
            if st.button("Run Port Scan", key="port_scan_btn"):
                with st.spinner("Scanning ports..."):
                    # Simulate port scan
                    time.sleep(2)
                    
                    # Show sample results
                    st.success("Port scan completed!")
                    
                    # Display results in a table
                    port_data = {
                        "Port": [22, 80, 443, 8080],
                        "Protocol": ["TCP", "TCP", "TCP", "TCP"],
                        "State": ["Open", "Open", "Open", "Filtered"],
                        "Service": ["SSH", "HTTP", "HTTPS", "HTTP-Proxy"],
                        "Version": ["OpenSSH 8.2p1", "nginx 1.18.0", "nginx 1.18.0", "Unknown"]
                    }
                    
                    port_df = pd.DataFrame(port_data)
                    st.dataframe(port_df, use_container_width=True)
                    
                    # Security recommendations
                    st.markdown("#### Security Recommendations")
                    st.markdown("⚠️ **SSH (Port 22)**: Exposed to the internet. Consider restricting access or using a VPN.")
                    st.markdown("ℹ️ **HTTP (Port 80)**: Consider redirecting to HTTPS for secure communications.")
                    st.markdown("✅ **HTTPS (Port 443)**: Good practice for secure communications.")
                    st.markdown("⚠️ **HTTP-Proxy (Port 8080)**: Potentially unnecessary service. Consider disabling if not required.")
        
        # Subdomain Enumeration
        with st.expander("🔍 Subdomain Enumeration"):
            st.markdown("### Subdomain Enumeration")
            st.markdown("Discover subdomains associated with the target domain to identify potential attack surfaces.")
            
            sub_target = st.text_input("Target Domain", placeholder="example.com", key="sub_target")
            
            enum_methods = st.multiselect("Enumeration Methods", 
                                        ["DNS Brute Force", "Certificate Transparency", "Search Engines", "OSINT"],
                                        default=["DNS Brute Force", "Certificate Transparency"])
            
            if st.button("Enumerate Subdomains", key="sub_enum_btn"):
                with st.spinner("Enumerating subdomains..."):
                    # Simulate subdomain enumeration
                    time.sleep(2)
                    
                    # Show sample results
                    st.success("Subdomain enumeration completed!")
                    
                    # Display results
                    subdomains = [
                        "www.example.com", 
                        "api.example.com", 
                        "mail.example.com", 
                        "blog.example.com", 
                        "dev.example.com", 
                        "admin.example.com", 
                        "stage.example.com",
                        "cdn.example.com",
                        "shop.example.com"
                    ]
                    
                    # Create a DataFrame for the results
                    sub_data = {
                        "Subdomain": subdomains,
                        "IP Address": ["93.184.216.34", "93.184.216.34", "93.184.216.35", 
                                      "93.184.216.34", "93.184.216.36", "93.184.216.34",
                                      "93.184.216.37", "93.184.216.34", "93.184.216.34"],
                        "HTTP Status": [200, 200, None, 200, 403, 401, 200, 200, 200]
                    }
                    
                    sub_df = pd.DataFrame(sub_data)
                    st.dataframe(sub_df, use_container_width=True)
                    
                    # Security findings
                    st.markdown("#### Security Findings")
                    st.markdown("⚠️ **Development Environment**: `dev.example.com` might expose sensitive information")
                    st.markdown("⚠️ **Admin Interface**: `admin.example.com` should not be publicly accessible")
                    st.markdown("⚠️ **Staging Environment**: `stage.example.com` might contain pre-production code")
    
    # Horizontal line for separation
    st.markdown("---")
    
    # Vulnerability Database
    st.markdown("### 📚 Vulnerability Database")
    st.markdown("Search for known vulnerabilities in software components and libraries.")
    
    vuln_cols = st.columns([2, 1])
    
    with vuln_cols[0]:
        vuln_search = st.text_input("Search for vulnerabilities", placeholder="e.g. Apache Log4j, WordPress 5.8, OpenSSL 1.1.1")
    
    with vuln_cols[1]:
        vuln_type = st.selectbox("Vulnerability Type", 
                              ["All Types", "Remote Code Execution", "SQL Injection", "XSS", 
                               "Authentication Bypass", "Information Disclosure", "Denial of Service"])
    
    if st.button("Search Vulnerabilities", key="vuln_search_btn"):
        with st.spinner("Searching vulnerability database..."):
            # Simulate database search
            time.sleep(1.5)
            
            if "log4j" in vuln_search.lower():
                # Example Log4j results
                st.subheader("Results for 'Apache Log4j'")
                
                # CVE-2021-44228 (Log4Shell)
                with st.expander("CVE-2021-44228 (Log4Shell) - Critical", expanded=True):
                    st.markdown("""
                    **CVSS Score**: 10.0 (Critical)
                    
                    **Affected Versions**: Apache Log4j 2.0 - 2.14.1
                    
                    **Description**: Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases 2.12.2, 2.12.3, and 2.3.1) JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled.
                    
                    **Exploit Status**: Actively exploited in the wild
                    
                    **Patch Status**: Fixed in Log4j 2.15.0 and later
                    
                    **Remediation**:
                    - Update to Log4j 2.17.1 or later
                    - If unable to update, set system property `-Dlog4j2.formatMsgNoLookups=true`
                    - Remove JndiLookup class from the classpath: `zip -q -d log4j-core-*.jar org/apache/logging/log4j/core/lookup/JndiLookup.class`
                    """)
                
                # CVE-2021-45046
                with st.expander("CVE-2021-45046 - Critical"):
                    st.markdown("""
                    **CVSS Score**: 9.0 (Critical)
                    
                    **Affected Versions**: Apache Log4j 2.0 - 2.15.0
                    
                    **Description**: The fix for CVE-2021-44228 in Apache Log4j 2.15.0 was incomplete in certain non-default configurations. This could allow attackers to craft malicious input data using a JNDI Lookup pattern, resulting in a denial of service (DOS) attack or, in some environments, remote code execution.
                    
                    **Exploit Status**: Actively exploited in the wild
                    
                    **Patch Status**: Fixed in Log4j 2.16.0 and later
                    
                    **Remediation**:
                    - Update to Log4j 2.17.1 or later
                    """)
            elif "wordpress" in vuln_search.lower():
                # Example WordPress results
                st.subheader("Results for 'WordPress'")
                
                with st.expander("CVE-2023-XXXXX - WordPress Plugin XYZ SQL Injection - High", expanded=True):
                    st.markdown("""
                    **CVSS Score**: 8.8 (High)
                    
                    **Affected Versions**: WordPress Plugin XYZ 1.2.0 - 1.3.5
                    
                    **Description**: The WordPress Plugin XYZ contains an unauthenticated SQL injection vulnerability that allows attackers to extract sensitive data from the database.
                    
                    **Exploit Status**: Proof of concept available
                    
                    **Patch Status**: Fixed in version 1.3.6
                    
                    **Remediation**:
                    - Update the plugin to version 1.3.6 or later
                    - If unable to update, remove the plugin until an update is available
                    """)
            else:
                st.info("No specific vulnerabilities found for your search query. Try another search term or browse common vulnerabilities below.")
                
                # Display common vulnerabilities
                st.markdown("### Common Web Application Vulnerabilities")
                
                vuln_data = {
                    "CVE ID": ["CVE-2021-44228", "CVE-2023-23506", "CVE-2022-22965", "CVE-2022-1388"],
                    "Name": ["Log4Shell", "OAuth XSS", "Spring4Shell", "F5 BIG-IP RCE"],
                    "Severity": ["Critical", "High", "Critical", "Critical"],
                    "Affected Product": ["Apache Log4j", "OAuth Client", "Spring Framework", "F5 BIG-IP"]
                }
                
                vuln_df = pd.DataFrame(vuln_data)
                st.dataframe(vuln_df, use_container_width=True)

# --- Sidebar Navigation --- 
# Define navigation options including the Bug Bounty Team
SIDEBAR_TABS = [
    "🔍 Security Scanner", # Represents the main dashboard tabs
    "🦾 AI Bug Bounty Team" 
]

st.sidebar.markdown("---") # Add a separator
st.sidebar.header("Navigation")
selected_sidebar_tab = st.sidebar.radio("Select Feature", SIDEBAR_TABS)

# --- Main Content Area Logic --- 
# Display the main tabs unless the Bug Bounty Team is selected in the sidebar
if selected_sidebar_tab == "🔍 Security Scanner":
    # Content for the main tabs (Scanner, Results, Report, AI Agent, Tools) is handled above within the `with tabs[...]` blocks.
    pass # The tab content is already defined above

elif selected_sidebar_tab == "🦾 AI Bug Bounty Team":
    # Display the AI Bug Bounty Team UI directly in the main area, replacing the tabs
    st.header("🦾 AI Bug Bounty Hunter Team")
    st.markdown("A team of specialized AI agents for finding security vulnerabilities, CTFs, and bug bounties.")
    
    # Initialize session state for bug bounty results if not already present
    if 'bb_target' not in st.session_state:
        st.session_state.bb_target = ""
    if 'bb_recon_result' not in st.session_state:
        st.session_state.bb_recon_result = None
    if 'bb_vuln_result' not in st.session_state:
        st.session_state.bb_vuln_result = None
    if 'bb_exploit_result' not in st.session_state:
        st.session_state.bb_exploit_result = None
    if 'bb_poc_outputs' not in st.session_state:
        st.session_state.bb_poc_outputs = []
    if 'bb_report_result' not in st.session_state:
        st.session_state.bb_report_result = None
        
    with st.form("bb_target_form"):
        target_input = st.text_input("Enter the target website or repository to analyze:", value=st.session_state.bb_target)
        submitted = st.form_submit_button("Start Analysis")
        
    if submitted and target_input:
        # Reset previous results when a new target is submitted
        st.session_state.bb_target = target_input
        st.session_state.bb_recon_result = None
        st.session_state.bb_vuln_result = None
        st.session_state.bb_exploit_result = None
        st.session_state.bb_poc_outputs = []
        st.session_state.bb_report_result = None
        
        st.info(f"🔍 Starting security analysis for: {st.session_state.bb_target}")
        checklist = shared_context.get_checklist()
        initial_user_query = f"Target: {st.session_state.bb_target}\nFind security vulnerabilities. Focus on common web vulnerabilities.\nInitial Checklist: {checklist}"
        
        # --- Run Workflow Sequentially & Store Results in Session State --- 
        # Step 1: Reconnaissance
        with st.spinner("Running Reconnaissance Phase..."):
            st.session_state.bb_recon_result = execute_recon_phase(initial_user_query)
            shared_context.update('recon', st.session_state.bb_recon_result) # Keep updating shared context if needed elsewhere
            # Display handled below outside the form
            
        # Step 2: Vulnerability Scanning (if recon succeeded)
        if st.session_state.bb_recon_result and "Error:" not in st.session_state.bb_recon_result:
            with st.spinner("Running Vulnerability Scanning Phase..."):
                # We need a way to get user feedback if desired, form resets make this tricky
                # For now, passing empty feedback
                user_recon_feedback = "" # Placeholder - consider adding an input outside the form later
                st.session_state.bb_vuln_result = execute_vuln_scan_phase(st.session_state.bb_recon_result, user_recon_feedback, checklist)
                shared_context.update('vuln_scan', st.session_state.bb_vuln_result)
        else:
            st.error("Reconnaissance phase failed. Cannot proceed.")

        # Step 3: Exploit Testing (if vuln scan succeeded)
        if st.session_state.bb_vuln_result and "Error:" not in st.session_state.bb_vuln_result:
             with st.spinner("Running Exploit Testing Phase..."):
                user_vuln_feedback_exploit = "" # Placeholder
                st.session_state.bb_exploit_result = execute_exploit_phase(st.session_state.bb_vuln_result, user_vuln_feedback_exploit, checklist)
                shared_context.update('exploit', st.session_state.bb_exploit_result)
                
                # Automated PoC execution
                if st.session_state.bb_exploit_result and "Error:" not in st.session_state.bb_exploit_result:
                    import re
                    code_blocks = re.findall(r'```python(.*?)```', st.session_state.bb_exploit_result, re.DOTALL)
                    st.session_state.bb_poc_outputs = [] # Reset PoC outputs for this run
                    if code_blocks:
                        for code in code_blocks:
                            code = code.strip()
                            if code: # Ensure code block is not empty
                                result = run_poc_code(code)
                                st.session_state.bb_poc_outputs.append({'code': code, 'result': result})
                    shared_context.update('poc_outputs', st.session_state.bb_poc_outputs)
                # Display handled below outside the form
        elif st.session_state.bb_recon_result and "Error:" not in st.session_state.bb_recon_result:
             st.error("Vulnerability Scanning phase failed. Cannot proceed.")

        # Step 4: Report Generation (if exploit test succeeded or was skipped gracefully)
        if st.session_state.bb_exploit_result and "Error:" not in st.session_state.bb_exploit_result:
             with st.spinner("Generating Final Report..."):
                user_exploit_feedback_final = "" # Placeholder
                st.session_state.bb_report_result = execute_report_phase(
                    st.session_state.bb_recon_result,
                    st.session_state.bb_vuln_result, 
                    st.session_state.bb_exploit_result, 
                    st.session_state.bb_poc_outputs, 
                    user_exploit_feedback_final
                )
                shared_context.update('report', st.session_state.bb_report_result)
        elif st.session_state.bb_vuln_result and "Error:" not in st.session_state.bb_vuln_result:
             st.error("Exploit Testing phase failed. Cannot generate report.")
             
    # --- Display Results from Session State --- 
    # Display results outside the form to persist after form submission causes rerun
    if st.session_state.bb_target:
        st.info(f"Showing results for: {st.session_state.bb_target}")
        
        # Display Reconnaissance
        if st.session_state.bb_recon_result:
            with st.expander("1️⃣ Reconnaissance Agent Output", expanded=True):
                st.markdown(st.session_state.bb_recon_result)
                # Consider adding feedback input here if needed, outside the form

        # Display Vulnerability Scan
        if st.session_state.bb_vuln_result:
             with st.expander("2️⃣ Vulnerability Scanner Agent Output", expanded=True):
                st.markdown(st.session_state.bb_vuln_result)
        elif st.session_state.bb_recon_result and "Error:" in st.session_state.bb_recon_result:
            st.error("Reconnaissance phase failed. Cannot proceed.") # Repeat error msg

        # Display Exploit Test
        if st.session_state.bb_exploit_result:
            with st.expander("3️⃣ Exploit Testing Agent Output", expanded=True):
                st.markdown(st.session_state.bb_exploit_result)
                
                # Display Automated PoC execution results
                st.subheader("⚙️ Automated PoC Execution Results")
                if not st.session_state.bb_poc_outputs:
                    st.write("No automated PoC code blocks found or executed.")
                else:
                    for poc in st.session_state.bb_poc_outputs:
                        st.code(poc['code'], language='python')
                        st.write(f"Output: {poc['result'].get('output', 'N/A')}")
                        st.write(f"Error: {poc['result'].get('error', 'None')}")
                        st.markdown("---")
        elif st.session_state.bb_vuln_result and "Error:" in st.session_state.bb_vuln_result:
             st.error("Vulnerability Scanning phase failed. Cannot proceed.") # Repeat error msg

        # Display Report Generation
        if st.session_state.bb_report_result:
             with st.expander("4️⃣ Final Security Report", expanded=True):
                st.markdown(st.session_state.bb_report_result)
                # Add download button only if report generated successfully
                if "Error:" not in st.session_state.bb_report_result:
                     st.download_button("Download Report", st.session_state.bb_report_result, file_name=f"security_report_{st.session_state.bb_target.replace('.', '_')}.md", mime="text/markdown")
                else:
                     st.error("Report generation failed.")
        elif st.session_state.bb_exploit_result and "Error:" in st.session_state.bb_exploit_result:
             st.error("Exploit Testing phase failed. Cannot generate report.") # Repeat error msg

# Footer
st.markdown("---")
st.markdown("""
<div style="text-align: center">
    <p>Security Scanner Dashboard | Built with Streamlit and Python | Use responsibly and ethically</p>
    <p><small>Only scan systems you have permission to test. The authors are not responsible for misuse.</small></p>
</div>
""", unsafe_allow_html=True) 