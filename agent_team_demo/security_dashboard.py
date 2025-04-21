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
# Added for real DNS analysis
import dns.resolver
import dns.zone
import dns.query
import dns.exception
# Additional imports
import pandas as pd
import ssl
# For port scanning and subdomain enumeration
import ipaddress
# requests already imported earlier
from concurrent.futures import ThreadPoolExecutor, as_completed
# --- ensure project root is on sys.path so that package imports resolve ---
PROJECT_ROOT = Path(__file__).resolve().parent.parent
BASE_DIR = Path(__file__).resolve().parent
for _p in (PROJECT_ROOT, BASE_DIR):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

# Dynamically resolve scanner utilities regardless of execution context
try:
    # Standard import when package is discoverable
    from agent_team_demo.security_scanner import scan_website, stop_current_scan
    from agent_team_demo.network_utils import expand_port_range, run_port_scan, enumerate_subdomains
except ModuleNotFoundError:
    import importlib.util as _ilu

    def _import_from_path(name: str, path: Path):
        spec = _ilu.spec_from_file_location(name, path)
        module = _ilu.module_from_spec(spec)  # type: ignore[arg-type]
        assert spec and spec.loader
        spec.loader.exec_module(module)  # type: ignore[arg-type]
        sys.modules[name] = module
        return module

    _scanner_mod = _import_from_path("_dynamic_scanner", BASE_DIR / "security_scanner.py")
    _nu_mod = _import_from_path("_dynamic_netutils", BASE_DIR / "network_utils.py")

    scan_website = _scanner_mod.scan_website
    stop_current_scan = _scanner_mod.stop_current_scan

    expand_port_range = _nu_mod.expand_port_range
    run_port_scan = _nu_mod.run_port_scan
    enumerate_subdomains = _nu_mod.enumerate_subdomains

# Helper function defined at the top of the file
def add_log_entry(message):
    """Add a log entry to the session state log and print to console for debugging"""
    if "log" not in st.session_state:
        st.session_state.log = []
    st.session_state.log.append(message)
    print(f"LOG: {message}")

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
tabs = st.tabs(["🔍 Security Scanner", "📊 Scan Results", "📝 Security Report", "🤖 AI Agent", "🛡️ Code Coach", "⚙️ Advanced Tools"])

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

# Initialize session state BEFORE it's used elsewhere
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
if "target_url" not in st.session_state:
    st.session_state.target_url = ""

# Function to run security scan
def run_security_scan():
    # Get scan parameters from session state
    scan_depth = st.session_state.get("scan_depth", 2)
    scan_options = st.session_state.get("scan_options", ["XSS", "SQL Injection", "Security Headers"])
    threads = st.session_state.get("threads", 3)
    timeout = st.session_state.get("timeout", 10)
    
    # Get target URL from sidebar or main input
    current_target_url = ""
    
    # Check if target_url is in locals (from sidebar)
    if 'target_url' in locals() and target_url:
        current_target_url = target_url
    # Otherwise check if it's in session state
    elif "target_url" in st.session_state and st.session_state.target_url:
        current_target_url = st.session_state.target_url
    
    # Fix @ symbol that might be at the start of the URL
    if current_target_url and current_target_url.startswith('@'):
        current_target_url = current_target_url[1:]
    
    # Validate URL
    if not current_target_url or not re.match(r'^https?://', current_target_url):
        st.error("Invalid URL. Please enter a valid URL starting with http:// or https://")
        st.session_state.scanning = False
        return
    
    # Update session state with current target
    st.session_state.target_url = current_target_url
    
    # Use a container to update scanning status
    status_container = st.empty()
    status_container.info("Scan in progress... Please wait")
    
    # Log container
    log_placeholder = st.empty()
    
    # Progress bar
    progress_bar = st.progress(0)
    
    # Define update_log at the top so it's always in scope
    log_output = []
    def update_log():
        log_placeholder.markdown("\n".join([f"- {entry}" for entry in log_output]))
    
    try:
        # Reset session state for the scan
        st.session_state.log = []
        st.session_state.vulnerability_count = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        
        # Initialize log output array directly
        log_output[:] = ["Starting scan...", f"Target URL: {current_target_url}", f"Scan depth: {scan_depth}"]
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
        
        progress_val = 5  # initial value already set above

        def website_callback(value: int | None = None, message: str | None = None):
            """Adapt SecurityScanner callback (message‑only) to our progress & log UI."""
            nonlocal progress_val
            if value is not None:
                progress_val = value
            else:
                progress_val = min(progress_val + 3, 95)
            progress_bar.progress(progress_val)
            if message:
                log_output.append(message)
                update_log()
        
        # Run the scan
        results = scan_website(
            current_target_url,
            scan_depth,
            scan_options,
            threads,
            timeout,
            website_callback,
        )
        
        # Build report data from real scanner structure
        stats = results.get("stats", {})
        report_data = {
            "target_url": current_target_url,
            "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "server_info": results.get("server_info", {}),
            "stats": {
                "urls_scanned": stats.get("urls_scanned", 0),
                "forms_analyzed": stats.get("forms_analyzed", 0),
                "total_vulnerabilities": stats.get("total_vulnerabilities", len(results.get("vulnerabilities", []))),
            },
            "vulnerabilities": results.get("vulnerabilities", []),
        }
        
        # Compute vulnerability counts by severity
        severity_map = {
            "critical": "critical",
            "high": "high",
            "medium": "medium",
            "low": "low",
            "info": "info",
        }
        vuln_count = {k: 0 for k in severity_map}
        for v in report_data["vulnerabilities"]:
            sev = v.get("severity", "").lower()
            if sev in vuln_count:
                vuln_count[sev] += 1
        
        # Save report
        report_path = os.path.join(os.getcwd(), report_filename)
        with open(report_path, 'w') as f:
            json.dump(report_data, f, indent=2)
        
        # Update session state
        st.session_state.report_path = report_path
        st.session_state.scan_results = report_data
        st.session_state.vulnerability_count = vuln_count
        st.session_state.log = log_output
        
        # Complete the progress
        progress_bar.progress(100)
        status_container.success("Scan completed successfully!")
        
    except Exception as e:
        print(f"LOG: Error during scan: {str(e)}")
        error_message = f"Error during scan: {str(e)}"
        if not log_output:
            log_output[:] = ["Starting scan...", error_message]
        else:
            log_output.append(error_message)
        update_log()
        status_container.error(error_message)
        traceback.print_exc()
    
    finally:
        st.session_state.scanning = False

# Security Scanner Tab - Use existing tabs from above, don't create new ones
with tabs[0]:
    st.subheader("Security Scanner")
    with st.form("scan_form"):
        st.markdown("#### Target URL")
        target_url_input = st.text_input("Target URL", placeholder="https://example.com", value=st.session_state.get("target_url", ""), key="target_url_main", help="Full URL including scheme e.g. https://my.site")
        st.markdown("#### Scan Options")
        scan_depth_input = st.slider("Crawl Depth", 1, 5, st.session_state.get("scan_depth", 2), key="scan_depth_main")
        scan_options_input = st.multiselect(
            "Security Tests",
            ["XSS", "SQL Injection", "CSRF", "Security Headers", "Port Scan"],
            default=st.session_state.get("scan_options", ["XSS", "SQL Injection", "Security Headers"]),
            key="scan_options_main"
        )
        with st.expander("Advanced Options"):
            threads_input = st.slider("Threads", 1, 10, st.session_state.get("threads", 3), key="threads_main")
            timeout_input = st.slider("Timeout (s)", 1, 30, st.session_state.get("timeout", 10), key="timeout_main")
        start_scan_button = st.form_submit_button(
            "🔍 Start Security Scan",
            disabled=st.session_state.get("scanning", False),
            help="Start a new security scan"
        )
    if start_scan_button:
        if not target_url_input:
            st.error("Please enter a target URL")
        else:
            st.session_state["target_url"] = target_url_input.strip()
            st.session_state["scan_depth"] = scan_depth_input
            st.session_state["scan_options"] = scan_options_input
            st.session_state["threads"] = threads_input
            st.session_state["timeout"] = timeout_input
            st.session_state["scanning"] = True
            st.session_state["progress"] = 0
            run_security_scan()
    if st.session_state.get("scanning", False):
        st.info("Scan in progress... Please wait")
    if st.session_state.get("log"):
        with st.expander("Scan Logs", expanded=True):
            for log_entry in st.session_state["log"]:
                st.markdown(f"- {log_entry}")

# Scan Results Tab
with tabs[1]:
    if st.session_state.scan_results:
        data = st.session_state.scan_results
        # Show all vulnerabilities without filtering by type
        vulns = data.get("vulnerabilities", [])
        st.markdown(f"<h3 style='margin-top:15px;margin-bottom:20px;'>Found {len(vulns)} Vulnerabilities</h3>", unsafe_allow_html=True)
        for i, vuln in enumerate(vulns):
            severity = vuln.get("severity", "").lower()
            with st.expander(f"{i+1}. {vuln.get('title', vuln.get('name', 'Unknown'))} ({vuln.get('severity', 'Unknown')})", expanded=True):
                for k, v in vuln.items():
                    st.markdown(f"**{k.title()}:** {v}")
        if "external_tools" in data:
            st.markdown("---")
            st.subheader("External Tools Output")
            for tool, output in data["external_tools"].items():
                with st.expander(f"{tool} Output"):
                    if isinstance(output, (list, dict)):
                        st.json(output)
                    else:
                        st.code(str(output))
        with st.expander("Show Raw Results JSON"):
            st.json(data)
    else:
        st.info("No scan results available. Run a scan first.")

# Security Report Tab
with tabs[2]:
    if report_module_available:
        render_report_tab(tabs[2])
    else:
        st.markdown("### 📝 Security Report")
        if st.session_state.scan_results and st.session_state.report_path:
            data = st.session_state.scan_results
            # Executive Summary
            st.subheader("Executive Summary")
            st.markdown(f"**Target:** {data.get('target_url', 'N/A')}")
            st.markdown(f"**Scan Date:** {data.get('scan_time', 'N/A')}")
            vuln_count = st.session_state.vulnerability_count
            total_vulns = sum(vuln_count.values())
            st.markdown(f"**Total Vulnerabilities:** {total_vulns}")
            st.markdown(f"**Risk Level:** {'High' if vuln_count.get('critical',0) or vuln_count.get('high',0) else 'Medium' if vuln_count.get('medium',0) else 'Low'}")
            st.markdown("---")
            # Methodology
            st.subheader("Methodology & Tools Used")
            tools_used = []
            if 'external_tools' in data:
                for tool, output in data['external_tools'].items():
                    tools_used.append(tool)
            st.markdown(f"**Automated Tools:** {', '.join(tools_used) if tools_used else 'Built-in scanner only'}")
            st.markdown("- Crawled the target, analyzed forms, headers, and URLs.")
            st.markdown("- Ran vulnerability checks for XSS, SQL Injection, Security Headers, and more.")
            if tools_used:
                st.markdown("- Ran external tools (see appendix for output).")
            st.markdown("---")
            # Findings
            st.subheader("Findings")
            vulnerabilities = data.get('vulnerabilities', [])
            if vulnerabilities:
                for i, vuln in enumerate(vulnerabilities):
                    with st.expander(f"{i+1}. {vuln.get('title', vuln.get('name', 'Unknown'))} ({vuln.get('severity', 'Unknown')})", expanded=True):
                        st.markdown(f"**Type:** {vuln.get('type', 'N/A')}")
                        st.markdown(f"**Severity:** {vuln.get('severity', 'Unknown')}")
                        st.markdown(f"**Description:** {vuln.get('description', 'No description available')}")
                        st.markdown(f"**URL:** {vuln.get('url', 'N/A')}")
                        # What we tried
                        st.markdown("**What We Tried:**")
                        tried = []
                        if 'external_tools' in data:
                            for tool in tools_used:
                                tried.append(f"Ran {tool}")
                        tried.append("Crawled site, analyzed forms and headers")
                        st.markdown("<ul>" + ''.join([f"<li>{t}</li>" for t in tried]) + "</ul>", unsafe_allow_html=True)
                        # What we found
                        st.markdown("**What We Found:**")
                        st.markdown(f"{vuln.get('title', vuln.get('name', 'Unknown'))} at {vuln.get('url', 'N/A')}")
                        # Evidence/Answer
                        if 'evidence' in vuln and vuln['evidence']:
                            st.markdown("**Evidence/Answer:**")
                            st.code(vuln['evidence'], language="text")
                        if 'payload' in vuln and vuln['payload']:
                            st.markdown(f"**Payload:** {vuln['payload']}")
                        if 'remediation' in vuln and vuln['remediation']:
                            st.markdown("**Remediation:**")
                            st.markdown(vuln['remediation'])
            else:
                st.info("No vulnerabilities were detected during the scan.")
            # Appendix
            if 'external_tools' in data:
                st.markdown("---")
                st.subheader("Appendix: External Tools Output")
                for tool, output in data["external_tools"].items():
                    with st.expander(f"{tool} Output"):
                        if isinstance(output, (list, dict)):
                            st.json(output)
                        else:
                            st.code(str(output))
            with st.expander("Show Raw Results JSON"):
                st.json(data)

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
            
            dns_target = st.text_input("Target Domain", placeholder="", key="dns_target", help="Root domain e.g. example.com")
            dns_options = st.multiselect("Analysis Options", 
                                       ["DNS Records", "DNSEC Validation", "SPF/DMARC Check", "Zone Transfer Test"],
                                       default=["DNS Records", "SPF/DMARC Check"])
            
            if st.button("Run DNS Analysis", key="dns_analysis_btn"):
                if not dns_target:
                    st.error("Please enter a domain to analyze.")
                else:
                    with st.spinner("Running DNS security analysis..."):
                        dns_results = analyze_dns(dns_target.strip(), dns_options)
                        st.success("DNS Analysis completed!")
        
        # SSL/TLS Scanner
        with st.expander("🔒 SSL/TLS Security Scanner"):
            st.markdown("### SSL/TLS Security Scanner")
            st.markdown("Analyze SSL/TLS configuration for security issues, cipher strength, protocol support, and certificate validation.")
            
            ssl_target = st.text_input("Target Host", placeholder="", key="ssl_target", help="Hostname or IP e.g. mysite.com")
            ssl_port = st.number_input("Port", min_value=1, max_value=65535, value=443, key="ssl_port")
            
            if st.button("Run SSL/TLS Scan", key="ssl_scan_btn"):
                if not ssl_target:
                    st.error("Please enter a target host for SSL/TLS scanning.")
                else:
                    with st.spinner("Analyzing SSL/TLS configuration..."):
                        try:
                            ssl_results = analyze_ssl_tls(ssl_target.strip(), int(ssl_port))
                            st.success("SSL/TLS Analysis completed!")

                            # Certificate info
                            st.markdown("#### Certificate Information")
                            for k, v in ssl_results["cert"].items():
                                if k == "sans":
                                    st.markdown(f"**Subject Alternative Names**: {', '.join(v)}")
                                else:
                                    st.markdown(f"**{k.replace('_', ' ').title()}**: {v}")

                            # Protocols
                            st.markdown("#### Supported Protocols")
                            for proto, supported in ssl_results["protocols"].items():
                                status = "✅ Supported" if supported else "❌ Not Supported"
                                st.markdown(f"**{proto}**: {status}")

                            # Cipher strength summary
                            st.markdown("#### Cipher Strength")
                            st.markdown(ssl_results["cipher_summary"])

                            # Overall rating
                            st.markdown("#### Overall Rating")
                            st.markdown(ssl_results["rating"])
                        except Exception as e:
                            st.error(f"Error during SSL/TLS scan: {str(e)}")
    
    with col2:
        # Port Scanner
        with st.expander("🔌 Network Port Scanner", expanded=True):
            st.markdown("### Network Port Scanner")
            st.markdown("Scan for open ports and services on the target host to identify potential security issues.")
            
            port_target = st.text_input("Target Host", placeholder="", key="port_target", help="Domain or IPv4/IPv6 address")
            port_range = st.text_input("Port Range", "21-25,80,443,3306,3389,8080,8443", key="port_range")
            
            if st.button("Run Port Scan", key="port_scan_btn"):
                if not port_target:
                    st.error("Enter a host to scan.")
                else:
                    with st.spinner("Scanning ports..."):
                        try:
                            ports_to_scan = expand_port_range(port_range)
                            scan_results = run_port_scan(port_target.strip(), ports_to_scan)

                            if not scan_results:
                                st.warning("No open ports found in the specified range.")
                            else:
                                st.success("Port scan completed!")
                                port_df = pd.DataFrame(scan_results)
                                st.dataframe(port_df, use_container_width=True)
                        except Exception as e:
                            st.error(f"Port scan error: {str(e)}")
        
        # Subdomain Enumeration
        with st.expander("🔍 Subdomain Enumeration"):
            st.markdown("### Subdomain Enumeration")
            sub_target = st.text_input("Target Domain", placeholder="", key="sub_target", help="Domain to enumerate subdomains for")
            enum_methods = st.multiselect(
                "Enumeration Methods", ["DNS Brute Force", "Certificate Transparency"],
                default=["DNS Brute Force", "Certificate Transparency"],
            )
            if st.button("Enumerate Subdomains", key="sub_enum_btn"):
                if not sub_target:
                    st.error("Enter a target domain.")
                else:
                    with st.spinner("Enumerating subdomains..."):
                        try:
                            subs = enumerate_subdomains(sub_target.strip(), enum_methods)
                            st.success(f"Found {len(subs)} subdomains")
                            if subs:
                                st.dataframe(pd.DataFrame(subs), use_container_width=True)
                        except Exception as e:
                            st.error(f"Enumeration error: {str(e)}")
        
        # Nmap Advanced Scan
        with st.expander("🛰️ Nmap Advanced Scan"):
            st.markdown("### Nmap Advanced Port & Service Scan")
            nmap_target = st.text_input("Target Host", placeholder="", key="nmap_target", help="Domain or IP address for Nmap scan")
            nmap_port_str = st.text_input("Ports (comma or range)", "22,80,443", key="nmap_ports")
            nmap_aggr = st.checkbox("Aggressive Scan (-A)", value=False)

            if st.button("Run Nmap Scan", key="nmap_scan_btn"):
                if not nmap_target:
                    st.error("Enter a target host.")
                else:
                    with st.spinner("Running Nmap scan..."):
                        try:
                            from agent_team_demo.nmap_tool import run_nmap_scan

                            scan_ports = expand_port_range(nmap_port_str)
                            nmap_json = run_nmap_scan(nmap_target.strip(), ports=scan_ports, aggressive=nmap_aggr)

                            host_data = next(iter(nmap_json.get("scan", {}).values()), {})
                            tcp_info = host_data.get("tcp", {})
                            rows = [
                                {
                                    "Port": port,
                                    "State": info.get("state"),
                                    "Service": info.get("name"),
                                    "Product": info.get("product"),
                                    "Version": info.get("version"),
                                }
                                for port, info in tcp_info.items()
                            ]

                            if rows:
                                st.success(f"Open ports found: {len(rows)}")
                                st.dataframe(pd.DataFrame(rows), use_container_width=True)
                            else:
                                st.info("No open ports detected by Nmap.")
                        except Exception as e:
                            st.error(f"Nmap scan error: {str(e)}")
    
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
        if not vuln_search:
            st.error("Please enter a search term.")
        else:
            with st.spinner("Searching NVD..."):
                try:
                    cve_results = search_nvd(vuln_search)
                    if not cve_results:
                        st.info("No CVEs found for your query.")
                    else:
                        st.subheader(f"Found {len(cve_results)} CVEs")
                        for cve in cve_results:
                            sev = cve.get("severity", "Unknown")
                            with st.expander(f"{cve['id']} - {sev}"):
                                st.markdown(f"**CVSS Score**: {cve.get('score', 'N/A')}")
                                st.markdown(f"**Published**: {cve.get('published')}")
                                st.markdown(f"**Last Modified**: {cve.get('modified')}")
                                st.markdown(f"**Summary**: {cve.get('summary')}")
                                st.markdown(f"[NVD Link](https://nvd.nist.gov/vuln/detail/{cve['id']})")
                except Exception as e:
                    st.error(f"Error querying NVD: {str(e)}")

# --- Sidebar Navigation --- 
# Define navigation options including the Bug Bounty Team
SIDEBAR_TABS = [
    "🔍 Security Scanner", # Represents the main dashboard tabs
    "🦾 AI Bug Bounty Team" 
]

st.sidebar.markdown("---") # Add a separator
st.sidebar.header("Navigation")
selected_sidebar_tab = st.sidebar.radio("Select Feature", SIDEBAR_TABS)

# Optionally, show scan status in sidebar
if st.session_state.get("scanning", False):
    st.sidebar.info("Scan in progress...")
elif st.session_state.get("scan_results"):
    st.sidebar.success("Last scan complete")

# --- Custom CSS for modern look ---
st.markdown(
    """
    <style>
    .stButton>button {background-color: #1f2937; color: #fff; border-radius: 8px; border: none; padding: 0.5em 1.5em; font-weight: 600;}
    .stButton>button:disabled {background-color: #374151; color: #888;}
    .st-expander {border-radius: 8px; border: 1px solid #374151;}
    .stTextInput>div>input, .stTextArea>div>textarea {background: #23272f; color: #fff; border-radius: 6px; border: 1px solid #374151;}
    .stMultiSelect>div {background: #23272f; color: #fff; border-radius: 6px; border: 1px solid #374151;}
    .stSlider>div {color: #fff;}
    .stRadio>div {background: #23272f; color: #fff; border-radius: 6px; border: 1px solid #374151;}
    </style>
    """,
    unsafe_allow_html=True,
)

# --- Main Content Area Logic --- 
if selected_sidebar_tab == "🦾 AI Bug Bounty Team":
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
        recon_feedback_in = st.text_area(
            "Clarifications / scope notes for Vulnerability Scanner (optional)",
            value=st.session_state.get("bb_recon_feedback", ""),
            key="bb_recon_feedback",
        )

        vuln_feedback_in = st.text_area(
            "Clarifications for Exploit Tester (optional)",
            value=st.session_state.get("bb_vuln_feedback", ""),
            key="bb_vuln_feedback",
        )

        final_feedback_in = st.text_area(
            "Clarifications for Report Generator (optional)",
            value=st.session_state.get("bb_final_feedback", ""),
            key="bb_final_feedback",
        )

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
                user_recon_feedback = recon_feedback_in
                st.session_state.bb_vuln_result = execute_vuln_scan_phase(st.session_state.bb_recon_result, user_recon_feedback, checklist)
                shared_context.update('vuln_scan', st.session_state.bb_vuln_result)
        else:
            st.error("Reconnaissance phase failed. Cannot proceed.")

        # Step 3: Exploit Testing (if vuln scan succeeded)
        if st.session_state.bb_vuln_result and "Error:" not in st.session_state.bb_vuln_result:
             with st.spinner("Running Exploit Testing Phase..."):
                user_vuln_feedback_exploit = vuln_feedback_in
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
                user_exploit_feedback_final = final_feedback_in
                st.session_state.bb_report_result = execute_report_phase(
                    st.session_state.bb_recon_result,
                    st.session_state.bb_vuln_result, 
                    st.session_state.bb_exploit_result, 
                    st.session_state.bb_poc_outputs, 
                    user_exploit_feedback_final
                )
                shared_context.update('report', st.session_state.bb_report_result)
        elif st.session_state.bb_vuln_result and "Error:" not in st.session_state.bb_vuln_result:
             st.error("Exploit Testing phase failed. Cannot generate report.") # Repeat error msg

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

# ---------------- DNS ANALYSIS UTIL -----------------

def analyze_dns(domain: str, options: list[str]):
    """Perform real DNS security analysis and return structured results."""
    res = {
        "dns_records": {},
        "spf_check": "Not checked",
        "dmarc_check": "Not checked",
        "zone_transfer": "Not tested",
        "dnssec": "Not checked",
    }

    resolver = dns.resolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 5

    # Fetch standard records
    if "DNS Records" in options:
        for rtype in ["A", "AAAA", "MX", "TXT", "NS"]:
            try:
                answers = resolver.resolve(domain, rtype, raise_on_no_answer=False)
                if answers:
                    res["dns_records"][rtype] = [str(rdata) for rdata in answers]
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException):
                pass

    # SPF / DMARC checks
    if any(opt in options for opt in ["SPF/DMARC Check"]):
        # SPF
        txt_records = res["dns_records"].get("TXT", [])
        spf_record = next((t for t in txt_records if t.lower().startswith("v=spf1")), None)
        if spf_record:
            res["spf_check"] = (
                "PASS - SPF record present with hard fail (-all)"
                if "-all" in spf_record
                else "WARNING - SPF record present but no hard fail"
            )
        else:
            res["spf_check"] = "FAIL - SPF record missing"

        # DMARC
        try:
            dmarc_domain = f"_dmarc.{domain}"
            dmarc_ans = resolver.resolve(dmarc_domain, "TXT", raise_on_no_answer=False)
            dmarc_txt = " ".join(str(r) for r in dmarc_ans) if dmarc_ans else ""
            if dmarc_txt:
                res["dmarc_check"] = (
                    "PASS - Reject/Quarantine policy present"
                    if "p=reject" in dmarc_txt or "p=quarantine" in dmarc_txt
                    else "WARNING - DMARC present but not strict"
                )
            else:
                res["dmarc_check"] = "FAIL - DMARC record missing"
        except dns.exception.DNSException:
            res["dmarc_check"] = "ERROR - Could not query DMARC"

    # DNSSEC detection (simple): look for DS record at parent zone
    if "DNSEC Validation" in options:
        try:
            ds_ans = resolver.resolve(domain, "DS", raise_on_no_answer=False)
            res["dnssec"] = "ENABLED" if ds_ans else "NOT ENABLED"
        except dns.exception.DNSException:
            res["dnssec"] = "ERROR - Unable to determine DNSSEC status"

    # Zone transfer test
    if "Zone Transfer Test" in options:
        ns_records = res["dns_records"].get("NS", [])
        protected = True
        for ns in ns_records:
            nshost = str(ns).rstrip('.')
            try:
                zone = dns.zone.from_xfr(dns.query.xfr(nshost, domain, timeout=5))
                # If we get here, zone transfer succeeded
                protected = False
                break
            except Exception:
                continue
        res["zone_transfer"] = "PROTECTED - Zone transfer not allowed" if protected else "VULNERABLE - Zone transfer succeeded"

    return res

# ---------------- SSL/TLS ANALYSIS UTIL -----------------

def analyze_ssl_tls(host: str, port: int = 443):
    """Connects to host:port, fetches certificate, and enumerates protocol support."""
    result = {
        "cert": {},
        "protocols": {},
        "cipher_summary": "",
        "rating": "",
    }

    # Helper to test protocol support
    def _supports(version: ssl.TLSVersion):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.minimum_version = version
        ctx.maximum_version = version
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection((host, port), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    return True
        except ssl.SSLError:
            return False
        except Exception:
            return False

    # Certificate retrieval (TLS1.2 context)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=5) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            cert = ssock.getpeercert()
            cipher = ssock.cipher()

    # Populate cert info
    result["cert"] = {
        "subject": ", ".join("=".join(t) for t in cert.get("subject", [[("")]])[0]),
        "issuer": ", ".join("=".join(t) for t in cert.get("issuer", [[("")]])[0]),
        "valid_from": cert.get("notBefore"),
        "valid_to": cert.get("notAfter"),
        "sans": [e[1] for e in cert.get("subjectAltName", []) if e[0] == "DNS"],
        "signature_algorithm": cert.get("signatureAlgorithm", "Unknown"),
        "key_size": f"{cert.get('subjectPublicKeyInfo', {}).get('RSA', {}).get('key_size', 'Unknown')} bits",
    }

    # Protocols check
    for version_label, version in [
        ("TLS 1.3", ssl.TLSVersion.TLSv1_3),
        ("TLS 1.2", ssl.TLSVersion.TLSv1_2),
        ("TLS 1.1", ssl.TLSVersion.TLSv1_1),
        ("TLS 1.0", ssl.TLSVersion.TLSv1),
    ]:
        result["protocols"][version_label] = _supports(version)

    # Simple cipher assessment
    cipher_name, protocol, bits = cipher
    if bits and bits >= 128:
        result["cipher_summary"] = f"✅ Strong cipher negotiated: {cipher_name} ({bits} bits)"
    else:
        result["cipher_summary"] = f"⚠️ Weak cipher negotiated: {cipher_name} ({bits} bits)"

    # Rating heuristics
    if result["protocols"].get("TLS 1.3") and not result["protocols"].get("TLS 1.0"):
        result["rating"] = "**A** - Modern protocols, strong cipher"
    else:
        result["rating"] = "**B** - Improve protocol/cipher configuration"

    return result

# ---------------- NVD SEARCH UTIL -----------------

def search_nvd(keyword: str, max_results: int = 20):
    """Query NVD API v2 for keyword and return simplified CVE list."""
    import urllib.parse
    base = "https://services.nvd.nist.gov/rest/json/v2/cves/1.0"  # legacy path fallback
    # New 2.0 endpoint
    base2 = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {
        "keywordSearch": keyword,
        "resultsPerPage": max_results,
    }

    url = f"{base2}?{urllib.parse.urlencode(params)}"
    r = requests.get(url, timeout=15)
    if r.status_code != 200:
        raise RuntimeError(f"NVD API error {r.status_code}")

    data = r.json()
    vulns = data.get("vulnerabilities", [])
    results = []
    for v in vulns:
        cve = v.get("cve", {})
        cve_id = cve.get("id")
        summary = next((d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"), "")
        published = cve.get("published")
        modified = cve.get("lastModified")
        metrics = cve.get("metrics", {})
        severity = "Unknown"
        score = None
        for key in ("cvssMetricV31", "cvssMetricV30"):
            if key in metrics:
                cvss = metrics[key][0].get("cvssData", {})
                severity = metrics[key][0].get("baseSeverity", "Unknown")
                score = cvss.get("baseScore")
                break
        results.append({
            "id": cve_id,
            "summary": summary,
            "published": published,
            "modified": modified,
            "severity": severity,
            "score": score,
        })
    return results

# ---------------------------------------------------------------------------
# Backward‑compatibility wrapper for old tests & modules
# ---------------------------------------------------------------------------

def run_embedded_scan(url: str, depth: int = 2, scan_options=None, timeout_value: int = 10, progress_callback=None):
    """Legacy function kept for compatibility. Internally delegates to `scan_website`.

    Args:
        url (str): Target URL.
        depth (int): Crawl depth (maps to scan_depth).
        scan_options (list[str] | None): Vulnerability tests to run.
        timeout_value (int): Request timeout.
        progress_callback (callable | None): Progress logger accepting (str).
    """
    if scan_options is None:
        scan_options = ["XSS", "SQL Injection", "Security Headers"]
    # Use default threads (3) to keep quick
    res = scan_website(
        url,
        scan_depth=depth,
        scan_options=scan_options,
        threads=3,
        timeout=timeout_value,
        callback=progress_callback,
    )
    # Inject flat keys for legacy callers
    stats = res.get("stats", {})
    if "urls_scanned" not in res:
        res["urls_scanned"] = stats.get("urls_scanned", 0)
    if "forms_analyzed" not in res:
        res["forms_analyzed"] = stats.get("forms_analyzed", 0)
    return res

# ---------------- CODE COACH UTIL -----------------

def analyze_code_snippet(code: str):
    """Very lightweight static checks for risky Python patterns.

    Returns list of (severity, message) tuples.
    """
    import ast, re

    issues: list[tuple[str, str]] = []

    try:
        tree = ast.parse(code)
    except SyntaxError as e:
        return [("critical", f"Syntax error: {e.msg} at line {e.lineno}")]

    class Visitor(ast.NodeVisitor):
        def visit_Call(self, node: ast.Call):
            # eval / exec
            if isinstance(node.func, ast.Name) and node.func.id in {"eval", "exec"}:
                issues.append(("high", f"Use of {node.func.id}() detected at line {node.lineno}"))
            # subprocess with shell=True
            elif (
                isinstance(node.func, ast.Attribute)
                and node.func.attr in {"Popen", "call", "run"}
            ):
                for kw in node.keywords:
                    if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                        issues.append(("high", f"subprocess.{node.func.attr}(shell=True) at line {node.lineno}"))
            self.generic_visit(node)

        def visit_ExceptHandler(self, node: ast.ExceptHandler):
            if node.type is None:
                issues.append(("medium", f"Bare except detected at line {node.lineno}"))
            self.generic_visit(node)

    Visitor().visit(tree)

    # Hard‑coded secrets regexes (simple)
    secret_patterns = [
        r"AKIA[0-9A-Z]{16}",  # AWS key
        r"AIza[0-9A-Za-z\-_]{35}",  # Google API
        r"sk_live_[0-9a-zA-Z]{24}",  # Stripe Live
    ]
    for pat in secret_patterns:
        for m in re.finditer(pat, code):
            issues.append(("critical", f"Possible credential matched '{pat}' at pos {m.start()}"))

    return issues

# ------------------ CODE COACH TAB ------------------

with tabs[4]:
    st.markdown("### 🛡️ Code Coach – Instant Secure‑Coding Feedback")

    snippet = st.text_area("Paste Python code to analyze", height=200, key="code_coach_input")

    if st.button("Analyze Snippet", key="code_coach_btn"):
        if not snippet.strip():
            st.error("Please paste some Python code first.")
        else:
            issues = analyze_code_snippet(snippet)
            if not issues:
                st.success("✅ No obvious issues detected. Great job!")
            else:
                sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
                issues.sort(key=lambda t: sev_order.get(t[0], 4))
                for sev, msg in issues:
                    color = {
                        "critical": "#f38ba8",
                        "high": "#fab387",
                        "medium": "#f9e2af",
                        "low": "#a6e3a1",
                    }.get(sev, "#cdd6f4")
                    st.markdown(f"<div style='border-left:6px solid {color};padding:8px;margin:6px 0;'>"
                                f"<strong>{sev.title()}:</strong> {msg}</div>", unsafe_allow_html=True)

    st.markdown("---")
    st.markdown("#### 📦 Dependency Risk Scanner (requirements.txt)")

    req_text = st.text_area("Paste requirements.txt content", height=120, key="dep_scan_input")

    if st.button("Analyze Dependencies", key="dep_scan_btn"):
        pkgs = []
        for line in req_text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # simple split on == or >= etc.
            import re as _re
            m = _re.match(r"([a-zA-Z0-9_\-]+)", line)
            if m:
                pkgs.append(m.group(1).lower())

        if not pkgs:
            st.error("No packages detected.")
        else:
            with st.spinner("Querying OSV database..."):
                import requests, json as _json
                vulns_found = []
                try:
                    # OSV bulk API
                    url = "https://api.osv.dev/v1/querybatch"
                    body = {"queries": [{"package": {"name": p, "ecosystem": "PyPI"}} for p in pkgs]}
                    r = requests.post(url, json=body, timeout=15)
                    data = r.json()
                    for pkg, result in zip(pkgs, data.get("results", [])):
                        for vuln in result.get("vulns", []):
                            vulns_found.append({
                                "package": pkg,
                                "id": vuln.get("id"),
                                "summary": vuln.get("summary", "")[:120],
                            })
                except Exception as e:
                    st.error(f"Error querying OSV: {e}")
                    vulns_found = []

            if not vulns_found:
                st.success("✅ No known vulnerabilities in listed packages!")
            else:
                st.error(f"Found {len(vulns_found)} vulnerable packages:")
                