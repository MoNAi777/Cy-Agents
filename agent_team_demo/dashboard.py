"""🔍 Bug Bounty Hunter Dashboard - A Streamlit UI for the Bug Bounty Hunter Team

This dashboard provides a user-friendly interface to interact with the Bug Bounty Hunter Team.
It offers different scanning options and displays results in a visually appealing format.

Run `pip install streamlit streamlit-chat` in addition to other requirements.
"""

import os
import time
import streamlit as st
from streamlit_chat import message
import threading
from io import StringIO
import sys
import re
import json

# Commenting out the problematic imports
# from agno.config import AgnoConfig
# from agno import AgnoConfig

# Initialize OpenAI configuration
if "OPENAI_API_KEY" in os.environ:
    os.environ["AGNO_OPENAI_API_KEY"] = os.environ["OPENAI_API_KEY"]

# Ensure the current directory is in the path
sys.path.append(os.path.dirname(os.path.realpath(__file__)))

def load_agents():
    """Load agents only when needed"""
    try:
        # Initialize Agno configuration
        if "OPENAI_API_KEY" not in os.environ:
            st.error("Please enter your OpenAI API key in the sidebar first.")
            return None
            
        try:
            from agno.agent import Agent
            from agno.models.openai import OpenAIChat
        except ImportError as e:
            st.error("Error importing Agno modules. Please install required packages:")
            st.code("pip install agno==1.3.1 openai==1.13.3 spider-client")
            return None
            
        from bug_bounty_team import bug_bounty_team, recon_agent, vuln_scanner_agent, exploit_agent, report_agent
        from web_scanner_agent import web_scanner_agent
        from enhanced_team import enhanced_team
        
        # Initialize agents with API key
        agents = {
            'recon': recon_agent,
            'scanner': vuln_scanner_agent,
            'exploit': exploit_agent,
            'report': report_agent,
            'web': web_scanner_agent,
            'team': bug_bounty_team
        }
        
        # Test agent initialization
        try:
            agents['recon'].initialize()
            return agents
        except Exception as e:
            st.error(f"Error initializing agents: {e}")
            st.error("Please make sure you have Agno and compatible OpenAI version installed.")
            st.code("pip install agno openai==1.13.3")
            return None
            
    except ImportError as e:
        st.error(f"Error loading agents: {e}")
        st.error("Please make sure all dependencies are installed:")
        st.code("pip install agno==1.3.1 openai==1.13.3 duckduckgo-search beautifulsoup4")
        return None
    except Exception as e:
        st.error(f"Unexpected error: {e}")
        return None

# Configure the Streamlit page
st.set_page_config(
    page_title="Bug Bounty Hunter Dashboard",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom CSS for better styling
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        color: #FF5757;
        text-align: center;
        margin-bottom: 1rem;
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
        background-color: #f9f9f9;
    }
    .highlight {
        background-color: #f0f7ff;
        padding: 8px;
        border-radius: 4px;
        border-left: 4px solid #00C4B4;
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
    .tool-call {
        background-color: #f0f7ff;
        border-left: 3px solid #00A8E8;
        padding: 8px;
        margin: 10px 0;
        font-family: monospace;
        font-size: 0.9rem;
        overflow-x: auto;
    }
    .stTabs [data-baseweb="tab-list"] {
        gap: 10px;
    }
    .stTabs [data-baseweb="tab"] {
        border-radius: 4px 4px 0px 0px;
        padding: 10px 16px;
        background-color: #f0f7ff;
    }
    .stTabs [aria-selected="true"] {
        background-color: #00C4B4;
        color: white;
    }
</style>

<div class="main-header">🔍 Bug Bounty Hunter Dashboard</div>
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
    This dashboard is powered by the Agno library for building AI agents with memory, knowledge, tools, and reasoning.
    
    The Bug Bounty Hunter Team consists of specialized agents for reconnaissance, vulnerability scanning, exploit testing, and report generation.
    """)

# Capture stdout to get streaming output from agents
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

# Function to parse and format the output with proper styling
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

# Create tabs for different scanning options
tab1, tab2, tab3, tab4 = st.tabs(["🚀 Quick Scan", "🔎 Web Scanner", "🧬 Full Team Scan", "📊 Results Dashboard"])

with tab1:
    st.markdown("### Quick Reconnaissance Scan")
    st.markdown("Quickly gather information about a target using the Reconnaissance Agent.")
    
    # Target input
    quick_target = st.text_input("Target Website or Repository URL", key="quick_target")
    quick_scan_button = st.button("Start Quick Scan", key="quick_scan")
    
    if quick_scan_button:
        if not api_key:
            st.error("Please enter your OpenAI API key in the sidebar first.")
        elif not quick_target:
            st.error("Please enter a target URL or repository.")
        else:
            with st.spinner("Loading agents..."):
                agents = load_agents()
                if agents:
                    st.success("Agents loaded successfully!")
                    
                    # Create a placeholder for streaming output
                    output_placeholder = st.empty()
                    
                    # Run the recon agent in a thread
                    def run_recon():
                        with CaptureOutput() as output:
                            prompt = f"Gather information about {quick_target}. Focus on technology stack and potential security concerns."
                            agents['recon'].print_response(prompt, stream=True, show_tool_calls=show_tools)
                            
                            # Update the placeholder with formatted output
                            formatted_output = format_agent_output(output.get_output())
                            output_placeholder.markdown(f'<div class="card">{formatted_output}</div>', unsafe_allow_html=True)
                    
                    # Start the thread
                    thread = threading.Thread(target=run_recon)
                    thread.start()
                    
                    # Show a spinner while waiting
                    with st.spinner("Running reconnaissance scan..."):
                        while thread.is_alive():
                            time.sleep(0.1)
                    
                    st.success("Reconnaissance scan completed!")

with tab2:
    st.markdown("### Web Vulnerability Scanner")
    st.markdown("Scan websites for security vulnerabilities.")
    
    # Target input
    web_target = st.text_input("Website URL", key="web_target")
    web_scan_button = st.button("Start Web Scan", key="web_scan")
    
    if web_scan_button:
        if not api_key:
            st.error("Please enter your OpenAI API key in the sidebar first.")
        elif not web_target:
            st.error("Please enter a target URL.")
        else:
            with st.spinner("Loading agents..."):
                agents = load_agents()
                if agents:
                    st.success("Agents loaded successfully!")
                    
                    # Create a placeholder for streaming output
                    output_placeholder = st.empty()
                    
                    # Run the web scanner agent in a thread
                    def run_web_scan():
                        with CaptureOutput() as output:
                            prompt = f"Scan {web_target} for security vulnerabilities. Focus on passive reconnaissance only."
                            agents['web'].print_response(prompt, stream=True, show_tool_calls=show_tools)
                            
                            # Update the placeholder with formatted output
                            formatted_output = format_agent_output(output.get_output())
                            output_placeholder.markdown(f'<div class="card">{formatted_output}</div>', unsafe_allow_html=True)
                    
                    # Start the thread
                    thread = threading.Thread(target=run_web_scan)
                    thread.start()
                    
                    # Show a spinner while waiting
                    with st.spinner("Scanning website..."):
                        while thread.is_alive():
                            time.sleep(0.1)
                    
                    st.success("Web scan completed!")

with tab3:
    st.markdown("### Full Team Analysis")
    st.markdown("Run a comprehensive security analysis using the full Bug Bounty Hunter Team.")
    
    # Target input
    full_target = st.text_input("Target Website or Repository URL", key="full_target")
    
    # Advanced options
    with st.expander("Advanced Options"):
        scan_mode = st.radio(
            "Scan Mode",
            ["Standard Team", "Enhanced Team (with Web Scanner)"],
            index=0
        )
        
        custom_prompt = st.text_area(
            "Custom Instructions (optional)",
            placeholder="Enter custom instructions for the team..."
        )
    
    full_scan_button = st.button("Start Full Analysis", key="full_scan")
    
    if full_scan_button:
        if not api_key:
            st.error("Please enter your OpenAI API key in the sidebar first.")
        elif not full_target:
            st.error("Please enter a target URL or repository.")
        else:
            with st.spinner("Loading agents..."):
                agents = load_agents()
                if agents:
                    st.success("Agents loaded successfully!")
                    
                    # Create a placeholder for streaming output
                    output_placeholder = st.empty()
                    
                    # Run the full team scan in a thread
                    def run_full_scan():
                        with CaptureOutput() as output:
                            team = agents['team']
                            prompt = custom_prompt if custom_prompt else f"Analyze {full_target} for security vulnerabilities. Perform a comprehensive security assessment."
                            team.print_response(prompt, stream=True, show_tool_calls=show_tools)
                            
                            # Update the placeholder with formatted output
                            formatted_output = format_agent_output(output.get_output())
                            output_placeholder.markdown(f'<div class="card">{formatted_output}</div>', unsafe_allow_html=True)
                    
                    # Start the thread
                    thread = threading.Thread(target=run_full_scan)
                    thread.start()
                    
                    # Show a spinner while waiting
                    with st.spinner("Running full team analysis..."):
                        while thread.is_alive():
                            time.sleep(0.1)
                    
                    st.success("Full analysis completed!")

with tab4:
    st.markdown("### Results Dashboard")
    st.markdown("View scan results and reports.")
    
    # Placeholder metrics
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric(label="Critical Issues", value="0")
    with col2:
        st.metric(label="High Severity", value="0")
    with col3:
        st.metric(label="Medium Severity", value="0")
    with col4:
        st.metric(label="Low Severity", value="0")
    
    st.info("Detailed results will appear here after running scans.")

def run_scan(target_url, scan_type="quick"):
    """Run a scan with proper error handling"""
    if not target_url:
        st.error("Please enter a target URL")
        return None
        
    agents = load_agents()
    if not agents:
        st.error("Failed to initialize agents. Please check your OpenAI API key and dependencies.")
        return None
        
    try:
        if scan_type == "quick":
            result = agents['web'].scan_url(target_url)
        elif scan_type == "full":
            result = agents['team'].scan_target(target_url)
        else:
            st.error(f"Unknown scan type: {scan_type}")
            return None
            
        return result
    except Exception as e:
        st.error(f"Error during scan: {e}")
        return None

def run_enhanced_scan(target_url):
    """Run an enhanced scan with proper error handling"""
    if not target_url:
        st.error("Please enter a target URL")
        return None
        
    agents = load_agents()
    if not agents:
        st.error("Failed to initialize agents. Please check your OpenAI API key and dependencies.")
        return None
        
    try:
        from enhanced_team import enhanced_team
        result = enhanced_team.scan_target(target_url)
        return result
    except Exception as e:
        st.error(f"Error during enhanced scan: {e}")
        return None

def main():
    st.title("Bug Bounty Hunter Dashboard")
    
    # Initialize session state
    if 'scan_results' not in st.session_state:
        st.session_state.scan_results = None
    
    # Input section
    target_url = st.text_input("Enter Target URL:", placeholder="https://example.com")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        if st.button("Quick Scan"):
            with st.spinner("Running quick scan..."):
                st.session_state.scan_results = run_scan(target_url, scan_type="quick")
    
    with col2:
        if st.button("Full Scan"):
            with st.spinner("Running full scan..."):
                st.session_state.scan_results = run_scan(target_url, scan_type="full")
    
    with col3:
        if st.button("Enhanced Scan"):
            with st.spinner("Running enhanced scan..."):
                st.session_state.scan_results = run_enhanced_scan(target_url)
    
    # Display results
    if st.session_state.scan_results:
        st.subheader("Scan Results")
        st.json(st.session_state.scan_results)
    else:
        st.info("Detailed results will appear here after running scans.")

# Add the requirements to the requirements.txt file
if __name__ == "__main__":
    print("Run this app with: streamlit run dashboard.py") 