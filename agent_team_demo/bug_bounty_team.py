"""🐞 Bug Bounty Hunter Team Logic - Functions for running specialized security phases

This module defines the logic, prompts, and tools for a multi-phase security assessment.
It replaces the Agno Agent/Team structure with direct OpenAI calls while preserving skills.
"""

import os
import sys
import re
import subprocess
import tempfile
import requests
import socket
from textwrap import dedent
from pathlib import Path
import openai # Use the direct OpenAI library

# Check for OpenAI API key
if not os.getenv("OPENAI_API_KEY"):
    print("\n⚠️ Error: OPENAI_API_KEY is required")
    print("Please check that your .env file exists and contains OPENAI_API_KEY")
    # sys.exit(1) # Removed to prevent app termination during import

# Check for GitHub token (if GithubTools are needed)
if not os.getenv("GITHUB_ACCESS_TOKEN"):
    print("\n⚠️ Warning: GitHub access token not found. GitHub tools may be limited.")
    # Removed sys.exit(1) to allow running without GitHub tools if needed

# Initialize OpenAI client
# try:
#     client = openai.OpenAI()
# except Exception as e:
#     print(f"Error initializing OpenAI client: {e}")
#     sys.exit(1)
# --- Client initialization moved into call_openai_api ---

# --- Knowledge Base & Checklists ---
OWASP_TOP_10 = [
    "Injection (A01)", "Broken Authentication (A02)", "Sensitive Data Exposure (A03)",
    "XML External Entities (A04)", "Broken Access Control (A05)", "Security Misconfiguration (A06)",
    "Cross-Site Scripting (XSS) (A07)", "Insecure Deserialization (A08)",
    "Using Components with Known Vulnerabilities (A09)", "Insufficient Logging & Monitoring (A10)",
]
CVE_SEARCH_URL = "https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword={query}"
CTF_WRITEUP_SEARCH_URL = "https://ctftime.org/writeups?search={query}"

# --- Shared Context ---
class SharedContext:
    # ... (Keep SharedContext class as is) ...
    def __init__(self):
        self.data = {}
        self.checklist = [
            "Check for SQL Injection (SQLi)",
            "Check for Cross-Site Scripting (XSS)",
            "Check for Local File Inclusion (LFI)",
            "Check for Remote Code Execution (RCE)",
            "Check for Command Injection",
            "Check for Directory Traversal",
            "Check for Authentication Bypass",
            "Check for Sensitive Data Exposure",
            "Check for Open Redirects",
            "Check for CSRF",
            "Check for SSRF",
            "Check for known CVEs in dependencies",
        ]
    def update(self, key, value):
        self.data[key] = value
    def get(self, key, default=None):
        return self.data.get(key, default)
    def add_finding(self, agent, finding):
        if agent not in self.data:
            self.data[agent] = []
        self.data[agent].append(finding)
    def get_all_findings(self):
        return self.data
    def get_checklist(self):
        return self.checklist

shared_context = SharedContext()

# --- Custom Tools (Keep as is) ---
def run_poc_code(code_snippet):
    """Safely execute a Python PoC code snippet and capture output/errors.
    Injects helper functions (http_request, port_scan, dir_bruteforce) for use.
    """
    # --- Helper Function Injection --- 
    # Define the helper functions and necessary imports as a string
    # Use raw strings (r"""...""") and carefully escape internal docstrings
    helper_code = r"""
import requests
import socket
import sys
import urllib3

# Suppress InsecureRequestWarning for cleaner PoC output
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def http_request(url, method='GET', data=None, headers=None, timeout=5):
    '''Perform an HTTP GET or POST request and return status, headers, and body.'''
    try:
        if method.upper() == 'GET':
            resp = requests.get(url, headers=headers, timeout=timeout, verify=False)
        else:
            resp = requests.post(url, data=data, headers=headers, timeout=timeout, verify=False)
        # Return a dictionary that can be easily printed or used
        return {{
            'status_code': resp.status_code,
            'headers': dict(resp.headers),
            'body': resp.text[:1000]
        }}
    except Exception as e:
        return {{'error': str(e)}}

def port_scan(host, ports=[80, 443, 8080, 22, 21, 3306, 5432], timeout=1):
    '''Scan a list of ports on a host and return open ports.'''
    open_ports = []
    try:
        ip_address = socket.gethostbyname(host)
    except socket.gaierror:
        return {{'error': f"Could not resolve hostname: {{host}}"}}
        
    for port in ports:
        try:
            # Use socket.create_connection for reliability
            with socket.create_connection((ip_address, port), timeout=timeout):
                open_ports.append(port)
        except Exception:
            continue # Port is likely closed or filtered
    return {{'open_ports': open_ports}}

def dir_bruteforce(url, wordlist=['admin', 'login', 'dashboard', 'test', 'backup', 'wp-admin', 'api'], timeout=3):
    '''Brute-force common directories on a web server.'''
    found = []
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    for word in wordlist:
        test_url = url.rstrip('/') + '/' + word.lstrip('/')
        try:
            # Use verify=False for simplicity, HEAD request might be faster
            resp = requests.get(test_url, timeout=timeout, allow_redirects=False, verify=False)
            if resp.status_code < 400:
                found.append({{'url': test_url, 'status': resp.status_code}})
        except requests.exceptions.RequestException:
            continue # Ignore connection errors, timeouts etc.
    return {{'found': found}}

# --- End Helper Function Injection ---

# --- Start Original User Snippet --- 
""" # This closing triple quote marks the end of the raw string

    # Prepend helper code to the user's snippet
    full_code = helper_code + "\n" + code_snippet
    
    tmp_path = None # Initialize tmp_path
    try:
        # Use 'utf-8' encoding for broader compatibility
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False, encoding='utf-8') as tmp:
            tmp.write(full_code)
            tmp_path = tmp.name
        
        # Execute the combined script
        result = subprocess.run(
            [sys.executable, tmp_path],
            capture_output=True,
            text=True,
            timeout=10
        )
        # Clean up the temp file
        os.unlink(tmp_path)
        output = result.stdout.strip()
        error = result.stderr.strip()
        return {'output': output, 'error': error}
    except Exception as e:
        # Ensure cleanup even on error
        if 'tmp_path' in locals() and os.path.exists(tmp_path):
            os.unlink(tmp_path)
        return {'output': '', 'error': str(e)}

def http_request(url, method='GET', data=None, headers=None, timeout=5):
    # ... (Keep http_request function as is) ...
    """Perform an HTTP GET or POST request and return status, headers, and body."""
    try:
        if method.upper() == 'GET':
            resp = requests.get(url, headers=headers, timeout=timeout, verify=False) # Added verify=False for simplicity, consider security implications
        else:
            resp = requests.post(url, data=data, headers=headers, timeout=timeout, verify=False)
        return {
            'status_code': resp.status_code,
            'headers': dict(resp.headers),
            'body': resp.text[:1000]  # limit output
        }
    except Exception as e:
        return {'error': str(e)}

def port_scan(host, ports=[80, 443, 8080, 22, 21, 3306, 5432], timeout=1):
    # ... (Keep port_scan function as is) ...
    """Scan a list of ports on a host and return open ports."""
    open_ports = []
    # Resolve hostname to IP if needed
    try:
        ip_address = socket.gethostbyname(host)
    except socket.gaierror:
        return {'error': f"Could not resolve hostname: {host}"}
        
    for port in ports:
        try:
            with socket.create_connection((ip_address, port), timeout=timeout):
                open_ports.append(port)
        except Exception:
            continue
    return {'open_ports': open_ports}

def dir_bruteforce(url, wordlist=['admin', 'login', 'dashboard', 'test', 'backup', 'wp-admin', 'api'], timeout=3):
    # ... (Keep dir_bruteforce function as is) ...
     """Brute-force common directories on a web server."""
     found = []
     if not url.startswith(("http://", "https://")):
         url = "http://" + url # Assume http if not specified

     for word in wordlist:
         # Ensure forward slashes and no double slashes
         test_url = url.rstrip('/') + '/' + word.lstrip('/')
         try:
             resp = requests.get(test_url, timeout=timeout, allow_redirects=False, verify=False)
             if resp.status_code < 400: # Success or redirect
                 found.append({'url': test_url, 'status': resp.status_code})
         except requests.exceptions.RequestException:
             continue
     return {'found': found}

# --- Agent Phase Execution Functions ---

def call_openai_api(system_prompt, user_prompt, model="gpt-4-turbo-preview", max_tokens=2048):
    """Generic function to call OpenAI Chat Completion API."""
    try:
        # --- Initialize client here --- 
        client = openai.OpenAI()
        
        response = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            max_tokens=max_tokens,
            temperature=0.5, # Adjust creativity
        )
        return response.choices[0].message.content
    except Exception as e:
        print(f"Error calling OpenAI API: {e}")
        return f"Error: Could not get response from AI model. Details: {str(e)}"

# -- Reconnaissance Phase --
RECON_SYSTEM_PROMPT = dedent(f"""
You are an expert in reconnaissance for security research. 🔍

Your responsibilities:
1. Gather comprehensive information about the target system based on the user query.
2. Find public repositories, documentation, and technical information.
3. Identify technologies, frameworks, and libraries used.
4. Look for known security issues in similar systems using the provided resources.
5. Document all findings with sources.

Focus on:
- Technology stack identification
- Open source repositories
- Public APIs and endpoints
- Documentation that reveals architecture
- Previous vulnerability reports or security concerns

Reference Resources:
- OWASP Top 10: {OWASP_TOP_10}
- CVE Search: {CVE_SEARCH_URL}
- CTF Writeup Search: {CTF_WRITEUP_SEARCH_URL}
Always check these resources for relevant vulnerabilities and techniques.

## Output Schema (Markdown Table):
| Category                | Finding/Details | Source/Link |
|-------------------------|-----------------|-------------|
| Technology Stack        | ...             | ...         |
| Public Repositories    | ...             | ...         |
| APIs/Endpoints         | ...             | ...         |
| Documentation          | ...             | ...         |
| Previous Vulnerabilities| ...            | ...         |
| Other Info             | ...            | ...         |

## Example Output:
| Category                | Finding/Details                | Source/Link                |
|-------------------------|-------------------------------|----------------------------|
| Technology Stack        | Django, PostgreSQL, React      | https://github.com/example |
| Public Repositories     | example/repo                   | https://github.com/example |

## Self-Reflection:
After completing your findings, write a short paragraph reflecting on the thoroughness and reliability of your reconnaissance. Mention any uncertainties or areas for further investigation.
""")
def execute_recon_phase(user_query):
    return call_openai_api(RECON_SYSTEM_PROMPT, user_query)

# -- Vulnerability Scanning Phase --
VULN_SCANNER_SYSTEM_PROMPT = dedent(f"""
You are an expert in identifying security vulnerabilities based on reconnaissance data. 🔒

Your responsibilities:
1. Analyze the provided reconnaissance data and user feedback.
2. Use the vulnerability checklist provided.
3. Identify potential vulnerabilities based on the findings and common patterns:
   - SQL injection, XSS, CSRF, Auth bypass, AuthZ issues, Info leakage, API flaws, Input validation.
4. Classify vulnerabilities by severity (Critical, High, Medium, Low).
5. Provide preliminary evidence or reasoning for each potential vulnerability.
6. Reference OWASP, CVEs, or CTF writeups where applicable.

Reference Resources:
- OWASP Top 10: {OWASP_TOP_10}
- CVE Search: {CVE_SEARCH_URL}
- CTF Writeup Search: {CTF_WRITEUP_SEARCH_URL}

## Output Schema (Markdown Table):
| Vulnerability Type | Location/Component | Severity | Evidence/Reasoning | Reference | Checklist Item |
|-------------------|--------------------|----------|--------------------|-----------|----------------|
| ...               | ...                | ...      | ...                | ...       | ...            |

## Example Output:
| Vulnerability Type | Location/Component | Severity | Evidence/Reasoning                | Reference                  | Checklist Item             |
|-------------------|--------------------|----------|-----------------------------------|----------------------------|----------------------------|
| SQL Injection     | /api/v1/login      | High     | User input not sanitized (suspected) | https://owasp.org/Top10    | SQL Injection (SQLi)       |

## Self-Reflection:
After listing vulnerabilities, reflect on the confidence of your findings, potential false positives, and areas needing exploit testing.
""")
def execute_vuln_scan_phase(recon_data, user_feedback, checklist):
    user_prompt = f"Reconnaissance Findings:\n{recon_data}\n\nUser Feedback/Clarifications:\n{user_feedback}\n\nVulnerability Checklist to Address:\n{checklist}\n\nPerform vulnerability analysis based on the above."
    return call_openai_api(VULN_SCANNER_SYSTEM_PROMPT, user_prompt)

# -- Exploit Testing Phase --
EXPLOIT_TESTER_SYSTEM_PROMPT = dedent(f"""
You are an expert in safely validating security vulnerabilities. ⚠️

Your responsibilities:
1. Review potential vulnerabilities from the scanner report and user feedback.
2. Design safe proof-of-concept (PoC) tests for each suspected vulnerability.
3. If possible, write simple, non-destructive Python code snippets using available tools to demonstrate the vulnerability.
   Available tools (callable within ```python blocks):
   - `http_request(url, method='GET' or 'POST', data=None, headers=None)`
   - `port_scan(host, ports=[...])`
   - `dir_bruteforce(url, wordlist=[...])`
   Use these tools responsibly.
4. Document the exact steps to reproduce each confirmed issue.
5. Rate confirmed vulnerabilities on the CVSS scale (provide estimate if unsure).

Important guidelines:
- NEVER suggest destructive tests or actions.
- Focus on proof of concept, not harmful exploitation.
- Document tests clearly with code examples where applicable.
- Explain the potential impact of each confirmed vulnerability.

Reference Resources:
- OWASP Top 10: {OWASP_TOP_10}
- CVE Search: {CVE_SEARCH_URL}
- CTF Writeup Search: {CTF_WRITEUP_SEARCH_URL}

## Output Schema (Markdown Table):
| Vulnerability | Status (Confirmed/Unconfirmed/Needs Manual Check) | PoC Code/Steps | CVSS Score (Est.) | Notes/Impact |
|--------------|---------------------------------------------------|----------------|-------------------|--------------|
| ...          | ...                                               | ...            | ...               | ...          |

## Example Output:
| Vulnerability | Status   | PoC Code/Steps                                                                 | CVSS Score (Est.) | Notes/Impact                               |
|--------------|----------|--------------------------------------------------------------------------------|-------------------|--------------------------------------------|
| SQL Injection| Confirmed| ```python\nresp = http_request('/api/v1/login', 'POST', data={{'user': "' OR 1=1--" }})\nprint(resp)\n``` | 8.6               | Potential data leak via login bypass.      |
| XSS          | Needs Manual Check | Visit /profile?name=<script>alert(1)</script> and check browser console | 4.3               | Needs browser validation. |

## Self-Reflection:
After providing PoCs, reflect on the safety/ethics of tests, confidence in confirmations, and any vulnerabilities requiring manual verification.
""")
def execute_exploit_phase(vuln_scan_data, user_feedback, checklist):
    user_prompt = f"Vulnerability Scan Report:\n{vuln_scan_data}\n\nUser Feedback/Clarifications:\n{user_feedback}\n\nChecklist Items to Focus On (if applicable):\n{checklist}\n\nDesign and document safe PoCs for the suspected vulnerabilities."
    return call_openai_api(EXPLOIT_TESTER_SYSTEM_PROMPT, user_prompt)

# -- Report Generation Phase --
REPORT_GENERATOR_SYSTEM_PROMPT = dedent(f"""
You are an expert in writing professional security assessment reports. 📝

Your responsibilities:
1. Compile findings from Reconnaissance, Vulnerability Scanning, and Exploit Testing phases, including PoC results and user feedback.
2. Structure the report clearly: Executive Summary, Technical Details (per vulnerability), Remediation Steps.
3. Create clear descriptions for each confirmed vulnerability: Severity, Description, PoC/Steps, Potential Impact, Remediation.
4. Include PoC code snippets and outputs where available.
5. Prioritize vulnerabilities by risk level (CVSS score or severity).

Report Requirements:
- Professional, clear, and technically accurate.
- Actionable with specific remediation steps.
- Well-organized with Markdown formatting.
- Cite sources or references where applicable (OWASP, CVEs).

Reference Resources:
- OWASP Top 10: {OWASP_TOP_10}
- CVE Search: {CVE_SEARCH_URL}

## Output Schema (Markdown Sections):
- Executive Summary
- Table of Confirmed Vulnerabilities (Markdown Table: Vulnerability, Severity, Location, CVSS)
- Technical Details (per vulnerability: Description, PoC/Steps, Impact, Remediation)
- Appendix (Optional: Recon/Scan data, PoC outputs)

## Self-Reflection:
After compiling the report, reflect on its clarity, completeness, and usefulness. Suggest improvements for future reports.
""")
def execute_report_phase(recon_data, vuln_scan_data, exploit_data, poc_outputs, user_feedback_final):
    user_prompt = f"Compile a final security report using the following data:\n\n" \
                  f"1. Reconnaissance Findings:\n{recon_data}\n\n" \
                  f"2. Vulnerability Scan Findings:\n{vuln_scan_data}\n\n" \
                  f"3. Exploit Testing Findings:\n{exploit_data}\n\n" \
                  f"4. Automated PoC Execution Results:\n{poc_outputs}\n\n" \
                  f"5. Final User Feedback:\n{user_feedback_final}\n\n" \
                  f"Generate the report according to the required schema."
    # Use a larger model for report generation if needed, and more tokens
    return call_openai_api(REPORT_GENERATOR_SYSTEM_PROMPT, user_prompt, model="gpt-4-turbo", max_tokens=4000)

# --- Main Execution Logic (Example - Now moved to dashboard) ---
# if __name__ == "__main__":
#     target = input("Enter the target website or repository to analyze: ")
#     initial_prompt = f"Find security vulnerabilities in {target}. Focus on common web vulnerabilities."
#     checklist = shared_context.get_checklist()
#     print(f"\n🔍 Starting security analysis for: {target}\n")
#
#     # Step 1: Recon
#     recon_result = execute_recon_phase(initial_prompt)
#     shared_context.update('recon', recon_result)
#     print("\n[Reconnaissance Phase Output]:\n", recon_result)
#     user_recon_feedback = input("... clarification for Scanner? ...")
#
#     # Step 2: Vuln Scan
#     vuln_result = execute_vuln_scan_phase(recon_result, user_recon_feedback, checklist)
#     shared_context.update('vuln_scan', vuln_result)
#     print("\n[Vulnerability Scan Phase Output]:\n", vuln_result)
#     user_vuln_feedback = input("... clarification for Exploit Tester? ...")
#
#     # Step 3: Exploit Test
#     exploit_result = execute_exploit_phase(vuln_result, user_vuln_feedback, checklist)
#     shared_context.update('exploit', exploit_result)
#     print("\n[Exploit Testing Phase Output]:\n", exploit_result)
#     code_blocks = re.findall(r'```python(.*?)```', exploit_result, re.DOTALL)
#     poc_outputs = [{'code': code.strip(), 'result': run_poc_code(code.strip())} for code in code_blocks]
#     shared_context.update('poc_outputs', poc_outputs)
#     print("\n[Automated PoC Execution Results]:\n", poc_outputs)
#     user_exploit_feedback = input("... clarification for Report Generator? ...")
#
#     # Step 4: Report
#     report_result = execute_report_phase(recon_result, vuln_result, exploit_result, poc_outputs, user_exploit_feedback)
#     shared_context.update('report', report_result)
#     print("\n[Final Security Report]:\n", report_result)