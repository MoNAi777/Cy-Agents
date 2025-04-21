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
# Additional imports for real scanning
import urllib3
from bs4 import BeautifulSoup

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
        return {
            'status_code': resp.status_code,
            'headers': dict(resp.headers),
            'body': resp.text[:1000]
        }
    except Exception as e:
        return {'error': str(e)}

def port_scan(host, ports=[80, 443, 8080, 22, 21, 3306, 5432], timeout=1):
    '''Scan a list of ports on a host and return open ports.'''
    open_ports = []
    try:
        ip_address = socket.gethostbyname(host)
    except socket.gaierror:
        return {'error': f"Could not resolve hostname: {host}"}
        
    for port in ports:
        try:
            # Use socket.create_connection for reliability
            with socket.create_connection((ip_address, port), timeout=timeout):
                open_ports.append(port)
        except Exception:
            continue # Port is likely closed or filtered
    return {'open_ports': open_ports}

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
                found.append({'url': test_url, 'status': resp.status_code})
        except requests.exceptions.RequestException:
            continue # Ignore connection errors, timeouts etc.
    return {'found': found}

# --- End Helper Function Injection ---

# --- Start Original User Snippet --- 
""" # This closing triple quote marks the end of the raw string

    # Prepend helper code to the user's snippet
    full_code = helper_code + "\n" + code_snippet
    
    tmp_dir = None
    try:
        # Create an isolated temp directory for execution
        tmp_dir = tempfile.mkdtemp(prefix="poc_")
        tmp_path = os.path.join(tmp_dir, "poc.py")

        with open(tmp_path, "w", encoding="utf-8") as fh:
            fh.write(full_code)

        # Minimal, deterministic environment – no user secrets
        safe_env = {"PYTHONIOENCODING": "utf-8", "PATH": os.getenv("PATH", "")}

        # Windows: hide console window to avoid flashing
        creation_flags = 0
        if hasattr(subprocess, "CREATE_NO_WINDOW"):
            creation_flags = subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP

        # Execute with isolated mode (-I) to ignore PYTHONPATH & site‑packages; 15‑second hard timeout
        result = subprocess.run(
            [sys.executable, "-I", tmp_path],
            cwd=tmp_dir,
            env=safe_env,
            capture_output=True,
            text=True,
            timeout=15,
            creationflags=creation_flags,
        )

        output = result.stdout.strip()
        error = result.stderr.strip()
        return {"output": output, "error": error}
    except subprocess.TimeoutExpired as te:
        return {"output": te.stdout or "", "error": "Execution timed out"}
    except Exception as e:
        return {"output": "", "error": str(e)}
    finally:
        # Clean up directory
        if tmp_dir and os.path.isdir(tmp_dir):
            import shutil
            shutil.rmtree(tmp_dir, ignore_errors=True)

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
    """Perform lightweight real reconnaissance: server headers & TLS info."""
    import re, requests, ssl
    from urllib.parse import urlparse

    # Extract URL
    match = re.search(r"https?://[\w./:-]+", user_query)
    if not match:
        return "Error: No valid URL found in input."

    url = match.group(0)
    parsed = urlparse(url)
    domain = parsed.netloc

    findings = [f"Target URL: {url}"]

    # Fetch headers
    try:
        resp = requests.get(url, timeout=10, verify=False)
        server = resp.headers.get("Server", "Not disclosed")
        findings.append(f"Server header: {server}")

        # Missing security headers
        for header in ["Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options"]:
            if header not in resp.headers:
                findings.append(f"Missing security header: {header}")
    except Exception as e:
        findings.append(f"Error fetching URL: {e}")

    # Simple TLS cert info
    try:
        import ssl, socket as sk
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(sk.socket(), server_hostname=domain) as s:
            s.settimeout(5)
            s.connect((domain, 443))
            cert = s.getpeercert()
            findings.append(f"TLS issuer: {cert.get('issuer')[0][0][1]}")
    except Exception as e:
        findings.append(f"TLS check error: {e}")

    # --- Additional enumeration using external CLI tools if available ---
    try:
        from agent_team_demo.external_tools import (
            tool_exists,
            subfinder_enum,
            dnsx_lookup,
        )

        if tool_exists("subfinder"):
            try:
                subs = subfinder_enum(domain)
                findings.append(f"Subfinder discovered {len(subs)} subdomains")
            except Exception as se:
                findings.append(f"Subfinder error: {se}")

        if tool_exists("dnsx"):
            try:
                a_records = dnsx_lookup(domain, "A")
                findings.append(f"dnsx A records: {', '.join(a_records[:5])}{' ...' if len(a_records)>5 else ''}")
            except Exception as de:
                findings.append(f"dnsx error: {de}")
    except ImportError:
        pass

    return "\n".join(findings)

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
    """Run embedded scanner for real basic results."""
    import re

    url_match = re.search(r"https?://[\w./:-]+", recon_data)
    if not url_match:
        return "Error: Could not determine target URL."

    url = url_match.group(0)

    # Attempt to import the Streamlit dashboard **only if it hasn't already been executed**.
    # When the dashboard is launched with `streamlit run`, the module name becomes `__main__`,
    # so a normal `import agent_team_demo.security_dashboard` will re‑execute the script and
    # fail (Streamlit only allows `st.set_page_config` once per session, etc.).
    try:
        import sys
        from importlib import import_module

        scan_func = None
        # Try to get run_embedded_scan from dashboard if available
        if "agent_team_demo.security_dashboard" in sys.modules:
            sd = sys.modules["agent_team_demo.security_dashboard"]
            scan_func = getattr(sd, "run_embedded_scan", None)
        elif "__main__" in sys.modules and hasattr(sys.modules["__main__"], "run_embedded_scan"):
            sd = sys.modules["__main__"]
            scan_func = getattr(sd, "run_embedded_scan", None)
        else:
            try:
                sd = import_module("agent_team_demo.security_dashboard")
                scan_func = getattr(sd, "run_embedded_scan", None)
            except Exception:
                scan_func = None
        # Fallback: always use scan_website from security_scanner.py if not found
        if scan_func is None:
            from agent_team_demo.security_scanner import scan_website as scan_func

    except Exception as _e:
        # Log for debugging without breaking user flow
        print(f"[execute_vuln_scan_phase] Import failure: {_e}")
        scan_func = None

    if not scan_func:
        return "Error: Scanner function unavailable."

    def _cb(v, m=None):
        pass  # silent progress

    results = scan_func(
        url,
        scan_depth=1,
        scan_options=["XSS", "SQL Injection", "Security Headers"],
        threads=3,
        timeout=10,
        callback=_cb,
    )

    stats = results.get('stats', {})
    summary_lines = [
        f"URLs scanned: {stats.get('urls_scanned', 0)}",
        f"Forms analyzed: {stats.get('forms_analyzed', 0)}",
    ]
    for v in results["vulnerabilities"]:
        summary_lines.append(f"{v.get('severity', 'Unknown')} - {v.get('title', v.get('name', 'Unknown'))} at {v.get('url', 'Unknown')}")

    # --- EXTRA: invoke external CLI scanners if available for *real* deep scan ---
    try:
        from agent_team_demo.external_tools import tool_exists, katana_scan, nuclei_scan

        # Katana crawler – gather additional URLs
        if tool_exists("katana"):
            try:
                kat_urls = katana_scan(url, depth=2, threads=5)
                summary_lines.append(f"Katana discovered {len(kat_urls)} additional URLs")
            except Exception as e:
                summary_lines.append(f"Katana error: {e}")

        # Nuclei quick vuln scan (low severity filter to keep it fast)
        if tool_exists("nuclei"):
            try:
                nuclei_out = nuclei_scan(url, severity="low,medium,high,critical")
                # show only first 5 findings to keep summary short
                nuclei_lines = nuclei_out.splitlines()
                shown = nuclei_lines[:5]
                more = len(nuclei_lines) - len(shown)
                summary_lines.append("Nuclei findings:\n" + "\n".join(shown) + (f"\n...and {more} more" if more > 0 else ""))
            except Exception as e:
                summary_lines.append(f"Nuclei error: {e}")
    except ImportError:
        # external_tools module missing; ignore
        pass

    return "\n".join(summary_lines)

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