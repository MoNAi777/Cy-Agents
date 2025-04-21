"""
Security Scanner Module

This module provides real scanning functionality for the security dashboard.
It implements port scanning, web vulnerability scanning, DNS analysis, and SSL/TLS scanning.
"""

import requests
import socket
import dns.resolver
import dns.zone
import dns.query
import ssl
import json
import time
import re
import subprocess
import threading
import concurrent.futures
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
import logging

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class SecurityScanner:
    """Main scanner class that coordinates all scanning activities"""
    
    def __init__(self):
        self.visited_urls = set()
        self.discovered_urls = set()
        self.scan_results = {
            'target_url': None,
            'scan_time': None,
            'server_info': {},
            'open_ports': [],
            'vulnerabilities': [],
            'stats': {
                'urls_scanned': 0,
                'forms_analyzed': 0,
                'total_vulnerabilities': 0,
            }
        }
        self.stop_scan = False
    
    def reset(self):
        """Reset scanner state for a new scan"""
        self.visited_urls = set()
        self.discovered_urls = set()
        self.scan_results = {
            'target_url': None,
            'scan_time': None,
            'server_info': {},
            'open_ports': [],
            'vulnerabilities': [],
            'stats': {
                'urls_scanned': 0,
                'forms_analyzed': 0,
                'total_vulnerabilities': 0,
            }
        }
        self.stop_scan = False
    
    def scan_target(self, target_url, scan_depth=2, scan_options=None, threads=3, timeout=10, callback=None):
        """Main scan function that orchestrates the entire scanning process"""
        self.reset()
        
        if callback:
            callback(None, "Starting security scan for target: " + target_url)
        
        # Parse and normalize URL
        if not target_url.startswith(('http://', 'https://')):
            target_url = 'https://' + target_url
        
        parsed_url = urlparse(target_url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
        self.scan_results['target_url'] = base_url
        self.scan_results['scan_time'] = time.strftime("%Y-%m-%d %H:%M:%S")
        
        # Default scan options if none provided
        if scan_options is None:
            scan_options = ["XSS", "SQL Injection", "Security Headers", "Port Scan"]
        
        # Extract hostname for DNS and port scanning
        hostname = parsed_url.netloc
        if ':' in hostname:
            hostname = hostname.split(':')[0]
        
        try:
            progress = 0
            if callback:
                callback(progress, "Initializing scan")
            
            # --- External tool results ---
            external_results = {}
            # Try nmap
            try:
                from agent_team_demo.nmap_tool import run_nmap_scan
                nmap_result = run_nmap_scan(hostname)
                external_results['nmap'] = nmap_result
                if callback:
                    callback(None, "Nmap scan completed.")
            except Exception as e:
                external_results['nmap'] = f"Nmap not run: {e}"
                if callback:
                    callback(None, f"Nmap scan skipped: {e}")
            # Try nuclei
            try:
                from agent_team_demo.external_tools import tool_exists, nuclei_scan
                if tool_exists("nuclei"):
                    nuclei_out = nuclei_scan(base_url)
                    external_results['nuclei'] = nuclei_out
                    if callback:
                        callback(None, "Nuclei scan completed.")
                else:
                    external_results['nuclei'] = "Nuclei not installed."
            except Exception as e:
                external_results['nuclei'] = f"Nuclei not run: {e}"
                if callback:
                    callback(None, f"Nuclei scan skipped: {e}")
            # Try katana
            try:
                from agent_team_demo.external_tools import katana_scan
                katana_urls = katana_scan(base_url, depth=2, threads=threads)
                external_results['katana'] = katana_urls
                if callback:
                    callback(None, f"Katana discovered {len(katana_urls)} URLs.")
            except Exception as e:
                external_results['katana'] = f"Katana not run: {e}"
                if callback:
                    callback(None, f"Katana scan skipped: {e}")

            # 1. Get server information
            if callback:
                progress = 10
                callback(progress, "Gathering initial server information...")
            
            self.get_server_info(base_url, callback)
            
            # 2. Port scanning
            if "Port Scan" in scan_options:
                if callback:
                    progress = 25
                    callback(progress, "Performing port scan...")
                
                self.scan_ports(hostname, callback)
            
            # 3. Web crawling and vulnerability scanning
            if callback:
                progress = 30
                callback(progress, "Starting web crawling and vulnerability analysis...")
            
            self.crawl_and_scan(base_url, scan_depth, scan_options, threads, timeout, callback)
            
            progress = 80
            if callback:
                callback(progress, "Web crawling complete")
            
            # 4. DNS analysis
            if callback:
                progress = 90
                callback(progress, "Performing DNS analysis…")
            
            self.analyze_dns(hostname, callback)
            
            # 5. SSL/TLS analysis
            if callback:
                progress = 95
                callback(progress, "Analyzing SSL/TLS configuration…")
            
            self.analyze_ssl_tls(hostname, callback)
            
            progress = 98
            if callback:
                callback(progress, "Finalizing results")
            
            # Update final statistics
            self.scan_results['stats']['urls_scanned'] = len(self.visited_urls)
            self.scan_results['stats']['total_vulnerabilities'] = len(self.scan_results['vulnerabilities'])
            # Add external tool results to report
            self.scan_results['external_tools'] = external_results
            
            if callback:
                callback(100, f"Scan completed. Found {len(self.scan_results['vulnerabilities'])} potential vulnerabilities.")
            
            return self.scan_results
            
        except Exception as e:
            error_msg = f"Error during scan: {str(e)}"
            logger.error(error_msg)
            if callback:
                callback(None, error_msg)
            self.scan_results['error'] = error_msg
            return self.scan_results
    
    def get_server_info(self, url, callback=None):
        """Get basic server information from headers"""
        try:
            response = requests.get(url, timeout=10, allow_redirects=True, verify=False)
            headers = response.headers
            
            self.scan_results['server_info'] = {
                'server': headers.get('Server', 'Not disclosed'),
                'x_powered_by': headers.get('X-Powered-By', 'Not disclosed'),
                'content_type': headers.get('Content-Type', 'Not disclosed'),
            }
            
            # Check security headers
            security_headers = {
                'Strict-Transport-Security': headers.get('Strict-Transport-Security', 'Missing'),
                'Content-Security-Policy': headers.get('Content-Security-Policy', 'Missing'),
                'X-Content-Type-Options': headers.get('X-Content-Type-Options', 'Missing'),
                'X-Frame-Options': headers.get('X-Frame-Options', 'Missing'),
                'X-XSS-Protection': headers.get('X-XSS-Protection', 'Missing'),
                'Referrer-Policy': headers.get('Referrer-Policy', 'Missing'),
                'Permissions-Policy': headers.get('Permissions-Policy', 'Missing'),
            }
            
            self.scan_results['security_headers'] = security_headers
            
            # Add vulnerabilities for missing security headers
            for header, value in security_headers.items():
                if value == 'Missing':
                    self.add_vulnerability(
                        title=f"Missing {header} Header",
                        description=f"The {header} security header is missing. This header helps protect against various attacks.",
                        severity="Medium",
                        type="Missing Headers",
                        url=url
                    )
            
            if callback:
                callback(None, f"Server information gathered: {headers.get('Server', 'Not disclosed')}")
            
        except Exception as e:
            logger.error(f"Error getting server info: {str(e)}")
            if callback:
                callback(None, f"Error getting server info: {str(e)}")
    
    def scan_ports(self, hostname, callback=None):
        """Perform port scanning using sockets instead of nmap"""
        try:
            if callback:
                callback(None, f"Scanning common ports on {hostname}...")
            
            # Common ports to scan
            common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 3389, 5432, 8080, 8443]
            open_ports = []
            
            # Get IP address
            try:
                ip_address = socket.gethostbyname(hostname)
                if callback:
                    callback(None, f"Resolved {hostname} to {ip_address}")
            except socket.gaierror:
                if callback:
                    callback(None, f"Could not resolve hostname: {hostname}")
                return
            
            # Scan ports
            for port in common_ports:
                try:
                    # Create socket
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)  # 1 second timeout
                    
                    # Try to connect
                    result = sock.connect_ex((ip_address, port))
                    if result == 0:  # Port is open
                        service_name = self.get_service_name(port)
                        port_result = {
                            'port': port,
                            'protocol': 'tcp',
                            'state': 'open',
                            'service': service_name,
                            'product': '',
                            'version': ''
                        }
                        open_ports.append(port_result)
                        self.scan_results['open_ports'].append(port_result)
                        
                        if callback:
                            callback(None, f"Port {port}/tcp is open - {service_name}")
                        
                        # Check for potentially risky services
                        high_risk_ports = {
                            21: "FTP service might transmit credentials in plaintext",
                            23: "Telnet service transmits all data in plaintext",
                            3389: "Remote Desktop Protocol should be restricted to trusted IPs",
                            3306: "MySQL database port should not be publicly exposed"
                        }
                        
                        medium_risk_ports = {
                            22: "SSH port exposed. Ensure it's properly secured",
                            25: "SMTP port exposed. Could be used for email spoofing if not secured",
                            5432: "PostgreSQL database port should be restricted"
                        }
                        
                        if port in high_risk_ports:
                            self.add_vulnerability(
                                title=f"Potentially Risky Port {port} ({service_name}) Exposed",
                                description=high_risk_ports[port],
                                severity="High",
                                type="Port Security",
                                url=f"{hostname}:{port}"
                            )
                        
                        elif port in medium_risk_ports:
                            self.add_vulnerability(
                                title=f"Security Consideration for Port {port} ({service_name})",
                                description=medium_risk_ports[port],
                                severity="Medium",
                                type="Port Security",
                                url=f"{hostname}:{port}"
                            )
                    
                    sock.close()
                except Exception as e:
                    if callback:
                        callback(None, f"Error scanning port {port}: {str(e)}")
            
            if callback:
                callback(None, f"Port scan completed. Found {len(open_ports)} open ports.")
                
        except Exception as e:
            logger.error(f"Error during port scan: {str(e)}")
            if callback:
                callback(None, f"Error during port scan: {str(e)}")
    
    def get_service_name(self, port):
        """Get the service name for a port number"""
        common_services = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            143: "IMAP",
            443: "HTTPS",
            465: "SMTPS",
            587: "SMTP (Submission)",
            993: "IMAPS",
            995: "POP3S",
            3306: "MySQL",
            3389: "RDP",
            5432: "PostgreSQL",
            8080: "HTTP-Proxy",
            8443: "HTTPS-Alt"
        }
        return common_services.get(port, "Unknown")
    
    def analyze_dns(self, hostname, callback=None):
        """Analyze DNS records for security issues"""
        try:
            if callback:
                callback(None, f"Analyzing DNS records for {hostname}...")
            
            dns_records = {}
            record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME']
            
            for record_type in record_types:
                try:
                    answers = dns.resolver.resolve(hostname, record_type)
                    records = [str(answer) for answer in answers]
                    dns_records[record_type] = records
                    
                    if callback:
                        callback(None, f"Found {len(records)} {record_type} records")
                    
                except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
                    dns_records[record_type] = []
                except Exception as e:
                    logger.error(f"Error resolving {record_type} records: {str(e)}")
            
            self.scan_results['dns_records'] = dns_records
            
            # Check SPF and DMARC records
            try:
                txt_records = dns_records.get('TXT', [])
                spf_record = None
                dmarc_record = None
                
                for record in txt_records:
                    if record.startswith('v=spf1'):
                        spf_record = record
                
                try:
                    dmarc_answers = dns.resolver.resolve(f"_dmarc.{hostname}", 'TXT')
                    for record in dmarc_answers:
                        record_text = record.to_text().strip('"')
                        if record_text.startswith('v=DMARC1'):
                            dmarc_record = record_text
                except Exception:
                    pass
                
                # Check SPF policy
                if not spf_record:
                    self.add_vulnerability(
                        title="Missing SPF Record",
                        description="No SPF (Sender Policy Framework) record found. SPF helps prevent email spoofing.",
                        severity="Medium",
                        type="DNS Security",
                        url=hostname
                    )
                
                # Check DMARC policy
                if not dmarc_record:
                    self.add_vulnerability(
                        title="Missing DMARC Record",
                        description="No DMARC (Domain-based Message Authentication, Reporting & Conformance) record found. DMARC helps prevent email spoofing and phishing.",
                        severity="Medium",
                        type="DNS Security",
                        url=hostname
                    )
                
            except Exception as e:
                logger.error(f"Error checking SPF/DMARC: {str(e)}")
            
            if callback:
                callback(None, "DNS analysis completed")
                
        except Exception as e:
            logger.error(f"Error during DNS analysis: {str(e)}")
            if callback:
                callback(None, f"Error during DNS analysis: {str(e)}")
    
    def analyze_ssl_tls(self, hostname, callback=None):
        """Analyze SSL/TLS configuration"""
        try:
            if callback:
                callback(None, f"Analyzing SSL/TLS configuration for {hostname}...")
            
            try:
                # Try to establish a connection using specific protocols
                ssl_versions = {
                    'SSLv23': ssl.PROTOCOL_TLS,  # Negotiates highest protocol, effectively SSLv2, SSLv3, TLS
                    'TLSv1': ssl.PROTOCOL_TLSv1,
                }
                
                # Check for newer protocols based on Python version
                if hasattr(ssl, 'PROTOCOL_TLSv1_1'):
                    ssl_versions['TLSv1.1'] = ssl.PROTOCOL_TLSv1_1
                if hasattr(ssl, 'PROTOCOL_TLSv1_2'):
                    ssl_versions['TLSv1.2'] = ssl.PROTOCOL_TLSv1_2
                if hasattr(ssl, 'PROTOCOL_TLSv1_3'):
                    ssl_versions['TLSv1.3'] = ssl.PROTOCOL_TLSv1_3
                
                supported_protocols = {}
                for protocol_name, protocol_const in ssl_versions.items():
                    try:
                        context = ssl.SSLContext(protocol_const)
                        conn = context.wrap_socket(socket.socket(socket.AF_INET))
                        conn.connect((hostname, 443))
                        conn.close()
                        supported_protocols[protocol_name] = True
                    except Exception:
                        supported_protocols[protocol_name] = False
                
                # Check certificate info
                context = ssl.create_default_context()
                conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=hostname)
                conn.connect((hostname, 443))
                cert = conn.getpeercert()
                conn.close()
                
                # Extract certificate details
                cert_info = {
                    'subject': dict(item[0] for item in cert['subject']),
                    'issuer': dict(item[0] for item in cert['issuer']),
                    'version': cert['version'],
                    'notBefore': cert['notBefore'],
                    'notAfter': cert['notAfter'],
                    'serialNumber': cert['serialNumber'],
                    'SANS': [san[1] for san in cert.get('subjectAltName', []) if san[0].lower() == 'dns'],
                }
                
                # Store SSL/TLS results
                self.scan_results['ssl_tls'] = {
                    'supported_protocols': supported_protocols,
                    'certificate': cert_info
                }
                
                # Check for vulnerabilities
                if supported_protocols.get('SSLv23', False) and not (supported_protocols.get('TLSv1.2', False) or supported_protocols.get('TLSv1.3', False)):
                    self.add_vulnerability(
                        title="Outdated SSL/TLS Protocols",
                        description="The server supports outdated SSL/TLS protocols. Modern applications should only support TLS 1.2 and above.",
                        severity="High",
                        type="SSL/TLS Security",
                        url=f"https://{hostname}"
                    )
                
                # Check certificate expiration
                import datetime
                expiry_date = ssl.cert_time_to_seconds(cert['notAfter'])
                current_time = time.time()
                days_to_expiry = (expiry_date - current_time) / (24 * 60 * 60)
                
                if days_to_expiry < 0:
                    self.add_vulnerability(
                        title="Expired SSL Certificate",
                        description="The SSL certificate has expired. This will cause browsers to display security warnings.",
                        severity="Critical",
                        type="SSL/TLS Security",
                        url=f"https://{hostname}"
                    )
                elif days_to_expiry < 15:
                    self.add_vulnerability(
                        title="SSL Certificate Expiring Soon",
                        description=f"The SSL certificate will expire in {int(days_to_expiry)} days. Renew the certificate to avoid disruption.",
                        severity="High",
                        type="SSL/TLS Security",
                        url=f"https://{hostname}"
                    )
                
                if callback:
                    callback(None, "SSL/TLS analysis completed")
                
            except Exception as e:
                # Site might not support HTTPS
                logger.error(f"Error analyzing SSL/TLS: {str(e)}")
                self.add_vulnerability(
                    title="No HTTPS Support",
                    description="The server does not support HTTPS or has an invalid SSL/TLS configuration. All websites should use HTTPS to encrypt data in transit.",
                    severity="High",
                    type="SSL/TLS Security",
                    url=f"http://{hostname}"
                )
        
        except Exception as e:
            logger.error(f"Error during SSL/TLS analysis: {str(e)}")
            if callback:
                callback(None, f"Error during SSL/TLS analysis: {str(e)}")
    
    def crawl_and_scan(self, base_url, max_depth=2, scan_options=None, threads=3, timeout=10, callback=None):
        """Crawl website and scan for vulnerabilities"""
        self.discovered_urls.add(base_url)
        
        # Default scan options
        if scan_options is None:
            scan_options = ["XSS", "SQL Injection", "CSRF", "Security Headers"]
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            # Submit the base URL to start crawling
            futures = {executor.submit(self.process_url, base_url, 0, max_depth, scan_options, timeout, callback)}
            
            while futures and not self.stop_scan:
                # Wait for the next future to complete
                done, futures = concurrent.futures.wait(
                    futures, return_when=concurrent.futures.FIRST_COMPLETED
                )
                
                for future in done:
                    try:
                        new_urls = future.result()
                        if new_urls and not self.stop_scan:
                            for url, depth in new_urls:
                                if url not in self.discovered_urls and depth <= max_depth:
                                    self.discovered_urls.add(url)
                                    futures.add(executor.submit(
                                        self.process_url, url, depth, max_depth, scan_options, timeout, callback
                                    ))
                    except Exception as e:
                        logger.error(f"Error processing URL: {str(e)}")
    
    def process_url(self, url, current_depth, max_depth, scan_options, timeout, callback=None):
        """Process a single URL - crawl and scan for vulnerabilities"""
        if url in self.visited_urls or self.stop_scan or current_depth > max_depth:
            return []
        
        try:
            if callback:
                callback(None, f"Scanning URL: {url}")
            
            self.visited_urls.add(url)
            
            # Make request to the URL
            response = requests.get(
                url, 
                timeout=timeout, 
                allow_redirects=True, 
                verify=False, 
                headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
            )
            
            if response.status_code != 200:
                return []
            
            # Process response for vulnerabilities
            self.scan_url_for_vulnerabilities(url, response, scan_options, callback)
            
            # If we're at max depth, don't extract more links
            if current_depth >= max_depth:
                return []
            
            # Extract links for further crawling
            soup = BeautifulSoup(response.text, 'html.parser')
            new_urls = []
            
            for link in soup.find_all('a', href=True):
                href = link.get('href')
                if not href:
                    continue
                
                # Normalize URL
                full_url = urljoin(url, href)
                
                # Skip URLs outside the target domain or with fragments
                base_domain = urlparse(url).netloc
                link_domain = urlparse(full_url).netloc
                
                if base_domain != link_domain:
                    continue
                
                # Remove fragments
                full_url = full_url.split('#')[0]
                
                if full_url not in self.discovered_urls and full_url not in self.visited_urls:
                    new_urls.append((full_url, current_depth + 1))
            
            return new_urls
            
        except Exception as e:
            logger.error(f"Error processing URL {url}: {str(e)}")
            return []
    
    def scan_url_for_vulnerabilities(self, url, response, scan_options, callback=None):
        """Scan a URL for various vulnerabilities based on scan options"""
        try:
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Check for reflective XSS vulnerabilities
            if "XSS" in scan_options:
                # Look for places where URL parameters are reflected in the page
                parsed_url = urlparse(url)
                query_params = parsed_url.query.split('&')
                
                for param in query_params:
                    if '=' in param:
                        name, value = param.split('=', 1)
                        if value and value in response.text:
                            # Check if the value appears in a potentially vulnerable context
                            if f'>{value}<' in response.text or f'"{value}"' in response.text or f"'{value}'" in response.text:
                                self.add_vulnerability(
                                    title="Potential Reflective XSS",
                                    description=f"The URL parameter '{name}' is reflected in the page response without proper encoding. This might allow cross-site scripting attacks.",
                                    severity="High",
                                    type="XSS",
                                    url=url
                                )
                                if callback:
                                    callback(None, f"Found potential XSS in parameter '{name}' at {url}")
            
            # Check for SQL Injection vectors
            if "SQL Injection" in scan_options:
                # Look for forms that might be vulnerable to SQL injection
                forms = soup.find_all('form')
                self.scan_results['stats']['forms_analyzed'] += len(forms)
                
                for form in forms:
                    form_action = form.get('action', '')
                    form_method = form.get('method', 'get').lower()
                    form_url = urljoin(url, form_action) if form_action else url
                    
                    input_fields = form.find_all(['input', 'textarea'])
                    input_names = [field.get('name', '') for field in input_fields if field.get('name')]
                    
                    if input_names:
                        self.add_vulnerability(
                            title="Potential SQL Injection Point",
                            description=f"Form with fields {', '.join(input_names)} might be vulnerable to SQL injection. Manual testing is recommended.",
                            severity="Medium",
                            type="SQL Injection",
                            url=form_url
                        )
                        if callback:
                            callback(None, f"Potential SQL injection point found in form at {form_url}")
            
            # Check for CSRF vulnerabilities
            if "CSRF" in scan_options:
                forms = soup.find_all('form')
                
                for form in forms:
                    # Check if the form has a CSRF token
                    has_csrf_token = False
                    
                    # Common CSRF token field names
                    csrf_fields = ['csrf', 'token', 'csrf_token', '_token', 'csrf-token', 'xsrf', 'xsrf_token', 'authenticity_token']
                    
                    for field in form.find_all('input', type='hidden'):
                        field_name = field.get('name', '').lower()
                        if any(csrf_name in field_name for csrf_name in csrf_fields):
                            has_csrf_token = True
                            break
                    
                    if not has_csrf_token and form.get('method', '').lower() in ['post', 'put', 'delete']:
                        self.add_vulnerability(
                            title="Potential CSRF Vulnerability",
                            description="Form does not appear to implement CSRF protection. This could allow attackers to trick users into submitting unauthorized actions.",
                            severity="Medium",
                            type="CSRF",
                            url=url
                        )
                        if callback:
                            callback(None, f"Potential CSRF vulnerability found in form at {url}")
            
            # Check for open redirects
            if any(attr in scan_options for attr in ["Open Redirect", "Security Headers"]):
                links = soup.find_all('a', href=True)
                
                for link in links:
                    href = link.get('href', '')
                    if 'redirecturl=' in href or 'redirect=' in href or 'next=' in href or 'return=' in href:
                        self.add_vulnerability(
                            title="Potential Open Redirect",
                            description=f"The link contains a redirect parameter which might be manipulated: {href}",
                            severity="Medium",
                            type="Open Redirect",
                            url=url
                        )
                        if callback:
                            callback(None, f"Potential open redirect found in link at {url}")
        
        except Exception as e:
            logger.error(f"Error scanning URL {url} for vulnerabilities: {str(e)}")
    
    def add_vulnerability(self, title, description, severity, type, url):
        """Add a vulnerability to the results"""
        vuln_id = len(self.scan_results['vulnerabilities']) + 1
        
        vulnerability = {
            'id': vuln_id,
            'title': title,
            'description': description,
            'severity': severity,
            'type': type,
            'url': url,
            'discovered_at': time.strftime("%Y-%m-%d %H:%M:%S")
        }
        
        # Check for duplicates (avoid reporting the same issue multiple times)
        for existing_vuln in self.scan_results['vulnerabilities']:
            if (existing_vuln['title'] == title and 
                existing_vuln['url'] == url and 
                existing_vuln['type'] == type):
                return  # Skip adding this duplicate
        
        self.scan_results['vulnerabilities'].append(vulnerability)

# Initialize scanner (singleton pattern)
scanner = SecurityScanner()

def scan_website(target_url, scan_depth=2, scan_options=None, threads=3, timeout=10, callback=None):
    """Public function to scan a website"""
    return scanner.scan_target(target_url, scan_depth, scan_options, threads, timeout, callback)

def stop_current_scan():
    """Stop any running scan"""
    scanner.stop_scan = True
    return True

def get_last_scan_results():
    """Get results from the last scan"""
    return scanner.scan_results 