"""
Professional Security Report Tab for Security Dashboard
This module provides a professional report tab that can be imported into the security dashboard.
"""

import streamlit as st
import json
import time
from datetime import datetime

def render_report_tab(tab):
    """Render the professional security report tab"""
    with tab:
        st.markdown("### 📊 Professional Security Assessment Report")
        
        # Only show detailed report if scan results exist
        if st.session_state.scan_results and st.session_state.report_path:
            data = st.session_state.scan_results
            
            # Executive Summary section
            with st.expander("📋 Executive Summary", expanded=True):
                st.markdown("""
                <div class="card">
                    <h3>Executive Summary</h3>
                    <p>This security assessment report details the findings from an automated web security scan. The assessment identifies security vulnerabilities, misconfigurations, and areas of concern, along with recommendations for remediation.</p>
                    
                    <div style='margin-top: 20px;'>
                        <h4>Key Findings</h4>
                        <ul>
                """, unsafe_allow_html=True)
                
                vuln_count = st.session_state.vulnerability_count
                total_vulns = sum(vuln_count.values())
                
                critical_count = vuln_count.get('critical', 0)
                high_count = vuln_count.get('high', 0)
                medium_count = vuln_count.get('medium', 0)
                
                # Summary based on findings
                if critical_count > 0:
                    st.markdown(f"<li><span class='critical'>{critical_count} Critical severity</span> vulnerabilities requiring immediate attention</li>", unsafe_allow_html=True)
                
                if high_count > 0:
                    st.markdown(f"<li><span class='high'>{high_count} High severity</span> vulnerabilities requiring prompt remediation</li>", unsafe_allow_html=True)
                
                if medium_count > 0:
                    st.markdown(f"<li><span class='medium'>{medium_count} Medium severity</span> vulnerabilities that should be addressed</li>", unsafe_allow_html=True)
                
                if total_vulns == 0:
                    st.markdown("<li>No significant vulnerabilities were detected during this scan</li>", unsafe_allow_html=True)
                
                # Security headers section
                missing_headers = False
                for vuln in data.get('vulnerabilities', []):
                    if 'header' in vuln.get('name', '').lower():
                        missing_headers = True
                        break
                
                if missing_headers:
                    st.markdown("<li>Missing critical security headers that could expose the application to various attacks</li>", unsafe_allow_html=True)
                
                st.markdown("""
                        </ul>
                    </div>
                    
                    <div style='margin-top: 20px;'>
                        <h4>Risk Assessment</h4>
                """, unsafe_allow_html=True)
                
                # Overall risk assessment
                if critical_count > 0:
                    risk_level = "Critical"
                    risk_color = "critical"
                    risk_description = "Immediate action required. The identified vulnerabilities pose an imminent risk of compromise."
                elif high_count > 0:
                    risk_level = "High"
                    risk_color = "high"
                    risk_description = "Prompt remediation needed. The identified vulnerabilities could lead to significant security breaches."
                elif medium_count > 0:
                    risk_level = "Medium"
                    risk_color = "medium"
                    risk_description = "Remediation recommended. The identified vulnerabilities present moderate security risks."
                elif total_vulns > 0:
                    risk_level = "Low"
                    risk_color = "low"
                    risk_description = "Low priority issues identified. These vulnerabilities present minimal security risks."
                else:
                    risk_level = "Informational"
                    risk_color = "info"
                    risk_description = "No significant security issues were identified during this assessment."
                
                st.markdown(f"""
                        <p>Overall Risk: <span class='{risk_color}'>{risk_level}</span></p>
                        <p>{risk_description}</p>
                    </div>
                </div>
                """, unsafe_allow_html=True)
            
            # Scope and Methodology
            with st.expander("🔍 Scope and Methodology"):
                target_url = data.get('target_url', 'N/A')
                scan_time = data.get('scan_time', 'N/A')
                
                st.markdown(f"""
                <div class="card">
                    <h3>Scope and Methodology</h3>
                    
                    <div style='margin-top: 20px;'>
                        <h4>Assessment Scope</h4>
                        <ul>
                            <li><strong>Target URL:</strong> {target_url}</li>
                            <li><strong>Assessment Date:</strong> {scan_time}</li>
                            <li><strong>Assessment Type:</strong> Automated Web Security Scan</li>
                        </ul>
                    </div>
                    
                    <div style='margin-top: 20px;'>
                        <h4>Methodology</h4>
                        <p>This assessment was conducted using the following methodology:</p>
                        <ol>
                            <li><strong>Reconnaissance:</strong> Information gathering about the target system</li>
                            <li><strong>Vulnerability Scanning:</strong> Automated scanning for common web vulnerabilities</li>
                            <li><strong>Security Header Analysis:</strong> Checking for properly implemented security headers</li>
                            <li><strong>Input Validation Testing:</strong> Testing for XSS, SQL Injection, and other input-based vulnerabilities</li>
                            <li><strong>Configuration Analysis:</strong> Identifying security misconfigurations</li>
                        </ol>
                    </div>
                    
                    <div style='margin-top: 20px;'>
                        <h4>Tools Utilized</h4>
                        <ul>
                            <li>Custom Web Security Scanner</li>
                            <li>HTTP Header Analyzer</li>
                            <li>Content Security Policy Evaluator</li>
                            <li>SSL/TLS Configuration Analyzer</li>
                        </ul>
                    </div>
                </div>
                """, unsafe_allow_html=True)
            
            # Detailed Findings
            with st.expander("🔎 Detailed Findings", expanded=True):
                vulns = data.get('vulnerabilities', [])
                if vulns:
                    # Group vulnerabilities by severity for better organization
                    severity_order = ["Critical", "High", "Medium", "Low", "Info"]
                    grouped_vulns = {}
                    
                    for severity in severity_order:
                        severity_vulns = [v for v in vulns if v.get('severity', '') == severity]
                        if severity_vulns:
                            grouped_vulns[severity] = severity_vulns
                    
                    for severity, severity_vulns in grouped_vulns.items():
                        st.markdown(f"<h3 class='{severity.lower()}'>{severity} Severity Findings</h3>", unsafe_allow_html=True)
                        
                        for i, vuln in enumerate(severity_vulns):
                            vuln_name = vuln.get('name', 'Unknown Vulnerability')
                            vuln_desc = vuln.get('description', 'No description available')
                            vuln_url = vuln.get('url', 'N/A')
                            vuln_evidence = vuln.get('evidence', 'No evidence provided')
                            vuln_remediation = vuln.get('remediation', 'No remediation advice available')
                            
                            st.markdown(f"""
                            <div class="card card-{severity.lower()}">
                                <h4>{i+1}. {vuln_name}</h4>
                                
                                <div style='margin-top: 15px;'>
                                    <h5>Description</h5>
                                    <p>{vuln_desc}</p>
                                </div>
                                
                                <div style='margin-top: 15px;'>
                                    <h5>Affected URL</h5>
                                    <p><code>{vuln_url}</code></p>
                                </div>
                                
                                <div style='margin-top: 15px;'>
                                    <h5>Evidence</h5>
                                    <p><pre style='background-color: rgba(0,0,0,0.1); padding: 10px; border-radius: 5px;'>{vuln_evidence}</pre></p>
                                </div>
                                
                                <div style='margin-top: 15px;'>
                                    <h5>Remediation</h5>
                                    <p>{vuln_remediation}</p>
                                </div>
                            </div>
                            """, unsafe_allow_html=True)
                else:
                    st.info("No vulnerabilities were identified during this assessment.")
            
            # Recommendations
            with st.expander("📝 Recommendations"):
                st.markdown("""
                <div class="card">
                    <h3>Recommendations</h3>
                    
                    <div style='margin-top: 20px;'>
                        <h4>Prioritized Remediation Plan</h4>
                """, unsafe_allow_html=True)
                
                # Generate recommendations based on findings
                recommendations = []
                
                # Check for critical and high severity issues
                has_critical = any(v.get('severity') == 'Critical' for v in data.get('vulnerabilities', []))
                has_high = any(v.get('severity') == 'High' for v in data.get('vulnerabilities', []))
                
                # Check for specific vulnerability types
                has_sql = any('sql' in v.get('name', '').lower() for v in data.get('vulnerabilities', []))
                has_xss = any('xss' in v.get('name', '').lower() for v in data.get('vulnerabilities', []))
                has_missing_headers = any('header' in v.get('name', '').lower() for v in data.get('vulnerabilities', []))
                
                if has_critical:
                    recommendations.append("""
                    <div style='margin-bottom: 15px;'>
                        <h5>1. Address Critical Vulnerabilities Immediately</h5>
                        <p>Critical vulnerabilities should be remediated immediately as they present an imminent security risk:</p>
                        <ul>
                            <li>Implement emergency patches or configuration changes</li>
                            <li>Consider temporary measures to mitigate risk until permanent fixes are in place</li>
                            <li>Verify fixes with follow-up targeted testing</li>
                        </ul>
                    </div>
                    """)
                
                if has_sql:
                    recommendations.append("""
                    <div style='margin-bottom: 15px;'>
                        <h5>2. Fix SQL Injection Vulnerabilities</h5>
                        <p>SQL injection vulnerabilities can lead to data breaches and must be addressed promptly:</p>
                        <ul>
                            <li>Use parameterized queries or prepared statements</li>
                            <li>Implement input validation and sanitization</li>
                            <li>Apply the principle of least privilege to database accounts</li>
                            <li>Consider using an ORM (Object-Relational Mapping) framework</li>
                        </ul>
                    </div>
                    """)
                
                if has_xss:
                    recommendations.append("""
                    <div style='margin-bottom: 15px;'>
                        <h5>3. Remediate Cross-Site Scripting (XSS) Vulnerabilities</h5>
                        <p>XSS vulnerabilities allow attackers to inject malicious scripts:</p>
                        <ul>
                            <li>Implement proper output encoding for all user-supplied content</li>
                            <li>Use Content-Security-Policy headers to restrict script execution</li>
                            <li>Sanitize user input before processing or storage</li>
                            <li>Consider using modern frameworks with built-in XSS protections</li>
                        </ul>
                    </div>
                    """)
                
                if has_missing_headers:
                    recommendations.append("""
                    <div style='margin-bottom: 15px;'>
                        <h5>4. Implement Missing Security Headers</h5>
                        <p>Security headers provide an additional layer of protection against various attacks:</p>
                        <ul>
                            <li>Add Strict-Transport-Security (HSTS) to enforce HTTPS</li>
                            <li>Implement Content-Security-Policy to mitigate XSS risks</li>
                            <li>Add X-Content-Type-Options with "nosniff" to prevent MIME-type sniffing</li>
                            <li>Set X-Frame-Options to prevent clickjacking attacks</li>
                            <li>Enable X-XSS-Protection as an additional layer of XSS protection</li>
                        </ul>
                    </div>
                    """)
                
                # General security best practices
                recommendations.append("""
                <div style='margin-bottom: 15px;'>
                    <h5>5. General Security Improvements</h5>
                    <p>Implement these security best practices to improve overall security posture:</p>
                    <ul>
                        <li>Establish a regular security testing program</li>
                        <li>Keep all software components and dependencies updated</li>
                        <li>Implement proper authentication and authorization controls</li>
                        <li>Maintain security logs and implement monitoring</li>
                        <li>Develop and practice an incident response plan</li>
                    </ul>
                </div>
                """)
                
                # Display recommendations
                for recommendation in recommendations:
                    st.markdown(recommendation, unsafe_allow_html=True)
                
                st.markdown("""
                    </div>
                </div>
                """, unsafe_allow_html=True)
            
            # Export options
            st.markdown("### Export Report")
            
            report_format = st.selectbox(
                "Report Format",
                ["PDF Report", "HTML Report", "JSON Report", "Executive Summary (PDF)"]
            )
            
            col1, col2 = st.columns([3, 1])
            with col1:
                company_name = st.text_input("Company Name (Optional)", placeholder="Enter company name for report branding")
            with col2:
                include_evidence = st.checkbox("Include Technical Evidence", value=True)
            
            if st.button("Generate Report", type="primary"):
                with st.spinner(f"Generating {report_format}..."):
                    # Simulate report generation
                    time.sleep(2)
                    
                    # For JSON, we already have the file
                    if report_format == "JSON Report":
                        with open(st.session_state.report_path, "r") as f:
                            report_data = f.read()
                            
                        st.download_button(
                            label="Download JSON Report",
                            data=report_data,
                            file_name=f"security_report_{datetime.now().strftime('%Y%m%d')}.json",
                            mime="application/json"
                        )
                        st.success("JSON Report generated successfully!")
                    else:
                        # Simulate other report formats
                        st.success(f"{report_format} generated successfully!")
                        st.info(f"This is a simulated report download. In a production environment, this would generate a properly formatted {report_format.split(' ')[0]} report.")
                        
                        # Provide a sample download button
                        if report_format == "HTML Report":
                            # Create a simple HTML report
                            html_content = f"""
                            <html>
                            <head>
                                <title>Security Assessment Report - {datetime.now().strftime('%Y-%m-%d')}</title>
                                <style>
                                    body {{ font-family: Arial, sans-serif; margin: 40px; }}
                                    h1 {{ color: #003366; }}
                                    h2 {{ color: #0055a4; margin-top: 30px; }}
                                    .critical {{ color: #d9534f; }}
                                    .high {{ color: #f0ad4e; }}
                                    .medium {{ color: #ffd700; }}
                                    .low {{ color: #5cb85c; }}
                                    .info {{ color: #5bc0de; }}
                                    .finding {{ border-left: 4px solid #ccc; padding: 10px; margin: 20px 0; }}
                                    .critical-finding {{ border-left-color: #d9534f; }}
                                    .high-finding {{ border-left-color: #f0ad4e; }}
                                    .medium-finding {{ border-left-color: #ffd700; }}
                                    .low-finding {{ border-left-color: #5cb85c; }}
                                </style>
                            </head>
                            <body>
                                <h1>Security Assessment Report</h1>
                                <p><strong>Target:</strong> {data.get('target_url', 'N/A')}</p>
                                <p><strong>Date:</strong> {datetime.now().strftime('%Y-%m-%d')}</p>
                                <p><strong>Prepared for:</strong> {company_name if company_name else 'Client'}</p>
                                
                                <h2>Executive Summary</h2>
                                <p>This report presents the findings of a security assessment conducted on {data.get('target_url', 'N/A')}.</p>
                                <!-- More report content would be here in a real implementation -->
                            </body>
                            </html>
                            """
                            
                            st.download_button(
                                label="Download HTML Report",
                                data=html_content,
                                file_name=f"security_report_{datetime.now().strftime('%Y%m%d')}.html",
                                mime="text/html"
                            )
        else:
            # Show a message when no scan has been run
            st.info("No scan results available. Run a security scan first to generate a report.")
            
            # Sample report preview
            st.markdown("### Sample Report Preview")
            st.image("https://cdn.dribbble.com/users/1544818/screenshots/8059934/media/7814da35f9f2b8e58bb8bc20b319fcc6.png", use_column_width=True) 