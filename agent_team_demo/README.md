# 🔍 Security Scanner & AI Agent Dashboard

A comprehensive web security scanning dashboard with AI agent capabilities. This tool allows you to:

1. Scan websites for security vulnerabilities
2. Detect missing security headers and common web vulnerabilities
3. Generate detailed security reports
4. Interact with an AI agent to analyze security issues and get recommendations

## 📋 Features

### Security Scanner
- Configurable scan depth and target URL
- Detection of missing security headers
- Vulnerability scanning (XSS, SQL Injection, CSRF)
- Detailed scan logs and results
- Vulnerability filtering by severity

### AI Agent
- Ask security-related questions
- Request automated scans with analysis
- Get remediation recommendations
- Learn about web security best practices

## 🚀 Getting Started

### Prerequisites
- Python 3.8+
- pip (Python package manager)

### Installation

1. Clone the repository
```bash
git clone <repository-url>
cd agent_team_demo
```

2. Install dependencies
```bash
pip install -r requirements.txt
```

3. Set up environment variables
```bash
# Copy the example environment file
cp .env.example .env

# Edit the .env file with your API keys
# You'll need an OpenAI API key for AI features
```

### Usage

1. Run the dashboard
```bash
streamlit run security_dashboard.py
```

2. Open your browser at http://localhost:8502

3. Enter a target URL and configure scan options

4. Click "Start Scan" to begin scanning

5. View results in the "Scan Results" tab

6. Use the "AI Agent" tab to ask questions or request analysis

## 🧩 Modules

- **Security Scanner**: Scans websites for vulnerabilities
- **Results Dashboard**: Displays scan results and vulnerabilities
- **Report Generator**: Creates security reports
- **AI Agent**: Provides intelligent security analysis and recommendations

## ⚠️ Disclaimer

This tool is intended for security professionals and should only be used on websites you have permission to scan. Unauthorized scanning may be illegal in some jurisdictions.

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details. 