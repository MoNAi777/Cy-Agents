"""🔍 Web Scanner Agent - A specialized agent for scanning websites for vulnerabilities

This agent uses website tools and reasoning to analyze websites for common security vulnerabilities.
It can be used standalone or added to the Bug Bounty Hunter Team.

Run `pip install agno openai duckduckgo-search` to install dependencies.
"""

import os
import sys
from textwrap import dedent

# Handle OpenAI version compatibility
try:
    from agno.agent import Agent
    from agno.models.openai import OpenAIChat
    from agno.tools.reasoning import ReasoningTools
    from agno.tools.website import WebsiteTools
    from agno.tools.spider import SpiderTools
    from agno.tools.duckduckgo import DuckDuckGoTools
except ImportError as e:
    print(f"Error importing Agno modules: {e}")
    print("Please make sure you have Agno and compatible OpenAI version installed.")
    print("Try running: pip install agno openai==1.13.0")
    sys.exit(1)

# Create the Web Scanner Agent
web_scanner_agent = Agent(
    name="Web Scanner Agent",
    role="Scan websites for security vulnerabilities",
    model=OpenAIChat(id="gpt-4o"),
    tools=[
        ReasoningTools(add_instructions=True),
        WebsiteTools(),
        SpiderTools(),
        DuckDuckGoTools(),
    ],
    instructions=dedent("""\
        You are an expert in web security scanning. 🕸️
        
        Your responsibilities:
        1. Analyze websites for security vulnerabilities
        2. Identify common security issues such as:
           - Missing security headers
           - Insecure cookies
           - Mixed content
           - Outdated software/frameworks
           - Exposed sensitive files
           - Open directories
           - Information disclosure
        3. Use the spider tool to discover endpoints
        4. Verify findings and avoid false positives
        5. Provide detailed explanations of each vulnerability
        
        Process for each website:
        1. Start by fetching and analyzing the main page
        2. Look for information leakage in HTML comments and response headers
        3. Check for security headers and secure cookie settings
        4. Use the spider to discover additional endpoints
        5. Research the technology stack for known vulnerabilities
        6. Document everything thoroughly
        
        Organize your findings by severity (Critical, High, Medium, Low).
        For each finding, include:
        - Description
        - Evidence
        - Impact
        - Remediation steps
    """),
    show_tool_calls=True,
    markdown=True,
)

# Example usage:
if __name__ == "__main__":
    # Make sure to set your API key
    if not os.getenv("OPENAI_API_KEY"):
        print("Please set your OPENAI_API_KEY environment variable first.")
        print("Example: export OPENAI_API_KEY=your-key-here")
        exit(1)
        
    target = input("Enter the website URL to scan: ")
    prompt = f"Scan {target} for security vulnerabilities. Focus on passive reconnaissance only."
    
    print(f"\n🔍 Starting security scan for: {target}\n")
    web_scanner_agent.print_response(prompt, stream=True) 