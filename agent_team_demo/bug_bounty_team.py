"""🐞 Bug Bounty Hunter Team - A team of specialized agents for finding security vulnerabilities

This team consists of four specialized agents working together to find and report security vulnerabilities:
1. Reconnaissance Agent: Gathers information about the target system
2. Vulnerability Scanner Agent: Identifies potential vulnerabilities
3. Exploit Testing Agent: Tests and validates security issues
4. Report Generator Agent: Creates professional security reports

Run `pip install agno openai duckduckgo-search` to install dependencies.
"""

import os
import sys
from textwrap import dedent
from pathlib import Path

# Load environment variables from .env file
env_path = Path(__file__).parent / '.env'
if env_path.exists():
    with open(env_path) as f:
        for line in f:
            if line.strip() and not line.startswith('#'):
                key, value = line.strip().split('=', 1)
                os.environ[key] = value

# Check for GitHub token
if not os.getenv("GITHUB_ACCESS_TOKEN"):
    print("\n⚠️ Error: GitHub access token is required")
    print("Please check that your .env file exists and contains GITHUB_ACCESS_TOKEN")
    sys.exit(1)

# Handle OpenAI version compatibility
try:
    from agno.agent import Agent
    from agno.models.openai import OpenAIChat
    from agno.team import Team
    from agno.tools.duckduckgo import DuckDuckGoTools
    from agno.tools.reasoning import ReasoningTools
    from agno.tools.github import GithubTools
    from agno.tools.python import PythonTools
except ImportError as e:
    print(f"Error importing Agno modules: {e}")
    print("Please make sure you have Agno and compatible OpenAI version installed.")
    print("Try running: pip install agno openai==1.13.0")
    sys.exit(1)

# Create the Reconnaissance Agent
recon_agent = Agent(
    name="Reconnaissance Agent",
    role="Gather information about the target system",
    model=OpenAIChat(id="gpt-4-turbo-preview"),
    tools=[
        DuckDuckGoTools(),
        GithubTools(),
    ],
    instructions=dedent("""\
        You are an expert in reconnaissance for security research. 🔍
        
        Your responsibilities:
        1. Gather comprehensive information about the target system
        2. Find public repositories, documentation, and technical information
        3. Identify technologies, frameworks, and libraries used
        4. Look for known security issues in similar systems
        5. Document all findings with sources
        
        Focus on:
        - Technology stack identification
        - Open source repositories
        - Public APIs and endpoints
        - Documentation that reveals architecture
        - Previous vulnerability reports or security concerns
        
        Always cite your sources and explain your reasoning.
    """),
    show_tool_calls=True,
    markdown=True,
)

# Create the Vulnerability Scanner Agent
vuln_scanner_agent = Agent(
    name="Vulnerability Scanner Agent",
    role="Identify potential security vulnerabilities",
    model=OpenAIChat(id="gpt-4-turbo-preview"),
    tools=[
        ReasoningTools(add_instructions=True),
        GithubTools(),
    ],
    instructions=dedent("""\
        You are an expert in identifying security vulnerabilities. 🔒
        
        Your responsibilities:
        1. Analyze reconnaissance data to identify potential vulnerabilities
        2. Look for common vulnerability patterns like:
           - SQL injection
           - XSS vulnerabilities
           - CSRF vulnerabilities
           - Authentication bypass
           - Authorization issues
           - Information leakage
           - API security flaws
           - Input validation issues
        3. Classify vulnerabilities by severity (Critical, High, Medium, Low)
        4. Provide preliminary evidence for each vulnerability
        
        Use your reasoning tools to think through potential attack vectors.
        Be thorough but avoid false positives.
    """),
    show_tool_calls=True,
    markdown=True,
)

# Create the Exploit Testing Agent
exploit_agent = Agent(
    name="Exploit Testing Agent",
    role="Test and validate security vulnerabilities",
    model=OpenAIChat(id="gpt-4-turbo-preview"),
    tools=[
        ReasoningTools(add_instructions=True),
        PythonTools(),
    ],
    instructions=dedent("""\
        You are an expert in validating security vulnerabilities. ⚠️
        
        Your responsibilities:
        1. Review vulnerability findings from the scanner
        2. Design safe proof-of-concept tests for each vulnerability
        3. Write Python code to demonstrate exploits (without causing damage)
        4. Document the exact steps to reproduce each issue
        5. Rate confirmed vulnerabilities on the CVSS scale
        
        Important guidelines:
        - Never suggest destructive tests
        - Always use ethical hacking principles
        - Focus on proof of concept, not actual exploitation
        - Document each test clearly with code examples
        - Explain why each vulnerability matters
        
        Use your reasoning tools to carefully think through the exploits.
    """),
    show_tool_calls=True,
    markdown=True,
)

# Create the Report Generator Agent
report_agent = Agent(
    name="Report Generator Agent",
    role="Create professional security reports",
    model=OpenAIChat(id="gpt-4-turbo-preview"),
    tools=[ReasoningTools(add_instructions=True)],
    instructions=dedent("""\
        You are an expert in security report writing. 📝
        
        Your responsibilities:
        1. Compile findings from all team members into a professional report
        2. Structure the report with Executive Summary, Technical Details, and Remediation
        3. Create clear vulnerability descriptions with:
           - Severity rating
           - Description
           - Proof of concept
           - Potential impact
           - Remediation steps
        4. Include screenshots or code snippets provided by other agents
        5. Prioritize vulnerabilities by risk level
        
        Your reports should be:
        - Professional and clear
        - Technically accurate
        - Actionable with specific remediation steps
        - Free of unnecessary jargon
        - Well-organized with proper formatting
    """),
    show_tool_calls=True,
    markdown=True,
)

# Create the Bug Bounty Team
bug_bounty_team = Team(
    name="Bug Bounty Hunter Team",
    members=[recon_agent, vuln_scanner_agent, exploit_agent, report_agent],
    model=OpenAIChat(id="gpt-4-turbo-preview"),
    mode="coordinate",  # Agents will work together with coordination
    success_criteria=dedent("""\
        A comprehensive security report that identifies vulnerabilities,
        demonstrates proof of concepts, and provides clear remediation steps.
    """),
    instructions=dedent("""\
        You are the coordinator of an elite bug bounty hunting team. 🏆
        
        Your responsibilities:
        1. Understand the target system from the user's description
        2. Coordinate the team's activities in a logical sequence:
           - Start with reconnaissance
           - Move to vulnerability scanning
           - Proceed to exploit testing
           - End with report generation
        3. Ensure information flows properly between team members
        4. Focus the team on high-value security concerns
        5. Deliver a comprehensive final report
        
        Process guidelines:
        - Begin by clarifying the scope with the user if needed
        - Have team members work sequentially for most efficient workflow
        - Summarize key findings after each agent completes their work
        - Allow agents to request clarification from each other
        - Deliver a final comprehensive report
        
        Remember: Security research must be conducted ethically and legally.
        Never suggest activities that could harm systems or violate laws.
    """),
    show_tool_calls=True,
    show_members_responses=True,
    markdown=True,
    enable_agentic_context=True,
)

# Example usage:
if __name__ == "__main__":
    # Make sure to set your API key
    if not os.getenv("OPENAI_API_KEY"):
        print("Please set your OPENAI_API_KEY environment variable first.")
        print("Example: export OPENAI_API_KEY=your-key-here")
        exit(1)
        
    target = input("Enter the target website or repository to analyze: ")
    prompt = f"Find security vulnerabilities in {target}. Focus on common web vulnerabilities."
    
    print(f"\n🔍 Starting security analysis for: {target}\n")
    bug_bounty_team.print_response(prompt, stream=True) 