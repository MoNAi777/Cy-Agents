"""🔍 Enhanced Bug Bounty Team - Adding a Web Scanner to the team

This example shows how to enhance the Bug Bounty Hunter Team by adding the Web Scanner Agent,
creating a more comprehensive security testing team.

Run `pip install agno openai duckduckgo-search` to install dependencies.
"""

import os
import sys
from textwrap import dedent

# Handle OpenAI version compatibility
try:
    from agno.models.openai import OpenAIChat
    from agno.team import Team

    # Import the agents from their respective files
    from bug_bounty_team import recon_agent, vuln_scanner_agent, exploit_agent, report_agent
    from web_scanner_agent import web_scanner_agent
except ImportError as e:
    print(f"Error importing Agno modules: {e}")
    print("Please make sure you have Agno and compatible OpenAI version installed.")
    print("Try running: pip install agno openai==1.13.0")
    sys.exit(1)

# Create the Enhanced Bug Bounty Team
enhanced_team = Team(
    name="Enhanced Bug Bounty Team",
    members=[recon_agent, web_scanner_agent, vuln_scanner_agent, exploit_agent, report_agent],
    model=OpenAIChat(id="gpt-4o"),
    mode="coordinate",
    success_criteria=dedent("""\
        A comprehensive security report that identifies vulnerabilities through both
        code analysis and web scanning, demonstrates proof of concepts, and provides 
        clear remediation steps.
    """),
    instructions=dedent("""\
        You are the coordinator of an elite bug bounty hunting team with enhanced web scanning capabilities. 🏆
        
        Your responsibilities:
        1. Understand the target system from the user's description
        2. Coordinate the team's activities in a logical sequence:
           - Start with reconnaissance to gather general information
           - Use the Web Scanner Agent to perform detailed web analysis
           - Move to vulnerability scanning of code and systems
           - Proceed to exploit testing
           - End with report generation
        3. Ensure information flows properly between team members
        4. Focus the team on high-value security concerns
        5. Deliver a comprehensive final report
        
        Process guidelines:
        - Begin by clarifying the scope with the user if needed
        - Have team members work in a logical sequence for most efficient workflow
        - Allow concurrent work when appropriate (e.g., recon and web scanning can happen in parallel)
        - Summarize key findings after each agent completes their work
        - Allow agents to request clarification from each other
        - Deliver a final comprehensive report that combines all findings
        
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
    prompt = f"Find security vulnerabilities in {target}. Perform both code analysis and web scanning."
    
    print(f"\n🔍 Starting enhanced security analysis for: {target}\n")
    enhanced_team.print_response(prompt, stream=True) 