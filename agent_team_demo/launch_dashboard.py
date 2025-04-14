"""
Launch the Bug Bounty Hunter Dashboard with proper error handling.
This script makes it easier to identify and fix issues when running the dashboard.
"""

import os
import sys
import subprocess
import importlib.metadata

def check_dependencies():
    """Check if all required dependencies are installed."""
    try:
        import streamlit
        import openai
        import agno
        print("✅ All core dependencies are installed")
        
        # Check OpenAI version
        print(f"🔍 OpenAI version: {openai.__version__}")
        if openai.__version__ != "1.73.0":
            print(f"⚠️ Warning: You're using OpenAI version {openai.__version__}, but version 1.73.0 is recommended.")
            print("   You may encounter compatibility issues.")
            
        # Check Agno version
        try:
            agno_version = importlib.metadata.version("agno")
            print(f"🔍 Agno version: {agno_version}")
        except importlib.metadata.PackageNotFoundError:
            print("⚠️ Warning: Could not determine Agno version.")
        
        return True
    except ImportError as e:
        print(f"❌ Missing dependency: {e}")
        print("Please run: pip install -r requirements.txt")
        return False

def run_dashboard(file_name="simple_dashboard.py"):
    """Run the specified dashboard file."""
    try:
        print(f"🚀 Launching {file_name}...")
        process = subprocess.Popen(
            ["streamlit", "run", file_name],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        
        # Print initial output
        print(f"Dashboard should be running at http://localhost:8501")
        print("If the browser doesn't open automatically, please visit the URL manually")
        print("Press Ctrl+C to stop the dashboard")
        
        # Return the process so it can continue running
        return process
    except Exception as e:
        print(f"❌ Error: {e}")
        return None

if __name__ == "__main__":
    print("🔍 Bug Bounty Hunter Dashboard Launcher 🔍")
    print("This script will help launch the dashboard with proper error handling.")
    print("-" * 60)
    
    if not check_dependencies():
        sys.exit(1)
    
    print("-" * 60)
    print("Options:")
    print("1. Run simple dashboard (no agent logic)")
    print("2. Run full dashboard (with agent logic)")
    print("3. Exit")
    
    choice = input("Enter your choice (1-3): ")
    
    if choice == "1":
        process = run_dashboard("simple_dashboard.py")
    elif choice == "2":
        process = run_dashboard("dashboard.py")
    else:
        print("Exiting...")
        sys.exit(0)
    
    if process:
        try:
            # Keep the script running until user interrupts
            process.wait()
        except KeyboardInterrupt:
            process.terminate()
            print("\nDashboard stopped.") 