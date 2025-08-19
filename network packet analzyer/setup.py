#!/usr/bin/env python3
"""
Setup Script for Network Packet Analyzer
========================================

This script helps set up the network packet analyzer tools
for educational purposes.
"""

import sys
import subprocess
import os
import platform

def check_python_version():
    """Check if Python version is compatible."""
    if sys.version_info < (3, 7):
        print("❌ ERROR: Python 3.7 or higher is required.")
        print(f"Current version: {sys.version}")
        return False
    else:
        print(f"✅ Python version: {sys.version.split()[0]}")
        return True

def install_dependencies():
    """Install required dependencies."""
    print("\n📦 Installing dependencies...")
    
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
        print("✅ Dependencies installed successfully!")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Error installing dependencies: {e}")
        return False

def check_scapy():
    """Check if Scapy is properly installed."""
    try:
        import scapy
        print("✅ Scapy is installed and ready to use!")
        return True
    except ImportError:
        print("❌ Scapy is not installed or not working properly.")
        return False

def check_permissions():
    """Check if user has necessary permissions."""
    print("\n🔐 Checking permissions...")
    
    system = platform.system().lower()
    
    if system == "windows":
        print("ℹ️  On Windows, you'll need to run as Administrator for packet capture.")
        print("   Right-click Command Prompt and select 'Run as Administrator'")
    elif system in ["linux", "darwin"]:
        print("ℹ️  On Linux/Mac, you'll need to use 'sudo' for packet capture.")
        print("   Example: sudo python packet_analyzer.py")
    else:
        print("ℹ️  You may need elevated privileges for packet capture.")
    
    return True

def display_usage():
    """Display usage instructions."""
    print("\n🚀 USAGE INSTRUCTIONS")
    print("=" * 50)
    
    print("""
📚 Educational Tool:
   python network_education.py

📦 Packet Analyzer:
   python packet_analyzer.py

📤 Packet Generator (for testing):
   python packet_generator.py

📖 Help for each tool:
   python packet_analyzer.py --help
   python packet_generator.py --help
        """)

def display_ethical_warning():
    """Display ethical use warning."""
    warning = """
╔══════════════════════════════════════════════════════════════════════════════╗
║                           ETHICAL USE WARNING                                ║
╠══════════════════════════════════════════════════════════════════════════════╣
║                                                                              ║
║  These tools are for EDUCATIONAL PURPOSES ONLY!                            ║
║                                                                              ║
║  ✅ DO:                                                                     ║
║     • Use on networks you own or have permission to monitor                ║
║     • Use for learning network protocols and traffic analysis               ║
║     • Respect privacy and legal requirements                                ║
║                                                                              ║
║  ❌ DON'T:                                                                  ║
║     • Capture sensitive or personal information                             ║
║     • Monitor networks without permission                                   ║
║     • Use for malicious purposes                                            ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
    """
    print(warning)

def main():
    """Main setup function."""
    print("🔧 Network Packet Analyzer Setup")
    print("=" * 40)
    
    # Display ethical warning
    display_ethical_warning()
    
    # Check Python version
    if not check_python_version():
        sys.exit(1)
    
    # Install dependencies
    if not install_dependencies():
        print("\n❌ Setup failed. Please check the error messages above.")
        sys.exit(1)
    
    # Check Scapy installation
    if not check_scapy():
        print("\n❌ Scapy installation failed. Please install manually:")
        print("   pip install scapy")
        sys.exit(1)
    
    # Check permissions
    check_permissions()
    
    # Display usage
    display_usage()
    
    print("\n✅ Setup complete! You're ready to learn about network packet analysis.")
    print("Remember to use these tools ethically and responsibly!")

if __name__ == "__main__":
    main() 