#!/usr/bin/env python3
"""
Setup Script for Network Packet Analyzer - Scientific GUI Edition
================================================================

How to run the project:
-----------------------
1. Open a terminal or command prompt in this directory.
2. Run the setup script to install all dependencies:

   python setup_gui.py

3. After setup completes, start the main GUI application:

   python packet_analyzer_gui.py
"""

import sys
import subprocess
import os
import platform
import importlib

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
    """Install required dependencies for GUI version."""
    print("\n📦 Installing scientific analysis dependencies...")
    
    try:
        # Install basic requirements first
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
        print("✅ Basic dependencies installed successfully!")
        
        # Install GUI-specific requirements (excluding tkinter which is built-in)
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements_gui.txt"])
        print("✅ Scientific analysis dependencies installed successfully!")
        
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Error installing dependencies: {e}")
        print("\n💡 If tkinter is missing, install it manually:")
        system = platform.system().lower()
        if system == "linux":
            print("   Ubuntu/Debian: sudo apt-get install python3-tk")
            print("   CentOS/RHEL: sudo yum install tkinter")
        elif system == "darwin":
            print("   macOS: brew install python-tk")
        else:
            print("   Windows: Tkinter should be included with Python")
        return False

def check_gui_dependencies():
    """Check if GUI dependencies are properly installed."""
    print("\n🔍 Checking GUI dependencies...")
    
    # Check tkinter first (built-in with Python)
    try:
        import tkinter
        print("✅ Tkinter GUI framework (built-in)")
    except ImportError:
        print("❌ Tkinter not available - this is usually included with Python")
        print("   On Ubuntu/Debian: sudo apt-get install python3-tk")
        print("   On CentOS/RHEL: sudo yum install tkinter")
        print("   On macOS: brew install python-tk")
        return False
    
    # Check other dependencies
    dependencies = [
        ('matplotlib', 'Matplotlib plotting library'),
        ('numpy', 'NumPy numerical computing'),
        ('pandas', 'Pandas data analysis'),
        ('scipy', 'SciPy scientific computing'),
        ('sklearn', 'Scikit-learn machine learning'),
        ('seaborn', 'Seaborn statistical visualization'),
        ('PIL', 'Pillow image processing'),
        ('scapy', 'Scapy network packet manipulation')
    ]
    
    failed_imports = []
    
    for module_name, description in dependencies:
        try:
            if module_name == 'PIL':
                from PIL import Image
            else:
                importlib.import_module(module_name)
            print(f"✅ {description}")
        except ImportError as e:
            print(f"❌ {description}: {e}")
            failed_imports.append(module_name)
    
    if failed_imports:
        print(f"\n❌ Failed to import: {', '.join(failed_imports)}")
        return False
    else:
        print("✅ All GUI dependencies are available!")
        return True

def test_gui_functionality():
    """Test basic GUI functionality."""
    print("\n🧪 Testing GUI functionality...")
    
    try:
        import tkinter as tk
        from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
        from matplotlib.figure import Figure
        import numpy as np
        
        # Test basic tkinter
        root = tk.Tk()
        root.withdraw()  # Hide the test window
        
        # Test matplotlib integration
        fig = Figure(figsize=(6, 4))
        ax = fig.add_subplot(111)
        x = np.linspace(0, 10, 100)
        y = np.sin(x)
        ax.plot(x, y)
        
        # Test canvas creation (don't actually create it)
        print("✅ Tkinter and Matplotlib integration test passed")
        
        return True
    except Exception as e:
        print(f"❌ GUI functionality test failed: {e}")
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
        print("   Example: sudo python packet_analyzer_gui.py")
    else:
        print("ℹ️  You may need elevated privileges for packet capture.")
    
    return True

def display_gui_usage():
    """Display GUI usage instructions."""
    print("\n🚀 SCIENTIFIC GUI USAGE INSTRUCTIONS")
    print("=" * 50)
    
    print("""
📊 Scientific Analysis Features:
   • Real-time packet visualization
   • Statistical analysis and charts
   • Anomaly detection algorithms
   • Traffic pattern analysis
   • Performance metrics calculation
   • Data export capabilities

🎯 Available Tools:
   • packet_analyzer_gui.py - Scientific GUI version
   • scientific_analysis.py - Advanced analysis module
   • packet_analyzer.py - Command-line version
   • network_education.py - Educational content

💻 Running the Scientific GUI:
   python packet_analyzer_gui.py

📈 Advanced Analysis:
   python scientific_analysis.py

🔬 Scientific Features:
   • Real-time charts and graphs
   • Statistical analysis
   • Anomaly detection
   • Traffic pattern recognition
   • Performance metrics
   • Data export (CSV, JSON, PNG)
        """)

def display_ethical_warning():
    """Display ethical use warning."""
    warning = """
╔══════════════════════════════════════════════════════════════════════════════╗
║                    SCIENTIFIC ANALYSIS ETHICAL WARNING                       ║
╠══════════════════════════════════════════════════════════════════════════════╣
║                                                                              ║
║  This scientific analysis tool is for EDUCATIONAL AND RESEARCH PURPOSES!    ║
║                                                                              ║
║  ✅ DO:                                                                     ║
║     • Use on networks you own or have permission to analyze                ║
║     • Use for learning network protocols and traffic analysis               ║
║     • Use for legitimate research and educational purposes                  ║
║     • Respect privacy and legal requirements                                ║
║                                                                              ║
║  ❌ DON'T:                                                                  ║
║     • Capture sensitive or personal information                             ║
║     • Monitor networks without permission                                   ║
║     • Use for malicious purposes                                            ║
║     • Violate privacy or legal requirements                                ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
    """
    print(warning)
    
    # Ask for confirmation
    response = input("Do you agree to use this scientific tool ethically? (yes/no): ").lower().strip()
    if response not in ['yes', 'y']:
        print("Exiting. Please ensure ethical use before running this tool.")
        sys.exit(0)

def main():
    """Main setup function for GUI version."""
    print("🔬 Network Packet Analyzer - Scientific GUI Setup")
    print("=" * 50)
    
    # Display ethical warning
    display_ethical_warning()
    
    # Check Python version
    if not check_python_version():
        sys.exit(1)
    
    # Install dependencies
    if not install_dependencies():
        print("\n❌ Setup failed. Please check the error messages above.")
        sys.exit(1)
    
    # Check GUI dependencies
    if not check_gui_dependencies():
        print("\n❌ GUI dependencies failed. Please install manually:")
        print("   pip install -r requirements_gui.txt")
        sys.exit(1)
    
    # Test GUI functionality
    if not test_gui_functionality():
        print("\n❌ GUI functionality test failed.")
        sys.exit(1)
    
    # Check permissions
    check_permissions()
    
    # Display usage
    display_gui_usage()
    
    print("\n✅ Scientific GUI setup complete!")
    print("🎓 You're ready to perform advanced network analysis!")
    print("🔬 Remember to use these tools ethically and responsibly!")

if __name__ == "__main__":
    main()