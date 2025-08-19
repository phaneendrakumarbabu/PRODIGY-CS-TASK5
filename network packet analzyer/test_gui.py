#!/usr/bin/env python3
"""
Test Script for GUI Components
==============================

This script tests the GUI components to ensure they work correctly.
"""

import sys
import importlib

def test_tkinter():
    """Test if tkinter is available."""
    try:
        import tkinter as tk
        root = tk.Tk()
        root.withdraw()  # Hide the test window
        root.destroy()
        print("✅ Tkinter is working correctly")
        return True
    except ImportError as e:
        print(f"❌ Tkinter import error: {e}")
        return False
    except Exception as e:
        print(f"❌ Tkinter test failed: {e}")
        return False

def test_matplotlib():
    """Test if matplotlib is available."""
    try:
        import matplotlib.pyplot as plt
        from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
        from matplotlib.figure import Figure
        print("✅ Matplotlib is working correctly")
        return True
    except ImportError as e:
        print(f"❌ Matplotlib import error: {e}")
        return False

def test_scientific_libraries():
    """Test scientific libraries."""
    libraries = [
        ('numpy', 'NumPy'),
        ('pandas', 'Pandas'),
        ('scipy', 'SciPy'),
        ('sklearn', 'Scikit-learn'),
        ('seaborn', 'Seaborn'),
        ('PIL', 'Pillow'),
        ('scapy', 'Scapy')
    ]
    
    all_working = True
    for module_name, display_name in libraries:
        try:
            if module_name == 'PIL':
                from PIL import Image
            else:
                importlib.import_module(module_name)
            print(f"✅ {display_name} is working correctly")
        except ImportError as e:
            print(f"❌ {display_name} import error: {e}")
            all_working = False
    
    return all_working

def test_gui_imports():
    """Test if GUI modules can be imported."""
    try:
        # Test importing the GUI module
        import packet_analyzer_gui
        print("✅ GUI module can be imported")
        return True
    except ImportError as e:
        print(f"❌ GUI module import error: {e}")
        return False
    except Exception as e:
        print(f"❌ GUI module test failed: {e}")
        return False

def test_scientific_analysis():
    """Test if scientific analysis module can be imported."""
    try:
        import scientific_analysis
        print("✅ Scientific analysis module can be imported")
        return True
    except ImportError as e:
        print(f"❌ Scientific analysis module import error: {e}")
        return False
    except Exception as e:
        print(f"❌ Scientific analysis module test failed: {e}")
        return False

def main():
    """Run all GUI tests."""
    print("🧪 GUI Component Tests")
    print("=" * 40)
    
    tests = [
        ("Tkinter Test", test_tkinter),
        ("Matplotlib Test", test_matplotlib),
        ("Scientific Libraries Test", test_scientific_libraries),
        ("GUI Module Test", test_gui_imports),
        ("Scientific Analysis Test", test_scientific_analysis)
    ]
    
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        print(f"\n📋 Running {test_name}...")
        try:
            if test_func():
                passed += 1
            else:
                print(f"❌ {test_name} failed")
        except Exception as e:
            print(f"❌ {test_name} failed with exception: {e}")
    
    print(f"\n{'='*40}")
    print(f"📊 Test Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All GUI tests passed! You can run the scientific GUI.")
        print("\n💻 To run the GUI:")
        print("   python packet_analyzer_gui.py")
    else:
        print("⚠️  Some tests failed. Please check the errors above.")
        print("\n🔧 Troubleshooting:")
        print("   • Install missing dependencies: pip install -r requirements_gui.txt")
        print("   • For tkinter issues, install system packages:")
        print("     Ubuntu/Debian: sudo apt-get install python3-tk")
        print("     CentOS/RHEL: sudo yum install tkinter")
        print("     macOS: brew install python-tk")
    
    return passed == total

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1) 