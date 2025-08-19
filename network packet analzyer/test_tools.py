#!/usr/bin/env python3
"""
Test Script for Network Packet Analyzer Tools
=============================================

This script tests the functionality of the network packet analyzer tools
to ensure they're working correctly for educational purposes.
"""

import sys
import importlib
import subprocess

def test_imports():
    """Test if all required modules can be imported."""
    print("🔍 Testing imports...")
    
    modules_to_test = [
        ('scapy', 'Scapy network library'),
        ('datetime', 'Python datetime module'),
        ('argparse', 'Python argparse module'),
        ('logging', 'Python logging module'),
        ('collections', 'Python collections module'),
        ('socket', 'Python socket module'),
        ('threading', 'Python threading module'),
        ('time', 'Python time module'),
        ('random', 'Python random module')
    ]
    
    failed_imports = []
    
    for module_name, description in modules_to_test:
        try:
            importlib.import_module(module_name)
            print(f"✅ {description}")
        except ImportError as e:
            print(f"❌ {description}: {e}")
            failed_imports.append(module_name)
    
    if failed_imports:
        print(f"\n❌ Failed to import: {', '.join(failed_imports)}")
        return False
    else:
        print("✅ All imports successful!")
        return True

def test_scapy_functionality():
    """Test basic Scapy functionality."""
    print("\n🔍 Testing Scapy functionality...")
    
    try:
        from scapy.all import IP, ICMP, get_if_list
        
        # Test basic packet creation
        packet = IP(dst="127.0.0.1")/ICMP()
        print("✅ Basic packet creation")
        
        # Test interface listing
        interfaces = get_if_list()
        print(f"✅ Interface listing ({len(interfaces)} interfaces found)")
        
        # Test packet parsing
        raw_packet = bytes(packet)
        parsed = IP(raw_packet)
        print("✅ Packet parsing")
        
        return True
    except Exception as e:
        print(f"❌ Scapy functionality test failed: {e}")
        return False

def test_script_execution():
    """Test if the main scripts can be executed (without actually running them)."""
    print("\n🔍 Testing script execution...")
    
    scripts_to_test = [
        ('packet_analyzer.py', 'Packet Analyzer'),
        ('packet_generator.py', 'Packet Generator'),
        ('network_education.py', 'Network Education'),
        ('setup.py', 'Setup Script')
    ]
    
    failed_scripts = []
    
    for script_name, description in scripts_to_test:
        try:
            # Try to compile the script
            with open(script_name, 'r', encoding='utf-8') as f:
                code = f.read()
            
            # Basic syntax check
            compile(code, script_name, 'exec')
            print(f"✅ {description} - Syntax OK")
            
        except Exception as e:
            print(f"❌ {description} - {e}")
            failed_scripts.append(script_name)
    
    if failed_scripts:
        print(f"\n❌ Failed scripts: {', '.join(failed_scripts)}")
        return False
    else:
        print("✅ All scripts have valid syntax!")
        return True

def test_help_commands():
    """Test help commands for the main tools."""
    print("\n🔍 Testing help commands...")
    
    help_commands = [
        (['python', 'packet_analyzer.py', '--help'], 'Packet Analyzer Help'),
        (['python', 'packet_generator.py', '--help'], 'Packet Generator Help')
    ]
    
    failed_help = []
    
    for cmd, description in help_commands:
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                print(f"✅ {description}")
            else:
                print(f"❌ {description} - Exit code: {result.returncode}")
                failed_help.append(description)
        except Exception as e:
            print(f"❌ {description} - {e}")
            failed_help.append(description)
    
    if failed_help:
        print(f"\n❌ Failed help commands: {', '.join(failed_help)}")
        return False
    else:
        print("✅ All help commands work!")
        return True

def test_educational_content():
    """Test the educational content script."""
    print("\n🔍 Testing educational content...")
    
    try:
        # Import the educational module
        import network_education
        
        # Test basic functionality
        educator = network_education.NetworkEducator()
        
        # Check if topics are available
        if hasattr(educator, 'topics') and len(educator.topics) > 0:
            print("✅ Educational topics available")
        else:
            print("❌ No educational topics found")
            return False
        
        # Test a specific topic
        if hasattr(educator, 'explain_tcp'):
            print("✅ TCP explanation method available")
        else:
            print("❌ TCP explanation method not found")
            return False
        
        return True
    except Exception as e:
        print(f"❌ Educational content test failed: {e}")
        return False

def run_comprehensive_test():
    """Run all tests and provide a summary."""
    print("🧪 COMPREHENSIVE TEST SUITE")
    print("=" * 50)
    
    tests = [
        ("Import Tests", test_imports),
        ("Scapy Functionality", test_scapy_functionality),
        ("Script Execution", test_script_execution),
        ("Help Commands", test_help_commands),
        ("Educational Content", test_educational_content)
    ]
    
    results = []
    
    for test_name, test_func in tests:
        print(f"\n📋 Running {test_name}...")
        try:
            result = test_func()
            results.append((test_name, result))
        except Exception as e:
            print(f"❌ {test_name} failed with exception: {e}")
            results.append((test_name, False))
    
    # Summary
    print("\n" + "=" * 50)
    print("📊 TEST SUMMARY")
    print("=" * 50)
    
    passed = 0
    total = len(results)
    
    for test_name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{test_name:25} {status}")
        if result:
            passed += 1
    
    print(f"\nOverall: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed! Your network packet analyzer tools are ready to use.")
        print("\n💡 Next steps:")
        print("   1. Run: python setup.py")
        print("   2. Learn: python network_education.py")
        print("   3. Analyze: python packet_analyzer.py")
        print("   4. Generate: python packet_generator.py")
    else:
        print("⚠️  Some tests failed. Please check the errors above.")
        print("\n🔧 Troubleshooting:")
        print("   • Ensure Python 3.7+ is installed")
        print("   • Run: pip install -r requirements.txt")
        print("   • Check file permissions")
    
    return passed == total

def main():
    """Main test function."""
    try:
        success = run_comprehensive_test()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n\n⏹️  Testing interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Test suite failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main() 