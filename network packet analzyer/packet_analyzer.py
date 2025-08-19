#!/usr/bin/env python3
"""
Network Packet Analyzer - Educational Tool
==========================================

This tool is designed for EDUCATIONAL PURPOSES ONLY.
It helps students understand network traffic, protocols, and data flow.

ETHICAL USE WARNING:
- Only use on networks you own or have explicit permission to monitor
- Do not capture sensitive or personal information
- This tool is for learning and educational purposes only
- Respect privacy and legal requirements in your jurisdiction

Author: Educational Network Analysis Tool
Purpose: Network traffic analysis for educational purposes
"""

import sys
import time
import datetime
import argparse
from scapy.all import *
import socket
import threading
import logging
from collections import defaultdict

class PacketAnalyzer:
    def __init__(self, interface=None, output_file=None, verbose=False):
        """
        Initialize the packet analyzer.
        
        Args:
            interface (str): Network interface to capture from
            output_file (str): File to save packet logs
            verbose (bool): Enable verbose output
        """
        self.interface = interface
        self.output_file = output_file
        self.verbose = verbose
        self.packet_count = 0
        self.protocol_stats = defaultdict(int)
        self.is_capturing = False
        
        # Setup logging
        self.setup_logging()
        
        # Display ethical warning
        self.display_ethical_warning()
    
    def setup_logging(self):
        """Setup logging configuration."""
        log_level = logging.DEBUG if self.verbose else logging.INFO
        log_format = '%(asctime)s - %(levelname)s - %(message)s'
        
        logging.basicConfig(
            level=log_level,
            format=log_format,
            handlers=[
                logging.StreamHandler(sys.stdout)
            ]
        )
        
        if self.output_file:
            file_handler = logging.FileHandler(self.output_file)
            file_handler.setFormatter(logging.Formatter(log_format))
            logging.getLogger().addHandler(file_handler)
    
    def display_ethical_warning(self):
        """Display ethical use warning."""
        warning = """
╔══════════════════════════════════════════════════════════════════════════════╗
║                           ETHICAL USE WARNING                                ║
╠══════════════════════════════════════════════════════════════════════════════╣
║                                                                              ║
║  This tool is for EDUCATIONAL PURPOSES ONLY!                               ║
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
║  By using this tool, you agree to use it ethically and responsibly.        ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
        """
        print(warning)
        
        # Ask for confirmation
        response = input("Do you agree to use this tool ethically? (yes/no): ").lower().strip()
        if response not in ['yes', 'y']:
            print("Exiting. Please ensure ethical use before running this tool.")
            sys.exit(0)
    
    def get_interface_info(self):
        """Get available network interfaces."""
        interfaces = get_if_list()
        print("\n📡 Available Network Interfaces:")
        for i, iface in enumerate(interfaces, 1):
            print(f"  {i}. {iface}")
        
        if not self.interface:
            try:
                choice = int(input("\nSelect interface number (or press Enter for default): ").strip() or "1")
                self.interface = interfaces[choice - 1]
            except (ValueError, IndexError):
                self.interface = interfaces[0]
        
        print(f"✅ Selected interface: {self.interface}")
        return self.interface
    
    def extract_packet_info(self, packet):
        """
        Extract key information from a packet.
        
        Args:
            packet: Scapy packet object
            
        Returns:
            dict: Packet information
        """
        info = {
            'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3],
            'protocol': 'Unknown',
            'src_ip': 'Unknown',
            'dst_ip': 'Unknown',
            'src_port': None,
            'dst_port': None,
            'length': len(packet),
            'payload': None
        }
        
        # Extract IP layer information
        if IP in packet:
            info['src_ip'] = packet[IP].src
            info['dst_ip'] = packet[IP].dst
            
            # Determine protocol
            if TCP in packet:
                info['protocol'] = 'TCP'
                info['src_port'] = packet[TCP].sport
                info['dst_port'] = packet[TCP].dport
            elif UDP in packet:
                info['protocol'] = 'UDP'
                info['src_port'] = packet[UDP].sport
                info['dst_port'] = packet[UDP].dport
            elif ICMP in packet:
                info['protocol'] = 'ICMP'
            elif packet[IP].proto == 1:
                info['protocol'] = 'ICMP'
            elif packet[IP].proto == 6:
                info['protocol'] = 'TCP'
            elif packet[IP].proto == 17:
                info['protocol'] = 'UDP'
        
        # Extract payload (first 100 bytes for safety)
        if Raw in packet:
            payload = bytes(packet[Raw].load)
            # Only show printable characters and limit length
            try:
                payload_str = payload.decode('utf-8', errors='ignore')
                # Filter out non-printable characters
                payload_str = ''.join(char for char in payload_str if char.isprintable())
                info['payload'] = payload_str[:100] + ('...' if len(payload_str) > 100 else '')
            except:
                info['payload'] = f"[Binary data: {len(payload)} bytes]"
        
        return info
    
    def display_packet(self, packet_info):
        """
        Display packet information in a formatted way.
        
        Args:
            packet_info (dict): Packet information
        """
        self.packet_count += 1
        self.protocol_stats[packet_info['protocol']] += 1
        
        # Create a formatted display
        display = f"""
{'='*80}
📦 PACKET #{self.packet_count} | {packet_info['timestamp']}
{'='*80}

🔍 Protocol: {packet_info['protocol']}
📏 Length: {packet_info['length']} bytes

🌐 Network Information:
   Source IP:      {packet_info['src_ip']}
   Destination IP: {packet_info['dst_ip']}
"""
        
        if packet_info['src_port'] and packet_info['dst_port']:
            display += f"   Source Port:     {packet_info['src_port']}\n"
            display += f"   Destination Port: {packet_info['dst_port']}\n"
        
        if packet_info['payload']:
            display += f"\n📄 Payload Preview:\n{'-'*40}\n{packet_info['payload']}\n"
        
        display += f"\n📊 Statistics: {dict(self.protocol_stats)}"
        display += f"\n{'='*80}\n"
        
        print(display)
        
        # Log to file if specified
        if self.output_file:
            logging.info(f"Packet #{self.packet_count} - {packet_info['protocol']} - "
                        f"{packet_info['src_ip']}:{packet_info['src_port']} -> "
                        f"{packet_info['dst_ip']}:{packet_info['dst_port']}")
    
    def packet_callback(self, packet):
        """
        Callback function for each captured packet.
        
        Args:
            packet: Scapy packet object
        """
        try:
            packet_info = self.extract_packet_info(packet)
            self.display_packet(packet_info)
        except Exception as e:
            logging.error(f"Error processing packet: {e}")
    
    def start_capture(self, packet_count=None, timeout=None):
        """
        Start capturing packets.
        
        Args:
            packet_count (int): Number of packets to capture (None for unlimited)
            timeout (int): Timeout in seconds (None for unlimited)
        """
        print(f"\n🚀 Starting packet capture on interface: {self.interface}")
        print("Press Ctrl+C to stop capture\n")
        
        self.is_capturing = True
        
        try:
            # Start packet capture
            sniff(
                iface=self.interface,
                prn=self.packet_callback,
                count=packet_count,
                timeout=timeout,
                store=0  # Don't store packets in memory
            )
        except KeyboardInterrupt:
            print("\n\n⏹️  Capture stopped by user")
        except Exception as e:
            logging.error(f"Error during capture: {e}")
        finally:
            self.is_capturing = False
            self.display_final_stats()
    
    def display_final_stats(self):
        """Display final capture statistics."""
        print(f"\n{'='*80}")
        print("📊 FINAL CAPTURE STATISTICS")
        print(f"{'='*80}")
        print(f"Total packets captured: {self.packet_count}")
        print(f"Protocol distribution: {dict(self.protocol_stats)}")
        print(f"Capture duration: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'='*80}\n")

def main():
    """Main function to run the packet analyzer."""
    parser = argparse.ArgumentParser(
        description="Network Packet Analyzer - Educational Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python packet_analyzer.py                    # Basic capture
  python packet_analyzer.py -i eth0           # Specific interface
  python packet_analyzer.py -c 100            # Capture 100 packets
  python packet_analyzer.py -t 60             # Capture for 60 seconds
  python packet_analyzer.py -o capture.log    # Save to log file
  python packet_analyzer.py -v                # Verbose output
        """
    )
    
    parser.add_argument('-i', '--interface', help='Network interface to capture from')
    parser.add_argument('-c', '--count', type=int, help='Number of packets to capture')
    parser.add_argument('-t', '--timeout', type=int, help='Capture timeout in seconds')
    parser.add_argument('-o', '--output', help='Output log file')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    try:
        # Create packet analyzer
        analyzer = PacketAnalyzer(
            interface=args.interface,
            output_file=args.output,
            verbose=args.verbose
        )
        
        # Get interface if not specified
        if not analyzer.interface:
            analyzer.get_interface_info()
        
        # Start capture
        analyzer.start_capture(
            packet_count=args.count,
            timeout=args.timeout
        )
        
    except PermissionError:
        print("\n❌ ERROR: Permission denied. This tool requires administrator/root privileges.")
        print("Please run with elevated permissions:")
        print("  Windows: Run as Administrator")
        print("  Linux/Mac: Use 'sudo python packet_analyzer.py'")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ ERROR: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main() 