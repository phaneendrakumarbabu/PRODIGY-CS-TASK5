#!/usr/bin/env python3
"""
Packet Generator - Educational Tool
==================================

This tool generates test packets for educational purposes.
It helps students understand packet structure and network protocols.

ETHICAL USE WARNING:
- Only use on networks you own or have permission to test
- Do not generate malicious packets
- This tool is for educational purposes only
"""

import sys
import time
import argparse
from scapy.all import *
import random
import socket

class PacketGenerator:
    def __init__(self, target_ip=None, target_port=None):
        """
        Initialize the packet generator.
        
        Args:
            target_ip (str): Target IP address for generated packets
            target_port (int): Target port for generated packets
        """
        self.target_ip = target_ip or "127.0.0.1"
        self.target_port = target_port or 80
        self.packet_count = 0
        
        # Display ethical warning
        self.display_ethical_warning()
    
    def display_ethical_warning(self):
        """Display ethical use warning."""
        warning = """
╔══════════════════════════════════════════════════════════════════════════════╗
║                        PACKET GENERATOR WARNING                              ║
╠══════════════════════════════════════════════════════════════════════════════╣
║                                                                              ║
║  This tool is for EDUCATIONAL PURPOSES ONLY!                               ║
║                                                                              ║
║  ✅ DO:                                                                     ║
║     • Use on networks you own or have permission to test                   ║
║     • Use for learning packet structure and protocols                      ║
║     • Test your own systems only                                           ║
║                                                                              ║
║  ❌ DON'T:                                                                  ║
║     • Generate malicious or harmful packets                                ║
║     • Target systems without permission                                    ║
║     • Use for network attacks                                              ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
        """
        print(warning)
        
        # Ask for confirmation
        response = input("Do you agree to use this tool ethically? (yes/no): ").lower().strip()
        if response not in ['yes', 'y']:
            print("Exiting. Please ensure ethical use before running this tool.")
            sys.exit(0)
    
    def generate_tcp_packet(self, src_ip=None, src_port=None, payload=None):
        """
        Generate a TCP packet for educational purposes.
        
        Args:
            src_ip (str): Source IP address
            src_port (int): Source port
            payload (str): Packet payload
            
        Returns:
            Packet: Generated TCP packet
        """
        if src_ip is None:
            src_ip = f"192.168.1.{random.randint(1, 254)}"
        if src_port is None:
            src_port = random.randint(1024, 65535)
        if payload is None:
            payload = f"Educational packet #{self.packet_count + 1} - {time.strftime('%H:%M:%S')}"
        
        # Create TCP packet
        packet = IP(src=src_ip, dst=self.target_ip) / \
                TCP(sport=src_port, dport=self.target_port) / \
                Raw(load=payload)
        
        return packet
    
    def generate_udp_packet(self, src_ip=None, src_port=None, payload=None):
        """
        Generate a UDP packet for educational purposes.
        
        Args:
            src_ip (str): Source IP address
            src_port (int): Source port
            payload (str): Packet payload
            
        Returns:
            Packet: Generated UDP packet
        """
        if src_ip is None:
            src_ip = f"192.168.1.{random.randint(1, 254)}"
        if src_port is None:
            src_port = random.randint(1024, 65535)
        if payload is None:
            payload = f"UDP Educational packet #{self.packet_count + 1}"
        
        # Create UDP packet
        packet = IP(src=src_ip, dst=self.target_ip) / \
                UDP(sport=src_port, dport=self.target_port) / \
                Raw(load=payload)
        
        return packet
    
    def generate_icmp_packet(self, src_ip=None, payload=None):
        """
        Generate an ICMP packet for educational purposes.
        
        Args:
            src_ip (str): Source IP address
            payload (str): Packet payload
            
        Returns:
            Packet: Generated ICMP packet
        """
        if src_ip is None:
            src_ip = f"192.168.1.{random.randint(1, 254)}"
        if payload is None:
            payload = f"ICMP Educational packet #{self.packet_count + 1}"
        
        # Create ICMP packet
        packet = IP(src=src_ip, dst=self.target_ip) / \
                ICMP() / \
                Raw(load=payload)
        
        return packet
    
    def send_packet(self, packet, verbose=True):
        """
        Send a packet and display information.
        
        Args:
            packet: Scapy packet to send
            verbose (bool): Display detailed information
        """
        self.packet_count += 1
        
        if verbose:
            print(f"\n📤 Sending Packet #{self.packet_count}")
            print(f"   Protocol: {packet.proto if hasattr(packet, 'proto') else 'Unknown'}")
            print(f"   Source: {packet[IP].src if IP in packet else 'Unknown'}")
            print(f"   Destination: {packet[IP].dst if IP in packet else 'Unknown'}")
            
            if TCP in packet:
                print(f"   Source Port: {packet[TCP].sport}")
                print(f"   Destination Port: {packet[TCP].dport}")
            elif UDP in packet:
                print(f"   Source Port: {packet[UDP].sport}")
                print(f"   Destination Port: {packet[UDP].dport}")
            
            if Raw in packet:
                payload = bytes(packet[Raw].load)
                print(f"   Payload: {payload.decode('utf-8', errors='ignore')[:50]}...")
        
        # Send the packet
        try:
            send(packet, verbose=False)
            if verbose:
                print("   ✅ Packet sent successfully")
        except Exception as e:
            print(f"   ❌ Error sending packet: {e}")
    
    def generate_packet_series(self, protocol='tcp', count=10, delay=1.0):
        """
        Generate and send a series of packets.
        
        Args:
            protocol (str): Protocol type ('tcp', 'udp', 'icmp')
            count (int): Number of packets to generate
            delay (float): Delay between packets in seconds
        """
        print(f"\n🚀 Generating {count} {protocol.upper()} packets...")
        print(f"   Target: {self.target_ip}:{self.target_port}")
        print(f"   Delay: {delay} seconds between packets\n")
        
        for i in range(count):
            if protocol.lower() == 'tcp':
                packet = self.generate_tcp_packet()
            elif protocol.lower() == 'udp':
                packet = self.generate_udp_packet()
            elif protocol.lower() == 'icmp':
                packet = self.generate_icmp_packet()
            else:
                print(f"❌ Unknown protocol: {protocol}")
                return
            
            self.send_packet(packet)
            
            if i < count - 1:  # Don't delay after the last packet
                time.sleep(delay)
        
        print(f"\n✅ Generated {count} {protocol.upper()} packets successfully!")
    
    def demonstrate_protocols(self):
        """Demonstrate different protocols for educational purposes."""
        print("\n🎓 PROTOCOL DEMONSTRATION")
        print("=" * 50)
        
        protocols = [
            ('tcp', 'Transmission Control Protocol - Connection-oriented'),
            ('udp', 'User Datagram Protocol - Connectionless'),
            ('icmp', 'Internet Control Message Protocol - Network diagnostics')
        ]
        
        for protocol, description in protocols:
            print(f"\n📚 {description}")
            print(f"   Generating 3 {protocol.upper()} packets...")
            
            for i in range(3):
                if protocol == 'tcp':
                    packet = self.generate_tcp_packet()
                elif protocol == 'udp':
                    packet = self.generate_udp_packet()
                elif protocol == 'icmp':
                    packet = self.generate_icmp_packet()
                
                self.send_packet(packet, verbose=False)
                time.sleep(0.5)
            
            print(f"   ✅ {protocol.upper()} demonstration complete")
        
        print(f"\n🎉 Protocol demonstration complete! Generated {self.packet_count} packets total.")

def main():
    """Main function to run the packet generator."""
    parser = argparse.ArgumentParser(
        description="Packet Generator - Educational Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python packet_generator.py                           # Basic TCP packets
  python packet_generator.py -p udp -c 5              # 5 UDP packets
  python packet_generator.py -t 192.168.1.100         # Custom target
  python packet_generator.py --demo                    # Protocol demonstration
  python packet_generator.py -p icmp -d 0.5           # ICMP with 0.5s delay
        """
    )
    
    parser.add_argument('-p', '--protocol', 
                       choices=['tcp', 'udp', 'icmp'],
                       default='tcp',
                       help='Protocol to generate (default: tcp)')
    parser.add_argument('-c', '--count', type=int, default=10,
                       help='Number of packets to generate (default: 10)')
    parser.add_argument('-t', '--target', default='127.0.0.1',
                       help='Target IP address (default: 127.0.0.1)')
    parser.add_argument('--port', type=int, default=80,
                       help='Target port (default: 80)')
    parser.add_argument('-d', '--delay', type=float, default=1.0,
                       help='Delay between packets in seconds (default: 1.0)')
    parser.add_argument('--demo', action='store_true',
                       help='Run protocol demonstration')
    
    args = parser.parse_args()
    
    try:
        # Create packet generator
        generator = PacketGenerator(
            target_ip=args.target,
            target_port=args.port
        )
        
        if args.demo:
            # Run protocol demonstration
            generator.demonstrate_protocols()
        else:
            # Generate packet series
            generator.generate_packet_series(
                protocol=args.protocol,
                count=args.count,
                delay=args.delay
            )
        
    except PermissionError:
        print("\n❌ ERROR: Permission denied. This tool requires administrator/root privileges.")
        print("Please run with elevated permissions:")
        print("  Windows: Run as Administrator")
        print("  Linux/Mac: Use 'sudo python packet_generator.py'")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ ERROR: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main() 