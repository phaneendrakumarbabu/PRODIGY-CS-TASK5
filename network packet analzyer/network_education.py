#!/usr/bin/env python3
"""
Network Education Tool
======================

This tool provides educational information about network concepts,
protocols, and packet analysis. It's designed to help students
understand networking fundamentals.

Educational content only - no packet capture or generation.
"""

import sys
import time

class NetworkEducator:
    def __init__(self):
        """Initialize the network educator."""
        self.topics = {
            'osi': 'OSI Model',
            'tcp': 'TCP Protocol',
            'udp': 'UDP Protocol',
            'icmp': 'ICMP Protocol',
            'ip': 'IP Addressing',
            'ports': 'Port Numbers',
            'packets': 'Packet Structure',
            'capture': 'Packet Capture',
            'security': 'Network Security'
        }
    
    def display_welcome(self):
        """Display welcome message and menu."""
        welcome = """
╔══════════════════════════════════════════════════════════════════════════════╗
║                        NETWORK EDUCATION TOOL                                ║
╠══════════════════════════════════════════════════════════════════════════════╣
║                                                                              ║
║  Welcome to the Network Education Tool!                                     ║
║  This tool helps you understand network concepts and protocols.             ║
║                                                                              ║
║  Select a topic to learn more about networking fundamentals.                ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
        """
        print(welcome)
    
    def display_menu(self):
        """Display the main menu."""
        print("\n📚 AVAILABLE TOPICS:")
        print("=" * 50)
        
        for key, topic in self.topics.items():
            print(f"  {key:10} - {topic}")
        
        print("\n💡 SPECIAL OPTIONS:")
        print("  all        - Show all topics")
        print("  quiz       - Take a network quiz")
        print("  exit       - Exit the program")
        print("=" * 50)
    
    def explain_osi_model(self):
        """Explain the OSI model."""
        print("\n🌐 OSI MODEL (Open Systems Interconnection)")
        print("=" * 60)
        
        layers = [
            ("7. Application", "HTTP, FTP, SMTP, DNS - User applications and services"),
            ("6. Presentation", "SSL/TLS, JPEG, MPEG - Data formatting and encryption"),
            ("5. Session", "NetBIOS, RPC - Connection management and synchronization"),
            ("4. Transport", "TCP, UDP - End-to-end communication and reliability"),
            ("3. Network", "IP, ICMP, OSPF - Logical addressing and routing"),
            ("2. Data Link", "Ethernet, WiFi, PPP - Physical addressing and error detection"),
            ("1. Physical", "Cables, hubs, repeaters - Physical transmission of bits")
        ]
        
        for layer, description in layers:
            print(f"\n{layer}")
            print(f"   {description}")
        
        print("\n💡 Key Concept: Each layer serves the layer above it and is served by the layer below it.")
    
    def explain_tcp(self):
        """Explain TCP protocol."""
        print("\n🔗 TCP (Transmission Control Protocol)")
        print("=" * 50)
        
        print("""
📋 Characteristics:
   • Connection-oriented protocol
   • Reliable data delivery
   • Error checking and correction
   • Flow control and congestion control
   • Ordered data transmission

🔄 TCP Handshake (3-way handshake):
   1. Client → SYN → Server
   2. Client ← SYN-ACK ← Server  
   3. Client → ACK → Server

📊 TCP Header Fields:
   • Source Port (16 bits)
   • Destination Port (16 bits)
   • Sequence Number (32 bits)
   • Acknowledgment Number (32 bits)
   • Flags (SYN, ACK, FIN, RST, PSH, URG)
   • Window Size (16 bits)
   • Checksum (16 bits)

🎯 Common TCP Ports:
   • 20, 21 - FTP (File Transfer Protocol)
   • 22 - SSH (Secure Shell)
   • 23 - Telnet
   • 25 - SMTP (Email)
   • 53 - DNS (Domain Name System)
   • 80 - HTTP (Web)
   • 443 - HTTPS (Secure Web)
   • 3306 - MySQL Database
   • 5432 - PostgreSQL Database
        """)
    
    def explain_udp(self):
        """Explain UDP protocol."""
        print("\n📦 UDP (User Datagram Protocol)")
        print("=" * 50)
        
        print("""
📋 Characteristics:
   • Connectionless protocol
   • No guaranteed delivery
   • No error correction
   • Faster than TCP
   • No flow control
   • Unordered data transmission

📊 UDP Header Fields:
   • Source Port (16 bits)
   • Destination Port (16 bits)
   • Length (16 bits)
   • Checksum (16 bits)

🎯 Common UDP Ports:
   • 53 - DNS (Domain Name System)
   • 67, 68 - DHCP (Dynamic Host Configuration)
   • 69 - TFTP (Trivial File Transfer)
   • 123 - NTP (Network Time Protocol)
   • 161, 162 - SNMP (Network Management)
   • 514 - Syslog
   • 1194 - OpenVPN
   • 5353 - mDNS (Multicast DNS)

💡 Use Cases:
   • Real-time applications (video, voice)
   • DNS queries
   • DHCP requests
   • Network monitoring
        """)
    
    def explain_icmp(self):
        """Explain ICMP protocol."""
        print("\n🔍 ICMP (Internet Control Message Protocol)")
        print("=" * 50)
        
        print("""
📋 Purpose:
   • Network diagnostics and error reporting
   • Used by ping and traceroute
   • Reports network problems to hosts

📊 ICMP Message Types:
   • 0 - Echo Reply (ping response)
   • 3 - Destination Unreachable
   • 5 - Redirect
   • 8 - Echo Request (ping request)
   • 11 - Time Exceeded
   • 13 - Timestamp Request
   • 14 - Timestamp Reply

🛠️ Common ICMP Tools:
   • ping - Test connectivity
   • traceroute - Trace network path
   • pathping - Advanced path analysis

⚠️ Security Note:
   • ICMP can be used for network scanning
   • Some firewalls block ICMP
   • Important for network troubleshooting
        """)
    
    def explain_ip_addressing(self):
        """Explain IP addressing."""
        print("\n🌐 IP ADDRESSING")
        print("=" * 50)
        
        print("""
📋 IPv4 Address Structure:
   • 32-bit address (4 bytes)
   • Dotted decimal notation: 192.168.1.1
   • Each octet: 0-255

🏠 IP Address Classes:
   • Class A: 1.0.0.0 - 126.255.255.255 (Default mask: 255.0.0.0)
   • Class B: 128.0.0.0 - 191.255.255.255 (Default mask: 255.255.0.0)
   • Class C: 192.0.0.0 - 223.255.255.255 (Default mask: 255.255.255.0)
   • Class D: 224.0.0.0 - 239.255.255.255 (Multicast)
   • Class E: 240.0.0.0 - 255.255.255.255 (Reserved)

🔒 Private IP Ranges:
   • 10.0.0.0 - 10.255.255.255
   • 172.16.0.0 - 172.31.255.255
   • 192.168.0.0 - 192.168.255.255

🌍 Special Addresses:
   • 127.0.0.1 - Loopback (localhost)
   • 0.0.0.0 - Default route
   • 255.255.255.255 - Broadcast

📏 Subnet Masks:
   • Define network portion vs host portion
   • Example: 255.255.255.0 = /24 (24 network bits)
        """)
    
    def explain_ports(self):
        """Explain port numbers."""
        print("\n🚪 PORT NUMBERS")
        print("=" * 50)
        
        print("""
📋 Port Number Ranges:
   • 0-1023: Well-known ports (privileged)
   • 1024-49151: Registered ports
   • 49152-65535: Dynamic/private ports

🔧 Common Well-Known Ports:
   • 20, 21 - FTP (File Transfer)
   • 22 - SSH (Secure Shell)
   • 23 - Telnet
   • 25 - SMTP (Email sending)
   • 53 - DNS (Domain Name System)
   • 67, 68 - DHCP
   • 80 - HTTP (Web)
   • 110 - POP3 (Email receiving)
   • 143 - IMAP (Email)
   • 443 - HTTPS (Secure Web)
   • 993 - IMAPS (Secure IMAP)
   • 995 - POP3S (Secure POP3)
   • 1433 - Microsoft SQL Server
   • 3306 - MySQL
   • 5432 - PostgreSQL
   • 8080 - Alternative HTTP port

💡 Port States:
   • LISTEN - Service is waiting for connections
   • ESTABLISHED - Active connection
   • TIME_WAIT - Connection closing
   • CLOSED - No connection
        """)
    
    def explain_packets(self):
        """Explain packet structure."""
        print("\n📦 PACKET STRUCTURE")
        print("=" * 50)
        
        print("""
📋 What is a Packet?
   • Unit of data transmitted over a network
   • Contains headers and payload
   • Follows protocol specifications

🏗️ Packet Components:
   • Headers (metadata about the packet)
   • Payload (actual data being transmitted)
   • Trailers (error checking, etc.)

📊 Common Headers:
   • Ethernet Header (Layer 2)
     - Source MAC address
     - Destination MAC address
     - EtherType (protocol identifier)
   
   • IP Header (Layer 3)
     - Source IP address
     - Destination IP address
     - Protocol (TCP/UDP/ICMP)
     - TTL (Time To Live)
     - Flags and options
   
   • TCP/UDP Header (Layer 4)
     - Source port
     - Destination port
     - Sequence numbers (TCP)
     - Checksum

📏 Typical Packet Sizes:
   • Ethernet: 64-1518 bytes
   • IP: 20-60 bytes (header)
   • TCP: 20-60 bytes (header)
   • UDP: 8 bytes (header)
   • Payload: Variable size

🔍 Packet Analysis:
   • Wireshark - GUI packet analyzer
   • tcpdump - Command-line packet capture
   • Scapy - Python packet manipulation
        """)
    
    def explain_capture(self):
        """Explain packet capture concepts."""
        print("\n🎣 PACKET CAPTURE")
        print("=" * 50)
        
        print("""
📋 What is Packet Capture?
   • Monitoring network traffic in real-time
   • Analyzing packet contents and headers
   • Network troubleshooting and security analysis

🛠️ Capture Methods:
   • Promiscuous Mode - Capture all packets on network
   • Monitor Mode - Capture wireless packets
   • Port Mirroring - Copy traffic to analysis port

📊 Capture Tools:
   • Wireshark - GUI packet analyzer
   • tcpdump - Command-line capture
   • Scapy - Python packet manipulation
   • Netcat - Network utility
   • Nmap - Network discovery

🔍 What You Can See:
   • Source and destination addresses
   • Protocol types and ports
   • Packet timing and size
   • Payload contents (if unencrypted)
   • Network conversations

⚠️ Legal and Ethical Considerations:
   • Only capture on networks you own/have permission
   • Don't capture sensitive or personal data
   • Respect privacy and legal requirements
   • Use for educational/authorized purposes only

💡 Educational Benefits:
   • Understand network protocols
   • Learn about data flow
   • Debug network issues
   • Security analysis (authorized)
        """)
    
    def explain_security(self):
        """Explain network security concepts."""
        print("\n🔒 NETWORK SECURITY")
        print("=" * 50)
        
        print("""
🛡️ Security Concepts:
   • Confidentiality - Data privacy
   • Integrity - Data accuracy
   • Availability - Service accessibility

🚨 Common Threats:
   • Packet sniffing - Unauthorized capture
   • Man-in-the-middle attacks
   • Denial of Service (DoS)
   • Port scanning
   • ARP spoofing
   • DNS poisoning

🛠️ Security Measures:
   • Encryption (SSL/TLS, VPN)
   • Firewalls (packet filtering)
   • Intrusion Detection Systems (IDS)
   • Network segmentation
   • Access control lists (ACLs)
   • Regular security audits

🔍 Security Monitoring:
   • Log analysis
   • Traffic monitoring
   • Anomaly detection
   • Incident response

💡 Best Practices:
   • Use strong passwords
   • Keep software updated
   • Encrypt sensitive data
   • Monitor network traffic
   • Implement least privilege
   • Regular security training
        """)
    
    def run_quiz(self):
        """Run a simple network quiz."""
        print("\n🧠 NETWORK KNOWLEDGE QUIZ")
        print("=" * 50)
        
        questions = [
            {
                'question': 'What does TCP stand for?',
                'options': ['A) Transfer Control Protocol', 'B) Transmission Control Protocol', 
                           'C) Transport Control Protocol', 'D) Transfer Connection Protocol'],
                'answer': 'B'
            },
            {
                'question': 'Which port is commonly used for HTTP?',
                'options': ['A) 21', 'B) 22', 'C) 80', 'D) 443'],
                'answer': 'C'
            },
            {
                'question': 'What is the purpose of ICMP?',
                'options': ['A) File transfer', 'B) Network diagnostics', 'C) Email delivery', 'D) Web browsing'],
                'answer': 'B'
            },
            {
                'question': 'Which IP address range is private?',
                'options': ['A) 192.168.0.0 - 192.168.255.255', 'B) 200.0.0.0 - 200.255.255.255',
                           'C) 172.16.0.0 - 172.31.255.255', 'D) Both A and C'],
                'answer': 'D'
            },
            {
                'question': 'What is the main difference between TCP and UDP?',
                'options': ['A) TCP is faster', 'B) UDP is more reliable', 
                           'C) TCP is connection-oriented, UDP is connectionless', 'D) UDP uses more bandwidth'],
                'answer': 'C'
            }
        ]
        
        score = 0
        total = len(questions)
        
        for i, q in enumerate(questions, 1):
            print(f"\n❓ Question {i}: {q['question']}")
            for option in q['options']:
                print(f"   {option}")
            
            answer = input("\nYour answer (A/B/C/D): ").upper().strip()
            
            if answer == q['answer']:
                print("✅ Correct!")
                score += 1
            else:
                print(f"❌ Incorrect. The correct answer is {q['answer']}.")
        
        print(f"\n📊 Quiz Results: {score}/{total} correct ({score/total*100:.1f}%)")
        
        if score == total:
            print("🎉 Perfect score! You're a networking expert!")
        elif score >= total * 0.8:
            print("👏 Great job! You have solid networking knowledge!")
        elif score >= total * 0.6:
            print("👍 Good work! Keep learning about networks!")
        else:
            print("📚 Keep studying! Review the topics above to improve your knowledge.")
    
    def show_all_topics(self):
        """Show all educational topics."""
        print("\n📚 ALL NETWORK TOPICS")
        print("=" * 60)
        
        self.explain_osi_model()
        time.sleep(2)
        
        self.explain_tcp()
        time.sleep(2)
        
        self.explain_udp()
        time.sleep(2)
        
        self.explain_icmp()
        time.sleep(2)
        
        self.explain_ip_addressing()
        time.sleep(2)
        
        self.explain_ports()
        time.sleep(2)
        
        self.explain_packets()
        time.sleep(2)
        
        self.explain_capture()
        time.sleep(2)
        
        self.explain_security()
        
        print("\n🎓 Educational content complete! Use this knowledge responsibly.")
    
    def run(self):
        """Run the educational tool."""
        self.display_welcome()
        
        while True:
            self.display_menu()
            choice = input("\nSelect a topic: ").lower().strip()
            
            if choice == 'exit':
                print("\n👋 Thanks for learning about networks! Use your knowledge responsibly.")
                break
            elif choice == 'all':
                self.show_all_topics()
            elif choice == 'quiz':
                self.run_quiz()
            elif choice in self.topics:
                if choice == 'osi':
                    self.explain_osi_model()
                elif choice == 'tcp':
                    self.explain_tcp()
                elif choice == 'udp':
                    self.explain_udp()
                elif choice == 'icmp':
                    self.explain_icmp()
                elif choice == 'ip':
                    self.explain_ip_addressing()
                elif choice == 'ports':
                    self.explain_ports()
                elif choice == 'packets':
                    self.explain_packets()
                elif choice == 'capture':
                    self.explain_capture()
                elif choice == 'security':
                    self.explain_security()
                
                input("\nPress Enter to continue...")
            else:
                print(f"❌ Unknown topic: {choice}")
                print("Please select a valid topic from the menu.")

def main():
    """Main function to run the network educator."""
    try:
        educator = NetworkEducator()
        educator.run()
    except KeyboardInterrupt:
        print("\n\n👋 Thanks for learning about networks!")
    except Exception as e:
        print(f"\n❌ Error: {e}")

if __name__ == "__main__":
    main() 