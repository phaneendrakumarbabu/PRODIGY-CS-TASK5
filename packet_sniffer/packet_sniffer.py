import pydivert
import struct
import textwrap

def main():
    # Open a WinDivert handle to capture packets
    with pydivert.WinDivert("true") as w:
        for packet in w:
            raw_data = packet.raw
            dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
            print('\nEthernet Frame:')
            print(f'Destination: {dest_mac}, Source: {src_mac}, Protocol: {eth_proto}')

            # Check for IPv4 packets (protocol number 8)
            if eth_proto == 8:
                (version, header_length, ttl, proto, src, target, data) = ipv4_packet(data)
                print('IPv4 Packet:')
                print(f'Version: {version}, Header Length: {header_length}, TTL: {ttl}')
                print(f'Protocol: {proto}, Source: {src}, Target: {target}')

                # ICMP packets (protocol number 1)
                if proto == 1:
                    icmp_type, code, checksum, data = icmp_packet(data)
                    print('ICMP Packet:')
                    print(f'Type: {icmp_type}, Code: {code}, Checksum: {checksum}')
                    print('Data:')
                    print(format_multi_line(data))

                # TCP packets (protocol number 6)
                elif proto == 6:
                    (src_port, dest_port, sequence, acknowledgment, flags, data) = tcp_segment(data)
                    print('TCP Segment:')
                    print(f'Source Port: {src_port}, Destination Port: {dest_port}')
                    print(f'Sequence: {sequence}, Acknowledgment: {acknowledgment}')
                    print(f'Flags:')
                    print(f'URG: {flags[0]}, ACK: {flags[1]}, PSH: {flags[2]}, RST: {flags[3]}, SYN: {flags[4]}, FIN: {flags[5]}')
                    print('Data:')
                    print(format_multi_line(data))

                # UDP packets (protocol number 17)
                elif proto == 17:
                    src_port, dest_port, length, data = udp_segment(data)
                    print('UDP Segment:')
                    print(f'Source Port: {src_port}, Destination Port: {dest_port}, Length: {length}')
                    print('Data:')
                    print(format_multi_line(data))

                else:
                    print('Data:')
                    print(format_multi_line(data))
            else:
                print('Data:')
                print(format_multi_line(data))

# Function to unpack ethernet frame
def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]

# Function to format MAC addresses into human-readable form
def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()

# Function to unpack IPv4 packets
def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]

# Function to format IPv4 addresses into human-readable form
def ipv4(addr):
    return '.'.join(map(str, addr))

# Function to unpack ICMP packets
def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]

# Function to unpack TCP segments
def tcp_segment(data):
    (src_port, dest_port, sequence, acknowledgment, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flags = offset_reserved_flags & 0x3F
    urg = (flags & 32) >> 5
    ack = (flags & 16) >> 4
    psh = (flags & 8) >> 3
    rst = (flags & 4) >> 2
    syn = (flags & 2) >> 1
    fin = flags & 1
    return src_port, dest_port, sequence, acknowledgment, (urg, ack, psh, rst, syn, fin), data[offset:]

# Function to unpack UDP segments
def udp_segment(data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]

# Function to format multi-line data for better readability
def format_multi_line(data, size=80):
    if isinstance(data, bytes):
        data = ''.join(r'\x{:02x}'.format(byte) for byte in data)
    return '\n'.join([data[i:i + size] for i in range(0, len(data), size)])

if __name__ == "__main__":
    main()
