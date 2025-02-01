import socket
import struct
import time
import select
from collections import defaultdict



# Function to check if a number is prime
def is_prime(n):
    if n < 2:
        return False
    for i in range(2, int(n ** 0.5) + 1):
        if n % i == 0:
            return False
    return True

# Create a raw socket
def create_socket(interface):
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        s.bind((interface, 0))
        print(f"Listening on {interface}")
        return s
    except PermissionError:
        print("Run the program as root to capture raw packets.")
        exit(1)

# Parse Ethernet header
def parse_ethernet_header(packet):
    eth_header = struct.unpack("!6s6sH", packet[:14])
    eth_type = socket.htons(eth_header[2])
    return eth_type

# Parse IP header
def parse_ip_header(packet):
    ip_header = packet[14:34]
    iph = struct.unpack("!BBHHHBBH4s4s", ip_header)
    src_ip = socket.inet_ntoa(iph[8])
    dest_ip = socket.inet_ntoa(iph[9])
    protocol = iph[6]
    return src_ip, dest_ip, protocol

# Parse TCP header
def parse_tcp_header(packet):
    tcp_header = struct.unpack("!HHLLBBHHH", packet[34:54])
    src_port = tcp_header[0]
    dest_port = tcp_header[1]
    seq_number = tcp_header[2]
    ack_number = tcp_header[3]
    flags = tcp_header[5]
    checksum = tcp_header[7]

    # Extract individual flags
    ack_flag = (flags >> 4) & 1
    psh_flag = (flags >> 3) & 1
    syn_flag = (flags >> 1) & 1

    return src_port, dest_port, seq_number, ack_number, flags, ack_flag, psh_flag, syn_flag, checksum

# Sniff packets
def sniff_packets(interface):
    s = create_socket(interface)
    start_time = time.time()

    ### Important field 
    duration = 30  # Capture packets for 30 seconds

    matching_packets_q1 = []
    matching_packets_q2 = []
    matching_packets_q3 = []
    matching_packets_q4 = []

    while True:
        if time.time() - start_time > duration:
            print(f"Duration of {duration} seconds reached. Exiting...")
            break

        ready, _, _ = select.select([s], [], [], 1)
        if not ready:
            continue

        raw_packet, _ = s.recvfrom(65535)
        eth_type = parse_ethernet_header(raw_packet)


        src_ip, dest_ip, protocol = parse_ip_header(raw_packet)

        # Process only TCP packets
        if protocol != 6:
            continue

        src_port, dest_port, seq_number, ack_number, flags, ack_flag, psh_flag, syn_flag, checksum = parse_tcp_header(raw_packet)

        # --- Condition 1: Find TCP Packet with ACK & PSH set, sum of source & dest ports = 60303 ---
        if ack_flag == 1 and psh_flag == 1 and (src_port + dest_port) == 60303:
            
            matching_packets_q1.append((src_ip, dest_ip, src_port, dest_port))

        # --- Condition 2: SYN flag set, source port divisible by 11, seq_number > 100000 ---
        if syn_flag == 1 and src_port % 11 == 0 and seq_number > 100000:
            
            matching_packets_q2.append((src_ip, dest_ip, src_port, dest_port))

        # --- Condition 3: Source IP 18.234.xx.xxx, source port is prime, dest port divisible by 11 ---
        if src_ip.startswith("18.234.") and is_prime(src_port) and dest_port % 11 == 0:
            
            matching_packets_q3.append((src_ip, dest_ip, src_port, dest_port))

        # --- Condition 4: Sequence + Acknowledgment = 2512800625, checksum last two digits = 70 ---
        if (seq_number + ack_number) == 2512800625 and (checksum & 0xFF) == 0x70:
            
            matching_packets_q4.append((src_ip, dest_ip, src_port, dest_port))

    # Display results
    print("\n===== Q1: TCP Packet with ACK & PSH set, sum of ports = 60303 =====")
    print(f" Count: {len(matching_packets_q1)} ")
    for p in matching_packets_q1:
        print(f"Source: {p[0]}:{p[2]} -> Destination: {p[1]}:{p[3]}")

    print("\n===== Q2: SYN Set, Source Port % 11 == 0, Sequence Number > 100000 =====")
    print(f" Count: {len(matching_packets_q2)} ")
    for p in matching_packets_q2:
        print(f"Source: {p[0]}:{p[2]} -> Destination: {p[1]}:{p[3]}")

    print("\n===== Q3: Source IP 18.234.xx.xxx, Prime Src Port, Dest Port % 11 == 0 =====")
    print(f" Count: {len(matching_packets_q3)} ")
    for p in matching_packets_q3:
        print(f"Source: {p[0]}:{p[2]} -> Destination: {p[1]}:{p[3]}")

    print("\n===== Q4: Sequence + Ack = 2512800625, Checksum ends in 70 =====")
    print(f" Count: {len(matching_packets_q4)} ")
    for p in matching_packets_q4:
        print(f"Source: {p[0]}:{p[2]} -> Destination: {p[1]}:{p[3]}")

if __name__ == "__main__":
    
    sniff_packets("eth0")
