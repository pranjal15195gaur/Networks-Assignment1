import argparse
import datetime
import socket
import struct
import time
import select
import json
import matplotlib.pyplot as plt
from collections import defaultdict

# Set the duration in seconds
DURATION = 30

# Data tracking variables
total_bytes = 0
total_packets = 0
packet_sizes = []
flow_counts_src = defaultdict(int)
flow_counts_dest = defaultdict(int)
flow_data = defaultdict(int)  # {("src_ip:port", "dest_ip:port"): bytes_transferred}
unique_pairs = set()

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

# Save dictionaries to JSON files
def save_to_json():
    with open("flow_counts_src.json", "w") as f:
        json.dump(dict(flow_counts_src), f, indent=4)
    with open("flow_counts_dest.json", "w") as f:
        json.dump(dict(flow_counts_dest), f, indent=4)
    
    with open("unique_pairs.json", "w") as f:
        json.dump(list(unique_pairs), f, indent=4)
    print("Saved statistics to JSON files.")

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

# Parse TCP/UDP headers to extract port numbers
def parse_transport_header(packet, protocol):
    if protocol == 6:  # TCP
        header_start = 34
        tcp_header = struct.unpack("!HH", packet[header_start:header_start + 4])
        return tcp_header[0], tcp_header[1]  # src_port, dest_port
    elif protocol == 17:  # UDP
        header_start = 34
        udp_header = struct.unpack("!HH", packet[header_start:header_start + 4])
        return udp_header[0], udp_header[1]  # src_port, dest_port
    return None, None  # If not TCP/UDP

# argparse
def parse_arguments():
    parser = argparse.ArgumentParser(description="CLI-based raw packet sniffer with analytics")
    parser.add_argument("-i", "--interface", required=True, help="Network interface to sniff on")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    return parser.parse_args()

def sniff_packets(args):
    global total_bytes, total_packets, packet_sizes
    s = create_socket(args.interface)
    start_time = time.time()

    while True:
        if time.time() - start_time > DURATION:
            print(f"Duration of {DURATION} seconds reached. Exiting...")
            break

        ready, _, _ = select.select([s], [], [], 1)
        if not ready:
            continue

        raw_packet, _ = s.recvfrom(65535)
        eth_type = parse_ethernet_header(raw_packet)

        src_ip, dest_ip, protocol = parse_ip_header(raw_packet)
        src_port, dest_port = parse_transport_header(raw_packet, protocol)

        # Store flow data
        flow_counts_src[src_ip] += 1
        flow_counts_dest[dest_ip] += 1

        # Track total data and packets
        packet_size = len(raw_packet)
        total_bytes += packet_size
        total_packets += 1
        packet_sizes.append(packet_size)

        # Store unique pairs and flow data
        if src_port and dest_port:
            flow_key = (f"{src_ip}:{src_port}", f"{dest_ip}:{dest_port}")
            unique_pairs.add(flow_key)
            flow_data[flow_key] += packet_size

    save_to_json()

def display_statistics():
    print("\n===== Packet Statistics =====")
    print(f"Total Packets: {total_packets}")
    print(f"Total Data Transferred: {total_bytes} bytes")
    if packet_sizes:
        print(f"Min Packet Size: {min(packet_sizes)} bytes")
        print(f"Max Packet Size: {max(packet_sizes)} bytes")
        print(f"Average Packet Size: {sum(packet_sizes) // len(packet_sizes)} bytes")
    
    print("\n===== Unique Source-Destination Pairs =====")
    print(len(unique_pairs))
    
    print("\n===== Flow Counts Per Source IP =====")
    print(len(flow_counts_src))
    
    print("\n===== Flow Counts Per Destination IP =====")
    print(len(flow_counts_dest))

    if flow_data:
        max_flow = max(flow_data, key=flow_data.get)
        print(f"\nTop Flow: {max_flow[0]} -> {max_flow[1]} transferred {flow_data[max_flow]} bytes")

    # Plot histogram
    if packet_sizes:
        plt.figure(figsize=(10, 5))
        plt.hist(packet_sizes, bins=20, color='blue', edgecolor='black')
        plt.xlabel("Packet Size (bytes)")
        plt.ylabel("Frequency")
        plt.title("Distribution of Packet Sizes")
        plt.show()

if __name__ == "__main__":
    args = parse_arguments()
    sniff_packets(args)
    display_statistics()
