import scapy
from scapy.all import sniff, IP, TCP, UDP, ARP, ICMP
import time
import matplotlib.pyplot as plt
from collections import defaultdict

packet_count = 0
total_bytes = 0
start_time = time.time()

# Dictionaries to store flow data
source_flows = defaultdict(int)
destination_flows = defaultdict(int)
source_dest_data = defaultdict(int)
unique_pairs = set()

# Counters for flow and non-flow packets
flow_packet_count = 0
non_flow_packet_count = 0

# Lists to store packet sizes for statistics
packet_sizes = []

def packet_handler(packet):
    global packet_count, total_bytes
    global flow_packet_count, non_flow_packet_count
    global source_flows, destination_flows, source_dest_data, unique_pairs
    
    if IP in packet:
        packet_count += 1
        packet_size = len(packet)
        total_bytes += packet_size
        packet_sizes.append(packet_size)
        
        # Check if it's a flow packet (TCP or UDP)
        if TCP in packet or UDP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            src_port = packet[TCP].sport if TCP in packet else packet[UDP].sport
            dst_port = packet[TCP].dport if TCP in packet else packet[UDP].dport
            pair = (src_ip, src_port, dst_ip, dst_port)
            unique_pairs.add(pair)
            source_dest_data[(src_ip, src_port, dst_ip, dst_port)] += packet_size

            # Count flows per IP address
            source_flows[src_ip] += 1
            destination_flows[dst_ip] += 1
            
            # Increment flow packet count
            flow_packet_count += 1
        else:
            # Non-flow packets could be ARP, ICMP, etc.
            non_flow_packet_count += 1

# Capture packets for 260 seconds
duration = 500
sniff(prn=packet_handler, iface="eth0", store=False, timeout=duration)

# Calculate PPS and Mbps
elapsed_time = time.time() - start_time
pps = packet_count / elapsed_time
mbps = (total_bytes * 8) / (elapsed_time * 1e6)

# Calculate packet size statistics
min_size = min(packet_sizes) if packet_sizes else 0
max_size = max(packet_sizes) if packet_sizes else 0
avg_size = sum(packet_sizes) / len(packet_sizes) if packet_sizes else 0

# Find the source-destination pair with the most data transferred
max_data_pair = max(source_dest_data, key=source_dest_data.get, default=None)
max_data_value = source_dest_data.get(max_data_pair, 0)

# Output results
print(f"\nTotal Packets: {packet_count}")
print(f"Total Data Transferred (Bytes): {total_bytes}")
print(f"\nMinimum Packet Size (Bytes): {min_size}")
print(f"Maximum Packet Size (Bytes): {max_size}")
print(f"Average Packet Size (Bytes): {avg_size:.2f}")

# Display source-destination flow data
print("\nSource IP to Flows:")
print(len(dict(source_flows)))
print("\nDestination IP to Flows:")
print(len(dict(destination_flows)))

# Display source-destination pair with the most data
if max_data_pair:
    print(f"\nSource-Destination pair with most data transfer: {max_data_pair} with {max_data_value} bytes")

# Display flow vs non-flow packet counts
print(f"\nFlow Packet Count: {flow_packet_count}")
print(f"Non-Flow Packet Count: {non_flow_packet_count}")

# Display PPS and Mbps
print(f"\nPackets Per Second (PPS): {pps:.2f}")
print(f"Megabits Per Second (Mbps): {mbps:.2f}")
