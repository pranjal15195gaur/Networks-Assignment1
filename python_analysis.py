from scapy.all import rdpcap, IP, TCP, UDP
import numpy as np
import matplotlib.pyplot as plt
from collections import defaultdict

def analyze_pcap(file_path):
    packets = rdpcap(file_path)  # Read the .pcap file
    total_packets = len(packets)
    total_bytes = sum(len(pkt) for pkt in packets)
    
    # Extract packet sizes
    packet_sizes = [len(pkt) for pkt in packets]
    
    # Compute min, max, and average packet size
    min_size = min(packet_sizes)
    max_size = max(packet_sizes)
    avg_size = total_bytes / total_packets
    
    # ** Plot Histogram **
    plt.figure(figsize=(8, 5))
    plt.hist(packet_sizes, bins=20, color='blue', alpha=0.7, edgecolor='black')
    plt.xlabel("Packet Size (Bytes)")
    plt.ylabel("Frequency")
    plt.title("Packet Size Distribution")
    plt.grid(True)
    plt.show()

    print(f"Total Packets: {total_packets}")
    print(f"Total Data Transferred: {total_bytes} Bytes")
    print(f"Min Packet Size: {min_size} Bytes")
    print(f"Max Packet Size: {max_size} Bytes")
    print(f"Average Packet Size: {avg_size:.2f} Bytes")

    # ** Step 2: Find Unique Source-Destination Pairs **
    unique_pairs = set()
    flow_source_count = defaultdict(int)
    flow_dest_count = defaultdict(int)
    flow_data = defaultdict(int)

    for pkt in packets:
        if IP in pkt and (TCP in pkt or UDP in pkt):
            src_ip = pkt[IP].src
            dest_ip = pkt[IP].dst
            src_port = pkt[TCP].sport if TCP in pkt else pkt[UDP].sport
            dest_port = pkt[TCP].dport if TCP in pkt else pkt[UDP].dport
            
            pair = (src_ip, src_port, dest_ip, dest_port)
            unique_pairs.add(pair)
            
            # Count flows
            flow_source_count[src_ip] += 1
            flow_dest_count[dest_ip] += 1
            
            # Track data transferred per pair
            flow_data[pair] += len(pkt)

    print(f"Unique Source-Destination Pairs: {len(unique_pairs)}")
    print("Example Unique Pairs (Source IP:Port → Dest IP:Port):")
    for i, pair in enumerate(unique_pairs):
        if i >= 10:  # Show only first 10
            break
        print(f"{pair[0]}:{pair[1]} → {pair[2]}:{pair[3]}")

    # ** Step 3: Compute Flow Statistics **
    print("\nTop 5 Source IPs by Flow Count:")
    for ip, count in sorted(flow_source_count.items(), key=lambda x: x[1], reverse=True)[:5]:
        print(f"{ip}: {count} flows")

    print("\nTop 5 Destination IPs by Flow Count:")
    for ip, count in sorted(flow_dest_count.items(), key=lambda x: x[1], reverse=True)[:5]:
        print(f"{ip}: {count} flows")

    # Find the (source → destination) pair that transferred the most data
    top_pair = max(flow_data, key=flow_data.get)
    print("\nTop Data Transfer Pair:")
    print(f"{top_pair[0]}:{top_pair[1]} → {top_pair[2]}:{top_pair[3]} transferred {flow_data[top_pair]} Bytes")

    return total_packets, total_bytes, packet_sizes

# Run analysis on the captured pcap file
pcap_file = "output.pcap"
analyze_pcap(pcap_file)
