import base64
import time
import os
from scapy.all import IP, ICMP, Raw, send, wrpcap
import zlib

# Function to calculate CRC32 checksum
def calculate_crc(data):
    return zlib.crc32(data) & 0xFFFFFFFF

def initialize_pcap_file(pcap_file):
    if os.path.exists(pcap_file):
        os.remove(pcap_file)  # Delete the file if it exists
    # Optionally create an empty file (not required for Scapy)
    with open(pcap_file, "wb") as f:
        pass

# Function to send data via ICMP and save to pcap
def send_icmp_packet(data, ip_dst, packet_number, pcap_file):
    checksum = calculate_crc(data)
    packet = (
        IP(dst=ip_dst)
        / ICMP(type="echo-request")
        / Raw(load=packet_number.to_bytes(4, byteorder="big") + data + checksum.to_bytes(4, byteorder="big"))
    )
    print(f"Sending packet {packet_number} to {ip_dst}")
    send(packet)
    wrpcap(pcap_file, packet, append=True)  # Save packet to .pcap

# Main logic
def main():
    filename = "./Robotergesetze.txt"  # File to read
    ip_dst = "172.16.10.36"         # Target IP
    packet_size = 1400               # Max ICMP packet size
    pcap_file = "sent_packets.pcap"
    initialize_pcap_file(pcap_file)

    # Read and encode the file
    if not os.path.exists(filename):
        raise FileNotFoundError(f"The file {filename} does not exist.")
    with open(filename, 'r') as file:
        data = file.read()
    encoded_data = base64.b64encode(data.encode())
    
    packet_number = 1
    while encoded_data:
        current_packet_data = encoded_data[:packet_size]
        encoded_data = encoded_data[packet_size:]
        
        send_icmp_packet(current_packet_data, ip_dst, packet_number, pcap_file)
        
        time.sleep(1)
        packet_number += 1

if __name__ == "__main__":
    main()

