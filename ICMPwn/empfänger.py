import os
import base64
import zlib
from scapy.all import sniff, wrpcap, ICMP, Raw

# File paths
pcap_file = "received_packets.pcap"  # File to save captured packets
output_file = "reconstructed_data.txt"  # File to write decoded data

# Function to clear or create the PCAP file
def initialize_pcap_file(pcap_file):
    if os.path.exists(pcap_file):
        os.remove(pcap_file)  # Delete if it exists
    with open(pcap_file, "wb") as f:
        pass  # Create an empty file (optional, Scapy can create it automatically)

# Function to verify CRC32 checksum
def verify_crc(data, checksum):
    calculated_checksum = zlib.crc32(data) & 0xFFFFFFFF
    return calculated_checksum == checksum

# Callback function to process each packet
def process_packet(packet):
    if packet.haslayer(ICMP) and packet[ICMP].type == 8:  # Check for ICMP Echo Request
        raw_data = packet[Raw].load
        
        # Extract packet number, data, and checksum
        packet_number = int.from_bytes(raw_data[:4], byteorder="big")
        data = raw_data[4:-4]
        received_checksum = int.from_bytes(raw_data[-4:], byteorder="big")
        
        # Verify checksum
        if verify_crc(data, received_checksum):
            print(f"Packet {packet_number}: Checksum verified. Writing data to file...")
            # Decode base64 and append to the output file
            with open(output_file, "ab") as file:  # Append in binary mode
                file.write(base64.b64decode(data))
        else:
            print(f"Packet {packet_number}: Checksum verification failed!")

        # Save the packet to the PCAP file
        wrpcap(pcap_file, packet, append=True)

# Start the listener
def start_listener():
    print("Initializing listener...")
    initialize_pcap_file(pcap_file)  # Clear the PCAP file before starting
    print(f"Listening for ICMP packets. Captured packets will be saved to {pcap_file}.")
    sniff(filter="icmp", prn=process_packet, store=False)  # Start sniffing for ICMP packets

if __name__ == "__main__":
    start_listener()

