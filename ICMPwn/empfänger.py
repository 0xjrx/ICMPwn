import os
import base64
import zlib
from scapy.all import sniff, wrpcap, ICMP, Raw, send, IP

# File paths
pcap_file = "received_packets.pcap"  # File to save captured packets
output_file = "reconstructed_data.txt"  # File to write decoded data

# Function to clear or create the PCAP file
def initialize_pcap_file(pcap_file):
    if os.path.exists(pcap_file):
        os.remove(pcap_file)  # Delete if it exists
    with open(pcap_file, "wb") as f:
        pass  # Create an empty file (optional, Scapy can create it automatically)

def initialize_output(output_file):
    if os.path.exists(output_file):
        os.remove(output_file)  # Delete if it exists
    with open(output_file, "wb") as f:
        pass  # Create an empty file (optional, Scapy can create it automatically)

# Function to verify CRC32 checksum
def verify_crc(data, checksum):
    calculated_checksum = zlib.crc32(data) & 0xFFFFFFFF
    return calculated_checksum == checksum

# Callback function to process each packet
def process_packet():
    packets = sniff(filter="icmp",store=True, count = 1)  # Start sniffing for ICMP packets
    
    ip_dst = "192.168.0.34"         # Target IP
    raw = packets[0]
    raw_data = raw[Raw].load
    wrpcap(pcap_file,packets[0], append = True )
    # Extract packet number, data, and checksum
    packet_number = int.from_bytes(raw_data[:4], byteorder="big")
    data = raw_data[4:-4]
    received_checksum = int.from_bytes(raw_data[-4:], byteorder="big")
    bool = verify_crc(data, received_checksum)
    print("bool", bool)
    # Verify checksum
    if bool:
        print(f"Packet {packet_number}: Checksum verified. Writing data to file...")

        checksum_verification = 1
        packet = (
                 IP(dst=ip_dst)
                / ICMP(type="echo-reply")
                / Raw(load = checksum_verification.to_bytes(1, byteorder="big"))
            )
        print(f"Sending packet {packet_number} to {ip_dst}")
        print(("Packet:", packet[Raw].load))
        send(packet)
         
        wrpcap(pcap_file,packet,append=True)

            # Decode base64 and append to the output file
        with open(output_file, "ab") as file:
            file.write(base64.b64decode(data))

    else:
            print(f"Packet {packet_number}: Checksum verification failed!")
            checksum_verification = 0
            packet = (
                IP(dst=ip_dst)
                / ICMP(type="echo-reply")
                / Raw(load = checksum_verification.to_bytes(1, byteorder="big"))
            )
            print(f"Sending packet {packet_number} to {ip_dst}")
            send(packet)
            wrpcap(pcap_file, packet, append=True)

            process_packet()



# Start the listener
def start_listener():
    print("Initializing listener...")
    initialize_pcap_file(pcap_file)  # Clear the PCAP file before starting
    initialize_output(output_file)
    print(f"Listening for ICMP packets. Captured packets will be saved to {pcap_file}.")
    process_packet() # Start sniffing for ICMP packets

if __name__ == "__main__":
    start_listener()

