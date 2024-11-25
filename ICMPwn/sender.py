import time
import os
import base64

from scapy.all import IP, ICMP, Raw, send, wrpcap, sniff
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

def receive_checksum(raw_data):
    checksum_value = int.from_bytes(raw_data, byteorder='big')
    if checksum_value == 1:
        return True
    else:
        return False

# Main logic
def main():
    filename = "./Robotergesetze.txt"  # File to read
    ip_dst = "192.168.0.148"         # Target IP
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
        value = False
        while value != True:
            current_packet_data = encoded_data[:packet_size]

            send_icmp_packet(current_packet_data, ip_dst, packet_number, pcap_file)

            #time.sleep(1)
            packets = sniff(filter="icmp", count = 1)
            #print(packets)
            new_data = packets[0]
            wrpcap(pcap_file,packets , append=True)  # Save packet to .pcap

            raw = new_data[Raw].load
            value = receive_checksum(raw)
            if value == True:
                packet_number += 1
                break
            else:
                continue
        encoded_data = encoded_data[packet_size:]

if __name__ == "__main__":
    main()


