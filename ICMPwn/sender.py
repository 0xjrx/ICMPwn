import base64
import time
import os
from base64 import b64encode
from scapy.all import IP, ICMP, Raw, send, wrpcap, sniff
import zlib
from typing import Optional

# Function to calculate CRC32 checksum
def calculate_crc(data: bytes) -> int:
    return zlib.crc32(data) & 0xFFFFFFFF

def initialize_pcap_file(pcap_file: str) -> None:
    if os.path.exists(pcap_file):
        os.remove(pcap_file)
    with open(pcap_file, "wb") as f:
        pass

def send_icmp_packet(data: bytes, ip_dst: str, packet_number: int, pcap_file: str) -> None:
    checksum = calculate_crc(data)
    packet = (
        IP(dst=ip_dst)
        / ICMP(type="echo-request")
        / Raw(load=packet_number.to_bytes(4, byteorder="big") + data + checksum.to_bytes(4, byteorder="big"))
    )
    print(f"Sending packet {packet_number} to {ip_dst}")
    send(packet)
    wrpcap(pcap_file, packet, append=True)

def process_verification_packet(packet) -> Optional[bool]:
    """Process verification packets from receiver"""
    if packet.haslayer(ICMP) and packet[ICMP].type == 0:  # Echo reply
        try:
            raw_data = packet[Raw].load
            # Last byte indicates verification status
            status = raw_data[-1]
            return status == 1
        except:
            return None
    return None

def wait_for_verification(timeout: int = 5) -> bool:
    """Wait for verification packet with timeout"""
    start_time = time.time()
    while time.time() - start_time < timeout:
        packets = sniff(filter="icmp", count=1, timeout=1)
        if packets:
            result = process_verification_packet(packets[0])
            if result is not None:
                return result
    return False

def main():
    filename = "./Robotergesetze.txt"
    ip_dst = "172.16.10.36"
    packet_size = 1400
    pcap_file = "sent_packets.pcap"
    max_retries = 3
    
    initialize_pcap_file(pcap_file)
    
    if not os.path.exists(filename):
        raise FileNotFoundError(f"The file {filename} does not exist.")
    
    with open(filename, 'r') as file:
        data = file.read()
    encoded_data = base64.b64encode(data.encode())
    
    packet_number = 1
    position = 0
    
    while position < len(encoded_data):
        current_packet_data = encoded_data[position:position + packet_size]
        
        retries = 0
        packet_verified = False
        
        while not packet_verified and retries < max_retries:
            send_icmp_packet(current_packet_data, ip_dst, packet_number, pcap_file)
            
            # Wait for verification packet
            packet_verified = wait_for_verification()
            
            if not packet_verified:
                print(f"Packet {packet_number} verification failed. Retrying... ({retries + 1}/{max_retries})")
                retries += 1
                time.sleep(1)
        
        if packet_verified:
            print(f"Packet {packet_number} verified successfully")
            position += packet_size
            packet_number += 1
        else:
            print(f"Failed to verify packet {packet_number} after {max_retries} attempts. Exiting...")
            break
        
        time.sleep(0.1)  # Small delay between packets

if __name__ == "__main__":
    main()
