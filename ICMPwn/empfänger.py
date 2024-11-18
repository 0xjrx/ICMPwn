import base64
import zlib
from scapy.all import sniff, IP, ICMP, Raw

# File to save the received data
output_file = "received_data.txt"

# Function to verify CRC32 checksum
def verify_crc(data, checksum):
    calculated_checksum = zlib.crc32(data) & 0xFFFFFFFF
    return calculated_checksum == checksum

# Callback function to process each packet
def process_packet(packet):
    if packet.haslayer(ICMP) and packet[ICMP].type == 8:  # Check if ICMP Echo Request
        raw_data = packet[Raw].load
        
        # Extract packet number, data, and checksum
        packet_number = int.from_bytes(raw_data[:4], byteorder="big")
        data = raw_data[4:-4]
        received_checksum = int.from_bytes(raw_data[-4:], byteorder="big")
        
        # Verify checksum
        if verify_crc(data, received_checksum):
            print(f"Packet {packet_number}: Checksum verified.")
            # Decode base64 and write to file
            with open(output_file, "ab") as file:  # Append binary mode
                file.write(base64.b64decode(data))
        else:
            print(f"Packet {packet_number}: Checksum failed!")

# Start the listener
def start_listener():
    print("Listening for ICMP packets...")
    sniff(filter="icmp", prn=process_packet, store=False)

if __name__ == "__main__":
    start_listener()

