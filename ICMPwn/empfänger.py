import os
import base64
import zlib
import binascii
from scapy.all import sniff, wrpcap, ICMP, Raw, send, IP
from typing import Dict, Optional

class PacketProcessor:
    def __init__(self):
        # File paths
        self.pcap_file = "received_packets.pcap"
        self.output_file = "reconstructed_data.txt"
        self.received_packets: Dict[int, bytes] = {}  # Store received packets
        self.ip_dst = "172.16.10.38"  # Target IP for verification responses
        
    def initialize_files(self):
        """Initialize or clear the PCAP and output files"""
        for file_path in [self.pcap_file, self.output_file]:
            if os.path.exists(file_path):
                os.remove(file_path)
            with open(file_path, "wb") as f:
                pass

    def verify_crc(self, data: bytes, checksum: int) -> bool:
        """Verify CRC32 checksum"""
        calculated_checksum = zlib.crc32(data) & 0xFFFFFFFF
        return calculated_checksum == checksum

    def send_verification_packet(self, verification_status: bool, packet_number: int):
        """Send verification packet back to sender"""
        status_byte = 1 if verification_status else 0
        verification_packet = (
            IP(dst=self.ip_dst)
            / ICMP(type=0, id=packet_number)  # Using echo-reply type
            / Raw(load=packet_number.to_bytes(4, byteorder="big") + bytes([status_byte]))
        )
        send(verification_packet)
        wrpcap(self.pcap_file, verification_packet, append=True)
        print(f"Sent verification packet for packet {packet_number}: {'Success' if verification_status else 'Failed'}")

    def save_data(self, packet_number: int, data: bytes):
        """Save decoded data to file in correct order"""
        self.received_packets[packet_number] = data
        
        # Write consecutive packets to file
        current_packet = min(self.received_packets.keys())
        while current_packet in self.received_packets:
            try:
                decoded_data = base64.b64decode(self.received_packets[current_packet])
                with open(self.output_file, "ab") as file:
                    file.write(decoded_data)
                del self.received_packets[current_packet]
                current_packet += 1
            except binascii.Error:
                print(f"Warning: Invalid base64 data in packet {current_packet}")
                break

    def process_packet(self, packet):
        """Process incoming ICMP packets"""
        if not (packet.haslayer(ICMP) and packet.haslayer(Raw)):
            return

        try:
            raw_data = packet[Raw].load
            
            # Ignore verification response packets
            if len(raw_data) < 8:  # Too short to be a data packet
                return
            
            # Extract packet components
            packet_number = int.from_bytes(raw_data[:4], byteorder="big")
            data = raw_data[4:-4]
            received_checksum = int.from_bytes(raw_data[-4:], byteorder="big")
            
            print(f"Received packet {packet_number}")
            
            # Verify checksum
            verification_status = self.verify_crc(data, received_checksum)
            
            if verification_status:
                print(f"Packet {packet_number}: Checksum verified")
                if packet_number not in self.received_packets:
                    self.save_data(packet_number, data)
            else:
                print(f"Packet {packet_number}: Checksum verification failed!")
            
            # Send verification response
            self.send_verification_packet(verification_status, packet_number)
            
        except Exception as e:
            print(f"Error processing packet: {e}")

def start_listener():
    """Initialize and start the packet listener"""
    processor = PacketProcessor()
    print("Initializing listener...")
    processor.initialize_files()
    print(f"Listening for ICMP packets. Captured packets will be saved to {processor.pcap_file}")
    print(f"Decoded data will be written to {processor.output_file}")
    
    # Start sniffing for ICMP packets
    sniff(filter="icmp", prn=processor.process_packet, store=False)

if __name__ == "__main__":
    start_listener()
