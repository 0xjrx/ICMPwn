# ICMPwn

**ICMPwn** is a pair of Python scripts designed to transfer and reconstruct data by encapsulating it within ICMP echo-request and echo-reply packets. This technique can be used for data exfiltration, covert communication, or experimenting with ICMP-based data transfer methods. This is just a proof of concept for a Network Security course at DHBW Mannheim.

## Overview

This project provides two primary scripts:

1. **Listener/Receiver Script** (`listener.py`):
   - Listens for incoming ICMP packets.
   - Verifies the integrity of received data using CRC32 checksums.
   - If verification succeeds, it sends back a confirmation packet (with a `load = b'\x01'` to indicate success) and appends the decoded data into an output file.
   - If verification fails, it sends back a failure packet (with a `load = b'\x00'`) and attempts to reprocess incoming packets.
   - Captured packets are saved to a `.pcap` file for further analysis.

2. **Sender Script** (`sender.py`):
   - Reads a local file (e.g., `Robotergesetze.txt`), Base64-encodes its contents, and chunks it into ICMP echo-request packets.
   - Each packet includes a packet number, the chunk of Base64 data, and a CRC32 checksum.
   - After sending each packet, it waits for a response. If the listener verifies the checksum and responds accordingly, the sender proceeds to the next chunk.
   - All sent and received packets are also saved to a `.pcap` file.

**Note:** Both scripts rely on the `scapy` library for packet crafting, sending, and sniffing.

## Features

- **ICMP-based Data Transfer:** Uses ICMP echo-request packets to transmit data, making it blend in with normal ping traffic.
- **Integrity Checking:** Each packet includes a CRC32 checksum. The receiver verifies this before writing data to the output.
- **Adaptive Packet Sending:** The sender waits for a positive acknowledgment (checksum-verified packet) before sending the next data chunk.
- **PCAP Logging:** Both scripts log captured and sent packets to `.pcap` files, allowing offline analysis with tools like Wireshark.

## Requirements

- Python 3.x
- [Scapy](https://scapy.net/) (`pip install scapy`)
- `zlib` (usually included with Python)
- `base64` (usually included with Python)
- `os` and `time` (usually included with Python)
- A file to transmit (for example `Robotergesetze.txt`)

**Note:** Running raw packet operations may require root or elevated privileges.

## Usage

### Receiver Setup

1. **Adjust Target IP Address:**  
   In `listener.py`, set the `ip_dst` variable to the target IP address (the machine running the sender script).

   ```python
   ip_dst = "172.16.10.32"  # Modify this as needed
   ```

2. **Run the Listener:**
   ```bash
   sudo python3 listener.py
   ```

   The script will:
   - Initialize and clear the output files (`received_packets.pcap` and `reconstructed_data.txt`).
   - Start listening for ICMP packets.
   - For verified packets, it decodes and writes the content to `reconstructed_data.txt`.

### Sender Setup

1. **Prepare the File:**
   Place the file you want to transmit (`Robotergesetze.txt`) in the same directory as `sender.py`.  
   You can modify the filename in the script:
   ```python
   filename = "./Robotergesetze.txt"
   ```

2. **Adjust Target IP Address:**
   In `sender.py`, set `ip_dst` to the IP address of the listener machine:
   ```python
   ip_dst = "172.16.10.32"  # Modify as needed
   ```

3. **Run the Sender:**
   ```bash
   sudo python3 sender.py
   ```

   The script will:
   - Base64-encode the content of the file.
   - Split it into chunks of `packet_size` bytes.
   - Send each chunk as an ICMP packet, followed by a wait for verification.

### Result

- After all packets have been verified and received, the listener writes the full decoded data to `reconstructed_data.txt`.
- Examine `received_packets.pcap` and `sent_packets.pcap` with Wireshark or another packet analyzer for verification and analysis.

## Troubleshooting

- **Permission Errors:**  
  If you encounter permission issues, try running the scripts with `sudo`.
  
- **No Packets Received:**  
  Ensure that the target IP is reachable and correct, and that no firewall rules block ICMP packets.

- **CRC Verification Fails Repeatedly:**  
  Check network reliability. Packet corruption or truncation can lead to invalid CRCs. Also, verify that `packet_size` in `sender.py` is not too large.


