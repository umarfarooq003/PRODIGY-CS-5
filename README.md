# Packet Sniffer

A simple packet sniffer implemented using the `scapy` library to capture and analyze network packets.

## Features

- Captures IP packets.
- Identifies and prints the source and destination IP addresses.
- Detects the transport layer protocol (TCP or UDP).
- Displays the payload of TCP/UDP packets.
- Saves captured packets to a `pcap` file.

## Dependencies

- `scapy`

## Installation

1. Clone the repository:
    ```bash
    git clone <repository_url>
    ```
2. Navigate to the project directory:
    ```bash
    cd <repository_name>
    ```
3. Install the required Python package:
    ```bash
    pip install scapy
    ```

## Usage

1. Run the script with root/administrator privileges:
    ```bash
    sudo python packet_sniffer.py
    ```
2. The sniffer will start capturing packets and printing the details to the console.
3. Captured packets will be saved to `captured_packets.pcap` in the same directory as the script.

## File

- `packet_sniffer.py`

```python
from scapy.all import sniff, conf, wrpcap
from scapy.layers.inet import IP, TCP, UDP

# List to hold captured packets
captured_packets = []

def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst

        protocol = None
        if packet.haslayer(TCP):
            protocol = "TCP"
        elif packet.haslayer(UDP):
            protocol = "UDP"

        print(f"IP Packet: {ip_src} -> {ip_dst} | Protocol: {protocol}")

        # Display payload if available
        if packet.haslayer(TCP) or packet.haslayer(UDP):
            payload = packet[TCP].payload if packet.haslayer(TCP) else packet[UDP].payload
            print(f"Payload: {payload}\n")

        # Append the packet to the list
        captured_packets.append(packet)

if __name__ == "__main__":
    print("Starting packet sniffer...")
    # Use Scapy's layer 3 socket for sniffing
    conf.L3socket = conf.L3socket
    # Sniff packets and run packet_callback for each packet
    sniff(prn=packet_callback, store=0)

    # Save captured packets to a pcap file
    if captured_packets:
        filename = "captured_packets.pcap"
        wrpcap(filename, captured_packets)
        print(f"Captured packets saved to {filename}")
    else:
        print("No packets were captured.")
```
# License
This project is licensed under the MIT License.

# Author 
`Umar Farooq`
