# Linux Network Packet Sniffer

A comprehensive Python-based network packet analyzer specifically designed for Linux systems. This tool captures and analyzes Ethernet frames and network packets at the data link layer (Layer 2) using raw sockets and the `AF_PACKET` socket family.

## 🚀 Key Features

- **Full Ethernet Frame Analysis**: Complete Layer 2 packet capture including MAC addresses
- **Multi-Protocol Support**: IPv4, IPv6, ARP, TCP, UDP, ICMP parsing
- **Real-time Monitoring**: Live network traffic analysis
- **Detailed Protocol Breakdown**: Headers, flags, and payload inspection
- **Raw Socket Implementation**: Low-level Linux networking demonstration
- **Enhanced Data Visualization**: Hex and text payload representation

## 🔧 Linux-Specific Advantages

This version leverages Linux's powerful networking capabilities:

- **`AF_PACKET` Sockets**: Direct access to Layer 2 (Ethernet) frames
- **Complete Frame Capture**: See actual MAC addresses and Ethernet protocols
- **Protocol Diversity**: Capture ARP, IPv6, and other non-IP traffic
- **Network Interface Binding**: Monitor specific network interfaces
- **Promiscuous Mode Support**: Capture all network traffic (with modifications)

## 📋 Requirements

- **Linux Operating System** (Ubuntu, CentOS, Debian, etc.)
- **Python 3.6+**
- **Root/sudo privileges** (required for raw socket creation)
- **Active network interface**

## 🛠️ Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/yourusername/linux-packet-sniffer.git
   cd linux-packet-sniffer
   ```

2. **No additional dependencies required** - uses only Python standard library

## 🚀 Usage

### Basic Usage
```bash
sudo python3 linux_sniffer.py
```

### Monitor Specific Interface (with modifications)
```bash
# Bind to specific interface (requires code modification)
sudo python3 linux_sniffer.py eth0
```

### Sample Output
```
Linux Packet Sniffer Started...
Capturing all ethernet frames...
Press Ctrl+C to stop
============================================================

Ethernet Frame:
	 - Destination: AA:BB:CC:DD:EE:FF, Source: 11:22:33:44:55:66, Protocol: 8
	 - IPv4 Packet:
		 - Version: 4, Header length: 20, TTL: 64
		 - Protocol: 6, Source: 192.168.1.100, Target: 93.184.216.34
	 - TCP Segment:
		 - Source Port: 52442, Destination Port: 80
		 - Sequence: 1234567890, Acknowledgement: 9876543210
		 - Flags:
			 - URG: 0, ACK: 1, PSH: 1, RST: 0, SYN: 0, FIN: 0
		 - Data:
			 Text: GET / HTTP/1.1
			 Host: example.com
			 User-Agent: Mozilla/5.0...
```

## 📊 Supported Protocols

### Layer 2 (Data Link)
- **Ethernet II**: Standard Ethernet frames
- **Protocol Detection**: IPv4, IPv6, ARP identification

### Layer 3 (Network)
- **IPv4**: Complete header analysis
- **IPv6**: Basic packet identification
- **ARP**: Address Resolution Protocol
- **ICMP**: Internet Control Message Protocol

### Layer 4 (Transport)
- **TCP**: Transmission Control Protocol with flag analysis
- **UDP**: User Datagram Protocol

## 🏗️ Architecture

```
┌─────────────────────────────────────┐
│           Raw Socket                │
│        (AF_PACKET)                  │
└─────────────────────────────────────┘
                    │
                    ▼
┌─────────────────────────────────────┐
│        Ethernet Frame               │  ← Layer 2
│  [Dest MAC][Src MAC][EtherType]     │
└─────────────────────────────────────┘
                    │
                    ▼
┌─────────────────────────────────────┐
│         IPv4 Packet                 │  ← Layer 3
│   [Version][TTL][Protocol][IPs]     │
└─────────────────────────────────────┘
                    │
                    ▼
┌─────────────────────────────────────┐
│      TCP/UDP/ICMP Segment           │  ← Layer 4
│    [Ports][Flags][Sequence]         │
└─────────────────────────────────────┘
```

## 📁 File Structure

```
linux-packet-sniffer/
├── linux_sniffer.py       # Main packet sniffer
├── README.md              # This documentation
├── examples/              # Usage examples
│   ├── tcp_analysis.py    # TCP-specific analysis
│   ├── arp_monitor.py     # ARP packet monitoring
│   └── bandwidth_monitor.py # Traffic analysis
├── filters/               # Packet filtering utilities
│   ├── protocol_filter.py
│   └── ip_filter.py
└── utils/                 # Utility functions
    ├── packet_parser.py
    └── data_formatter.py
```

## 🔍 Advanced Features

### Protocol-Specific Analysis

**TCP Connection Tracking**:
```python
# Monitor TCP handshake
if flag_syn and not flag_ack:
    print("TCP Connection Initiated")
elif flag_syn and flag_ack:
    print("TCP Connection Acknowledged")
```

**ARP Monitoring**:
```python
# Detect ARP requests/responses
if eth_proto == 1544:  # ARP
    print("ARP Traffic Detected")
```

### Custom Filtering

Add packet filtering by modifying the main loop:
```python
# Filter by IP address
if src == "192.168.1.1" or target == "192.168.1.1":
    # Process only packets from/to specific IP
```

## 🛡️ Security Considerations

### Legal Usage
- ✅ **Authorized networks only**
- ✅ **Personal learning environments**
- ✅ **Network troubleshooting with permission**
- ❌ **Unauthorized network monitoring**
- ❌ **Corporate networks without explicit permission**

### Ethical Guidelines
- Use in isolated lab environments
- Respect privacy and data protection laws
- Only capture your own network traffic
- Follow responsible disclosure for vulnerabilities

## 🐛 Troubleshooting

### Common Issues

**Permission Denied**:
```bash
PermissionError: [Errno 1] Operation not permitted
```
**Solution**: Run with sudo privileges
```bash
sudo python3 linux_sniffer.py
```

**No Packets Captured**:
- Check network interface status: `ip link show`
- Verify network activity: `ping google.com`
- Check firewall rules: `sudo iptables -L`

**AF_PACKET Not Available**:
```bash
AttributeError: module 'socket' has no attribute 'AF_PACKET'
```
**Solution**: This version is Linux-specific. Use macOS or Scapy version on other platforms.

## 📈 Performance Optimization

### High-Traffic Networks
- Implement packet filtering to reduce processing
- Use ringbuffer for packet storage
- Consider multithreading for analysis

### Memory Management
- Limit packet data display
- Implement packet rotation
- Use generators for large datasets

## 🔄 Contributing

1. Fork the repository
2. Create feature branch (`git checkout -b feature/packet-analysis`)
3. Implement changes with proper testing
4. Add documentation and examples
5. Submit pull request

### Development Setup
```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install development dependencies
pip install -r requirements-dev.txt

# Run tests
python -m pytest tests/
```

## 📚 Educational Resources

- [Linux Network Programming](https://man7.org/linux/man-pages/man7/packet.7.html)
- [AF_PACKET Documentation](https://man7.org/linux/man-pages/man7/packet.7.html)
- [Ethernet Frame Format](https://en.wikipedia.org/wiki/Ethernet_frame)
- [TCP/IP Protocol Suite](https://tools.ietf.org/rfc/rfc793.txt)

## 🏆 Advanced Usage Examples

### Monitor Specific Protocol
```bash
# Monitor only TCP traffic (requires code modification)
sudo python3 linux_sniffer.py --protocol tcp

# Monitor specific port
sudo python3 linux_sniffer.py --port 80
```

### Save Packets to File
```bash
# Capture and save (requires implementation)
sudo python3 linux_sniffer.py --output packets.pcap
```


## 🙏 Acknowledgments

- Linux kernel networking subsystem
- Python socket programming community
- Network security research community
- Open source packet analysis tools

---

**⚠️ Important**: This tool is designed for educational purposes and authorized network analysis only. Users must ensure compliance with local laws and regulations regarding network monitoring and data privacy.
