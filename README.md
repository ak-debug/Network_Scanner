
---

# Network Scanner

This is a Python-based network scanner script which is designed to function similarly to tools such as Nmap. It uses Scapy to perform different types of scans including TCP SYN scan, ARP scan, and ICMP ping sweep.

## Features
* TCP SYN scan
* ARP scan
* ICMP ping sweep

## Dependencies
* Python 3
* Scapy

## Usage
You can use this script by running:
```bash
python3 network_scanner.py [-sS | -sA | -P] -t <target> [-p <ports>]
```
The options are as follows:

* `-sS`, `--syn-scan`: Perform a TCP Stealth scan
* `-sA`, `--arp-scan`: Perform an ARP scan
* `-P`, `--ping-sweep`: Perform an ICMP ping sweep
* `-t`, `--target`: Specify the target IP address, domain, or IP range
* `-p`, `--ports`: (Optional) Specify the port range for a TCP SYN scan (e.g., `1-100`). If this option is not used, the script will scan the top 10 most common ports.

## Note
Please note that the TCP SYN scan (`-sS` option) currently does not support scanning multiple IP addresses at once. You would need to scan each IP address individually. On the other hand, the ARP scan and ICMP ping sweep options do support scanning multiple IP addresses at once when an IP range is specified in CIDR notation (e.g., `192.168.1.0/24`).

## Disclaimer
This tool is intended for network analysis and security auditing only. Unauthorized scanning can be illegal and unethical. Always obtain proper permission before scanning networks.

## Contributions
Contributions are welcome! Please feel free to submit a Pull Request.

---

