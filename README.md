# Network Scanner

This is a simple network scanner script written in Python that allows you to perform both host discovery using ARP scan and port scanning using TCP SYN scan. It utilizes the Scapy library for sending and receiving network packets.

## Features

- ARP scan: Discover hosts on the network by sending ARP requests and collecting responses.
- TCP SYN scan: Scan a target host or domain for open ports by sending TCP SYN packets and analyzing the responses.
- Flexible input: Specify the target IP address or IP range and port range via command-line arguments or user prompts.

## Requirements

- Python 3.x
- Scapy library (`pip install scapy`)

## Usage

1. Clone or download the script from the GitHub repository.
2. Install the required dependencies (`pip install scapy`).
3. Run the script from the command line using the following options:

```shell
python network_scanner.py [-h] [-t TARGET] [-p PORTS]
```

- `-t/--target`: Specify the target IP address or IP range to scan (e.g., `192.168.0.1` or `192.168.0.1/24`).
- `-p/--ports`: Specify the port range to scan (e.g., `1-100`). If not provided, the script will prompt you to enter the port range.

### Examples

1. Perform an ARP scan on a specific IP range and TCP SYN scan on the specified port range:

```shell
python network_scanner.py -t 192.168.0.1/24 -p 1-100
```

2. Perform a TCP SYN scan on a specific IP or domain and port range:

```shell
python network_scanner.py -t example.com -p 1-1000
```

3. Run the script without command-line arguments (interactive mode):

```shell
python network_scanner.py
```

## Note

- Ensure that you have the necessary permissions to send and receive network packets (superuser/administrator access may be required).
- Be mindful of the potential legal and ethical implications of scanning networks and hosts without proper authorization. Always seek permission and adhere to applicable laws and regulations.

Feel free to contribute, provide feedback, or report any issues via the GitHub repository. Happy scanning!