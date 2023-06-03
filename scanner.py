import socket
import scapy.all as scapy
import argparse
import sys

def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="Target IP/ Domain")
    parser.add_argument("-p", "--ports", dest="ports", help="Port range (e.g., 1-100)")
    options = parser.parse_args()
    return options

def is_ip_address(target):
    try:
        socket.inet_aton(target)
        return True
    except socket.error:
        return False

def is_ip_or_domain(target):
    try:
        socket.inet_aton(target)
        return True
    except socket.error:
        try:
            socket.gethostbyname(target)
            return True
        except socket.gaierror:
            return False

def arp_scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    return answered_list

def tcp_syn_scan(ip, start_port, end_port):
    open_ports = []
    for port in range(start_port, end_port + 1):
        print(f"Checking port {port}...", end="\r")
        sys.stdout.flush()
        ip_packet = scapy.IP(dst=ip)
        tcp_packet = scapy.TCP(dport=port, flags="S")
        packet = ip_packet / tcp_packet
        response = scapy.sr1(packet, timeout=1, verbose=False)
        if response is not None and response.haslayer(scapy.TCP) and response.getlayer(scapy.TCP).flags == 0x12:
            open_ports.append(port)
    print("\n")
    return open_ports

def print_result(result_list, open_ports):
    print("IP\t\t\tMAC ADDRESS")
    for ele in result_list:
        print(ele[1].psrc + "\t\t" + ele[1].hwsrc)

    if open_ports:
        print("\nOpen Ports:")
        for port in open_ports:
            print(port)
    else:
        print("\nNo open ports found.")

if __name__ == "__main__":
    print("Choose the Scan Type")
    print("[1] ARP Scan\n[2] TCP SYN Scan")
    x = input()
    if x == "1":
        options = get_arguments()
        if not options.target:
            options.target = input("Enter IP or IP range: ")
        if not is_ip_address(options.target):
            print("ARP scan requires an IP address or IP range.")
            exit(0)
        if not options.ports:
            options.ports = input("Enter port range (e.g., 1-100): ")
        port_range = options.ports.split("-")
        start_port = int(port_range[0])
        end_port = int(port_range[1])
        scan_result = arp_scan(options.target)
        open_ports = tcp_syn_scan(options.target, start_port, end_port)
        print_result(scan_result, open_ports)
    elif x == "2":
        options = get_arguments()
        if not options.target:
            options.target = input("Enter Destination's IP or Domain: ")
        if not is_ip_or_domain(options.target):
            print("TCP SYN scan requires an IP address or domain name.")
            exit(0)
        if not options.ports:
            options.ports = input("Enter port range (e.g., 1-100): ")
        port_range = options.ports.split("-")
        start_port = int(port_range[0])
        end_port = int(port_range[1])
        open_ports = tcp_syn_scan(options.target, start_port, end_port)
        print("Open Ports:")
        for port in open_ports:
            print(port)
    else:
        print("No such option")
        exit(0)
