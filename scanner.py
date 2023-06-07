import socket
import scapy.all as scapy
import argparse
import sys

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

def ping_sweep(ip_range):
    request = scapy.IP(dst=ip_range)/scapy.ICMP()
    answered, _ = scapy.sr(request, timeout=1, verbose=False)
    return answered

def arp_scan(ip_range):
    request = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")/scapy.ARP(pdst=ip_range)
    answered, _ = scapy.srp(request, timeout=1, verbose=False)
    return answered

def tcp_stealth_scan(ip, ports):
    open_ports = []
    for port in ports:
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

def print_ping_result(result_list):
    print("IP\t\t\tMAC ADDRESS")
    for _, pkt in result_list:
        print(pkt[scapy.IP].src)

def print_arp_result(result_list):
    print("IP\t\t\tMAC ADDRESS")
    for _, pkt in result_list:
        print(pkt[scapy.ARP].psrc + "\t\t" + pkt[scapy.Ether].src)

def print_ports(open_ports):
    if open_ports:
        print("\nOpen Ports:")
        for port in open_ports:
            print(port)
    else:
        print("\nNo open ports found.")

def main():
    parser = argparse.ArgumentParser(description="Network scanner similar to Nmap")
    parser.add_argument("-sS", "--stealth-scan", action="store_true", help="Perform TCP Stealth scan")
    parser.add_argument("-sA", "--arp-scan", action="store_true", help="Perform ARP scan")
    parser.add_argument("-P", "--ping-sweep", action="store_true", help="Perform ping sweep")
    parser.add_argument("-t", "--target", dest="target", required=True, help="Target IP/Domain")
    parser.add_argument("-p", "--ports", dest="ports", required=False, help="Port range (e.g., 1-100)")
    args = parser.parse_args()

    # Default ports if no port range specified 
    top_ports = [80, 23, 443, 21, 22, 25, 3389, 110, 445, 139]

    if args.stealth_scan:
        if not is_ip_or_domain(args.target):
            print("TCP Stealth scan requires an IP address or domain name.")
            exit(0)
        if args.ports:
            port_range = args.ports.split("-")
            start_port = int(port_range[0])
            end_port = int(port_range[1])
            ports = list(range(start_port, end_port + 1))
        else:
            ports = top_ports
        open_ports = tcp_stealth_scan(args.target, ports)
        print_ports(open_ports)

    elif args.arp_scan:
        if not is_ip_address(args.target):
            print("ARP scan requires an IP address or IP range.")
            exit(0)
        scan_result = arp_scan(args.target)
        print_arp_result(scan_result)

    elif args.ping_sweep:
        if not is_ip_address(args.target):
            print("Ping sweep requires an IP address or IP range.")
            exit(0)
        scan_result = ping_sweep(args.target)
        print_ping_result(scan_result)

if __name__ == "__main__":
    main()
