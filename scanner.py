from tabnanny import verbose
import scapy.all as scapy
import argparse

def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t","--target",dest="target",help="Target IP/ IP range")
    options= parser.parse_args()
    return options

def scan(ip):
    arp_request= scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast,timeout=1,verbose=False)[0]
    return answered_list

def print_result(result_list):
    print("IP\t\t\tMAC ADDRESS\n")
    for ele in result_list:
        print(ele[1].psrc+"\t\t"+ele[1].hwsrc)


if __name__ == "__main__":
    
    print("Choose the Scan Type")
    print("[1] ARP Scan\n[2] TCP SYN Scan")
    x=input()
    if x=="1": 
        options=get_arguments() 
        if not options.target:
            options.target=input("Enter ip or ip range\n") 
        scan_result=scan(options.target)
        print_result(scan_result)

    elif x=="2":
        destination=input("Enter Destination's IP or Domain\n")
        tcp_pack=scapy.TCP(dport=80,flags="S") #http SYN
        ip_pack=scapy.IP(dst=destination)
        answer=scapy.sr1(ip_pack/tcp_pack)
        print(answer.summary())
    
    else:
        print("No such option")
        exit(0)




