import socket
from scapy.all import *
from scapy.layers.inet import IP, ICMP
from scapy.layers.l2 import Ether, ARP

#packet = IP(dst="www.google.com")/ICMP()
#resp = sr1(packet, timeout=1, verbose=0)
#print(resp[IP].src)


def get_details():
    host = socket.gethostname()
    ip = socket.gethostbyname(host)
    net = ip[0:ip.rfind('.') + 1]
    print(net)
    arp_scanner(net)

def arp_scanner(net):
    for port in range(255):
        ip = net + str(port)
        arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip, hwdst="ff:ff:ff:ff:ff:ff")
        response = srp1(arp_request, timeout=1, verbose=0)
        if response:
            print("IP: {}, MAC: {}".format(response.psrc, response.hwsrc))
    time.sleep(0.5)


if __name__=='__main__':
    h_name = socket.gethostname()
    IP_addres = socket.gethostbyname(h_name)
    print("Host Name is: " + h_name)
    print("Computer IP Address is: " + IP_addres)
    get_details()

