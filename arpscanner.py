import socket
import os
import scapy
from time import sleep
from scapy.layers.l2 import ARP, Ether
from scapy.all import *

def networkEnum():
    hname = socket.gethostname()
    hipaddy = socket.gethostbyname(hname)
    lastdot = hipaddy.rfind(".")
    networkoctets = hipaddy[:11]
    return hname, hipaddy, networkoctets


"""ARP scanning function tingz"""
def arpscan(netID):
    for o in range(255):
        try:
            targetIP = netID + str(o)
            arprequest = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=targetIP, hwdst="ff:ff:ff:ff:ff:ff")
            response = srp1(arprequest, timeout=1, verbose=0)
            if response:
                print("IP: {}, MAC: {}".format(response.psrc, response.hwsrc))
                time.sleep(.5)
        except:
            print("Something went wrong")

def main():
    hname, hipaddy, networkoctets = networkEnum()
    arpscan(networkoctets)

if __name__ == '__main__':
    main()