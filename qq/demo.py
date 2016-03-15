#!/usr/bin/env python
#coding=utf-8

from scapy.all import *

pcap_path = "qq2.pcap" 

def main():
    pkg = rdpcap(pcap_path)
    hexdump(pkg[0])
    pkg[0].show()
    ls(pkg[0])
    print pkg[0]



if __name__  == "__main__":
    main()
