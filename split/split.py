#!/usr/bin/env python
#-*- coding:utf-8 -*-
import sys
import os
import argparse
import scapy.all

def makeQuadruple(pcapDir, outDir):
    count = 0
    result = os.popen("tshark -r " + pcapDir + " -R \"udp\" -Tfields -e ip.addr -e udp.port")
    dic = {}
    for i in result.readlines():
        if(i.count(',') != 2):
           continue
        tmp = i.split('\t')
        ip = tmp[0]
        port = tmp[1]
        ip1 = ip.split(',')[0]
        ip2 = ip.split(',')[1]

        port1 = int(port.split(',')[0])
        port2 = int(port.split(',')[1])

        if( ip1 > ip2 ):
            ip1, ip2 = ip2, ip1
            port1, port2 = port2, port1
        quadruple = ('UDP', ip1, port1, ip2, port2)
        dic[quadruple] = outDir + '/' + "UDP-" + ip1 + ":" + str(port1) + "-" + ip2 + ":" + str(port2) + ".pcap"
        count = count + 1
        print dic[quadruple]

    #print dic
    result = os.popen("tshark -r " + pcapDir + " -R \"tcp\" -Tfields -e ip.addr -e tcp.port")
    #dic = {}
    for i in result.readlines():
        if(i.count(',') != 2):
           continue
        tmp = i.split('\t')
        ip = tmp[0]
        port = tmp[1]
        ip1 = ip.split(',')[0]
        ip2 = ip.split(',')[1]

        port1 = int(port.split(',')[0])
        port2 = int(port.split(',')[1])

        if( ip1 > ip2 ):
            ip1, ip2 = ip2, ip1
            port1, port2 = port2, port1
        quadruple = ('TCP', ip1, port1, ip2, port2)
        dic[quadruple] = outDir + '/' + "TCP-" + ip1 + ":" + str(port1) + "-" + ip2 + ":" + str(port2) + ".pcap"
        count = count + 1
        print dic[quadruple]
    return dic

        
class SplitWorker(object):
    def __init__(self,pcapName,outPcapdir):
        self.pcapName = pcapName
        self.outPcapdir = outPcapdir
        self.tupleDict = None
        self.tupleNameDict = {} #四元组作为Key
        
    def run(self):
        currdir = os.curdir

        self.tupleDict = makeQuadruple(self.pcapName, self.outPcapdir)         # 生成四元组
        self.splitePcap(self.pcapName,self.outPcapdir)       # 分割pcap
        

    def splitePcap(self,pcapName,outPcapdir):
        
        #print "helloworkd",self.tupleDict
        the_result_writer={}
        self.tupleNameDict = self.tupleDict
        print "helloworld",self.tupleNameDict
        print "begin"
        
        aReader = scapy.utils.PcapReader(pcapName)
        #for pkt in scapy.utils.PcapReader(pcapName):
        while True:
            pkt = aReader.read_packet()
            if pkt is None :
                print "finish read pcap"
                break
            try:
                if pkt.type != 2048:
                    continue
            except:
                continue

            try:
                if pkt.payload.proto == 6   :
                    #print type(pkt.payload.src)
                    src_key = ("TCP",pkt.payload.src,pkt.payload.sport,pkt.payload.dst,pkt.payload.dport)
                    src_reverse_key = ("TCP",pkt.payload.dst,pkt.payload.dport,pkt.payload.src,pkt.payload.sport)

                elif pkt.payload.proto == 17  :
                    #print type(pkt.payload.src)
                    src_key = ("UDP",pkt.payload.src,pkt.payload.sport,pkt.payload.dst,pkt.payload.dport)
                    src_reverse_key = ("UDP",pkt.payload.dst,pkt.payload.dport,pkt.payload.src,pkt.payload.sport)
            except:
                continue
            #print "src_key",src_key
            #print "src_reverse_key",src_reverse_key
            # just use ip to check
            try:
                #print type(pkt.payload.src)
                ip_src_key = ("IP",pkt.payload.src,0,pkt.payload.dst,0)
                ip_src_reverse_key = ("IP",pkt.payload.dst,0,pkt.payload.src,0)

            except:
                continue

            tupKeys = self.tupleNameDict.keys()
                                    
            if src_key in tupKeys or src_reverse_key in tupKeys or ip_src_key in tupKeys  or ip_src_reverse_key in tupKeys:
                #print "herehaskey"
                if src_key in tupKeys:
                    print "src_key in keys" ,src_key
                    pktdump = scapy.all.PcapWriter(self.tupleNameDict[src_key] , append=True, sync=True)
                    pktdump.write(pkt)
                    pktdump.close()
                    continue
                    
                if src_reverse_key in tupKeys:
                    print "src_reverse_key in keys" ,src_reverse_key                    
                    pktdump = scapy.all.PcapWriter(self.tupleNameDict[src_reverse_key] , append=True, sync=True)
                    pktdump.write(pkt)
                    pktdump.close()
                    continue
                
                if ip_src_key in tupKeys:
                    print "ip_src_key in keys" ,ip_src_key
                    pktdump = scapy.all.PcapWriter(self.tupleNameDict[ip_src_key] , append=True, sync=True)
                    pktdump.write(pkt)
                    pktdump.close()
                    continue

                if ip_src_reverse_key in tupKeys:
                    print "ip_src_reverse_key in keys" ,ip_src_reverse_key                    
                    pktdump = scapy.all.PcapWriter(self.tupleNameDict[ip_src_reverse_key] , append=True, sync=True)
                    pktdump.write(pkt)
                    pktdump.close()
                    continue
        
        
# use dir to parse arg is list        
def HandleArg(passarg):

    argParser = argparse.ArgumentParser()
    argParser.add_argument("-p",dest="pcap",help="一次分析大的pcap")
    argParser.add_argument("-o",dest='outpcapdir',help= "分割后pcap存放的目录")

    args = argParser.parse_args(passarg)
    if args.pcap is None or args.outpcapdir is None :
        print "any option should offer, use -h to see how to use"
        sys.exit(1)

    pcapName = args.pcap
    outPcapdir = args.outpcapdir

    if os.path.exists(outPcapdir):
        pass
    else:
        #shutil.rmtree(outPcapdir)
        os.mkdir(outPcapdir)


    splitWorker = SplitWorker(pcapName,outPcapdir)
    splitWorker.run()
        

    pass


    
if __name__ == "__main__":
    HandleArg(sys.argv[1:])
    
