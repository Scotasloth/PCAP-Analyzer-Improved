import dpkt
import datetime
from Average import *

def tcpTime():
    tcpTs = 0
    print("i exist")

    
def udpTime():
    udpTs = 0
    print("i exist")


def igmpTime():
    igmpTs = 0
    print("i exist")


def packetType(pcapFile):
    
    try:
        f = open(pcapFile, 'rb')
        pcap = dpkt.pcap.Reader(f)

        tcp = 0
        udp = 0
        igmp = 0
        udp_ts = 0
        tcp_len = 0
        tcp_total = 0
        udp_len = 0
        udp_total = 0
        igmp_len = 0
        igmp_total = 0
        
        for ts, buf in pcap:
        
            eth = dpkt.ethernet.Ethernet(buf)
            
            ip = eth.data

            #checks wwhat type of packet is present
            #and gets the information from it
            if (ip.p == 6):
                tcp = tcp + 1
                tcp_total = tcp_total + len(buf)
                tcp_len = tcp_len + 1
                tcp_ts2 = str(datetime.datetime.utcfromtimestamp(ts))
                
            elif (ip.p == 17):
                udp = udp + 1
                udp_total = udp_total + len(buf)
                udp_len = udp_len + 1
                udp_ts2 = str(datetime.datetime.utcfromtimestamp(ts))
                
            elif (ip.p == 2):
                igmp = igmp + 1
                igmp_total = igmp_total + len(buf)
                igmp_len = igmp_len + 1
                igmp_ts2 = str(datetime.datetime.utcfromtimestamp(ts))

            #gets the first timestamp of the packet type
            if (tcp == 1):
                tcp_ts = str(datetime.datetime.utcfromtimestamp(ts))
                
            elif (udp == 1):
                udp_ts = str(datetime.datetime.utcfromtimestamp(ts))
                
            elif (igmp == 1):
                igmp_ts = str(datetime.datetime.utcfromtimestamp(ts))
            
        mean_tcp = meanAvg(tcp_total, tcp_len)
        mean_udp = meanAvg(udp_total, udp_len)
        mean_igmp = meanAvg(igmp_total, igmp_len)

        tcpStr = str(tcp)
        tcpAvgStr = str(mean_tcp)
        udpStr = str(udp)
        udpAvgStr = str(mean_udp)
        igmpStr = str(igmp)
        igmpAvgStr = str(mean_igmp)

        tcpOut = "\n" + "TCP " + tcpStr + "\n" + "FIRST TIMESTAMP " + tcp_ts + "\n" + "LAST TIMESTAMP " + tcp_ts2 + "\n" + "MEAN LENGTH " + tcpAvgStr + "\n" 
        udpOut =  "\n" + "UDP " + udpStr + "\n" + "FIRST TIMESTAMP " + udp_ts + "\n" + "LAST TIMESTAMP " + udp_ts2 + "\n" + "MEAN LENGTH " + udpAvgStr + "\n"
        igmpOut =  "\n" + "IGMP " + igmpStr + "\n" + "FIRST TIMESTAMP " + igmp_ts + "\n" + "LAST TIMESTAMP " + igmp_ts2 + "\n" + "MEAN LENGTH " + igmpAvgStr + "\n"

        output = tcpOut + udpOut + igmpOut
        return output

    except Exception as err:
        print(f'{err}')