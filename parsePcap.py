import dpkt 
import socket 

def parsePcap(pcapFile):
    f = open(pcapFile, 'rb')
    pcap= dpkt.pcap.Reader(f)
    ipDict = {}

    #loops through all ips
    for ts, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)
        ip = eth.data
        tcp = ip.data

       #key for the dictionaty
        key = f'{socket.inet_ntoa(ip.src)} -> { socket.inet_ntoa(ip.dst)}'
      
        packet = 0
        ipDict[key]= ipDict.setdefault(key, 0) + 1

    f.close()

    #prints all keye and values in dictionary
    #for keys, value in ipDict.items():
            #print(keys, value)
    return ipDict