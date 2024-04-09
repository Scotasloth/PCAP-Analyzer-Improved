from PIL import ImageTk,Image
import sys
import os
from customtkinter import * 
from tkinter.filedialog import askopenfilename
from tkinter.filedialog import asksaveasfile
import dpkt 
import socket 
import datetime
import networkx as nx
import matplotlib.pyplot as plt
import geoip2
import simplekml
import re

pcapFile = "main.py"

def main():

    root = CTk()
    root.geometry("500x500")
    root.title("PCAP Analyzer Requeim")

    CTkButton(master=root, text="Read PCAP", command =lambda:get_pcap()).place(relx=.5, rely=.5, anchor="center")
    CTkButton(master=root, text="Save IP Info", command=lambda:save_ile()).place(relx=.5, rely=.7, anchor="center")
    CTkButton(master=root, text="Create Network Model", command=lambda:net_model()).place(relx=.9, rely=.5, anchor="center")
    CTkButton(master=root, text="Create Graph", command=lambda:geo()).place(relx=.9, rely=.3, anchor="center")
    CTkButton(master=root, text="Geolocation", command=lambda:graph()).place(relx=.9, rely=.1, anchor="center")

    root.mainloop()

def get_pcap():
    filetypes = (
        ('pcap files', '*.pcap'),
    )

    pcapFile = askopenfilename(title='Select File', initialdir='*\PCAP Analyzer Improved', filetypes=filetypes )

    return pcapFile

def save_ile():
    ip = parsePcap(pcapFile)

    files = [('Text Document', '*.txt')]
    file = asksaveasfile(filetypes = files, defaultextension = files)

    for keys, value in ip.items():
        valueStr = str(value)
        data = keys + " " + valueStr 
        file.write(data + "\n")

    file.write(packet_type(pcapFile))
    file.close

def selectDir():
    dir = None
    
    print("i exist")

def net_model():
    pcap = parsePcap(pcapFile)

    g = nx.Graph()

    for keys, value in pcap.items():
        srcip = re.search(r'^\d+\.\d+\.\d+\.\d+', keys)  
        dstip = re.search(r'\s\d+\.\d+\.\d+\.\d+', keys)
       
        g.add_nodes_from([f'{srcip.group()}', f'{dstip.group()}'])
        g.add_edge(f'{srcip.group()}', f'{dstip.group()}', width = 6)       
          
    pos = nx.spring_layout(g,k=0.15,iterations=20)

    nx.draw_networkx(g, pos)
    plt.savefig("Network.png", format="PNG")
    print('Network.png has been saved successfully')
    plt.show()

def parsePcap():
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
      
        ipDict[key]= ipDict.setdefault(key, 0) + 1

    f.close()

    #prints all keye and values in dictionary
    #for keys, value in ipDict.items():
            #print(keys, value)
    return ipDict  

def tcpTime():
    tcpTs = 0
    print("i exist")

    
def udpTime():
    udpTs = 0
    print("i exist")


def igmpTime():
    igmpTs = 0
    print("i exist")


def packet_type():
    
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

def geo():
    ip = parsePcap()

    files = [('KML Document', '*.kml')]
    kmlName = asksaveasfile(filetypes = files, defaultextension = files)

    for keys, value in ip.items():
        try:
            srcip = re.search(r'^\d+\.\d+\.\d+\.\d+', keys)
            dstip = re.search(r'\s\d+\.\d+\.\d+\.\d+', keys)
        
            reader = geoip2.database.Reader(r'*\PCAP Analyzer Improved\GeoLite2-City_20190129.mmdb')
            type(reader)
            rec = reader.city(f'{srcip.group()}')
           

            kml = simplekml.Kml()
            pnt = kml.newpoint(name = f'{srcip.group()}', coords = [(rec.location.longitude, rec.location.latitude)])
            
            print(f'File {kmlName} has been saved')
            kml.save(f'{kmlName}.kml')

        except Exception as err:
            print(f'{err}')

def extract():
    f = open(pcapFile, 'rb')
    pcap= dpkt.pcap.Reader(f)

def graph():
    print("i exist") 

def meanAvg(val1, val2):
    mean = val1/val2

    return mean

def medianAvg():
    return


def modeAvg():
    return

if __name__ == '__main__':
    main()