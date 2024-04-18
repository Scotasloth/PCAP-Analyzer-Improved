from customtkinter import * 
from tkinter.filedialog import askopenfilename, asksaveasfile
import socket, dpkt, re, base64, datetime
import networkx as nx
import matplotlib.pyplot as plt
import geoip2, simplekml
import geoip2.database
import os

def main():

    root = CTk()
    root.geometry("700x500")
    root.title("PCAP Analyzer Requeim")
    set_appearance_mode("dark")

    button_frame = CTkFrame(master=root, fg_color="#8D6F3A", width=400, height=300)
    button_frame.pack(expand=True)

    CTkButton(master=button_frame, text="Read PCAP", command =lambda:get_pcap()).place(relx=.3, rely=.1, anchor="center")
    CTkButton(master=button_frame, text="Save IP Info", command=lambda:save_file()).place(relx=.3, rely=.3, anchor="center")
    CTkButton(master=button_frame, text="Create Network Model", command=lambda:net_model(pcap)).place(relx=.3, rely=.5, anchor="center")
    CTkButton(master=button_frame, text="Create Graph", command=lambda:graph(pcap)).place(relx=.7, rely=.3, anchor="center")
    CTkButton(master=button_frame, text="Geolocation", command=lambda:geo(pcap)).place(relx=.7, rely=.1, anchor="center")
    CTkButton(master=button_frame, text="Exctract Data", command=lambda: extract(pcap, root)).place(relx=.7, rely=.5, anchor="center")

    global pcap_name

    pcap_name = StringVar()

    CTkLabel(master=root, textvariable=pcap_name).place(relx=.5, rely=.9, anchor="center")

    root.mainloop()

def get_pcap():
    filetypes = (
        ('pcap files', '*.pcap'),
    )
    global pcap
    pcap = askopenfilename(title='Select File', initialdir='*\PCAP Analyzer Improved', filetypes=filetypes )
    pcap_name.set(pcap)

def save_file():
    global pcap 
    if pcap is None:
        print("No pcap file selected.")
        return
    
    ip = parsePcap(pcap)

    files = [('Text Document', '*.txt')]
    file = asksaveasfile(filetypes = files, defaultextension = files)

    for keys, value in ip.items():
        valueStr = str(value)
        data = keys + " " + valueStr 
        file.write(data + "\n")

    file.write(packet_type(pcap))
    file.close

def selectDir():
    dir = None
    
    print("i exist")

def net_model(pcap):
    pcap = parsePcap(pcap)

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

def parsePcap(pcap):
    f = open(pcap, 'rb')
    pcap = dpkt.pcap.Reader(f)
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


def packet_type(pcap):
    
    try:
        f = open(pcap, 'rb')
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

def geo(pcap):
    ip = parsePcap(pcap)

    files = [('KML Document', '*.kml')]
    kmlName = asksaveasfile(filetypes = files, defaultextension = files)

    kml = simplekml.Kml()

    for keys, value in ip.items():
        try:
            srcip = re.search(r'^\d+\.\d+\.\d+\.\d+', keys)
            dstip = re.search(r'\s\d+\.\d+\.\d+\.\d+', keys)
        
            reader = geoip2.database.Reader(r'C:\Users\Ross\OneDrive\Documents\Programs\Python\PCAP Analyzer Improved\GeoLite2-City_20190129.mmdb')
            type(reader)
            rec = reader.city(f'{srcip.group()}')
        
            pnt = kml.newpoint(name = f'{srcip.group()}', coords = [(rec.location.longitude, rec.location.latitude)])

        except Exception as err:
            print(f'{err}')

        try:
            # Save the KML file with the correct extension
            kml_filename = kmlName.name
            if not kml_filename.endswith('.kml'):
                kml_filename += '.kml'

            # Save the KML file
            kml.save(kml_filename)

            # Print a message indicating the successful save
            print(f'File {kml_filename} has been saved')

        except Exception as err:
            print(f'Error saving KML file: {err}')

def extract(pcap, root):
    new_window = CTkToplevel(root)
    new_window.geometry("150x150")

    CTkButton(master=new_window, text="Email", command=lambda:extract_email(pcap)).place(relx=.5, rely=.3, anchor="center")

    CTkButton(master=new_window, text="Images", command=lambda:extract_image(pcap)).place(relx=.5, rely=.5, anchor="center")
    

def extract_image(pcap):
    try:
        f = open(pcap, 'rb')
        pcap= dpkt.pcap.Reader(f)

        for timestamp, buf in pcap:

            eth = dpkt.ethernet.Ethernet(buf)

            if eth.type != dpkt.ethernet.ETH_TYPE_IP:
                continue
            
            ip = eth.data
            if ip.p != dpkt.ip.IP_PROTO_TCP:
                continue
            
            tcp = ip.data
            if tcp.dport != 80 and tcp.sport != 80:
                continue    

            http_data = tcp.data.decode("utf-8", errors="ignore")
            image_match = re.findall(r'Content-Type: image/png\r\n\r\n([\s\S]+)', http_data)
            print(image_match)

            for img_data in image_match:

                    image = base64.b64decode(img_data)
    
                    with open(f'image_{timestamp}.png', 'wb') as img_file:
                        img_file.write(image)
                    print(f"Image extracted and saved: image_{timestamp}.png")

    except Exception as e:  
        print(f"Error: {e}")

def extract_email(pcap):
    try:
        f = open(pcap, 'rb')
        pcap= dpkt.pcap.Reader(f)

        files = [('Text Document', '*.txt')]
        file = asksaveasfile(filetypes = files, defaultextension = files)

        for timestamp, buf in pcap:

            eth = dpkt.ethernet.Ethernet(buf)
            if eth.type != dpkt.ethernet.ETH_TYPE_IP:
                continue
            
            ip = eth.data
            if ip.p != dpkt.ip.IP_PROTO_TCP:
                continue
            
            tcp = ip.data
            if tcp.dport == 25 and tcp.sport == 25:
                continue
            
            email_addresses = re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', tcp.data.decode('utf-8', errors='ignore'))
            for email in email_addresses:
                file.write(email + "\n")
                
    except Exception as e:  
        print(f"Error: {e}")

def graph(pcap):
    print("i exist") 

def meanAvg(val1, val2):
    mean = val1/val2

    return mean

if __name__ == '__main__':
    main()