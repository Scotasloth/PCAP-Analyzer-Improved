import networkx as nx
import matplotlib.pyplot as plt
import re
from parsePcap import *

def makeModel(pcapFile):
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