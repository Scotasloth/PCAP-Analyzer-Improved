from parsePcap import *
import dpkt
import socket

def extract(pcapFile):
    f = open(pcapFile, 'rb')
    pcap= dpkt.pcap.Reader(f)

    