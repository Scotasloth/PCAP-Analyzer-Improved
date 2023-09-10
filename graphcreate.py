from tkinter import *
from parsePcap import *
import matplotlib.pyplot as plt

pcap = None

def linegraph(pcapFile):
    global pcap
    pcap = parsePcap(pcapFile)
    print("i exist")


