from tkinter import *
from tkinter.filedialog import askopenfilename

def openFile():
    filetypes = (
        ('pcap files', '*.pcap'),
    )

    pcapFile = askopenfilename(title='Select File', initialdir='*\PCAP Analyzer Improved', filetypes=filetypes )

    return pcapFile