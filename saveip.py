from selectdir import *
from tkinter.filedialog import asksaveasfile
from parsePcap import *
from packettype import *

def saveFile(pcapFile):
    ip = parsePcap(pcapFile)

    files = [('Text Document', '*.txt')]
    file = asksaveasfile(filetypes = files, defaultextension = files)

    for keys, value in ip.items():
        valueStr = str(value)
        data = keys + " " + valueStr 
        file.write(data + "\n")

    file.write(packetType(pcapFile))
    file.close


    
    
