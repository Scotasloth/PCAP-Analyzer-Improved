from choosefile import *
from geo import *
from parsePcap import *
from tkinter import *
from saveip import *
from graphcreate import *
from networkmodel import *
from extract import *
from PIL import ImageTk,Image
import sys
import os

pcapFile = None

def getPcap():
    global pcapFile
    pcapFile = openFile()
   

def save():
    saveFile(pcapFile)


def getGraph():
    linegraph(pcapFile)


def getNet():
    makeModel(pcapFile)


def getData():
    extract(pcapFile)
    print("i exist")


def geoOpen():
    geoLoc(pcapFile)


def main():
    root = Tk(className=" PCAP Analyzer Requiem") 
 
    program_directory=sys.path[0]
    root.iconphoto(True, PhotoImage(file=os.path.join(program_directory, "arrow.gif")))

    img = ImageTk.PhotoImage(file=os.path.join(program_directory, "GER.png"))

    imgLabel = Label(image=img)
    imgLabel.place(x=0, y=0, relwidth=1, relheight=1)
    title = Label(root, text="PCAP Analyzer Requiem").grid(row=1, column=2)

    pcapButton = Button(root, text="Select PCAP File", padx=66, pady=30, command=getPcap).grid(row=1, column=1)
    geoButton = Button(root, text="Geolocation", padx=62, pady=30, command=geoOpen).grid(row=1, column=3)
    extractButton = Button(root, text="Extract Packet Info", padx=59, pady=30, command=getData).grid(row=2, column=1)
    graphButton = Button(root, text="Create Linegraph", padx=50, pady=30, command=getGraph).grid(row=2, column=3)
    netButton = Button(root, text="Create Network Model", padx=49, pady=30, command=getNet).grid(row=3, column=1)
    saveButton = Button(root, text="Save IP List", padx=66, pady=30, command=save).grid(row=3, column=3)

    root.mainloop()

main()

