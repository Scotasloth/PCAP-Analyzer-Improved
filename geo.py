from tkinter import *
from parsePcap import *
from tkinter.filedialog import asksaveasfile
import geoip2
import simplekml
import re


def geoLoc(pcapFile):
    global ip
    ip = parsePcap(pcapFile)

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

   
    