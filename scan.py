import os, nmap
from xml.dom import minidom



def create_xml(nmScan, host):
    root = minidom.Document()

    xml = root.createElement('device')
    root.appendChild(xml)

    productChild = root.createElement('host')

    productChild.setAttribute('name', nmScan[host].hostname())
    productChild.setAttribute('IP', host)

    for proto in nmScan[host].all_protocols():
        #print('Protocol : %s' % proto)

        lport = nmScan[host][proto].keys()
        # lport.sort()
        for port in lport:
            productChild.setAttribute('ports', nmScan[host][proto][port]['state'])

    xml.appendChild(productChild)

    xml_str = root.toprettyxml(indent="\t")

    save_path_file = "data.xml"

    with open(save_path_file, "w") as f:
        f.write(xml_str)

    #return 0


def DB():

    return 0


def scan_net():
    nmScan = nmap.PortScanner()

    nmScan.scan('192.168.1.0/24')

    for host in nmScan.all_hosts():

        #create_xml(nmScan, host)

        print('Host : %s (%s)' % (host, nmScan[host].hostname()))
        print('State : %s' % nmScan[host].state())
        for proto in nmScan[host].all_protocols():
            print('Protocol : %s' % proto)

            lport = nmScan[host][proto].keys()
            #lport.sort()
            for port in lport:
                print('port : %s\tstate : %s' % (port, nmScan[host][proto][port]['state']))

        print('----------')

