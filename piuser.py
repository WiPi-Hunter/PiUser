# coding=utf-8
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from termcolor import colored
#import argparse
import time
import netifaces
import commands
import os


#parser = argparse.ArgumentParser()
#parser.add_argument('-c', '--corp', help="(Company name)", type=str)
#args = parser.parse_args()

banner = """
＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿__
| PiUser -*-    　　　　　　　　　　　　　　　　  [－] [口] [×]   |
| ￣￣￣￣￣￣￣￣￣￣￣￣￣￣￣￣￣￣￣￣￣￣￣￣￣￣￣￣￣￣ ￣ |
|　Analyze user behavior against fake access points               |
|                   　　　　　　                                  |
|　 　　＿＿＿＿＿＿　　　　＿＿＿＿＿＿　　　 ＿＿＿＿＿＿　　   |
| 　 　｜　 WiFi　  |　　  ｜  Threat  ｜ 　  |  Analysis |       |
|　 　　￣￣￣￣￣￣　　　　￣￣￣￣￣￣　　　 ￣￣￣￣￣￣　     |
|＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿ __|

-------------------------------------------------------------------
"""

def Sniff_Probe(pkt):
    if pkt.haslayer(Dot11ProbeReq):
        ssid = pkt.info
        mac  = pkt.addr2
        info = mac+"*-*"+ssid
        #print info
        if info not in probereq_list:
            probereq_list.append(info)

def sniff_channel_hop(iface):
    for i in range(1, 14):
        os.system("iwconfig " + iface + " channel " + str(i))
        sniff(iface=iface, count=60, prn=Sniff_Probe)

def PiUser(probereq_list):
    blackssids = open("blacklist.txt","r").readlines()
    blackssids = [black[:-1].lower() for black in blackssids]
    for black in blackssids:
        for probe in probereq_list:
            ssid = probe.split("*-*")[1]
            mac  = probe.split("*-*")[0]
            if black in ssid.lower():
                mal_probe.append(probe)

"""
def CompanySSIDAnalysis(company_ssids, probereq_list):
    for black in company_ssids:
        for probe in probereq_list:
            ssid = probe.split("*-*")[1]
            mac  = probe.split("*-*")[0]
            if black in ssid.lower():
                mal_probe.append(probe)
"""


if __name__ == "__main__":
    probereq_list = []
    mal_probe = []
    ifaces = netifaces.interfaces()
    #company_ssids = args.corp
    #print company_ssids
    print "[*] Available interfaces: ", ifaces
    interface = raw_input("[*] Please select the wireless interface you wish to use: ")
    print "-----------------------------------------------------\n"
    if interface in ifaces:
        iface_mode = commands.getoutput("iwconfig " + interface + "| awk '/Frequency:/ {print $4}'")
        if "Monitor" in iface_mode:
            os.system("reset")
            print banner
            print u"\u001b[43;1m P \u001b[41;1m R \u001b[42;1m O \u001b[43;1m B \u001b[45;1m E \u001b[46;1m R \u001b[41;1m E \u001b[45;1m G \u001b[0m______\n"
            sniff_channel_hop(interface)
	    PiUser(probereq_list)
            if len(mal_probe) != 0:
                print "[*] Analyzed ", len(probereq_list), "Probe Request(s)"
                print "[*] Find ", len(mal_probe), "critical probe request!!!"
                print "[*] Critical Probe Requests:"
                for i in mal_probe:
		    print " [-] MAC: ", i.split("*-*")[0], " Critical SSID: ", i.split("*-*")[1]
                if len(mal_probe) >=3: #Treshold
                    print "[*] Critical enviromental !!!"
            else:
                print "[*] Analyzed ", len(probereq_list), "Probe Request(s)"
                print "[*] Not found critical SSID(s) :)"
