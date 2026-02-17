from scapy.all import *

# Get all Network Interfaces
print(conf.ifaces)

# Names of my Network Interfaces
# Software Loopback Interface 1
# Realtek Gaming 2.5GbE Family Controller
# VirtualBox Host-Only Ethernet Adapter

# 1. Learning how to capture packets from network interfaces using sniff()
sniff(count=5, iface=conf.iface) # or grabbing from results of conf.ifaces
print("")

# 2. Captures live packets for a specified duration or packet count
count_packets = sniff(filter="tcp", count=5, iface="Realtek Gaming 2.5GbE Family Controller")
print("Capturing TCP packets till 5 are received: ", count_packets)

timer_packets = sniff(filter="tcp", timeout=10, iface="Software Loopback Interface 1")
print("Capturing TCP packets for 10 seconds: ", timer_packets, "\n")