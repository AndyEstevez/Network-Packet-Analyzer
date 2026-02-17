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