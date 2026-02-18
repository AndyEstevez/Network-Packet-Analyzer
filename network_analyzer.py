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



# 3. Build protocol analysis and statistics by parsing captured packets to categorize them by protocol type
packet_count = {'TCP': 0, 'UDP': 0, 'ICMP': 0, 'DNS': 0, 'ARP': 0, 'HTTP': 0, 'HTTPS': 0, 'SSDP': 0, 'Other': 0, 'Total': 0}
packet_size = {'TCP': 0, 'UDP': 0, 'ICMP': 0, 'DNS': 0, 'ARP': 0, 'HTTP': 0, 'HTTPS': 0, 'SSDP': 0, 'Total': 0}

def counting_packets(pkt):
    packet_count['Total'] += 1
    packet_size['Total'] += len(pkt['Ether'])

    if pkt.haslayer('TCP'):
        packet_count['TCP'] += 1
        packet_size['TCP'] += len(pkt['TCP'])
        if pkt['TCP'].sport == 443 or pkt['TCP'].dport == 443:
            packet_count['HTTPS'] += 1
        elif pkt['TCP'].sport == 80 or pkt['TCP'].dport == 80:
            packet_count['HTTP'] += 1
        else:
            packet_count['Other'] += 1

    elif pkt.haslayer('UDP'):
        packet_count['UDP'] += 1
        packet_size['UDP'] += len(pkt['UDP'])
        if pkt['UDP'].sport == 1900 or pkt['UDP'].dport == 1900:
            packet_count['SSDP'] += 1
        elif pkt['UDP'].sport == 443 or pkt['UDP'].dport == 443:
            packet_count['HTTPS'] += 1
        elif pkt['UDP'].sport == 80 or pkt['UDP'].dport == 80:
            packet_count['HTTP'] += 1
        elif pkt['UDP'].sport == 53 or pkt['UDP'].dport == 53:
            packet_count['DNS'] += 1
            packet_size['DNS'] += len(pkt['DNS'])
        else:
            packet_count['Other'] += 1
    elif pkt.haslayer('ICMP'):
        packet_count['ICMP'] += 1
        packet_size['ICMP'] += len(pkt['ICMP'])
    elif pkt.haslayer('ARP'):
        packet_count['ARP'] += 1
        packet_size['ARP'] += len(pkt['ARP'])

    else:
        packet_count['Other'] += 1

print("Capturing and analyzing packets for 60 seconds")
sniff(timeout=30, prn=counting_packets)

print("Total Packet Count: ", packet_count)
print("Total Packet Size: ", packet_size, "\n")

packet_percentages = {'TCP': 0.00, 'UDP': 0.00, 'ICMP': 0.00, 'DNS': 0.00, 'ARP': 0.00, 'HTTP': 0.00, 'HTTPS': 0.00, 'SSDP': 0.00, 'Other': 0.00}

for pkt_name in packet_count:
    if pkt_name in packet_percentages:
        packet_percentages.update({pkt_name: round(packet_count.get(pkt_name) / packet_count.get('Total') * 100, 2)})

print("Packet Percentages: ", packet_percentages)