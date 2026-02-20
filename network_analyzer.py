from scapy.all import *
import json
import matplotlib.pyplot as plt
import numpy as np
import csv

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



# 4. Track top talkers for source & destination IP addresses
sending_packets_addresses = {}
receiving_packets_addresses = {}

def track_ips(pkt):
    if not pkt.haslayer('IP'):
        return

    if pkt['IP'].src in sending_packets_addresses:
        if pkt['IP'].dst not in sending_packets_addresses[pkt['IP'].src]:
            sending_packets_addresses[pkt['IP'].src].update({pkt['IP'].dst : 1})
        else:
            sending_packets_addresses[pkt['IP'].src][pkt['IP'].dst] += 1
    else:
        sending_packets_addresses[pkt['IP'].src] = {pkt['IP'].dst : 1}


    if pkt['IP'].dst in receiving_packets_addresses:
        if pkt['IP'].src not in receiving_packets_addresses[pkt['IP'].dst]:
            receiving_packets_addresses[pkt['IP'].dst].update({pkt['IP'].src : 1})
        else:
            receiving_packets_addresses[pkt['IP'].dst][pkt['IP'].src] += 1
    else:
        receiving_packets_addresses[pkt['IP'].dst] = {pkt['IP'].src : 1}
       
sniff(timeout=10, prn=track_ips, iface='Software Loopback Interface 1')

pretty_dict1 = json.dumps(sending_packets_addresses, indent=4)
pretty_dict2 = json.dumps(receiving_packets_addresses, indent=4)

print(pretty_dict1)
print("*"*50)
print(pretty_dict2)



# 5. Data Visualization
# ---- Pie Chart (protocol distribution)
pie_packet_count = {k: v for k, v in sorted(packet_count.items(), key=lambda item: item[1])}
pie_packet_count.pop('Total')
data = []
labels = []

for x, y in pie_packet_count.items():
    if y >= 10:
        labels.append(x)
        data.append(y)

plt.title("Protocol Distribution")
plt.pie(data, labels=labels, autopct='%1.1f%%')
plt.legend(labels, loc="center left")
plt.savefig('pie_chart_protocol_distribution.png')
plt.show()


# ---- Bar Graph (top talkers)
# TOP RECEIVERS 
fig, ax = plt.subplots()
sum_values = dict()
for subdict in sending_packets_addresses.values():
    for key, elem in subdict.items():
        sum_values[key] = elem + sum_values.get(key, 0)

ips_labels = []
data = []

for x, y in sum_values.items():
    if y > 100:
        ips_labels.append(x)
        data.append(y)

bar_colors = ['tab:red', 'tab:blue', 'tab:orange', 'tab:green', 'tab:pink', 'tab:purple', 'tab:cyan', 'tab:gray', 'tab:olive', 'tab:brown']

ax.bar(ips_labels, data, label=ips_labels, color=bar_colors)
ax.set_title('Top IPs Receiving Packets')
ax.legend(ips_labels, title='IP', loc="center left")
plt.savefig('bar_graph_top_receivers.png')
plt.show()


# TOP SENDERS
fig, ax = plt.subplots()
sum_values = dict()
for subdict in receiving_packets_addresses.values():
    for key, elem in subdict.items():
        sum_values[key] = elem + sum_values.get(key, 0)

ips_labels = []
data = []

for x, y in sum_values.items():
    if y > 100:
        ips_labels.append(x)
        data.append(y)

bar_colors = ['tab:red', 'tab:blue', 'tab:orange', 'tab:green', 'tab:pink', 'tab:purple', 'tab:cyan', 'tab:gray', 'tab:olive', 'tab:brown']

ax.bar(ips_labels, data, label=ips_labels, color=bar_colors)
ax.set_title('Top IPs Sending Packets')
ax.legend(title='IP')
plt.savefig('bar_graph_top_senders.png')
plt.show()