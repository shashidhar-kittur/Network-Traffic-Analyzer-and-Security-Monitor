from scapy.all import sniff

def packet_callback(packet):
    print(packet.summary())

sniff(filter="tcp or udp or icmp", prn=packet_callback, store=0, count=10) #prn:process, sniff captures packet, filter excludes ARP packets