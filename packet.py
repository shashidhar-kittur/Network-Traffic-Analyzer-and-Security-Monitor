from scapy.all import sniff

def packet_callback(packet):
    if packet.haslayer("IP"):
        src_ip = packet["IP"].src
        dst_ip = packet["IP"].dst
        proto_num = packet["IP"].proto
        protocol = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(proto_num, f"Unknown({proto_num})")
        print(f"Protocol: {protocol} | src_ip:{src_ip} -> dst_ip:{dst_ip}") 
sniff(filter="tcp or udp or icmp", prn=packet_callback, store=0, count=10) #prn:process, sniff captures packet, filter excludes ARP packets_callback(packet):