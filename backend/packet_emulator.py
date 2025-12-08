from scapy.all import *

print("=== PACKET EMULATOR STARTED ===")
print("Listening for packets...")

MY_MAC = "00:0c:29:11:22:33"
MY_IP = "192.168.1.1"
MY_IPV6 = "fe80::2"
CLIENT_MAC = "aa:bb:cc:dd:ee:ff"

def reply_packet(pkt):
    if pkt.src != CLIENT_MAC:
        return
    
    if ARP in pkt and pkt[ARP].op == 1:
        print("ARP Request → Sending ARP Reply")

        arp = ARP(
            op=2,
            psrc=pkt[ARP].pdst,
            pdst=pkt[ARP].psrc,
            hwsrc=MY_MAC,
            hwdst=pkt[ARP].hwsrc
        )
        ether = Ether(src=MY_MAC, dst=pkt.src)

        sendp(ether/arp, verbose=0)
        return

    if ICMP in pkt and pkt[ICMP].type == 8:
        print("ICMP Echo Request → Echo Reply")

        ether = Ether(src=MY_MAC, dst=pkt.src)
        ip = IP(src=MY_IP, dst=pkt[IP].src, ttl=64)
        icmp = ICMP(type=0)
        payload = pkt[Raw].load if Raw in pkt else b""

        sendp(ether/ip/icmp/payload, verbose=0)
        return

    if TCP in pkt and pkt[TCP].flags == "S":
        print("TCP SYN → SYN-ACK")

        ether = Ether(src=MY_MAC, dst=pkt.src)
        ip = IP(src=MY_IP, dst=pkt[IP].src)
        tcp = TCP(
            sport=pkt[TCP].dport,
            dport=pkt[TCP].sport,
            flags="SA",
            seq=1,
            ack=pkt[TCP].seq + 1
        )
        sendp(ether/ip/tcp, verbose=0)
        return

    if TCP in pkt and pkt[TCP].flags == "A":
        print("TCP ACK → session established")
        return

    if TCP in pkt and Raw in pkt and b"GET" in pkt[Raw].load:
        print("HTTP GET → 200 OK")

        ether = Ether(src=MY_MAC, dst=pkt.src)
        ip = IP(src=MY_IP, dst=pkt[IP].src)
        tcp = TCP(
            sport=pkt[TCP].dport,
            dport=pkt[TCP].sport,
            flags="PA",
            seq=2,
            ack=pkt[TCP].ack
        )
        payload = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\nHello"
        sendp(ether/ip/tcp/payload, verbose=0)
        return

    if UDP in pkt and pkt[UDP].dport == 53:
        print("DNS Query → DNS Response")

        ether = Ether(src=MY_MAC, dst=pkt.src)
        ip = IP(src=MY_IP, dst=pkt[IP].src)
        udp = UDP(sport=53, dport=pkt[UDP].sport)

        dns = DNS(
            id=1,
            qr=1,
            aa=1,
            qd=DNSQR(qname="example.com"),
            an=DNSRR(rrname="example.com", rdata="93.184.216.34")
        )

        sendp(ether/ip/udp/dns, verbose=0)
        return

    if UDP in pkt and pkt[UDP].dport == 514:
        print("SYSLOG MESSAGE:", pkt[Raw].load if Raw in pkt else "")
        return

    if UDP in pkt and pkt[UDP].sport == 68:
        print("DHCP DISCOVER → OFFER")

        ether = Ether(src=MY_MAC, dst="ff:ff:ff:ff:ff:ff")
        ip = IP(src="192.168.1.1", dst="255.255.255.255")
        udp = UDP(sport=67, dport=68)

        dhcp = BOOTP(
            yiaddr="192.168.1.50",
            siaddr="192.168.1.1",
            chaddr=pkt[BOOTP].chaddr
        ) / DHCP(options=[("message-type","offer"), "end"])

        sendp(ether/ip/udp/dhcp, verbose=0)
        return
    
    if ICMPv6EchoRequest in pkt:
        print("ICMPv6 Echo → Reply")

        ether = Ether(src=MY_MAC, dst=pkt.src)
        ipv6 = IPv6(src=MY_IPV6, dst=pkt[IPv6].src)
        icmp = ICMPv6EchoReply()

        sendp(ether/ipv6/icmp, verbose=0)
        return

    print("Received packet but no handler:", pkt.summary())


sniff(prn=reply_packet, store=False)
