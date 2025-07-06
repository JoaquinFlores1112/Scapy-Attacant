from scapy.all import IP, TCP, send, sr1

ip_dst = "172.16.30.64"
port_dst = 8080
port_src = 12345  

ip = IP(dst=ip_dst)
SYN = TCP(sport=port_src, dport=port_dst, flags="S", seq=1000)
SYN_ACK = sr1(ip/SYN)
ACK = TCP(sport=port_src, dport=port_dst, flags="A", seq=SYN.seq+1, ack=SYN_ACK.seq+1)
send(ip/ACK)


payload = b"FUZZ / HTTP/1.1\r\nHost: 172.16.30.64\r\n\r\n"
send(ip/TCP(sport=port_src, dport=port_dst, flags="PA", seq=ACK.seq, ack=ACK.ack)/payload)
