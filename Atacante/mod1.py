from scapy.all import *

target_ip = "172.16.30.64"
target_port = 8080

def tcp_handshake():
    sport = RandShort()
    ip = IP(dst=target_ip)
    syn = TCP(sport=sport, dport=target_port, flags='S', seq=1000)
    synack = sr1(ip/syn, timeout=2, verbose=0)
    if not synack:
        print("No se recibió SYN-ACK")
        return None, None
    ack = TCP(sport=sport, dport=target_port, flags='A', seq=1001, ack=synack.seq + 1)
    send(ip/ack, verbose=0)
    return ip, sport

def send_fin_only(ip, sport):
    payload = (
        "GET / HTTP/1.1\r\n"
        f"Host: {target_ip}\r\n"
        "User-Agent: mod-tcp-fin\r\n"
        "Connection: close\r\n\r\n"
    )
    tcp = TCP(sport=sport, dport=target_port, flags='F', seq=1001, ack=1)
    packet = ip/tcp/Raw(load=payload)
    send(packet, verbose=0)
    print("[+] Paquete TCP con flag FIN solo enviado.")

def main():
    ip, sport = tcp_handshake()
    if not ip:
        print("Error al establecer conexión TCP")
        return
    send_fin_only(ip, sport)

if __name__ == "__main__":
    main()

