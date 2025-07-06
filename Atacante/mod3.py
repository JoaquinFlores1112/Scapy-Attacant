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

def send_bad_content_length(ip, sport):
    body = "Este es un cuerpo más largo que el indicado."
    payload = (
        "POST / HTTP/1.1\r\n"
        f"Host: {target_ip}\r\n"
        "User-Agent: mod-bad-content-length\r\n"
        "Content-Length: 10\r\n" 
        "Connection: close\r\n\r\n" +
        body
    )
    tcp = TCP(sport=sport, dport=target_port, flags='PA', seq=1001, ack=1)
    packet = ip/tcp/Raw(load=payload)
    send(packet, verbose=0)
    print("[+] Paquete HTTP con Content-Length incorrecto enviado.")

def main():
    ip, sport = tcp_handshake()
    if not ip:
        print("Error al establecer conexión TCP")
        return
    send_bad_content_length(ip, sport)

if __name__ == "__main__":
    main()
