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

