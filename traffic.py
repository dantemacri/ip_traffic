import platform
from scapy.all import sniff, get_if_list, IP, conf
from collections import defaultdict

# Detectar la interfaz de red según el sistema operativo
if platform.system() == "Windows":
    conf.iface = get_if_list()[0]  # Primera interfaz disponible en Windows
elif platform.system() == "Darwin":  # macOS
    conf.iface = "en0"  # Interfaz en Mac
else:  # Linux o Docker
    conf.iface = "eth0"

# Diccionarios para estadísticas
protocol_count = defaultdict(int)
source_ip_traffic = defaultdict(int)
destination_ip_traffic = defaultdict(int)

# Mapeo de números de protocolo a nombres
protocol_names = {
    6: "TCP", 17: "UDP", 1: "ICMP", 2: "IGMP", 47: "GRE", 50: "ESP", 51: "AH", 89: "OSPF"
}

def process_packet(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src       # Dirección IP de origen
        dst_ip = packet[IP].dst       # Dirección IP de destino
        proto_num = packet[IP].proto  # Número del protocolo
        proto_name = protocol_names.get(proto_num, f"Desconocido ({proto_num})")  # Obtener nombre del protocolo
        size = len(packet)            # Tamaño del paquete en bytes

        # Contar paquetes por protocolo
        protocol_count[proto_name] += 1

        # Contar tráfico por IP de origen y destino
        source_ip_traffic[src_ip] += size
        destination_ip_traffic[dst_ip] += size

        print(f" Origen: {src_ip} -> Destino: {dst_ip} | Protocolo: {proto_name} | Tamaño: {size} bytes")

def print_top_traffic(traffic_dict, title):
    # Mostrar las 5 principales IPs con mayor tráfico.
    sorted_traffic = sorted(traffic_dict.items(), key=lambda x: x[1], reverse=True)[:5]
    print(f"\n {title}:")
    for ip, traffic in sorted_traffic:
        print(f"-  {ip}: {traffic} bytes")

def start_sniffing(count=10):
    # Capturar paquetes en la interfaz configurada.
    print(f" Capturando {count} paquetes en {conf.iface}...\n")
    sniff(iface=conf.iface, prn=process_packet, count=count)

    # Mostrar estadísticas después de la captura
    print("\n Estadísticas de paquetes por protocolo:")
    for proto, num in protocol_count.items():
        print(f"Protocolo {proto}: {num} paquetes")

    # Mostrar las 5 IPs con más tráfico
    print_top_traffic(source_ip_traffic, "Top 5 IPs de origen con mayor tráfico")
    print_top_traffic(destination_ip_traffic, "Top 5 IPs de destino con mayor tráfico")

if __name__ == "__main__":
    start_sniffing()
