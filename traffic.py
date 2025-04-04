import platform
import tkinter as tk
import threading
from scapy.all import sniff, get_if_list, IP, conf
from collections import defaultdict

# Diccionarios para estadísticas
protocol_count = defaultdict(int)
source_ip_traffic = defaultdict(int)
destination_ip_traffic = defaultdict(int)

# Mapeo de números de protocolo a nombres
protocol_names = {
    6: "TCP", 17: "UDP",
}

# Variable de control para la captura
sniffer_thread = None
lock = threading.Lock()

# Configurar interfaz según el sistema operativo
if platform.system() == "Windows":
    conf.iface = get_if_list()[0]
elif platform.system() == "Darwin":  # macOS
    conf.iface = "en0"
else:  # Linux o Docker
    conf.iface = "eth0"

# Crear ventana de tkinter
root = tk.Tk()
root.title("Monitor de tráfico de red")

text_widget = tk.Text(root, height=40, width=110)
text_widget.pack()

# Mensaje inicial al abrir la app
text_widget.insert(tk.END, "Presione el botón inferior para arrancar el análisis de paquetes 🔍\n")

def update_gui(text):
    text_widget.insert(tk.END, text + "\n")
    text_widget.see(tk.END)  # Auto-scroll cada vez que aparece una nueva linea de texto
    root.update()

def process_packet(packet):
    with lock:
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            proto_num = packet[IP].proto
            proto_name = protocol_names.get(proto_num, f"Desconocido ({proto_num})")
            size = len(packet)

            protocol_count[proto_name] += 1
            source_ip_traffic[src_ip] += size
            destination_ip_traffic[dst_ip] += size

            update_gui(f"Origen: {src_ip} -> Destino: {dst_ip} | Protocolo: {proto_name} | Tamaño: {size} bytes")

def print_top_traffic(traffic_dict, title):
    sorted_traffic = sorted(traffic_dict.items(), key=lambda x: x[1], reverse=True)[:5]
    update_gui(f"\n{title}:")
    for ip, traffic in sorted_traffic:
        update_gui(f"- {ip}: {traffic} bytes")

def print_protocol_stats():
    update_gui("\n📊 Cantidad de paquetes por protocolo:")
    for proto, count in protocol_count.items():
        update_gui(f"- {proto}: {count} paquetes")

def full_capture_and_analysis():
    # Limpiar estadísticas antes de cada ejecución
    protocol_count.clear()
    source_ip_traffic.clear()
    destination_ip_traffic.clear()

    iface = conf.iface
    update_gui(f"Iniciando captura de paquetes 📦...\n")
    sniff(iface=iface, prn=process_packet, timeout=10, promisc=False)
    update_gui("\nCaptura detenida. Resultados:")
    print_protocol_stats()
    print_top_traffic(source_ip_traffic, "🏆 Top 5 IPs de origen con mayor tráfico")
    print_top_traffic(destination_ip_traffic, "🏆 Top 5 IPs de destino con mayor tráfico")
    update_gui("\nAnálisis completado. ✅")
    update_gui("\nPresione nuevamente el botón en caso de necesitar un nuevo análisis.")
    root.after(0, show_main_button)

def run_capture_and_analysis():
    main_button.pack_forget()  # Ocultar botón mientras se ejecuta todo
    thread = threading.Thread(target=full_capture_and_analysis)
    thread.start()

def show_main_button():
    main_button.pack()

main_button = tk.Button(root, text="Analizar tráfico de red", command=run_capture_and_analysis)
main_button.pack()

root.mainloop()
