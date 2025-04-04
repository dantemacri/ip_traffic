import platform
import tkinter as tk
import threading
import csv
import os
from datetime import datetime
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

def print_top_traffic(traffic_dict):
    return sorted(traffic_dict.items(), key=lambda x: x[1], reverse=True)[:5]

def format_traffic_list(traffic_list):
    return [(ip, traffic) for ip, traffic in traffic_list]

def print_protocol_stats():
    return dict(protocol_count)

def export_to_csv(protocol_stats, top_sources, top_destinations):
    now = datetime.now()
    date = now.strftime("%Y-%m-%d")
    time = now.strftime("%H:%M:%S")

    file_exists = os.path.exists("traffic_capture.csv")

    with open("traffic_capture.csv", "a", newline='', encoding='utf-8') as f:
        writer = csv.writer(f)

        if not file_exists:
            writer.writerow(["Fecha", "Hora", "Protocolo", "Cant. de paquetes", "Top IPs de origen", "Tráfico (bytes)", "Top IPs de destino", "Tráfico (bytes)"])

        max_len = max(len(protocol_stats), len(top_sources), len(top_destinations))
        protocol_items = list(protocol_stats.items())

        for i in range(max_len):
            row = [date if i == 0 else "", time if i == 0 else ""]
            row += [protocol_items[i][0], protocol_items[i][1]] if i < len(protocol_items) else ["", ""]
            row += [top_sources[i][0], top_sources[i][1]] if i < len(top_sources) else ["", ""]
            row += [top_destinations[i][0], top_destinations[i][1]] if i < len(top_destinations) else ["", ""]
            writer.writerow(row)

    update_gui("\n📁 Exportación a CSV completada ✅: traffic_capture.csv")

def full_capture_and_analysis():
    protocol_count.clear()
    source_ip_traffic.clear()
    destination_ip_traffic.clear()

    iface = conf.iface
    update_gui(f"Iniciando captura de paquetes 📦...\n")
    sniff(iface=iface, prn=process_packet, timeout=10, promisc=False)
    update_gui("\nCaptura detenida. Resultados:")

    global last_protocol_stats, last_top_sources, last_top_destinations
    last_protocol_stats = print_protocol_stats()
    last_top_sources = print_top_traffic(source_ip_traffic)
    last_top_destinations = print_top_traffic(destination_ip_traffic)

    update_gui("\nAnálisis completado. ✅")
    update_gui("\nPresione nuevamente el botón en caso de necesitar un nuevo análisis.")
    root.after(0, show_main_buttons)

def run_capture_and_analysis():
    main_button.pack_forget()
    csv_button.pack_forget()
    thread = threading.Thread(target=full_capture_and_analysis)
    thread.start()

def run_export():
    if last_protocol_stats and last_top_sources and last_top_destinations:
        export_to_csv(last_protocol_stats, last_top_sources, last_top_destinations)

def show_main_buttons():
    main_button.pack()
    csv_button.config(text="Actualizar CSV" if os.path.exists("traffic_capture.csv") else "Crear CSV del registro")
    csv_button.pack()

last_protocol_stats = {}
last_top_sources = []
last_top_destinations = []

main_button = tk.Button(root, text="Analizar tráfico de red", command=run_capture_and_analysis)
main_button.pack()

csv_button = tk.Button(root, text="Crear CSV del registro", command=run_export)
csv_button.pack_forget()

root.mainloop()

