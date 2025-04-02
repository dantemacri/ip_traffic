# IP Traffic
## Programa de análisis de tráfico de red 🔍
## Función paso a paso:
- Captura los 10 primeros paquetes que recibe el host luego de ejecutar el programa.
- Los analiza y describe su dirección IP de origen, dirección IP de destino, tipo de protocolo y tamaño.
  
![image](https://github.com/user-attachments/assets/bbac6ff8-4d2a-4a92-af8d-54625135adf4)

- Realiza conteo según el tipo de paquete recibido y los enumera según las 5 direcciones IP de origen y destino con mayor tráfico.
  
![image](https://github.com/user-attachments/assets/c593a05b-a3ab-4266-b9e6-8e9e3f42dafb)

## Para ejecutarlo en tu máquina:

### Si posees Docker, se puede hacer pull y run con este comando:

```docker pull dantemacri/traffic```

```docker run --rm --net=host --privileged dantemacri/traffic```

### Si NO posees Docker y eres host en MacOS/Linux:
- Instala Scapy:

```pip install scapy```

- Ejecuta el programa como administrador:

```sudo python traffic.py```

### Si NO posees Docker y eres host en Windows:
- Instala Scapy:

```pip install scapy```

- Descarga Npcap desde: https://npcap.com/ (es un driver necesario para poder capturar paquetes en windows)

- Ejecuta el programa:

```docker run --rm --net=host --name sniffer_container traffic```
