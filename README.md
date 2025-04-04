# IP Traffic
## Programa de análisis de tráfico de red 🔍
## Función paso a paso:
- Captura durante 10 segundos los paquetes que recibe el host luego de ejecutar el programa.
- Los analiza y describe su dirección IP de origen, dirección IP de destino, tipo de protocolo y tamaño.
  
![image](https://github.com/user-attachments/assets/e22680ea-5220-4d2b-b287-736685acac76)


- Realiza conteo según el tipo de paquete recibido y los enumera según las 5 direcciones IP de origen y destino con mayor tráfico.
  
![image](https://github.com/user-attachments/assets/5570f976-cac3-45dd-84c1-a8ff86e1576d)


## Para ejecutarlo en tu máquina:
- Descarga Python https://www.python.org/downloads/
  
- Instala Scapy desde la terninal:

```pip install scapy```

- Solo en Linux, descarga tkinter:

```sudo apt update```
```sudo apt install python3-tk```

- Descarga el progama traffic.py

- Ejecuta el programa como administrador en la carpeta/dirección donde lo hayas guardado:

```sudo python traffic.py``` en equipos MacOS/Linux

```python C:\ruta\al\script.py``` en equipos Windows, siempre ejecutando el CMD/Powershell como administrador.

## ¿Cómo se utiliza el programa?
Es muy fácil, ¡simplemente hay que presionar el botón inferior una vez ejecutado el programa!

<img width="412" alt="image" src="https://github.com/user-attachments/assets/b21587f0-32c3-4d46-b6f0-81503e135b44" />

Y si se desea, se puede seguir presionando el botón las veces que el usuario lo vea necesario para hacer distintos análisis de red.
