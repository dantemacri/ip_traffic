# Usamos una imagen base de Python
FROM python:3.10

# Instalamos herramientas necesarias
RUN apt-get update && apt-get install -y tcpdump libcap2-bin sudo

# Copiamos los archivos al contenedor
WORKDIR /app
COPY traffic.py /app/traffic.py
COPY requirements.txt /app/requirements.txt

# Instalamos las dependencias
RUN pip install --no-cache-dir -r requirements.txt

# Ejecutamos el script
CMD ["sudo", "python", "/app/traffic.py"]
