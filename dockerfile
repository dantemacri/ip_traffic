FROM python:3.10
RUN apt-get update && apt-get install -y tcpdump libcap2-bin sudo
WORKDIR /app
COPY traffic.py /app/traffic.py
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
CMD ["sudo", "python", "/app/traffic.py"]
