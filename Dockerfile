# OffSploit v1.0 - Dockerfile
# ============================
# Kullanım:
#   docker build -t offsploit .
#   docker run -it --rm offsploit
#
# Ollama ile birlikte:
#   docker run -it --rm --network host offsploit --ollama-url http://host.docker.internal:11434

FROM python:3.12-slim

LABEL maintainer="Egnake"
LABEL description="OffSploit - Offline Exploit Adaptation Tool"
LABEL version="1.0.0"

# Sistem bağımlılıkları (gcc exploit derleme için)
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    nmap \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/offsploit

# Bağımlılıkları önce yükle (cache optimizasyonu)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Uygulama dosyalarını kopyala
COPY pyproject.toml .
COPY cli_app.py .
COPY offsploit/ offsploit/
COPY web/ web/
COPY mock_data/ mock_data/

# Paketi editable modda yükle
RUN pip install --no-cache-dir -e .

# NOT: exploitdb/ klasörü çok büyük olduğu için dahil edilmez.
# Kullanıcı kendi exploit DB'sini mount etmelidir:
#   docker run -it --rm -v /path/to/exploitdb:/opt/offsploit/exploitdb offsploit

# Çıktı dizinini oluştur
RUN mkdir -p /opt/offsploit/output

ENTRYPOINT ["python", "cli_app.py"]
CMD []
