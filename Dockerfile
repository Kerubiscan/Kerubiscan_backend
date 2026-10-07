FROM python:3.12-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/src

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    nmap \
    wget \
    unzip \
    git \
    default-jre \
    fonts-open-sans \
    && rm -rf /var/lib/apt/lists/*

# Install OWASP ZAP
RUN wget https://github.com/zaproxy/zaproxy/releases/download/v2.17.0/ZAP_2.17.0_Linux.tar.gz \
    && tar -xzf ZAP_2.17.0_Linux.tar.gz \
    && mv ZAP_2.17.0 /opt/zaproxy \
    && rm ZAP_2.17.0_Linux.tar.gz \
    && ln -s /opt/zaproxy/zap.sh /usr/local/bin/zap

# Get latest Nuclei directly from official image
COPY --from=projectdiscovery/nuclei:latest /usr/local/bin/nuclei /usr/local/bin/nuclei
RUN nuclei -ut || true

# Install Nmap vulners and vulscan scripts
RUN wget https://raw.githubusercontent.com/vulnersCom/nmap-vulners/master/vulners.nse -O /usr/share/nmap/scripts/vulners.nse \
    && git clone https://github.com/scipag/vulscan.git /usr/share/nmap/scripts/vulscan \
    && nmap --script-updatedb

# Install python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --default-timeout=1000 --retries 10 -r requirements.txt

# Headless Chromium prints the HTML reports to PDF (identical layout in both formats)
RUN playwright install --with-deps chromium

# Copy application code
COPY src/ /app/src/

# Expose port
EXPOSE 8000

# Command to run the application
CMD ["uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "8000"]
