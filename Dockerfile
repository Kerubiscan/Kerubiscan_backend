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
    && rm -rf /var/lib/apt/lists/*

# Install Nuclei
RUN wget https://github.com/projectdiscovery/nuclei/releases/download/v3.3.0/nuclei_3.3.0_linux_amd64.zip \
    && unzip nuclei_3.3.0_linux_amd64.zip \
    && mv nuclei /usr/local/bin/ \
    && rm nuclei_3.3.0_linux_amd64.zip \
    && nuclei -update-templates

# Install Nmap vulners script
RUN wget https://raw.githubusercontent.com/vulnersCom/nmap-vulners/master/vulners.nse -O /usr/share/nmap/scripts/vulners.nse \
    && nmap --script-updatedb

# Install python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --default-timeout=100 -r requirements.txt

# Copy application code
COPY src/ /app/src/

# Expose port
EXPOSE 8000

# Command to run the application
CMD ["uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "8000"]
