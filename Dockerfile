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

# Nuclei, pinned to a fixed release (was COPY from projectdiscovery/nuclei:latest).
# Pin NUCLEI_SHA256 to the checksum from the release's checksums.txt before production (see REVUE_SCANNER.md R13).
ENV NUCLEI_VERSION=3.11.1
RUN wget -q "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip" -O /tmp/nuclei.zip \
    && unzip -o /tmp/nuclei.zip nuclei -d /usr/local/bin/ \
    && rm /tmp/nuclei.zip && chmod +x /usr/local/bin/nuclei
# Templates, pinned like the binary and fetched with wget. nuclei's own updater (-ut) goes through
# the GitHub API: it failed on the test server, and does nothing at all when combined with -duc.
# /root/nuclei-templates is nuclei's default directory (the image runs as root).
# .nuclei-ignore (excludes dos/fuzz/bruteforce templates) is normally installed by -ut: copy it.
ENV NUCLEI_TEMPLATES_VERSION=10.5.0 \
    NUCLEI_TEMPLATES_DIR=/root/nuclei-templates
RUN mkdir -p "$NUCLEI_TEMPLATES_DIR" /root/.config/nuclei \
    && wget -q "https://github.com/projectdiscovery/nuclei-templates/archive/refs/tags/v${NUCLEI_TEMPLATES_VERSION}.tar.gz" -O /tmp/nuclei-templates.tgz \
    && tar -xzf /tmp/nuclei-templates.tgz -C "$NUCLEI_TEMPLATES_DIR" --strip-components=1 \
    && rm /tmp/nuclei-templates.tgz \
    && cp "$NUCLEI_TEMPLATES_DIR/.nuclei-ignore" /root/.config/nuclei/.nuclei-ignore \
    && test "$(find "$NUCLEI_TEMPLATES_DIR" -name '*.yaml' | wc -l)" -ge 100

# Nmap vulners script: the one shipped with the distribution's nmap package. Its "ID  CVSS  URL"
# output is what the parser reads. Do not download it from vulnersCom/nmap-vulners: the 2.x rewrite
# (current master) prints a truncated table with the score first, so severities would be lost.
# vulscan is intentionally NOT installed: it matches on product names only and floods reports (R13).
RUN test -s /usr/share/nmap/scripts/vulners.nse \
    && grep -q 'https://vulners.com/%s/%s' /usr/share/nmap/scripts/vulners.nse \
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
