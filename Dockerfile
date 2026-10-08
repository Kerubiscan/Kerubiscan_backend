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
# Download templates into a fixed directory; fail the build if too few are present.
# Never combine -duc with -ut: nuclei 3.11 then skips the download silently (exit 0, no template).
ENV NUCLEI_TEMPLATES_DIR=/opt/nuclei-templates
RUN nuclei -ut -ud "$NUCLEI_TEMPLATES_DIR" \
    && test "$(find "$NUCLEI_TEMPLATES_DIR" -name '*.yaml' | wc -l)" -ge 100

# Nmap vulners script. Pinned to a tag rather than the moving master branch.
# vulscan is intentionally NOT installed: it matches on product names only and floods reports (R13).
# Before production: pin VULNERS_REF to a commit and verify a SHA256 (see REVUE_SCANNER.md R13).
ENV VULNERS_REF=1.9
RUN wget -q "https://raw.githubusercontent.com/vulnersCom/nmap-vulners/${VULNERS_REF}/vulners.nse" \
      -O /usr/share/nmap/scripts/vulners.nse \
    && test -s /usr/share/nmap/scripts/vulners.nse \
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
