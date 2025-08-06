# Vulnerability Scanning Stage Dockerfile
#
# Builds a container for comprehensive black-box vulnerability scanning
# with integration to various security tools and frameworks.

FROM python:3.11-slim as base

# Install system dependencies and security tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Core system tools
    curl \
    wget \
    git \
    unzip \
    build-essential \
    ca-certificates \
    python3-pip \
    python3-venv \
    python3-setuptools \
    python3-dev \
    python3-wheel \
    make \
    gcc \
    g++ \
    
    # Security and scanning tools
    nmap \
    nikto \
    wapiti \
    arachni \
    skipfish \
    openvas \
    nuclei \
    zap \
    subfinder \
    amass \
    httpx \
    dirb \
    gobuster \
    ffuf \
    wfuzz \
    whatweb \
    wafw00f \
    feroxbuster \
    
    # Additional dependencies
    libmagic-dev \
    libmagic1 \
    libffi-dev \
    libssl-dev \
    libxml2-dev \
    libxslt-dev \
    libjpeg-dev \
    libpng-dev \
    libfreetype6-dev \
    liblcms2-dev \
    libwebp-dev \
    libharfbuzz-dev \
    libfribidi-dev \
    libxcb1-dev \
    libxrandr-dev \
    libxss-dev \
    libasound2-dev \
    libatk-bridge2.0-dev \
    libgtk-3-dev \
    libgdk-pixbuf2.0-dev \
    libcairo2-dev \
    libpango1.0-dev \
    libgirepository1.0-dev \
    
    # Font dependencies (minimal for smaller image)
    fonts-liberation \
    fonts-dejavu-core \
    fonts-dejavu-extra \
    
    # Cleanup
    && rm -rf /var/lib/apt/lists/*

# Install Go for Go-based security tools
RUN wget https://go.dev/dl/go1.24.4.linux-amd64.tar.gz \
    && tar -C /usr/local -xzf go1.24.4.linux-amd64.tar.gz \
    && rm go1.24.4.linux-amd64.tar.gz
ENV PATH="/usr/local/go/bin:${PATH}"
RUN go version

# Install Go-based security tools
RUN go install -v github.com/owasp-amass/amass/v4/...@master && \
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest && \
    go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest && \
    CGO_ENABLED=1 go install github.com/projectdiscovery/katana/cmd/katana@latest && \
    go install -v github.com/ffuf/ffuf@latest && \
    go install -v github.com/OJ/gobuster/v3@latest && \
    go install -v github.com/praetorian-inc/fingerprintx/cmd/fingerprintx@latest

# Install OWASP ZAP
RUN mkdir -p /opt/zap && \
    wget -q https://github.com/zaproxy/zaproxy/releases/download/v2.14.0/ZAP_2.14.0_Linux.tar.gz && \
    tar -xzf ZAP_2.14.0_Linux.tar.gz -C /opt/zap --strip-components=1 && \
    rm ZAP_2.14.0_Linux.tar.gz && \
    chmod +x /opt/zap/zap.sh

# Install additional security tools
RUN pip install --no-cache-dir \
    wapiti \
    arachni \
    skipfish \
    nikto \
    wafw00f

# Set working directory
WORKDIR /app

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Create necessary directories
RUN mkdir -p /app/outputs /app/runners /app/tools /app/scans /app/logs

# Copy stage files
COPY . /app

# Set environment variables
ENV PYTHONPATH=/app
ENV PATH="/app/tools:/usr/local/go/bin:/opt/zap:${PATH}"
ENV ZAP_PATH=/opt/zap/zap.sh

# Set tool paths
ENV NMAP_PATH=/usr/bin/nmap
ENV NIKTO_PATH=/usr/bin/nikto
ENV WAPITI_PATH=/usr/bin/wapiti
ENV ARACHNI_PATH=/usr/bin/arachni
ENV SKIPFISH_PATH=/usr/bin/skipfish
ENV OPENVAS_PATH=/usr/bin/openvas
ENV NUCLEI_PATH=/root/go/bin/nuclei
ENV ZAP_PATH=/opt/zap/zap.sh
ENV SUBFINDER_PATH=/root/go/bin/subfinder
ENV AMASS_PATH=/root/go/bin/amass
ENV HTTPX_PATH=/root/go/bin/httpx
ENV DIRB_PATH=/usr/bin/dirb
ENV GOBUSTER_PATH=/usr/bin/gobuster
ENV FFUF_PATH=/usr/bin/ffuf
ENV WFUZZ_PATH=/usr/bin/wfuzz
ENV WHATWEB_PATH=/usr/bin/whatweb
ENV WAFW00F_PATH=/usr/bin/wafw00f
ENV FEROXBUSTER_PATH=/usr/bin/feroxbuster
ENV FINGERPRINTX_PATH=/root/go/bin/fingerprintx

# Create non-root user for security
RUN groupadd -r appuser && useradd -r -g appuser appuser
RUN chown -R appuser:appuser /app /app/outputs
USER appuser

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:8000/health/', timeout=5)" || exit 1

# Set entry point
ENTRYPOINT ["python", "run_vuln_scan.py"] 