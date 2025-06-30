# Passive Recon Stage Dockerfile
#
# Builds a container with all passive recon tools and runners.

FROM python:3.11-slim as base

# Install system dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        git \
        curl \
        wget \
        build-essential \
        ca-certificates \
        python3-pip \
        python3-venv \
        unzip \
        golang-go \
    && rm -rf /var/lib/apt/lists/*

# Set Go environment
ENV GOPATH=/root/go
ENV PATH="$GOPATH/bin:/usr/local/go/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/sbin:/root/.local/bin:/root/go/bin"

# Install Amass (prebuilt binary)
RUN wget https://github.com/owasp-amass/amass/releases/latest/download/amass_linux_amd64.zip -O /tmp/amass.zip && \
    unzip /tmp/amass.zip -d /tmp/amass && \
    mv /tmp/amass/amass_linux_amd64/amass /usr/bin/amass && \
    chmod +x /usr/bin/amass && \
    rm -rf /tmp/amass*

# Install Subfinder
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Install Assetfinder
RUN go install github.com/tomnomnom/assetfinder@latest

# Install Gau
RUN go install github.com/lc/gau/v2/cmd/gau@latest

# Install Sublist3r
RUN git clone https://github.com/aboul3la/Sublist3r.git /opt/Sublist3r && \
    pip install -r /opt/Sublist3r/requirements.txt
ENV SUBLIST3R_PATH=/opt/Sublist3r/sublist3r.py

# Install SecLists (wordlists)
RUN mkdir -p /usr/share/wordlists && \
    git clone --depth 1 https://github.com/danielmiessler/SecLists.git /usr/share/wordlists/seclists

# Install Cero
RUN go install github.com/glebarez/cero@latest
ENV CERO_PATH=/root/go/bin/cero
ENV PATH="/root/go/bin:$PATH"

# Set workdir and copy code
WORKDIR /app
COPY . /app

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Set environment variables for tool paths
ENV AMASS_PATH=/usr/bin/amass
ENV SUBFINDER_PATH=/root/go/bin/subfinder
ENV ASSETFINDER_PATH=/root/go/bin/assetfinder
ENV GAU_PATH=/root/go/bin/gau
ENV SECLISTS_PATH=/usr/share/wordlists/seclists
ENV PATH="/root/go/bin:/opt/Sublist3r:$PATH"

# Entrypoint
ENTRYPOINT ["python", "run_passive_recon.py"]
