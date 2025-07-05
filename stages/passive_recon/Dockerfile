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
        dnsutils \
    && rm -rf /var/lib/apt/lists/*

# Install Go
RUN wget https://go.dev/dl/go1.24.4.linux-amd64.tar.gz \
    && tar -C /usr/local -xzf go1.24.4.linux-amd64.tar.gz \
    && rm go1.24.4.linux-amd64.tar.gz
ENV PATH="/usr/local/go/bin:${PATH}"
RUN go version

# Install Amass (prebuilt binary)
RUN go install -v github.com/owasp-amass/amass/v4/...@master

# Install Subfinder
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Install Assetfinder
RUN go install github.com/tomnomnom/assetfinder@latest

# Install Gau
RUN go install github.com/lc/gau/v2/cmd/gau@latest

# Install waybackurls
RUN go install github.com/tomnomnom/waybackurls@latest

# Install Sublist3r
RUN git clone https://github.com/aboul3la/Sublist3r.git /opt/Sublist3r && \
pip install -r /opt/Sublist3r/requirements.txt

# Install trufflehog
RUN curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin

# Install Python dependencies for new tools
RUN pip install --no-cache-dir \
    dnspython \
    requests \
    python-dotenv

# Create Gau config file
RUN mkdir -p /root/.config && \
    echo 'providers = ["wayback", "otx", "urlscan", "github"]' > /root/.gau.toml


# Install SecLists (wordlists)
RUN mkdir -p /usr/share/wordlists && \
git clone --depth 1 https://github.com/danielmiessler/SecLists.git /usr/share/wordlists/seclists

# Set workdir and copy code
WORKDIR /app
COPY . /app

# Set environment variables for tool paths
ENV AMASS_PATH=/root/go/bin/amass
ENV SUBFINDER_PATH=/root/go/bin/subfinder
ENV ASSETFINDER_PATH=/root/go/bin/assetfinder
ENV GAU_PATH=/root/go/bin/gau
ENV WAYBACKURLS_PATH=/root/go/bin/waybackurls
ENV SECLISTS_PATH=/usr/share/wordlists/seclists
ENV SUBLIST3R_PATH=/opt/Sublist3r/sublist3r.py
ENV TRUFFLEHOG_PATH=/usr/local/bin/trufflehog
ENV PATH="/usr/local/go/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/sbin:/root/.local/bin:/root/go/bin"

# Entrypoint
ENTRYPOINT ["python", "run_passive_recon.py"]
