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
        whois \
        jq \
        nmap \
        netcat-openbsd \
        net-tools \
        iputils-ping \
        libpcap-dev \
        ruby \
        ruby-dev \
        nodejs \
        npm \
        python3-setuptools \
        libyaml-dev \
        python3-dev \
        python3-wheel \
        make \
        gcc \
        libmagic-dev \
        libmagic1 \
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

# Install httpx (for HTTP probing)
RUN go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

# Install nuclei (for vulnerability scanning)
RUN go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest

# Install naabu (for port scanning)
RUN go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest

# Install katana (for web crawling)
RUN CGO_ENABLED=1 go install github.com/projectdiscovery/katana/cmd/katana@latest

# Install Feroxbuster (for directory/file bruteforcing)
RUN wget https://github.com/epi052/feroxbuster/releases/download/v2.11.0/x86_64-linux-feroxbuster.zip \
    && unzip x86_64-linux-feroxbuster.zip \
    && mv feroxbuster /usr/local/bin/feroxbuster \
    && chmod +x /usr/local/bin/feroxbuster \
    && rm x86_64-linux-feroxbuster.zip

# Install GoBuster (for DNS/VHost bruteforcing)
RUN go install -v github.com/OJ/gobuster/v3@latest

# Install LinkFinder (for extracting endpoints from JS files)
RUN git clone https://github.com/GerbenJavado/LinkFinder.git /root/LinkFinder \
    && cd /root/LinkFinder && python3 setup.py install
ENV PATH="/root/LinkFinder:$PATH"

# Install getJS (for extracting endpoints from JS files)
RUN go install github.com/003random/getJS@latest

# Install eyewitness (screenshot tool)
RUN git clone https://github.com/RedSiege/EyeWitness.git /root/EyeWitness \
    && cd /root/EyeWitness && ./Python/setup/setup.sh
ENV PATH="/root/EyeWitness/Python/:$PATH"

# Install EyeBaller (Screenshot analysis)
RUN git clone https://github.com/BishopFox/eyeballer.git /root/eyeballer \
    && cd /root/eyeballer \
    && pip install -r requirements.txt \
    && wget https://github.com/BishopFox/eyeballer/releases/download/3.0/bishop-fox-pretrained-v3.h5
ENV PATH="/root/eyeballer:$PATH"

# Install webanalyze (web app technology detection)
RUN wget https://github.com/rverton/webanalyze/releases/download/v0.4.1/webanalyze_Linux_x86_64.tar.gz \
    && tar -C /usr/local/bin/ -xzf webanalyze_Linux_x86_64.tar.gz \
    && rm webanalyze_Linux_x86_64.tar.gz \
    && cd /usr/local/bin/ && ./webanalyze -update

# Install WhatWeb (web app fingerprinting)
RUN git clone https://github.com/urbanadventurer/WhatWeb.git /root/WhatWeb \
    && cd /root/WhatWeb && gem install bundler && bundle install

# Install FingerprintX (web app fingerprinting)
RUN go install github.com/praetorian-inc/fingerprintx/cmd/fingerprintx@latest

# Install Retire.js (JS vulnerability scanner)
RUN npm install -g retire

# Install arjun (API endpoint parameter bruteforcer)
RUN pip install arjun

# Install massdns (DNS enumeration)
RUN git clone https://github.com/blechschmidt/massdns.git /root/massdns \
    && cd /root/massdns && make && make install

# Install PureDNS (DNS enumeration)
RUN go install github.com/d3mondev/puredns/v2@latest

# Create PureDNS config directory and add resolvers
RUN mkdir -p /root/.config/puredns \
    && echo "8.8.8.8\n8.8.4.4\n1.1.1.1\n1.0.0.1\n208.67.222.222\n208.67.220.220" > /root/.config/puredns/resolvers.txt

# Install ffuf (web directory/file bruteforcer)
RUN go install github.com/ffuf/ffuf@latest

# Install WAFW00F (WAF detection)
RUN pip install wafw00f

# Install cloudfail (CDN detection)
RUN git clone https://github.com/m0rtem/CloudFail.git /root/CloudFail \
    && cd /root/CloudFail && pip install -r requirements.txt
ENV PATH="/root/CloudFail:$PATH"

# Install CF-Hero (Cloudflare bypass) - Repository removed due to accessibility issues
# Alternative: Use cloudfail for CDN detection instead

# Install cloud_enum (cloud enumeration)
RUN git clone https://github.com/initstring/cloud_enum.git /root/cloud_enum \
    && cd /root/cloud_enum && pip install -r requirements.txt
ENV PATH="/root/cloud_enum:$PATH"

# Install S3enum (S3 bucket enumeration)
RUN git clone https://github.com/koenrh/s3enum.git /root/s3enum
# Note: s3enum doesn't have requirements.txt, it's a standalone script
ENV PATH="/root/s3enum:$PATH"

# Install Sublist3r
RUN git clone https://github.com/aboul3la/Sublist3r.git /opt/Sublist3r && \
pip install -r /opt/Sublist3r/requirements.txt

# Install trufflehog
RUN curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin

# Install Python dependencies for new tools
RUN pip install --no-cache-dir \
    dnspython \
    requests \
    python-dotenv \
    playwright \
    beautifulsoup4 \
    lxml \
    ipcalc \
    shodan \
    censys
# Note: binaryedge, hunterio, leakix packages not available - removed

# Install Playwright browsers
RUN playwright install chromium

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
ENV HTTPX_PATH=/root/go/bin/httpx
ENV NUCLEI_PATH=/root/go/bin/nuclei
ENV NAABU_PATH=/root/go/bin/naabu
ENV KATANA_PATH=/root/go/bin/katana
ENV FEROXBUSTER_PATH=/usr/local/bin/feroxbuster
ENV GOBUSTER_PATH=/root/go/bin/gobuster
ENV LINKFINDER_PATH=/root/LinkFinder/linkfinder.py
ENV GETJS_PATH=/root/go/bin/getJS
ENV EYEWITNESS_PATH=/root/EyeWitness/Python/EyeWitness.py
ENV EYEBALLER_PATH=/root/eyeballer/eyeballer
ENV WEBANALYZE_PATH=/usr/local/bin/webanalyze
ENV WHATWEB_PATH=/usr/local/bin/whatweb
ENV ARJUN_PATH=/usr/local/bin/arjun
ENV FFUF_PATH=/root/go/bin/ffuf
ENV FINGERPRINTX_PATH=/root/go/bin/fingerprintx
ENV MASSDNS_PATH=/root/massdns/bin/massdns
ENV PUREDNS_PATH=/root/go/bin/puredns
ENV WAFW00F_PATH=/usr/local/bin/wafw00f
ENV CLOUDFAIL_PATH=/root/CloudFail/cloudfail.py
# CF_HERO_PATH removed - tool not available
ENV CLOUD_ENUM_PATH=/root/cloud_enum/cloud_enum.py
ENV S3ENUM_PATH=/root/s3enum/s3enum.py
ENV PATH="/root/EyeWitness/Python/:/root/eyeballer:/root/massdns/bin/:/root/CloudFail:/root/cloud_enum:/root/s3enum:/usr/local/go/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/sbin:/root/.local/bin:/root/go/bin"

# Entrypoint
ENTRYPOINT ["python", "run_passive_recon.py"]
