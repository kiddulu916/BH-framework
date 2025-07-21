# Active Recon Stage Dockerfile
#
# Builds a container with all active recon tools and runners.

FROM python:3.11-slim as base

WORKDIR /app
COPY . /app

# Install system dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        git \
        curl \
        wget \
        build-essential \
        ca-certificates \
        nmap \
        netcat-openbsd \
        net-tools \
        iputils-ping \
        dnsutils \
        libpcap-dev \
        ruby \
        ruby-dev \
        nodejs \
        npm \
        python3-setuptools \
        python3-pip \
        libyaml-dev \
        python3-dev \
        python3-venv \
        python3-wheel \
        unzip \
        make \
        gcc \
        libmagic-dev \
        libmagic1 \
    && rm -rf /var/lib/apt/lists/*
        
RUN pip install -r /app/requirements.txt

# Install Go
RUN wget https://go.dev/dl/go1.24.4.linux-amd64.tar.gz
RUN tar -C /usr/local -xzf go1.24.4.linux-amd64.tar.gz
RUN rm go1.24.4.linux-amd64.tar.gz
ENV PATH="/usr/local/go/bin:${PATH}"

# Install naabu (port scanner)
RUN go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest

# Install katana (web crawler)
RUN CGO_ENABLED=1 go install github.com/projectdiscovery/katana/cmd/katana@latest

# Install Feroxbuster (web directory/file bruteforcer)
RUN wget https://github.com/epi052/feroxbuster/releases/download/v2.11.0/x86_64-linux-feroxbuster.zip
RUN unzip x86_64-linux-feroxbuster.zip
RUN mv feroxbuster /usr/local/bin/feroxbuster
RUN chmod +x /usr/local/bin/feroxbuster
RUN rm x86_64-linux-feroxbuster.zip

# Install GoBuster (DNS/VHost bruteforcer)
RUN go install -v github.com/OJ/gobuster/v3@latest

# Install LinkFinder (for extracting endpoints from JS files)
RUN git clone https://github.com/GerbenJavado/LinkFinder.git /root/LinkFinder
RUN cd /root/LinkFinder && python3 setup.py install
ENV PATH="/root/LinkFinder:$PATH"

# Install getJS (for extracting endpoints from JS files)
RUN go install github.com/003random/getJS@latest

# Install eyewitness (screenshot tool)
RUN git clone https://github.com/RedSiege/EyeWitness.git /root/EyeWitness
RUN cd /root/EyeWitness && \
    ./Python/setup/setup.sh
ENV PATH="/root/EyeWitness/Python/:$PATH"

# Install EyeBaller (Screenshot analysis)
RUN git clone https://github.com/BishopFox/eyeballer.git /root/eyeballer
RUN cd /root/eyeballer && \
    pip install -r requirements.txt && \
    wget https://github.com/BishopFox/eyeballer/releases/download/3.0/bishop-fox-pretrained-v3.h5
ENV PATH="/root/eyeballer:$PATH"

# Install webanalyze (web app technology detection)
RUN wget https://github.com/rverton/webanalyze/releases/download/v0.4.1/webanalyze_Linux_x86_64.tar.gz
RUN tar -C /usr/local/bin/ -xzf webanalyze_Linux_x86_64.tar.gz
RUN rm webanalyze_Linux_x86_64.tar.gz
RUN cd /usr/local/bin/ && ./webanalyze -update

# Install WhatWeb (web app fingerprinting)
RUN git clone https://github.com/urbanadventurer/WhatWeb.git /root/WhatWeb
RUN cd /root/WhatWeb && gem install bundler && bundle install

# Install FingerprintX (web app fingerprinting)
RUN go install github.com/praetorian-inc/fingerprintx/cmd/fingerprintx@latest

# Install Retire.js (JS vulnerability scanner)
RUN npm install -g retire

# Install arjun (API endpoint parameter bruteforcer)
RUN pip install arjun

# Install massdns (DNS enumeration)
RUN git clone https://github.com/blechschmidt/massdns.git /root/massdns
RUN cd /root/massdns && make && make install

# Install PureDNS (DNS enumeration)
RUN go install github.com/d3mondev/puredns/v2@latest

# Create PureDNS config directory and add resolvers
RUN mkdir -p /root/.config/puredns
RUN echo "8.8.8.8\n8.8.4.4\n1.1.1.1\n1.0.0.1\n208.67.222.222\n208.67.220.220" > /root/.config/puredns/resolvers.txt

# Install ffuf (web directory/file bruteforcer)
RUN go install github.com/ffuf/ffuf@latest

# Set environment variables for tool paths
ENV NMAP_PATH=/usr/bin/nmap
ENV HTTPX_PATH=/root/go/bin/httpx
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

ENV PATH="/root/EyeWitness/Python/:/root/eyeballer:/root/massdns/bin/:/usr/local/go/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/sbin:/root/.local/bin:/root/go/bin"

# Entrypoint
ENTRYPOINT ["python", "run_active_recon.py"]
