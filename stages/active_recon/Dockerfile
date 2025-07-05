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

# Install httpx
RUN go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

# Install naabu (port scanner)
RUN go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest

# Install katana (web crawler)
RUN CGO_ENABLED=1 go install github.com/projectdiscovery/katana/cmd/katana@latest

# Install Feroxbuster (web directory/file bruteforcer)
RUN curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/master/install-nix.sh | bash

# Install GoBuster (DNS/VHost bruteforcer)
RUN go install -v github.com/OJ/gobuster/v3@latest

# Install LinkFinder (for extracting endpoints from JS files)
RUN git clone https://github.com/GerbenJavado/LinkFinder.git
RUN cd LinkFinder && python3 setup.py install
RUN cd /root/
ENV PATH="/root/LinkFinder:$PATH"

# Install getJS (for extracting endpoints from JS files)
RUN go install github.com/003random/getJS/v2@latest

# Install eyewitness (screenshot tool)
RUN git clone https://github.com/RedSiege/EyeWitness.git
RUN cd EyeWitness && \
    ./Python/setup/setup.sh && \
    cd /root/
ENV PATH="/root/EyeWitness/Python/:$PATH"

# Install EyeBaller (Screenshot analysis)
RUN git clone https://github.com/BishopFox/eyeballer.git
RUN cd eyeballer
RUN pip install -r requirements.txt
RUN wget https://github.com/BishopFox/eyeballer/releases/download/3.0/bishop-fox-pretrained-v3.h5
RUN cd /root/
ENV PATH="/root/eyeballer:$PATH"

# Install webanalyze (web app technology detection)
RUN wget https://github.com/rverton/webanalyze/releases/download/v0.4.1/webanalyze_Linux_x86_64.tar.gz
RUN tar -C /usr/local/bin/ -xzf webanalyze_Linux_x86_64.tar.gz
RUN rm webanalyze_Linux_x86_64.tar.gz
RUN cd /usr/local/bin/ && ./webanalyze -update && cd /root/

# Install WhatWeb (web app fingerprinting)
RUN git clone https://github.com/urbanadventurer/WhatWeb.git
RUN cd WhatWeb && gem install bundler && bundle install
RUN cd /root/

# Install FingerprintX (web app fingerprinting)
RUN go install github.com/praetorian-inc/fingerprintx/cmd/fingerprintx@latest

# Install Retire.js (JS vulnerability scanner)
RUN npm install -g retire

# Install arjun (API endpoint parameter bruteforcer)
RUN pip install arjun

# Install massdns (DNS enumeration)
RUN git clone https://github.com/blechschmidt/massdns.git
RUN cd massdns && make && make install
RUN cd /root/

# Install PureDNS (DNS enumeration)
RUN go install github.com/d3mondev/puredns/v2@latest

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
ENV EYE_BALLER_PATH=/root/eyeballer/eyeballer.py
ENV WEBANALYZE_PATH=/usr/local/bin/webanalyze
ENV WHATWEB_PATH=/usr/local/bin/whatweb
ENV ARJUN_PATH=/usr/local/bin/arjun
ENV FFUF_PATH=/root/go/bin/ffuf
ENV FINGERPRINTX_PATH=/root/go/bin/fingerprintx
ENV MASSDNS_PATH=/root/massdns/bin/massdns
ENV PUREDNS_PATH=/root/go/bin/puredns

ENV PATH="/root/EyeWitness/Python/:/root/massdns/bin/:/usr/local/go/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/sbin:/root/.local/bin:/root/go/bin"

# Entrypoint
ENTRYPOINT ["python", "run_active_recon.py"]
