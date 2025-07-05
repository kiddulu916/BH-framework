# Cursor Background Agent Dockerfile for Bug Hunting Framework
# Based on Cursor's requirements for background agents

# Use Ubuntu as base image for better tool compatibility
FROM ubuntu:22.04

# Set environment variables to avoid interactive prompts
ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=UTC

# Create ubuntu user with proper sudo access
RUN useradd -m -s /bin/bash ubuntu && \
    usermod -aG sudo ubuntu && \
    echo "ubuntu ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

# Set working directory to ubuntu's home
WORKDIR /home/ubuntu

# Install essential system dependencies
RUN apt-get update && apt-get install -y \
    # Basic development tools
    git \
    curl \
    wget \
    python3 \
    python3-pip \
    python3-venv \
    unzip \
    zip \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

RUN apt-get update && apt-get install -y \
    vim \
    nano \
    htop \
    tree \
    python3-dev \
    nodejs \
    npm \
    postgresql-client \
    nmap \
    netcat \
    telnet \
    jq \
    docker \
    docker-compose \

# Set up Python virtual environment
RUN python3 -m venv /home/ubuntu/venv
ENV PATH="/home/ubuntu/venv/bin:$PATH"

# Install essential Python packages for development
RUN pip3 install --no-cache-dir \
    # Core development tools
    black \
    flake8 \
    mypy \
    pytest \
    pytest-asyncio \
    pytest-cov \
    pytest-mock \
    pytest-django \
    pytest-xdist \
    pytest-timeout \
    pytest-randomly \
    pytest-random-order \
    
    # Database and ORM
    psycopg2-binary \
    sqlalchemy \
    alembic \
    asyncpg \
    
    # Web framework and API
    django-rest-framework \
    django-ninja \
    django \
    django-cors-headers \
    typescript \
    @types/node \
    postgres \
    python-dotenv \
    redux \
    react \
    
    # Data validation and serialization
    pydantic \
    pydantic[email] \
    pydantic-settings \
    openapi-schema-pydantic \
    
    # HTTP client for testing
    httpx \
    
    # Authentication & Security
    PyJWT \
    bcrypt \
    python-jose \
    
    # Environment and configuration
    drf-spectacular \
    sentry-sdk \
    tenacity \
    
    # Development and testing utilities
    faker \
    factory-boy \
    isort \
    pre-commit \
    
    # Logging & Monitoring
    structlog \
    python-json-logger \
    prometheus-client \
    
    # Documentation
    sphinx \
    mkdocs \
    mkdocs-material \
    mkdocstrings \
    
    # Security tools
    bandit \
    safety \
    
    # Performance testing
    locust \
    
    # Bug hunting tools
    arjun \
    ffuf \
    trufflehog \
    amass

# Install Node.js packages globally
RUN npm install -g \
    pnpm \
    eslint \
    prettier \
    typescript \
    redux \
    react \
    react-dom \
    react-router \
    react-router-dom \
    nextjs

# Create common directories
RUN mkdir -p /home/ubuntu/projects \
    && mkdir -p /home/ubuntu/.ssh \
    && mkdir -p /home/ubuntu/.config

# Set proper permissions
RUN chown -R ubuntu:ubuntu /home/ubuntu

# Switch to ubuntu user
USER ubuntu

# Set up shell environment
RUN echo 'export PATH="/home/ubuntu/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/home/ubuntu/go/bin:/home/ubuntu/bin:/home/ubuntu/.local/bin:$PATH"' >> /home/ubuntu/.bashrc \
    && echo 'export PYTHONPATH="/home/ubuntu/venv/bin/python3:$PYTHONPATH"' >> /home/ubuntu/.bashrc \
    && echo 'alias python=python3' >> /home/ubuntu/.bashrc \
    && echo 'alias pip=pip3' >> /home/ubuntu/.bashrc

# Set default command
CMD ["/bin/bash"]

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1
