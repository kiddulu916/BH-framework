# Comprehensive Reporting Stage Dockerfile
#
# Builds a container for comprehensive reporting and stakeholder communication.
# Optimized for Phase 6 - stakeholder communication with minimal font dependencies.

FROM python:3.11-slim as base

# Install system dependencies with minimal font packages
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
        jq \
        pandoc \
        texlive-latex-base \
        texlive-fonts-recommended \
        wkhtmltopdf \
        nodejs \
        npm \
        python3-setuptools \
        python3-dev \
        python3-wheel \
        make \
        gcc \
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
        libgstreamer1.0-dev \
        libgstreamer-plugins-base1.0-dev \
        libgstreamer-plugins-bad1.0-dev \
        libgstreamer-gl1.0-0 \
        libgstreamer-plugins-base1.0-0 \
        libgstreamer-plugins-bad1.0-0 \
        libgstreamer-plugins-good1.0-0 \
        fonts-liberation \
        fonts-dejavu-core \
        fonts-dejavu-extra \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install additional reporting tools
RUN pip install --no-cache-dir \
    reportlab \
    weasyprint \
    python-pptx \
    openpyxl \
    xlsxwriter \
    matplotlib \
    seaborn \
    plotly \
    dash \
    dash-bootstrap-components

# Install Node.js packages for advanced reporting
RUN npm install -g \
    puppeteer \
    @puppeteer/browsers

# Create output directories
RUN mkdir -p /app/outputs /app/templates /app/reports

# Copy stage files
COPY . /app

# Set environment variables
ENV PYTHONPATH=/app
ENV PATH="/app:${PATH}"

# Create non-root user for security
RUN groupadd -r appuser && useradd -r -g appuser appuser
RUN chown -R appuser:appuser /app
USER appuser

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:8000/health/', timeout=5)" || exit 1

# Entry point
ENTRYPOINT ["python", "run_comprehensive_reporting.py"]