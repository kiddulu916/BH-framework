FROM python:3.11-slim

# Install system dependencies and security tools
RUN apt-get update && apt-get install -y \
    curl \
    wget \
    git \
    unzip \
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
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Create necessary directories
RUN mkdir -p /outputs /app/runners /app/tools

# Copy stage files
COPY . .

# Set environment variables
ENV PYTHONPATH=/app
ENV PATH="/app/tools:${PATH}"

# Create non-root user for security
RUN groupadd -r appuser && useradd -r -g appuser appuser
RUN chown -R appuser:appuser /app /outputs
USER appuser

# Set entry point
CMD ["python", "run_vuln_scan.py"] 