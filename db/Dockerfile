# PostgreSQL Database Container for Bug Hunting Framework
FROM postgres:15-alpine

# Set environment variables for development
ENV POSTGRES_DB=bug_hunting_framework
ENV POSTGRES_USER=postgres

# Copy initialization scripts if needed
COPY postgres/ /docker-entrypoint-initdb.d/

# Expose PostgreSQL port
EXPOSE 5432

# Health check to ensure database is ready
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD pg_isready -U postgres -d bug_hunting_framework
