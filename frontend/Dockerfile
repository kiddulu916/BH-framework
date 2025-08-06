# Multi-stage build for optimized Docker container
# Stage 1: Dependencies
FROM node:20-alpine as builder

# Set working directory
WORKDIR /app

# Copy package files
COPY package*.json ./

# Install all dependencies (including dev dependencies for build)
RUN npm ci && npm cache clean --force

# Copy source code
COPY . .

# Build the application with optimizations
RUN npm run build

FROM node:20-alpine as production

# Install dumb-init for proper signal handling
RUN apk add --no-cache dumb-init curl

# Create non-root user for security
RUN addgroup -g 1001 -S appuser && adduser -S appuser -G appuser

# Copy necessary files from builder
COPY --from=builder /app/.next /app/.next
COPY --from=builder /app/public /app/public
COPY --from=builder /app/package.json /app/package.json
COPY --from=builder /app/package-lock.json /app/package-lock.json

# Set working directory
WORKDIR /app

# Install only production dependencies
RUN npm ci --only=production && npm cache clean --force

# Set proper permissions
RUN mkdir -p /app/logs /app/tmp \
    && chown -R appuser:appuser /app \
    && chmod -R 755 /app

# Create health check script
RUN echo '#!/bin/sh\ncurl -f http://localhost:3000/health || exit 1' > /app/healthcheck.sh \
    && chmod +x /app/healthcheck.sh

# Security hardening
RUN chmod -R 755 /app \
    && find /app -type f -name "*.js" -exec chmod 644 {} \; \
    && find /app -type f -name "*.css" -exec chmod 644 {} \; \
    && find /app -type f -name "*.html" -exec chmod 644 {} \;

# Switch to non-root user
USER appuser

# Expose port
EXPOSE 3000

# Set environment variables for container optimization
ENV NODE_ENV=production
ENV PORT=3000
ENV HOST=0.0.0.0

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD ["/app/healthcheck.sh"]

# Use dumb-init for proper signal handling
ENTRYPOINT ["dumb-init", "--"]

CMD ["npm", "start"]
