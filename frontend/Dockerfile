# Multi-stage build for optimized Docker container
# Stage 1: Dependencies
FROM node:20-bullseye AS deps

# Set working directory
WORKDIR /app

# Copy package files
COPY package.json package-lock.json ./

# Install all dependencies (including dev dependencies for build)
RUN npm ci && npm cache clean --force

# Stage 2: Builder
FROM node:20-bullseye AS builder

# Set working directory
WORKDIR /app

# Copy dependencies from deps stage
COPY --from=deps /app/node_modules ./node_modules

# Copy source code
COPY . .

# Set environment variables for build optimization
ENV NODE_ENV=production
ENV PORT=3000
ENV HOST=0.0.0.0
ENV KEEP_ALIVE_TIMEOUT=60000
ENV DOCKER_ENV=true
ENV NEXT_TELEMETRY_DISABLED=1
ENV NEXT_PRIVATE_DISABLE_LIGHTNINGCSS=1

# Build the application with optimizations
RUN npm run build

# Stage 3: Production runner
FROM node:20-bullseye AS runner

# Set working directory
WORKDIR /app

# Install dumb-init for proper signal handling
RUN apt-get update && apt-get install -y dumb-init curl && rm -rf /var/lib/apt/lists/*

# Create non-root user for security
RUN groupadd -r appuser && useradd -r -g appuser appuser

# Copy necessary files from builder
COPY --from=builder /app/public ./public
COPY --from=builder /app/.next/standalone ./
COPY --from=builder /app/.next/static ./.next/static

# Set proper permissions
RUN chown -R appuser:appuser /app

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
  CMD curl -f http://localhost:3000/health || exit 1

# Use dumb-init for proper signal handling
ENTRYPOINT ["dumb-init", "--"]

CMD ["node", "server.js"]
