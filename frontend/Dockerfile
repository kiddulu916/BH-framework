# 1. Installer stage for fetching dependencies
FROM node:20 AS deps

# Set working directory
WORKDIR /app

# Copy package.json and package-lock.json
COPY package.json package-lock.json ./

# Install dependencies
RUN npm install

# 2. Builder stage for creating the production build
FROM node:20 AS builder

# Set working directory
WORKDIR /app

# Copy dependencies from the 'deps' stage
COPY --from=deps /app/node_modules ./node_modules
COPY . .

# Build the Next.js app
RUN npm run build

# 3. Runner stage for running the app
FROM node:20-alpine AS runner

# Set working directory
WORKDIR /app

# Create a non-root user
RUN addgroup -g 1001 -S nodejs
RUN adduser -S nextjs -u 1001

# Copy built app from the 'builder' stage
COPY --from=builder /app/public ./public
COPY --from=builder /app/.next ./.next
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/package.json ./package.json

# Change ownership of the app directory
RUN chown -R nextjs:nodejs /app/.next

# Set the user
USER nextjs

# Expose the port
EXPOSE 3000

# Set the entrypoint
CMD ["npm", "start"] 