# Frontend Dockerfile for DDoS Attack Visualizer
# Multi-stage build: Node for building, Nginx for serving

# ============ Build Stage ============
# Use Debian-based image for Tailwind CSS v4 (lightningcss native bindings)
FROM node:18-slim AS builder

# Build argument for API URL (can be overridden at build time)
ARG VITE_API_URL=http://localhost:8000

# Set environment variable for Vite build
ENV VITE_API_URL=$VITE_API_URL

# Set working directory
WORKDIR /app

# Copy package files first for better caching
COPY package.json package-lock.json* ./

# Install dependencies (clean install with platform-specific binaries)
RUN npm ci

# Copy source code
COPY . .

# Build the application
RUN npm run build

# ============ Production Stage ============
FROM nginx:alpine AS production

# Copy custom nginx config
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Copy built assets from builder stage
COPY --from=builder /app/dist /usr/share/nginx/html

# Expose port
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:3000/ || exit 1

# Start nginx
CMD ["nginx", "-g", "daemon off;"]
