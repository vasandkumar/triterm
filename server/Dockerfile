# Stage 1: Build
FROM node:22-alpine AS builder

# Install build dependencies
RUN apk add --no-cache python3 make g++

WORKDIR /app

# Copy package files
COPY package*.json ./
COPY server/package*.json ./server/

# Install all dependencies (including devDependencies for build)
RUN npm ci

# Copy source code
COPY server/ ./server/
COPY tsconfig.json ./

# Generate Prisma Client
RUN cd server && npx prisma generate

# Build TypeScript
RUN cd server && npm run build

# Stage 2: Production
FROM node:22-alpine

# Install production dependencies
RUN apk add --no-cache \
    ca-certificates \
    tzdata

# Create app user
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nodejs -u 1001

WORKDIR /app

# Copy package files
COPY --chown=nodejs:nodejs package*.json ./
COPY --chown=nodejs:nodejs server/package*.json ./server/

# Install only production dependencies
ENV NODE_ENV=production
RUN npm ci --only=production --workspace=server && \
    npm cache clean --force

# Copy built files from builder
COPY --chown=nodejs:nodejs --from=builder /app/server/dist ./server/dist
COPY --chown=nodejs:nodejs --from=builder /app/server/prisma ./server/prisma
COPY --chown=nodejs:nodejs --from=builder /app/server/node_modules/.prisma ./server/node_modules/.prisma

# Create necessary directories
RUN mkdir -p /app/server/logs /app/server/recordings && \
    chown -R nodejs:nodejs /app/server/logs /app/server/recordings

# Switch to non-root user
USER nodejs

# Expose port
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=40s --retries=3 \
    CMD node -e "require('http').get('http://localhost:3000/health', (r) => {process.exit(r.statusCode === 200 ? 0 : 1)})"

# Start server
WORKDIR /app/server
CMD ["node", "dist/index.js"]
