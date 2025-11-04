# Use official Node LTS image
FROM node:18-alpine

# Set working directory
WORKDIR /app

# Copy package.json and lock files first for caching
COPY package*.json ./

# Install dependencies
RUN npm ci --only=production

# Copy all project files
COPY . .

# Default command to run the scanner CLI
ENTRYPOINT ["node", "src/index.js"]
