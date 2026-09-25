FROM node:22-alpine

# Install curl for healthcheck utility
RUN apk add --no-cache curl

WORKDIR /app

# Copy package definitions
COPY package*.json ./

# Install dependencies
RUN npm ci --omit=dev

# Copy application code and files
COPY . .

EXPOSE 3000

CMD ["node", "src/server.js"]
