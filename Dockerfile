FROM node:20-slim
WORKDIR /app

# Install build tools for native modules (sharp, etc)
RUN apt-get update && apt-get install -y python3 make g++ && rm -rf /var/lib/apt/lists/*

COPY package*.json ./
RUN npm install --omit=dev

COPY server.js ./
EXPOSE 8080
CMD ["node", "server.js"]
