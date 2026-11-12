# syntax=docker/dockerfile:1

FROM node:20-alpine

WORKDIR /app

# Copy application files
COPY server.js index.html index.v1.html logo.svg ./
COPY data ./data

# Ensure data and uploads directories exist and are writable
RUN mkdir -p /app/data/uploads

ENV PORT=3000
EXPOSE 3000

# Persist database and uploaded files
VOLUME ["/app/data"]

CMD ["node", "server.js"]
