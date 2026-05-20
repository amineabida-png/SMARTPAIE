FROM node:20-bullseye-slim

WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .

RUN mkdir -p /app/data

ENV PORT=3000
EXPOSE 3000
CMD ["node", "server/index.js"]
