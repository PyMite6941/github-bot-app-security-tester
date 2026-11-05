FROM node:20-alpine

WORKDIR /app

COPY package.json ./
RUN npm install --only=production

COPY server.js ./

ENV PORT=8080
ENV SEPATCH_LOG_LEVEL=info

EXPOSE 8080

CMD ["node", "server.js"]
