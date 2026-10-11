FROM node:24-bookworm-slim
LABEL org.opencontainers.image.source="https://github.com/r4venrudy/rudy-dns-checker" org.opencontainers.image.licenses="MIT"
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --no-audit --no-fund
COPY index.js raven.png LICENSE ./
COPY packaging ./packaging
RUN npm test && node --check index.js
ENV NODE_ENV=production
USER node
ENTRYPOINT ["node", "/app/index.js"]
