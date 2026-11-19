FROM node:24-bookworm-slim
WORKDIR /srv/lockey
COPY security-agent/vendor/acorn/ security-agent/vendor/acorn/
COPY security-review-mvp/ security-review-mvp/
COPY sites/zoro-security-demo/ sites/zoro-security-demo/
WORKDIR /srv/lockey/sites/zoro-security-demo
RUN npm ci --omit=dev --ignore-scripts --no-audit --no-fund
USER node
CMD ["node", "server.mjs"]
