FROM node:22-alpine@sha256:1314fb30ec37592d5845e5a160d522c0e680972aa534549940b8d73bde88481a
WORKDIR /audit
COPY scanner.mjs flow-analysis.mjs /audit/
COPY vendor/acorn/ /audit/vendor/acorn/
COPY vendor/babel-parser/ /audit/vendor/babel-parser/
COPY worker.mjs /audit/worker.mjs
USER 65534:65534
ENTRYPOINT ["node", "/audit/worker.mjs"]
