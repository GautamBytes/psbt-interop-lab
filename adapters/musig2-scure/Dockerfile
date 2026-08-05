FROM node:24.18.0-bookworm-slim@sha256:6f7b03f7c2c8e2e784dcf9295400527b9b1270fd37b7e9a7285cf83b6951452d AS build

WORKDIR /adapter
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts
COPY adapter.mjs ./
COPY test ./test
COPY tsconfig.json ./
RUN npm test \
    && npm run typecheck

FROM build AS production-dependencies

RUN npm pkg delete devDependencies \
    && npm ci --ignore-scripts --omit=dev --omit=peer

FROM node:24.18.0-bookworm-slim@sha256:6f7b03f7c2c8e2e784dcf9295400527b9b1270fd37b7e9a7285cf83b6951452d

ENV NODE_ENV=production \
    NODE_OPTIONS=--disable-proto=throw

RUN useradd --create-home --uid 10001 adapter
WORKDIR /opt/psbt-lab
COPY --from=production-dependencies --chown=adapter:adapter /adapter/node_modules ./node_modules
COPY --from=production-dependencies --chown=adapter:adapter /adapter/package.json /adapter/adapter.mjs ./

USER adapter
ENTRYPOINT ["node", "/opt/psbt-lab/adapter.mjs"]
