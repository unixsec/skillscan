# skillscan web console build image (coding spec §16.1). Same-origin BFF
# reverse proxy (see nginx.conf) so session/CSRF cookies (SameSite=Strict)
# work correctly - the SPA is never served from a different origin than /v1.
FROM node:22-slim@sha256:6c74791e557ce11fc957704f6d4fe134a7bc8d6f5ca4403205b2966bd488f6b3 AS builder

# node:22-slim currently bundles npm 10.9.8, which hits a reproducible
# "Exit handler never called!" crash (an npm CLI regression, not a project
# issue - confirmed by isolating out DNS/network causes first) on `npm ci`
# in this container image. Pin back to 10.8.2, the last version verified not
# to hit it, until upstream node:22-slim bundles a fixed npm.
RUN npm install -g npm@10.8.2

WORKDIR /build
COPY web/package.json web/package-lock.json ./
# SECURITY (INV-14): `npm ci` never resolves new versions or reaches out
# beyond what package-lock.json already pins - point NPM_CONFIG_REGISTRY at
# an internal mirror for a real air-gapped build (coding spec §2's own "Web UI
# 依赖离线化" requirement), same posture as the backend Dockerfile's
# PIP_INDEX_URL handling.
ARG NPM_CONFIG_REGISTRY
ARG ALLOW_PUBLIC_INDEXES

# INV-14 build-time egress gate. `npm ci` resolves no NEW versions, but it still
# DOWNLOADS every locked tarball, and an empty NPM_CONFIG_REGISTRY does not fail
# closed - `npm config get registry` reports registry.npmjs.org (measured).
COPY scripts/require_build_index.sh /usr/local/bin/require_build_index.sh
RUN require_build_index.sh NPM_CONFIG_REGISTRY "${NPM_CONFIG_REGISTRY}" \
        "${ALLOW_PUBLIC_INDEXES}" registry.npmjs.org
RUN npm ci
COPY web/ .
RUN npm run build

FROM nginx:1.27-alpine@sha256:65645c7bb6a0661892a8b03b89d0743208a18dd2f3f17a54ef4b76fb8e2f2a10

RUN addgroup -S skillscan && adduser -S skillscan -G skillscan
COPY --from=builder /build/dist /usr/share/nginx/html
COPY web/nginx.conf /etc/nginx/nginx.conf
RUN chown -R skillscan:skillscan /usr/share/nginx/html \
    && touch /var/run/nginx.pid \
    && chown skillscan:skillscan /var/run/nginx.pid

USER skillscan
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
