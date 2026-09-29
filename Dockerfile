# syntax=docker/dockerfile:1
#
# Aegis control-plane image: web UI bundle + the four release binaries
# (aegis CLI, aegis-server, aegis-agent, aegis-mcp) in one slim runtime layer.
#
#   docker build -t aegis .
#   docker run --rm -p 8080:8080 -v aegis-data:/data -e AEGIS_PASSPHRASE=… aegis
#
# or `docker compose up -d` (see docker-compose.yml).

# ---------------------------------------------------------------- web bundle
FROM node:22-bookworm-slim AS web
WORKDIR /web
COPY crates/aegis-web/package.json crates/aegis-web/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY crates/aegis-web/ ./
RUN npm run build

# ---------------------------------------------------------------- rust build
FROM rust:1-bookworm AS rust
# cc/pkg-config only: every crypto/codec dependency vendors its C.
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential pkg-config \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
# The image already ships a full toolchain; rust-toolchain.toml would make
# rustup download a second one ("stable") before every cargo invocation.
RUN rm -f rust-toolchain.toml
# Cargo's registry/git caches and `target/` are BuildKit caches, so repeat
# builds only recompile changed crates; the finished binaries are copied into
# a real layer (/out) because cache-mount writes do not persist in layers.
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked -p aegis-cli -p aegis-server -p aegis-agent -p aegis-mcp \
    && mkdir -p /out \
    && cp /src/target/release/aegis /src/target/release/aegis-server \
       /src/target/release/aegis-agent /src/target/release/aegis-mcp /out/

# ------------------------------------------------------------------- runtime
FROM debian:bookworm-slim
# ca-certificates: outbound TLS (HTTPS repositories, webhooks). curl: healthcheck.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --create-home --home-dir /home/aegis aegis \
    && mkdir -p /data /usr/share/aegis \
    && chown -R aegis:aegis /data /usr/share/aegis
COPY --from=rust /out/ /usr/local/bin/
COPY --from=web /web/dist/ /usr/share/aegis/web/
RUN chmod 0755 /usr/local/bin/aegis /usr/local/bin/aegis-server \
    /usr/local/bin/aegis-agent /usr/local/bin/aegis-mcp

ENV AEGIS_LISTEN=0.0.0.0:8080 \
    AEGIS_CATALOG=/data/catalog.db \
    AEGIS_WEB_DIST=/usr/share/aegis/web \
    AEGIS_KNOWN_HOSTS=/data/ssh/known_hosts
WORKDIR /data
VOLUME ["/data"]
USER aegis
EXPOSE 8080
HEALTHCHECK --interval=15s --timeout=5s --start-period=5s --retries=5 \
    CMD curl -fsS http://127.0.0.1:8080/health || exit 1
ENTRYPOINT ["aegis-server"]
