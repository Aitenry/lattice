# lattice-node image (② §10 deliverable: single-binary node).
#
# Build only the crates the workspace needs; migration scripts are embedded at
# compile time via `sqlx::migrate!("./migrations")` (store/pg.rs::migrate), so the runtime image needs no .sql files.

FROM rust:1-bookworm AS build
WORKDIR /src
ENV CARGO_NET_GIT_FETCH_WITH_CLI=true

# Bake dependencies first: source changes do not invalidate the dependency layer
COPY Cargo.toml Cargo.lock ./
COPY crates/lattice-core/Cargo.toml crates/lattice-core/
COPY crates/lattice-plugins/Cargo.toml crates/lattice-plugins/
COPY crates/lattice-node/Cargo.toml crates/lattice-node/
RUN mkdir -p crates/lattice-core/src crates/lattice-plugins/src crates/lattice-node/src \
    && echo "fn main(){}" > crates/lattice-node/src/main.rs \
    && touch crates/lattice-core/src/lib.rs crates/lattice-plugins/src/lib.rs \
    && cargo build --release -p lattice-node || true

COPY crates ./crates
RUN touch crates/lattice-node/src/main.rs \
    && cargo build --release -p lattice-node

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl tzdata \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --create-home lattice \
    && mkdir -p /etc/lattice/keys /var/lib/lattice/wal \
    && chown -R lattice:lattice /etc/lattice /var/lib/lattice

COPY --from=build /src/target/release/lattice-node /usr/local/bin/lattice-node

USER lattice
EXPOSE 8080 9100
ENV LATTICE_CONFIG=/etc/lattice/config.toml \
    RUST_LOG=info

HEALTHCHECK --interval=10s --timeout=3s --start-period=20s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8080/v1/health || exit 1

ENTRYPOINT ["/usr/local/bin/lattice-node"]
