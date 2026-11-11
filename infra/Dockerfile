# syntax=docker/dockerfile:1.7
# Locksmith Ring 1 Clean-Room Container Image
#
# Invariants:
# - Multi-stage build pinned by immutable SHA-256 base-image digests.
# - Compiled strictly with `--locked --release` and linked via `mold`.
# - Production binary installed as `0555` (`root:root` / `0:0`) at `/usr/local/bin/locksmith-daemon`.
# - Distroless non-root runtime (`65532:65532`), zero shell, zero `node`/`npm`, zero per-user dot-local paths.
# - Designed for `docker run --read-only --cap-drop=ALL --security-opt=no-new-privileges`.

ARG BUILDER_IMAGE=docker.io/library/rust:1.85-bookworm@sha256:df38be31bfab9fbbf88a41b88a71b7112bf5a0b3a054ef8a2ef686da2405626c
ARG RUNTIME_IMAGE=gcr.io/distroless/cc-debian12:nonroot@sha256:6714977f9f02632c31377650c15d89a7efaebf43bab0f37c712c30fc01edb973

# -----------------------------------------------------------------------------
# Stage 1: Hermetic Rust + aws-lc-rs + mold Builder
# -----------------------------------------------------------------------------
FROM ${BUILDER_IMAGE} AS builder

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        clang \
        cmake \
        lld \
        mold \
        pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src/locksmith

COPY Cargo.toml Cargo.lock ./
COPY crates ./crates

ENV CARGO_TERM_COLOR=always \
    RUSTFLAGS="-C link-arg=-fuse-ld=mold"

RUN cargo build --locked --release -p locksmith-daemon \
    && ./target/release/locksmith-daemon verify-self \
    && install -o 0 -g 0 -m 0555 ./target/release/locksmith-daemon /usr/local/bin/locksmith-daemon

# -----------------------------------------------------------------------------
# Stage 2: Immutable Non-Root Distroless Runtime (`--read-only` compatible)
# -----------------------------------------------------------------------------
FROM ${RUNTIME_IMAGE} AS runtime

COPY --from=builder --chown=0:0 --chmod=0555 /usr/local/bin/locksmith-daemon /usr/local/bin/locksmith-daemon

USER 65532:65532
WORKDIR /

ENTRYPOINT ["/usr/local/bin/locksmith-daemon"]
CMD ["verify-self"]
