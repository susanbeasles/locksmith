# syntax=docker/dockerfile:1.7
# Locksmith Ring 1 Clean-Room Container Image
#
# Invariants:
# - Multi-stage build hardcoded to verified multi-platform SHA-256 base-image digests (zero ARG overrides).
# - Compiled strictly with `--locked --release --features prod-strict` (compile-time ban on `test-hsm`) and linked via `mold`.
# - Verified at build time via `nm` symbol audit and clean-environment `verify-self` KAT execution.
# - Production binary installed as `0555` (`root:root` / `0:0`) at `/usr/local/bin/locksmith-daemon`.
# - Distroless non-root runtime (`65532:65532`), zero shell, zero `node`/`npm`, zero per-user dot-local paths.
# - Designed for `docker run --read-only --cap-drop=ALL --security-opt=no-new-privileges`.

# -----------------------------------------------------------------------------
# Stage 1: Hermetic Rust 1.85 Bookworm + aws-lc-rs + mold Builder
# -----------------------------------------------------------------------------
FROM docker.io/library/rust:1.85-bookworm@sha256:e51d0265072d2d9d5d320f6a44dde6b9ef13653b035098febd68cce8fa7c0bc4 AS builder

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        binutils \
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

RUN cargo build --locked --release -p locksmith-daemon --features prod-strict \
    && ! nm ./target/release/locksmith-daemon | grep -Eq 'SoftwareTestHsm|serve_ring0_hmac_stream|ConnectedRing0StreamUnwrapper' \
    && env -i PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" ./target/release/locksmith-daemon verify-self \
    && install -o 0 -g 0 -m 0555 ./target/release/locksmith-daemon /usr/local/bin/locksmith-daemon

# -----------------------------------------------------------------------------
# Stage 2: Immutable Non-Root Distroless Runtime (`--read-only` compatible)
# -----------------------------------------------------------------------------
FROM gcr.io/distroless/cc-debian12:nonroot@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f AS runtime

COPY --from=builder --chown=0:0 --chmod=0555 /usr/local/bin/locksmith-daemon /usr/local/bin/locksmith-daemon

USER 65532:65532
WORKDIR /

ENTRYPOINT ["/usr/local/bin/locksmith-daemon"]
CMD ["verify-self"]
