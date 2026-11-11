# Locksmith

Clean-room Linux-first zero-trust credential broker and mTLS egress splicer written in memory-safe Rust (`#![forbid(unsafe_code)]`).

## Architecture & Governance

- [`SPEC.md`](./SPEC.md) — Normative privilege ring topology (Ring 0 Hardware Authority ↔ Ring 1 Host Broker ↔ Ring 2 Zero-NIC Guest), wire framing, HKDF domain separation, RFC 8705 mTLS binding, TOCTOU-immune `memfd` cache sealing, and adversarial threat matrix.
- [`AGENTS.md`](./AGENTS.md) — Workspace lint invariants, secret hygiene rules, and mandatory Adversarial TDD (`RED -> GREEN -> HARDEN`) workflow.
- [`docs/LEGACY_INTENT_AUDIT.md`](./docs/LEGACY_INTENT_AUDIT.md) — Quarantine audit of legacy prototype capabilities vs. eliminated attack surfaces.

## Workspace Crates

| Crate | Responsibility |
| :--- | :--- |
| `crates/anvil-core` | Canonical length-prefixed HKDF-SHA256, 2-of-2 hardware-attested ChaCha20-Poly1305 secret unwrapping, concurrency-safe single-use nonce replay filter, and `BLAKE3` hash-chained audit ledger. |
| `crates/anvil-cache` | Content-addressed untrusted cache verification, `openat2` path confinement, anonymous sealed `memfd` (`F_SEAL_*`) TOCTOU protection, and Unicode/ANSI prompt-injection metadata sanitizer. |
| `crates/anvil-ipc` | Bounded `LKSM` binary wire framing (`MAX_FRAME_BYTES = 65_536`), Linux `AF_VSOCK` CID and `AF_UNIX` `SO_PEERCRED` peer authentication, and attested command envelopes. |
| `crates/locksmith-proxy` | Unforgeable move-only `ApprovedEgressTicket` typestate, RFC 8705 mTLS thumbprint policy engine, RFC 9110/9112 canonicalizer, TLS 1.3 egress splicer, and upstream secret-reflection scrubber. |
| `crates/locksmith-daemon` | Hardened host broker binary (`PR_SET_DUMPABLE(0)`, redacted audit logging, `SIGTERM`/`SIGINT` zeroization drain, and `verify-self` startup checks). |
