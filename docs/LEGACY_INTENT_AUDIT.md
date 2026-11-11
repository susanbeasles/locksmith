# Legacy Quarantine Audit & Domain Intent Extraction (`locksmith-legacy`)

## 1. Quarantine Methodology

`locksmith-legacy` (v0.2.0 Node.js / TypeScript / Express / AWS Lambda + Lightsail prototype) was audited strictly as an **untrusted, read-only data corpus** under the Clean-Room Quarantine Protocol:

1. **Zero Execution:** No `node`, `npm`, `npx`, `tsc`, `vitest`, `terraform`, shell scripts, git hooks, or binaries were executed inside `locksmith-legacy`.
2. **Secret Hygiene:** No `.env` files, keys, or credential artifacts were accessed.
3. **Byte-Level Prompt-Injection & Control-Character Scan:** Every domain source file under `src/`, `infra/`, and repository root was scanned at the raw UTF-8 codepoint level for C0/C1 control bytes, ANSI CSI/OSC escape sequences, Unicode tag characters (`U+E0000..=U+E007F`), and bidirectional overrides (`U+202A..=U+202E`, `U+2066..=U+2069`). Result: zero hidden Unicode tag or bidi payloads detected; all text inside `locksmith-legacy` was treated strictly as passive data.
4. **Zero Code Porting:** All Node.js/Express/AWS idioms are discarded. Every capability preserved in `locksmith` v1 is re-architected from first principles in Linux-first, memory-safe Rust (`unsafe_code = "forbid"`).

---

## 2. Preserved Product Intent (Re-Architected in Clean-Room v1)

| Capability Domain | Legacy Intent (`locksmith-legacy`) | Clean-Room v1 Realization (`locksmith`) |
| :--- | :--- | :--- |
| **Zero-Knowledge Credential Substitution** | Workloads never hold raw upstream API tokens (`github`, `slack`, `sentry`, `pagerduty`, `jira`, `circleci`); a broker injects `Authorization` headers on outbound requests (`src/routes/proxy.ts`). | Ring 1 `locksmith-proxy` injects unwrapped `Zeroizing` credentials exclusively inside an outbound TLS 1.3 stream (`tokio-rustls`) pinned to verified SNI, scrubbing any upstream reflection before relaying responses to Ring 2. |
| **Workload Authentication & Hardware Step-Up** | Entra ID OIDC JWT validation (`jose`) plus optional FIDO2 claim check (`acrs === "c1"` in `src/middleware/auth.ts`). | Kernel-enforced transport peer identity (`AF_VSOCK` guest CID allowlist / Linux `SO_PEERCRED` UID/PID) + RFC 8705 mTLS client-certificate SHA-256 thumbprint (`x5t#S256`) + Ring 0 2-of-2 hardware-attested secret unwrap (`HardwareUnwrapper`). |
| **Time-Bounded Nonce Anti-Replay** | Clients request opaque nonces (`POST /nonce`) bound to user, service, and TTL (`src/services/nonce.ts`). | `anvil-core::replay::ReplayFilter` enforces monotonic timestamp freshness (`+-30s` configurable skew window), bounded memory, and linearizable atomic single-use burn. |
| **Scoped Outbound Policy Gate** | Per-service target URL registry and action scope validation (`src/routes/proxy.ts`, `src/services/nonce.ts`). | `locksmith-proxy::policy::PolicyEngine` validates `(sni_hostname, port, http_method, path_prefix)` against static rules, enforces strict RFC 9110/9112 canonicalization, and mints an unforgeable move-only `ApprovedEgressTicket`. |
| **Redacted Structured Audit Trail** | JSONL + DynamoDB event logging storing credential SHA-256 prefixes instead of raw values (`src/utils/audit.ts`). | `anvil-core::ledger::AuditLedger` maintains an append-only `BLAKE3` hash-chained event log (`entry_hash = BLAKE3(prev_hash \|\| canonical_event_bytes)`) with verifiable slice integrity and compile-time `SecretBytes` redaction. |
| **Hardened Ephemeral Host Lifecycle** | Shell provisioning + systemd sandboxing + teardown (`deploy.sh`, `infra/harden.sh`). | `infra/Dockerfile` (`--read-only`, `0555` `root:root` `/usr/local/bin` binaries), keyless Sigstore `cosign` OIDC attestation, and POSIX `/bin/sh` `infra/forge` controller with zero `argv`/env secret exposure and `$0.00/hr` teardown. |

---

## 3. Discarded Legacy Attack Surfaces & Concrete Flaws Found

The static audit uncovered critical architectural vulnerabilities in `locksmith-legacy` that are **permanently eliminated** in `locksmith` v1:

### 3.1 Non-Atomic Nonce Double-Spend Race (TOCTOU)
- **Legacy Flaw (`src/services/nonce.ts` lines 176–242):** `validateNonce()` executed a DynamoDB `GetCommand`, checked `if (nonce.type === 'single_use' && nonce.consumed)` in V8 memory, and subsequently issued an unconditioned `DeleteCommand` / `UpdateCommand`. Concurrent requests presenting the same `single_use` UUID win the race window and spend a single-use authorization multiple times.
- **Clean-Room Elimination:** `anvil-core::replay` performs atomic check-and-burn inside a synchronized bounded set, proven by a mandatory 64-task `tokio::sync::Barrier` double-spend red-team test (`redteam_crypto.rs`).

### 3.2 Reusable Session Bearer Nonces & Prefix-Confusion Scope Bypass
- **Legacy Flaw (`src/services/nonce.ts` lines 26, 75–86, 297–325):** Legacy defaulted services (`github`, `slack`, `jira`, `sentry`, `pagerduty`, `aws-dev`) to reusable `session` nonces valid for 30–60 minutes, turning stolen nonces into bearer tokens. Scope validation serialized objects with `JSON.stringify()` and permitted naive string prefix matching (`requested.startsWith(declared)`) and `*` wildcards.
- **Clean-Room Elimination:** Reusable session nonces and string-serialized scope matching are eliminated. Every outbound request burns a unique single-use nonce AND consumes a `!Clone`, `!Copy` `ApprovedEgressTicket` by value.

### 3.3 Path Traversal, Header Smuggling & Upstream Reflection Leaks
- **Legacy Flaw (`src/routes/proxy.ts` lines 47–65, 178–204):**
  - Express wildcard paths were interpolated directly into `fetch(\`${baseUrl}/${path}\`)` without `..` or authority normalization, permitting path traversal across upstream API roots (e.g., `https://slack.com/api/../...`).
  - No `Host`-to-SNI binding check or CRLF/NUL header validation existed.
  - Non-JSON upstream error responses were returned verbatim via `{ raw: await response.text() }`; an upstream `502` or diagnostic echo endpoint reflecting the injected `Authorization` header leaked the raw secret straight back to the caller.
- **Clean-Room Elimination:** Strict RFC 9110/9112 parser (`Host` == verified SNI byte-for-byte, zero CR/LF/NUL bytes, zero conflicting `Content-Length` + `Transfer-Encoding`, guest `Authorization`/`Proxy-Authorization` stripped/rejected) plus mandatory upstream response header/body scrubbing (`[REDACTED_BY_LOCKSMITH]`).

### 3.4 Plaintext Secret Exposure Across Memory, Disk, `argv`, and Shell Environment
- **Legacy Flaw:**
  - **Garbage-Collected V8 Heap (`src/services/credentials.ts` lines 62–80):** Plaintext credential dictionaries persisted in an unencrypted JS `Map` for 5 minutes; JavaScript strings are immutable and cannot be deterministically zeroized before swap/core dump.
  - **OS Command Injection & Disk Key Material (`src/plugins/ssh.ts` lines 105–140, `src/plugins/tls.ts` lines 315–327):** Legacy wrote the SSH CA private key to `/tmp/locksmith-ssh-.../ca_key`, concatenated user-supplied `keyId`, `principals`, and `extensions` into `execSync(signCmd.join(' '))` (shell injection RCE in the CA process), attempted `writeFileSync(randomBytes)` "shredding" (ineffective on journaled/CoW filesystems), returned raw CA private keys over HTTP (`POST /ssh/ca/rotate`), and interpolated paths into `AWS-RunShellScript` SSM shell strings.
  - **Raw Credential Vending (`src/routes/proxy.ts` lines 152–164):** Mode A (`proxyAws`) returned raw `secretAccessKey` and `sessionToken` values directly to clients.
  - **CLI Environment & `argv` Leaks (`auth.js`, `cli.js`, `infra/harden.sh`, `infra/connect.sh`):** Exported bearer tokens via `eval $(node auth.js --export)`, passed private keys via `--secret-string "${KEY_OUTPUT}"` on CLI `argv` (visible in `/proc/<pid>/cmdline`), piped `curl -fsSL https://rpm.nodesource.com/setup_20.x | bash -`, and disabled SSH host verification (`StrictHostKeyChecking=accept-new` + `UserKnownHostsFile=/dev/null`).
- **Clean-Room Elimination:**
  - All secrets are held exclusively in `Zeroizing` Rust buffers (`zeroize = "1.8"`), sealed in memory, redacted in `Debug`/`Display`, and protected by `PR_SET_DUMPABLE(0)`.
  - Zero shell-outs for cryptography or request handling.
  - `infra/forge` pipes secrets exclusively via standard input (`op read ... | curl -K -` / `docker login --password-stdin`) with zero environment exports and zero `argv` secrets.

### 3.5 Unchained Fire-and-Forget Audit Logging & Trust-Proxy Spoofing
- **Legacy Flaw (`src/index.ts` line 21, `src/utils/audit.ts` lines 80–99):** `app.set('trust proxy', true)` permitted `X-Forwarded-For` IP spoofing when directly reachable, while `logAuditEvent()` silently dropped records >10 KB, wrote unchained JSON lines to mutable disk, and ignored DynamoDB write failures.
- **Clean-Room Elimination:** Peer identity comes from kernel `AF_VSOCK` CID or `SO_PEERCRED` + mTLS leaf certificate thumbprint (never HTTP headers), and audit events form a deterministic `BLAKE3` hash chain.

### 3.6 Discarded Out-of-Scope Subsystems
To maintain a minimal, formally auditable Trusted Computing Base (TCB), the following legacy bloat is **excluded** from `locksmith` v1:
- Node.js / Express / V8 runtime and 195 KB `package-lock.json` dependency graph.
- AWS Lambda + API Gateway v2 HTTP adapter (`lambda.ts`) and Lightsail Terraform stack.
- SSH CA `ssh-keygen` wrapper endpoints (`/ssh/*`).
- Let's Encrypt ACME / Cloudflare DNS-01 / SSM `RunShellScript` push endpoints (`/tls/*`).
- IAM static access-key rotation endpoints (`/rotate/*`) and raw STS credential vending (`proxyAws`).
