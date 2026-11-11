#!/bin/sh
# Adversarial input-validation suite for `infra/forge` (POSIX /bin/sh).
# Lives alongside `infra/forge` so Rust workspace crates stay 100% decoupled
# from host-provisioning scripts and CI configuration.

set -eu

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
FORGE_BIN="${SCRIPT_DIR}/forge"

WORK_DIR=$(mktemp -d "${TMPDIR:-/tmp}/forge-test.XXXXXX")
cleanup() {
    rm -rf -- "${WORK_DIR}"
}
trap cleanup EXIT INT TERM HUP

MOCK_BIN="${WORK_DIR}/bin"
mkdir -p -- "${MOCK_BIN}"

for cmd_name in ssh install op curl; do
    cat > "${MOCK_BIN}/${cmd_name}" <<EOF
#!/bin/sh
echo "SENTINEL_EXECUTED:${cmd_name}" >&2
exit 42
EOF
    chmod 0755 "${MOCK_BIN}/${cmd_name}"
done

SAFE_PATH="${MOCK_BIN}:/usr/bin:/bin"
VALID_DIGEST="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
VALID_IMAGE="ghcr.io/susanbeasles/locksmith@sha256:${VALID_DIGEST}"

assert_rejected() {
    err_file="${WORK_DIR}/stderr.log"
    rc=0
    env -i PATH="${SAFE_PATH}" /bin/sh "${FORGE_BIN}" "$@" >/dev/null 2>"${err_file}" || rc=$?

    if [ "${rc}" -eq 0 ]; then
        echo "FAIL: forge succeeded on hostile args: $*" >&2
        exit 1
    fi
    if [ "${rc}" -eq 42 ] || grep -Fq "SENTINEL_EXECUTED:" "${err_file}"; then
        echo "FAIL: forge invoked external binary on hostile args: $*" >&2
        cat -- "${err_file}" >&2
        exit 1
    fi
}

# 1. Command substitution smuggled inside repository slug
assert_rejected verify --host 203.0.113.10 --image "ghcr.io/susanbeasles/\$(id)@sha256:${VALID_DIGEST}"

# 2. Uppercase hex inside @sha256: digest
assert_rejected verify --host 203.0.113.10 --image "ghcr.io/susanbeasles/locksmith@sha256:ABCDEF6789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

# 3. Truncated 63-nibble digest
assert_rejected verify --host 203.0.113.10 --image "ghcr.io/susanbeasles/locksmith@sha256:123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

# 4. Oversized 65-nibble digest
assert_rejected verify --host 203.0.113.10 --image "${VALID_IMAGE}0"

# 5. SSH option injection via leading hyphen in --host
assert_rejected verify --host "-oProxyCommand=id" --image "${VALID_IMAGE}"

# 6. Out-of-range IPv4 octet in --host
assert_rejected verify --host "999.0.113.10" --image "${VALID_IMAGE}"

# 7. Path traversal in install-self bypassing /usr/local/bin/* prefix
assert_rejected install-self "/usr/local/bin/../../../tmp/pwned-forge"

# 8. Leading hyphen in --region on `forge up`
assert_rejected up --region "-ewr" --ssh-key-id "11111111-2222-3333-4444-555555555555" --image "${VALID_IMAGE}"

echo "infra/test-forge.sh: OK (8/8 hostile CLI vectors rejected fail-closed)"
