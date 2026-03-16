#!/bin/bash
# Connect to Locksmith instance — key never touches disk or persistent memory
#
# Usage: ./connect.sh <environment> [command]
#
# The SSH private key is pulled from Secrets Manager, used via process substitution
# (bash named pipe — /dev/fd/XX), and discarded when the SSH session ends.
# It never touches your filesystem. It exists in a pipe buffer for microseconds.
#
# For truly zero-key access, use SSM instead:
#   aws ssm start-session --target <instance-id>

set -euo pipefail

ENVIRONMENT="${1:?Usage: ./connect.sh <environment> [command]}"
shift
COMMAND="${*:-}"
AWS_REGION="${AWS_REGION:-us-east-1}"
SECRET_ID="locksmith/ssh/${ENVIRONMENT}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Get instance IP from Terraform outputs
INSTANCE_IP=$(cd "${SCRIPT_DIR}" && terraform output -raw lightsail_ip 2>/dev/null)

if [ -z "${INSTANCE_IP}" ]; then
  echo "ERROR: Could not get instance IP. Run deploy.sh apply first."
  exit 1
fi

# Pull private key from Secrets Manager — stays in a variable, never on disk
# The variable is unset in the trap below
PRIVATE_KEY=$(aws secretsmanager get-secret-value \
  --secret-id "${SECRET_ID}" \
  --region "${AWS_REGION}" \
  --query 'SecretString' \
  --output text | python3 -c "import sys,json; print(json.load(sys.stdin)['private_key'])")

if [ -z "${PRIVATE_KEY}" ]; then
  echo "ERROR: Could not retrieve SSH key from Secrets Manager"
  echo "  Secret: ${SECRET_ID}"
  echo "  Region: ${AWS_REGION}"
  echo ""
  echo "Fallback: aws ssm start-session --target <instance-id>"
  exit 1
fi

# Cleanup: wipe the key variable on exit
cleanup() {
  unset PRIVATE_KEY
}
trap cleanup EXIT INT TERM

# Connect using process substitution — key never touches disk
# /dev/fd/XX is a named pipe, not a file. Data flows through a kernel buffer.
if [ -n "${COMMAND}" ]; then
  # Run a command
  ssh -o StrictHostKeyChecking=accept-new \
      -o UserKnownHostsFile=/dev/null \
      -o LogLevel=ERROR \
      -i <(echo "${PRIVATE_KEY}") \
      "ec2-user@${INSTANCE_IP}" \
      "${COMMAND}"
else
  # Interactive session
  ssh -o StrictHostKeyChecking=accept-new \
      -o UserKnownHostsFile=/dev/null \
      -o LogLevel=ERROR \
      -i <(echo "${PRIVATE_KEY}") \
      "ec2-user@${INSTANCE_IP}"
fi
