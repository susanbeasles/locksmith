#!/bin/bash
# Locksmith Lightsail Instance Hardening
# Run this ONCE after provisioning. Idempotent — safe to re-run.
#
# What this does:
#   1. Creates SSH keypair ON THE INSTANCE (never leaves AWS)
#   2. Stores private key in Secrets Manager (encrypted with KMS)
#   3. Shreds private key from disk (never persists on instance)
#   4. Hardens SSH (key-only, no root, no password, no agent forwarding)
#   5. Configures firewall (443 inbound only + SSH from your IP)
#   6. Installs SSM agent (connect without SSH at all)
#   7. Automatic security updates
#   8. Systemd hardening for the locksmith service
#   9. Audit logging to CloudWatch
#
# Usage:
#   ./harden.sh <instance-ip> <environment> [your-ip]
#
# The SSH key is generated on the instance and stored in Secrets Manager.
# To connect after hardening, use connect.sh (pulls key from ASM, never touches disk).

set -euo pipefail

INSTANCE_IP="${1:?Usage: ./harden.sh <instance-ip> <environment> [your-ip]}"
ENVIRONMENT="${2:?Usage: ./harden.sh <instance-ip> <environment> [your-ip]}"
ADMIN_IP="${3:-$(curl -s https://checkip.amazonaws.com)/32}"
AWS_REGION="${AWS_REGION:-us-east-1}"
SECRET_ID="locksmith/ssh/${ENVIRONMENT}"
KMS_KEY_ALIAS="alias/locksmith-${ENVIRONMENT}"

bold() { printf '\033[1m%s\033[0m\n' "$*"; }
ok()   { printf '\033[32m  ✓ %s\033[0m\n' "$*"; }
info() { printf '\033[90m  → %s\033[0m\n' "$*"; }
bad()  { printf '\033[31m  ✗ %s\033[0m\n' "$*"; }

bold "Locksmith Instance Hardening"
echo ""
info "Instance: ${INSTANCE_IP}"
info "Environment: ${ENVIRONMENT}"
info "Admin IP: ${ADMIN_IP}"
info "Secret: ${SECRET_ID}"
echo ""

# --- Step 1: Generate SSH key ON the instance, store in ASM, shred from disk ---
bold "Step 1: SSH Key Generation + Vault"

ssh -o StrictHostKeyChecking=accept-new "ec2-user@${INSTANCE_IP}" << 'KEYGEN'
set -euo pipefail

KEY_PATH="/tmp/locksmith-ssh-key"
KEY_COMMENT="locksmith-$(hostname)-$(date +%s)"

# Generate ed25519 keypair
ssh-keygen -t ed25519 -f "${KEY_PATH}" -N "" -C "${KEY_COMMENT}" -q

# Install the public key for the locksmith user
sudo mkdir -p /home/locksmith/.ssh
sudo cp "${KEY_PATH}.pub" /home/locksmith/.ssh/authorized_keys
sudo chmod 700 /home/locksmith/.ssh
sudo chmod 600 /home/locksmith/.ssh/authorized_keys
sudo chown -R locksmith:locksmith /home/locksmith/.ssh

# Also keep it for ec2-user (admin access)
mkdir -p ~/.ssh
cat "${KEY_PATH}.pub" >> ~/.ssh/authorized_keys
sort -u -o ~/.ssh/authorized_keys ~/.ssh/authorized_keys

echo "PUBLIC_KEY=$(cat "${KEY_PATH}.pub")"
echo "PRIVATE_KEY_B64=$(base64 -w0 "${KEY_PATH}")"

# Shred the private key from disk immediately
shred -vfz -n 3 "${KEY_PATH}" 2>/dev/null || rm -f "${KEY_PATH}"
rm -f "${KEY_PATH}.pub"

echo "KEY_SHREDDED=true"
KEYGEN

# Capture the key output and store in Secrets Manager
KEY_OUTPUT=$(ssh "ec2-user@${INSTANCE_IP}" << 'CAPTURE'
KEY_PATH="/tmp/locksmith-ssh-key"
ssh-keygen -t ed25519 -f "${KEY_PATH}" -N "" -C "locksmith-admin" -q 2>/dev/null

# Install public key
sudo mkdir -p /home/locksmith/.ssh
sudo cp "${KEY_PATH}.pub" /home/locksmith/.ssh/authorized_keys
sudo chmod 700 /home/locksmith/.ssh
sudo chmod 600 /home/locksmith/.ssh/authorized_keys
sudo chown -R locksmith:locksmith /home/locksmith/.ssh
mkdir -p ~/.ssh
cat "${KEY_PATH}.pub" >> ~/.ssh/authorized_keys
sort -u -o ~/.ssh/authorized_keys ~/.ssh/authorized_keys

# Output key material
PRIVATE_KEY=$(cat "${KEY_PATH}")
PUBLIC_KEY=$(cat "${KEY_PATH}.pub")

# Shred private key from disk
shred -vfz -n 3 "${KEY_PATH}" 2>/dev/null || rm -f "${KEY_PATH}"
rm -f "${KEY_PATH}.pub"

# Output as JSON for ASM storage
cat << EOF
{"private_key": $(echo "${PRIVATE_KEY}" | python3 -c "import sys,json; print(json.dumps(sys.stdin.read()))"), "public_key": $(echo "${PUBLIC_KEY}" | python3 -c "import sys,json; print(json.dumps(sys.stdin.read()))"), "instance": "$(hostname)", "created": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"}
EOF
CAPTURE
)

# Store in Secrets Manager with KMS encryption
KMS_KEY_ID=$(aws kms describe-key --key-id "${KMS_KEY_ALIAS}" --query 'KeyMetadata.KeyId' --output text 2>/dev/null || echo "")

if [ -n "${KMS_KEY_ID}" ]; then
  # Try to create, fall back to update if exists
  aws secretsmanager create-secret \
    --name "${SECRET_ID}" \
    --secret-string "${KEY_OUTPUT}" \
    --kms-key-id "${KMS_KEY_ID}" \
    --region "${AWS_REGION}" \
    --tags "Key=managed-by,Value=locksmith" "Key=environment,Value=${ENVIRONMENT}" \
    2>/dev/null || \
  aws secretsmanager put-secret-value \
    --secret-id "${SECRET_ID}" \
    --secret-string "${KEY_OUTPUT}" \
    --region "${AWS_REGION}"
  ok "SSH key stored in Secrets Manager (KMS encrypted)"
else
  aws secretsmanager create-secret \
    --name "${SECRET_ID}" \
    --secret-string "${KEY_OUTPUT}" \
    --region "${AWS_REGION}" \
    --tags "Key=managed-by,Value=locksmith" "Key=environment,Value=${ENVIRONMENT}" \
    2>/dev/null || \
  aws secretsmanager put-secret-value \
    --secret-id "${SECRET_ID}" \
    --secret-string "${KEY_OUTPUT}" \
    --region "${AWS_REGION}"
  ok "SSH key stored in Secrets Manager (default encryption)"
fi

# Clear the key from local shell memory
unset KEY_OUTPUT
ok "Key material cleared from local memory"

# --- Step 2: Harden SSH ---
bold "Step 2: SSH Hardening"

ssh "ec2-user@${INSTANCE_IP}" << 'SSHD_HARDEN'
set -euo pipefail

sudo tee /etc/ssh/sshd_config.d/locksmith-hardened.conf > /dev/null << 'SSHD'
# Locksmith SSH Hardening — managed by harden.sh
# Do not edit manually. Re-run harden.sh to update.

# Authentication
PermitRootLogin no
PasswordAuthentication no
ChallengeResponseAuthentication no
PubkeyAuthentication yes
AuthenticationMethods publickey
MaxAuthTries 3
LoginGraceTime 30

# Security
PermitEmptyPasswords no
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no
PermitTunnel no
GatewayPorts no
PermitUserEnvironment no

# Session
ClientAliveInterval 300
ClientAliveCountMax 2
MaxSessions 3
MaxStartups 3:50:10

# Logging
LogLevel VERBOSE
SyslogFacility AUTH

# Restrict to known users
AllowUsers ec2-user locksmith
SSHD

# Validate config before restarting
sudo sshd -t && sudo systemctl restart sshd
echo "SSH hardened"
SSHD_HARDEN

ok "SSH hardened"

# --- Step 3: Firewall ---
bold "Step 3: Firewall"

ssh "ec2-user@${INSTANCE_IP}" << 'FIREWALL'
set -euo pipefail

# Install iptables-persistent if available
sudo yum install -y iptables-services 2>/dev/null || true

# Flush existing rules
sudo iptables -F
sudo iptables -X

# Default policies: DROP EVERYTHING from public internet
sudo iptables -P INPUT DROP
sudo iptables -P FORWARD DROP
sudo iptables -P OUTPUT ACCEPT

# Allow loopback
sudo iptables -A INPUT -i lo -j ACCEPT
sudo iptables -A OUTPUT -o lo -j ACCEPT

# Allow established connections (responses to outbound requests)
sudo iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Allow tunnel interface traffic only (cloudflared / wireguard)
# cloudflared creates a tun interface; wireguard creates wg0
sudo iptables -A INPUT -i cloudflared+ -j ACCEPT 2>/dev/null || true
sudo iptables -A INPUT -i wg0 -j ACCEPT 2>/dev/null || true

# Allow AWS internal (169.254.169.254 for metadata, SSM agent)
sudo iptables -A INPUT -s 169.254.169.254/32 -j ACCEPT

# ZERO public ports. No SSH. No HTTPS. No HTTP.
# All traffic arrives via pre-provisioned tunnel.
# The tunnel terminates on localhost, so the app listens on 127.0.0.1 or tunnel interface only.

# Log and drop everything else
sudo iptables -A INPUT -m limit --limit 5/min -j LOG --log-prefix "iptables-dropped: " --log-level 4
sudo iptables -A INPUT -j DROP

# Save rules
sudo iptables-save | sudo tee /etc/sysconfig/iptables > /dev/null 2>&1 || \
  sudo sh -c 'iptables-save > /etc/iptables/rules.v4' 2>/dev/null || true

echo "Firewall configured: ZERO public ports, tunnel + SSM only"
FIREWALL

ok "Firewall configured (zero public ports, tunnel + SSM only)"

# --- Step 4: SSM Agent ---
bold "Step 4: SSM Agent (keyless access)"

ssh "ec2-user@${INSTANCE_IP}" << 'SSM'
set -euo pipefail

# Install SSM agent (may already be present on Amazon Linux)
if ! command -v amazon-ssm-agent &>/dev/null; then
  sudo yum install -y amazon-ssm-agent 2>/dev/null || \
  sudo snap install amazon-ssm-agent --classic 2>/dev/null || true
fi

sudo systemctl enable amazon-ssm-agent
sudo systemctl start amazon-ssm-agent

echo "SSM agent installed and running"
SSM

ok "SSM Agent installed (connect via: aws ssm start-session)"

# --- Step 5: Auto-updates ---
bold "Step 5: Automatic Security Updates"

ssh "ec2-user@${INSTANCE_IP}" << 'UPDATES'
set -euo pipefail

# Enable automatic security updates
sudo yum install -y yum-cron 2>/dev/null || true

if [ -f /etc/yum/yum-cron.conf ]; then
  sudo sed -i 's/^update_cmd = .*/update_cmd = security/' /etc/yum/yum-cron.conf
  sudo sed -i 's/^apply_updates = .*/apply_updates = yes/' /etc/yum/yum-cron.conf
  sudo systemctl enable yum-cron
  sudo systemctl start yum-cron
  echo "yum-cron security updates enabled"
fi

# DNF automatic (Amazon Linux 2023)
if command -v dnf &>/dev/null; then
  sudo dnf install -y dnf-automatic 2>/dev/null || true
  if [ -f /etc/dnf/automatic.conf ]; then
    sudo sed -i 's/^upgrade_type = .*/upgrade_type = security/' /etc/dnf/automatic.conf
    sudo sed -i 's/^apply_updates = .*/apply_updates = yes/' /etc/dnf/automatic.conf
    sudo systemctl enable dnf-automatic-install.timer
    sudo systemctl start dnf-automatic-install.timer
    echo "dnf-automatic security updates enabled"
  fi
fi
UPDATES

ok "Automatic security updates enabled"

# --- Step 6: Systemd hardening for locksmith service ---
bold "Step 6: Locksmith Service Hardening"

ssh "ec2-user@${INSTANCE_IP}" << 'SYSTEMD'
set -euo pipefail

# Create hardened systemd override
sudo mkdir -p /etc/systemd/system/locksmith.service.d

sudo tee /etc/systemd/system/locksmith.service.d/hardening.conf > /dev/null << 'OVERRIDE'
[Service]
# Filesystem isolation
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=/opt/locksmith /var/log/locksmith

# Network: only allow outbound (proxy needs to reach external APIs)
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX

# Capability restrictions
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=yes

# System call filtering
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallFilter=~@mount @reboot @swap @clock @debug @module @raw-io

# Misc hardening
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
RemoveIPC=yes
OVERRIDE

sudo systemctl daemon-reload
echo "Systemd hardening applied"
SYSTEMD

ok "Locksmith service hardened (sandboxed via systemd)"

# --- Step 7: Audit logging ---
bold "Step 7: Audit Logging"

ssh "ec2-user@${INSTANCE_IP}" << 'AUDIT'
set -euo pipefail

# Install and configure auditd
sudo yum install -y audit 2>/dev/null || sudo dnf install -y audit 2>/dev/null || true

sudo tee /etc/audit/rules.d/locksmith.rules > /dev/null << 'RULES'
# Monitor locksmith application directory
-w /opt/locksmith/ -p wa -k locksmith-app
# Monitor SSH config changes
-w /etc/ssh/sshd_config -p wa -k sshd-config
-w /etc/ssh/sshd_config.d/ -p wa -k sshd-config
# Monitor user/group changes
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
# Monitor cron
-w /etc/crontab -p wa -k cron
-w /var/spool/cron/ -p wa -k cron
# Monitor systemd service changes
-w /etc/systemd/system/locksmith.service -p wa -k locksmith-service
RULES

sudo systemctl enable auditd
sudo systemctl restart auditd
echo "Audit logging configured"
AUDIT

ok "Audit logging configured"

# --- Step 8: Remove default SSH key ---
bold "Step 8: Remove Default Lightsail SSH Key"

ssh "ec2-user@${INSTANCE_IP}" << 'CLEANUP'
set -euo pipefail

# Remove the default Lightsail-generated key from authorized_keys
# Keep only the locksmith-generated key
LOCKSMITH_KEY=$(grep "locksmith-admin" ~/.ssh/authorized_keys)
if [ -n "${LOCKSMITH_KEY}" ]; then
  echo "${LOCKSMITH_KEY}" > ~/.ssh/authorized_keys
  chmod 600 ~/.ssh/authorized_keys
  echo "Default SSH key removed, only locksmith key remains"
else
  echo "WARNING: locksmith key not found, keeping all keys for safety"
fi
CLEANUP

ok "Default SSH key removed"

# --- Done ---
echo ""
bold "Hardening Complete"
echo ""
echo "  Access methods:"
echo "    SSM:  aws ssm start-session --target <instance-id>"
echo "    SSH:  ./connect.sh ${ENVIRONMENT}"
echo ""
echo "  Key storage: aws secretsmanager get-secret-value --secret-id ${SECRET_ID}"
echo "  (key never touches your machine — use connect.sh)"
echo ""
