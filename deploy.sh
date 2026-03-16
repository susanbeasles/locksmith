#!/bin/bash
# Locksmith — Idempotent deploy pipeline
# Usage: ./deploy.sh [plan|apply|destroy]
#
# plan    — show what would change (default)
# apply   — provision infra + deploy code
# destroy — tear everything down (requires --destroy flag)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
INFRA_DIR="${SCRIPT_DIR}/infra"
DIST_DIR="${SCRIPT_DIR}/dist"
ACTION="${1:-plan}"

# Colors
bold() { printf '\033[1m%s\033[0m\n' "$*"; }
ok()   { printf '\033[32m  ✓ %s\033[0m\n' "$*"; }
bad()  { printf '\033[31m  ✗ %s\033[0m\n' "$*"; }
info() { printf '\033[90m  → %s\033[0m\n' "$*"; }

# --- Preflight checks ---
preflight() {
  bold "Preflight"

  command -v terraform >/dev/null || { bad "terraform not found"; exit 1; }
  command -v node >/dev/null || { bad "node not found"; exit 1; }
  command -v npm >/dev/null || { bad "npm not found"; exit 1; }
  command -v aws >/dev/null || { bad "aws cli not found"; exit 1; }
  ok "Tools present"

  if [ ! -f "${INFRA_DIR}/terraform.tfvars" ]; then
    bad "Missing infra/terraform.tfvars — copy from terraform.tfvars.example"
    exit 1
  fi
  ok "Config present"

  # Verify AWS credentials are available
  aws sts get-caller-identity --output text >/dev/null 2>&1 || {
    bad "AWS credentials not configured"
    exit 1
  }
  ok "AWS authenticated"
}

# --- Build Lambda package ---
build_lambda() {
  bold "Building Lambda package"

  mkdir -p "${DIST_DIR}"

  # Install production deps in a clean directory
  local build_dir="${DIST_DIR}/lambda-build"
  rm -rf "${build_dir}"
  mkdir -p "${build_dir}"

  # Copy source
  cp -r "${SCRIPT_DIR}/src" "${build_dir}/src"
  cp "${SCRIPT_DIR}/package.json" "${build_dir}/"
  cp "${SCRIPT_DIR}/lambda.js" "${build_dir}/" 2>/dev/null || {
    info "lambda.js not found — will need Lambda adapter"
  }

  # Install production deps only
  cd "${build_dir}"
  npm install --omit=dev --ignore-scripts
  ok "Dependencies installed"

  # Zip it
  cd "${build_dir}"
  zip -r "${DIST_DIR}/lambda.zip" . -x "*.git*" >/dev/null
  ok "Lambda package: $(du -h "${DIST_DIR}/lambda.zip" | cut -f1)"

  # Cleanup
  rm -rf "${build_dir}"
  cd "${SCRIPT_DIR}"
}

# --- Terraform ---
terraform_action() {
  local action="$1"
  bold "Terraform ${action}"

  cd "${INFRA_DIR}"
  terraform init -input=false -no-color 2>&1 | tail -1
  ok "Initialized"

  case "${action}" in
    plan)
      terraform plan -input=false
      ;;
    apply)
      terraform apply -input=false -auto-approve
      ok "Infrastructure provisioned"
      ;;
    destroy)
      terraform destroy -input=false -auto-approve
      ok "Infrastructure destroyed"
      ;;
  esac

  cd "${SCRIPT_DIR}"
}

# --- Deploy to Lightsail ---
deploy_lightsail() {
  bold "Deploying to Lightsail"

  local instance_name
  instance_name=$(cd "${INFRA_DIR}" && terraform output -raw lightsail_instance_name 2>/dev/null)

  if [ -z "${instance_name}" ]; then
    bad "Lightsail instance not found — run deploy.sh apply first"
    return 1
  fi

  local lightsail_ip
  lightsail_ip=$(cd "${INFRA_DIR}" && terraform output -raw lightsail_ip 2>/dev/null)

  info "Instance: ${instance_name} (${lightsail_ip})"

  # Sync code to Lightsail via SSH
  rsync -az --delete \
    --exclude node_modules \
    --exclude .git \
    --exclude dist \
    --exclude infra \
    -e "ssh -o StrictHostKeyChecking=accept-new" \
    "${SCRIPT_DIR}/" \
    "ec2-user@${lightsail_ip}:/opt/locksmith/"

  ok "Code synced"

  # Install deps and restart on remote
  ssh "ec2-user@${lightsail_ip}" << 'REMOTE'
    cd /opt/locksmith
    npm install --omit=dev --ignore-scripts
    sudo systemctl restart locksmith
    sleep 2
    sudo systemctl is-active locksmith && echo "RUNNING" || echo "FAILED"
REMOTE

  ok "Lightsail deployed"
}

# --- Update Lambda code ---
deploy_lambda() {
  bold "Deploying Lambda code"

  local function_name
  function_name=$(cd "${INFRA_DIR}" && terraform output -raw lambda_function_name 2>/dev/null)

  if [ -z "${function_name}" ]; then
    bad "Lambda function not found — run deploy.sh apply first"
    return 1
  fi

  aws lambda update-function-code \
    --function-name "${function_name}" \
    --zip-file "fileb://${DIST_DIR}/lambda.zip" \
    --output text --query 'FunctionName' 2>&1

  ok "Lambda code updated: ${function_name}"
}

# --- Print deployment info ---
print_outputs() {
  bold "Deployment Info"
  cd "${INFRA_DIR}"
  echo ""
  echo "  Agent Proxy:   $(terraform output -raw api_gateway_url 2>/dev/null || echo 'not deployed')"
  echo "  Browser Proxy: $(terraform output -raw lightsail_ip 2>/dev/null || echo 'not deployed')"
  echo "  DynamoDB:      $(terraform output -raw dynamodb_nonces_table 2>/dev/null || echo 'not deployed')"
  echo "  KMS Key:       $(terraform output -raw kms_key_id 2>/dev/null || echo 'not deployed')"
  echo ""
  cd "${SCRIPT_DIR}"
}

# --- Main ---
preflight

case "${ACTION}" in
  plan)
    build_lambda
    terraform_action plan
    ;;
  apply)
    build_lambda
    terraform_action apply
    deploy_lambda
    deploy_lightsail
    print_outputs
    bold "Done. Locksmith deployed."
    ;;
  destroy)
    if [ "${2:-}" != "--destroy" ]; then
      bad "Destroy requires: ./deploy.sh destroy --destroy"
      exit 1
    fi
    terraform_action destroy
    rm -rf "${DIST_DIR}"
    bold "Everything destroyed."
    ;;
  *)
    echo "Usage: ./deploy.sh [plan|apply|destroy]"
    echo ""
    echo "  plan     Show what would change (default)"
    echo "  apply    Provision infra + deploy code"
    echo "  destroy  Tear everything down (requires --destroy)"
    exit 1
    ;;
esac
