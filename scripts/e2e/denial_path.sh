#!/usr/bin/env bash
set -euo pipefail

SCRIPT_NAME="e2e_denial_path"
SEED="0xDEADBEEF"
ZONE="z:work"
CONNECTOR="fcp.test-echo"
OUT_DIR="${OUT_DIR:-./out/${SCRIPT_NAME}}"
LOG_JSONL="${LOG_JSONL:-${OUT_DIR}/${SCRIPT_NAME}.jsonl}"
CURRENT_STEP=""
EXPECTED_FAILURE=""
ACTUAL_FAILURE=""

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 1
  fi
}

log_step() {
  local step="$1"
  local result="$2"
  local expected_failure="${3:-}"
  local actual_failure="${4:-}"
  local timestamp
  timestamp="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  mkdir -p "$(dirname "${LOG_JSONL}")"
  printf '{"timestamp":"%s","script":"%s","step":"%s","expected_failure":"%s","actual_failure":"%s","result":"%s"}\n' \
    "${timestamp}" "${SCRIPT_NAME}" "${step}" "${expected_failure}" "${actual_failure}" "${result}" >> "${LOG_JSONL}"
}

on_error() {
  local exit_code="$1"
  if [[ -n "${CURRENT_STEP}" ]]; then
    log_step "${CURRENT_STEP}" "fail" "${EXPECTED_FAILURE}" "${ACTUAL_FAILURE:-exit_code_${exit_code}}"
  fi
  exit "${exit_code}"
}

trap 'on_error $?' ERR

require_cmd fcp-harness
require_cmd fcp
require_cmd jq

mkdir -p "${OUT_DIR}"

CURRENT_STEP="init"
EXPECTED_FAILURE=""
ACTUAL_FAILURE=""
log_step "${CURRENT_STEP}" "start"
fcp-harness init --nodes=3 --deterministic --seed "${SEED}"

CURRENT_STEP="install_connector"
EXPECTED_FAILURE=""
ACTUAL_FAILURE=""
log_step "${CURRENT_STEP}" "start"
fcp install "${CONNECTOR}" --zone "${ZONE}"

# Step 2: Invoke without token (expect denial)
CURRENT_STEP="invoke_without_token"
EXPECTED_FAILURE="FCP-2101"
ACTUAL_FAILURE=""
log_step "${CURRENT_STEP}" "start" "${EXPECTED_FAILURE}"
fcp-harness invoke \
  --connector="${CONNECTOR}" \
  --operation=echo \
  --args='{"message":"hello"}' \
  --expect-failure=FCP-2101 \
  --output="${OUT_DIR}/denial.cbor"
ACTUAL_FAILURE="FCP-2101"
log_step "${CURRENT_STEP}" "pass" "${EXPECTED_FAILURE}" "${ACTUAL_FAILURE}"

# Step 3: Explain denial
CURRENT_STEP="explain_denial"
EXPECTED_FAILURE=""
ACTUAL_FAILURE=""
log_step "${CURRENT_STEP}" "start"
fcp explain --receipt="${OUT_DIR}/denial.cbor" --output="${OUT_DIR}/decision.json"
jq -e '.decision == "deny"' "${OUT_DIR}/decision.json" >/dev/null
jq -e '.reason_code == "FCP-2101"' "${OUT_DIR}/decision.json" >/dev/null
jq -e '.evidence | length > 0' "${OUT_DIR}/decision.json" >/dev/null
log_step "${CURRENT_STEP}" "pass"

# Step 4: Expired token path
CURRENT_STEP="expired_token"
EXPECTED_FAILURE="FCP-2102"
ACTUAL_FAILURE=""
log_step "${CURRENT_STEP}" "start" "${EXPECTED_FAILURE}"
fcp-harness create-token \
  --connector="${CONNECTOR}" \
  --operations=echo \
  --ttl=-1 \
  --output="${OUT_DIR}/expired_token.cbor"

fcp-harness invoke \
  --connector="${CONNECTOR}" \
  --operation=echo \
  --token="${OUT_DIR}/expired_token.cbor" \
  --expect-failure=FCP-2102 \
  --output="${OUT_DIR}/expired_denial.cbor"
ACTUAL_FAILURE="FCP-2102"
log_step "${CURRENT_STEP}" "pass" "${EXPECTED_FAILURE}" "${ACTUAL_FAILURE}"

# Step 5: Wrong zone token
CURRENT_STEP="wrong_zone"
EXPECTED_FAILURE="FCP-3001"
ACTUAL_FAILURE=""
log_step "${CURRENT_STEP}" "start" "${EXPECTED_FAILURE}"
fcp-harness create-token \
  --connector="${CONNECTOR}" \
  --operations=echo \
  --zone=z:private \
  --output="${OUT_DIR}/wrong_zone_token.cbor"

fcp-harness invoke \
  --connector="${CONNECTOR}" \
  --operation=echo \
  --token="${OUT_DIR}/wrong_zone_token.cbor" \
  --expect-failure=FCP-3001 \
  --output="${OUT_DIR}/zone_denial.cbor"
ACTUAL_FAILURE="FCP-3001"
log_step "${CURRENT_STEP}" "pass" "${EXPECTED_FAILURE}" "${ACTUAL_FAILURE}"

# Step 6: Audit tail check (best-effort; harness controls log availability)
CURRENT_STEP="audit_tail"
EXPECTED_FAILURE=""
ACTUAL_FAILURE=""
log_step "${CURRENT_STEP}" "start"
fcp audit tail --zone "${ZONE}" --event-type=security.violation --limit=3
log_step "${CURRENT_STEP}" "pass"

echo "${SCRIPT_NAME} complete. Logs: ${LOG_JSONL}"
