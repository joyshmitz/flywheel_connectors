#!/usr/bin/env bash
set -euo pipefail

SCRIPT_NAME="e2e_revocation_flow"
SEED="0xDEADBEEF"
ZONE="z:work"
CONNECTOR="fcp.test-echo"
OUT_DIR="${OUT_DIR:-./out/${SCRIPT_NAME}}"
LOG_JSONL="${LOG_JSONL:-${OUT_DIR}/${SCRIPT_NAME}.jsonl}"

TOKEN_ID=""
PROPAGATION_MS=""

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 1
  fi
}

now_ms() {
  local now
  now=$(date +%s%3N 2>/dev/null || true)
  if [[ -z "${now}" || "${now}" == *N ]]; then
    now="$(date +%s)000"
  fi
  printf '%s' "${now}"
}

hash256() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum
    return 0
  fi
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256
    return 0
  fi
  if command -v openssl >/dev/null 2>&1; then
    openssl dgst -sha256
    return 0
  fi
  echo "Missing required command: sha256sum/shasum/openssl" >&2
  exit 1
}

correlation_id_for_step() {
  local step_number="$1"
  local hex
  hex=$(printf '%s-%s-%s' "${SCRIPT_NAME}" "${SEED}" "${step_number}" | hash256 | awk '{print $1}')
  printf '%s-%s-%s-%s-%s' \
    "${hex:0:8}" "${hex:8:4}" "${hex:12:4}" "${hex:16:4}" "${hex:20:12}"
}

json_or_null() {
  local value="$1"
  if [[ -z "${value}" ]]; then
    printf 'null'
  else
    printf '"%s"' "${value}"
  fi
}

json_number_or_null() {
  local value="$1"
  if [[ -z "${value}" ]]; then
    printf 'null'
  else
    printf '%s' "${value}"
  fi
}

log_step() {
  local step="$1"
  local step_number="$2"
  local result="$3"
  local duration_ms="$4"
  local artifacts_json="$5"
  local timestamp
  local correlation_id
  local token_json
  local propagation_json
  local details

  timestamp="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  correlation_id="$(correlation_id_for_step "${step_number}")"
  token_json="$(json_or_null "${TOKEN_ID}")"
  propagation_json="$(json_number_or_null "${PROPAGATION_MS}")"
  details="{\"token_id\":${token_json},\"propagation_time_ms\":${propagation_json}}"

  mkdir -p "$(dirname "${LOG_JSONL}")"
  printf '{"timestamp":"%s","script":"%s","step":"%s","step_number":%s,"correlation_id":"%s","duration_ms":%s,"result":"%s","artifacts":%s,"details":%s}\n' \
    "${timestamp}" "${SCRIPT_NAME}" "${step}" "${step_number}" "${correlation_id}" "${duration_ms}" "${result}" "${artifacts_json}" "${details}" >> "${LOG_JSONL}"
}

run_step() {
  local step="$1"
  local step_number="$2"
  local artifacts_json="$3"
  shift 3

  local start_ms end_ms duration_ms rc
  start_ms="$(now_ms)"
  set +e
  "$@"
  rc=$?
  set -e
  end_ms="$(now_ms)"
  duration_ms=$((end_ms - start_ms))

  if [[ ${rc} -eq 0 ]]; then
    log_step "${step}" "${step_number}" "pass" "${duration_ms}" "${artifacts_json}"
  else
    log_step "${step}" "${step_number}" "fail" "${duration_ms}" "${artifacts_json}"
    exit ${rc}
  fi
}

step_setup() {
  fcp-harness init --nodes=3 --deterministic --seed "${SEED}"
  fcp install "${CONNECTOR}" --zone "${ZONE}"
}

step_create_token() {
  fcp-harness create-token \
    --connector="${CONNECTOR}" \
    --operations=echo \
    --zone="${ZONE}" \
    --output="${OUT_DIR}/token.cbor"

  TOKEN_ID="$(jq -r '.token_id' "${OUT_DIR}/token.cbor")"
  if [[ -z "${TOKEN_ID}" || "${TOKEN_ID}" == "null" ]]; then
    echo "Missing token_id in ${OUT_DIR}/token.cbor" >&2
    exit 1
  fi
}

step_initial_invoke() {
  fcp-harness invoke \
    --connector="${CONNECTOR}" \
    --operation=echo \
    --token="${OUT_DIR}/token.cbor" \
    --expect-success
}

step_revoke() {
  local start_ms end_ms
  start_ms="$(now_ms)"
  fcp-harness revoke \
    --token-id="${TOKEN_ID}" \
    --reason="Testing revocation"
  fcp-harness wait-revocation \
    --token-id="${TOKEN_ID}" \
    --timeout=5s
  end_ms="$(now_ms)"
  PROPAGATION_MS=$((end_ms - start_ms))
}

step_invoke_revoked() {
  fcp-harness invoke \
    --connector="${CONNECTOR}" \
    --operation=echo \
    --token="${OUT_DIR}/token.cbor" \
    --expect-failure=FCP-2201 \
    --output="${OUT_DIR}/revoked_denial.cbor"

  fcp explain --receipt="${OUT_DIR}/revoked_denial.cbor" --output="${OUT_DIR}/revoked_decision.json"
  jq -e '.reason_code == "FCP-2201"' "${OUT_DIR}/revoked_decision.json" >/dev/null
  jq -e '.evidence.revocation_id' "${OUT_DIR}/revoked_decision.json" >/dev/null
}

step_audit_verify() {
  fcp audit tail --zone "${ZONE}" --filter=type=RevocationEvent --limit=1
}

step_issuer_revocation() {
  fcp-harness create-token \
    --issuer=test-issuer \
    --connector="${CONNECTOR}" \
    --operations=echo \
    --zone="${ZONE}" \
    --output="${OUT_DIR}/issuer_token.cbor"

  fcp-harness invoke \
    --connector="${CONNECTOR}" \
    --operation=echo \
    --token="${OUT_DIR}/issuer_token.cbor" \
    --expect-success

  fcp-harness revoke-issuer --issuer=test-issuer

  fcp-harness invoke \
    --connector="${CONNECTOR}" \
    --operation=echo \
    --token="${OUT_DIR}/issuer_token.cbor" \
    --expect-failure=FCP-2202
}

require_cmd fcp-harness
require_cmd fcp
require_cmd jq

mkdir -p "${OUT_DIR}"

run_step "setup" 1 "[]" step_setup
run_step "create_token" 2 "[\"${OUT_DIR}/token.cbor\"]" step_create_token
run_step "initial_invoke" 3 "[]" step_initial_invoke
run_step "revoke_token" 4 "[]" step_revoke
run_step "invoke_revoked" 5 "[\"${OUT_DIR}/revoked_denial.cbor\",\"${OUT_DIR}/revoked_decision.json\"]" step_invoke_revoked
run_step "audit_verify" 6 "[]" step_audit_verify
run_step "issuer_revocation" 7 "[\"${OUT_DIR}/issuer_token.cbor\"]" step_issuer_revocation

echo "${SCRIPT_NAME} complete. Logs: ${LOG_JSONL}"
