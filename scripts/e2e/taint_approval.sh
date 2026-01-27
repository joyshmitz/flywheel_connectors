#!/usr/bin/env bash
set -euo pipefail

SCRIPT_NAME="e2e_taint_approval"
SEED="0xDEADBEEF"
ZONE="z:work"
CONNECTOR="fcp.test-echo"
TAINT_LABEL="external_input"
APPROVER="owner"
OUT_DIR="${OUT_DIR:-./out/${SCRIPT_NAME}}"
LOG_JSONL="${LOG_JSONL:-${OUT_DIR}/${SCRIPT_NAME}.jsonl}"

TOKEN_ID=""
APPROVAL_ID=""

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

log_step() {
  local step="$1"
  local step_number="$2"
  local result="$3"
  local duration_ms="$4"
  local artifacts_json="$5"
  local timestamp
  local correlation_id
  local token_json
  local approval_json
  local approver_json
  local details

  timestamp="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  correlation_id="$(correlation_id_for_step "${step_number}")"
  token_json="$(json_or_null "${TOKEN_ID}")"
  approval_json="$(json_or_null "${APPROVAL_ID}")"
  approver_json="$(json_or_null "${APPROVER}")"
  details="{\"taint_labels\":[\"${TAINT_LABEL}\"],\"approver\":${approver_json},\"approval_id\":${approval_json},\"token_id\":${token_json}}"

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
  fcp-harness set-policy \
    --zone="${ZONE}" \
    --require-approval-for="taint:${TAINT_LABEL}"
}

step_create_token() {
  fcp-harness create-token \
    --connector="${CONNECTOR}" \
    --operations=echo \
    --zone="${ZONE}" \
    --ttl=3600 \
    --output="${OUT_DIR}/token.cbor"

  TOKEN_ID="$(jq -r '.token_id' "${OUT_DIR}/token.cbor")"
  if [[ -z "${TOKEN_ID}" || "${TOKEN_ID}" == "null" ]]; then
    echo "Missing token_id in ${OUT_DIR}/token.cbor" >&2
    exit 1
  fi
}

step_create_tainted_input() {
  fcp-harness create-object \
    --content='{"message":"untrusted user input"}' \
    --taint="${TAINT_LABEL}" \
    --output="${OUT_DIR}/tainted_input.cbor"
}

step_invoke_denied() {
  fcp-harness invoke \
    --connector="${CONNECTOR}" \
    --operation=echo \
    --args-file="${OUT_DIR}/tainted_input.cbor" \
    --token="${OUT_DIR}/token.cbor" \
    --expect-failure=FCP-4401 \
    --output="${OUT_DIR}/taint_denial.cbor"

  fcp explain --receipt="${OUT_DIR}/taint_denial.cbor" --output="${OUT_DIR}/taint_decision.json"
  jq -e '.reason_code == "FCP-4401"' "${OUT_DIR}/taint_decision.json" >/dev/null
  jq -e --arg label "${TAINT_LABEL}" '.evidence.taint_labels | contains([$label])' "${OUT_DIR}/taint_decision.json" >/dev/null
}

step_create_approval() {
  local operation_id
  operation_id="$(jq -r '.operation_id' "${OUT_DIR}/taint_denial.cbor")"
  if [[ -z "${operation_id}" || "${operation_id}" == "null" ]]; then
    echo "Missing operation_id in ${OUT_DIR}/taint_denial.cbor" >&2
    exit 1
  fi

  fcp-harness create-approval \
    --operation-intent="${operation_id}" \
    --taint="${TAINT_LABEL}" \
    --approver="${APPROVER}" \
    --output="${OUT_DIR}/approval.cbor"

  APPROVAL_ID="$(jq -r '.approval_id' "${OUT_DIR}/approval.cbor")"
  if [[ -z "${APPROVAL_ID}" || "${APPROVAL_ID}" == "null" ]]; then
    APPROVAL_ID=""
  fi
}

step_invoke_approved() {
  fcp-harness invoke \
    --connector="${CONNECTOR}" \
    --operation=echo \
    --args-file="${OUT_DIR}/tainted_input.cbor" \
    --token="${OUT_DIR}/token.cbor" \
    --approval="${OUT_DIR}/approval.cbor" \
    --expect-success \
    --output="${OUT_DIR}/approved_receipt.cbor"

  fcp explain --receipt="${OUT_DIR}/approved_receipt.cbor" --output="${OUT_DIR}/approved_decision.json"
  jq -e '.approval_used == true' "${OUT_DIR}/approved_decision.json" >/dev/null
}

step_audit_verify() {
  fcp audit tail --zone "${ZONE}" --filter=reason_code=FCP-4401 --limit=1
  fcp audit tail --zone "${ZONE}" --filter=approval_id --limit=1
}

require_cmd fcp-harness
require_cmd fcp
require_cmd fcp-e2e
require_cmd jq

mkdir -p "${OUT_DIR}"

run_step "setup" 1 "[]" step_setup
run_step "create_token" 2 "[\"${OUT_DIR}/token.cbor\"]" step_create_token
run_step "create_tainted_input" 3 "[\"${OUT_DIR}/tainted_input.cbor\"]" step_create_tainted_input
run_step "invoke_denied" 4 "[\"${OUT_DIR}/taint_denial.cbor\",\"${OUT_DIR}/taint_decision.json\"]" step_invoke_denied
run_step "create_approval" 5 "[\"${OUT_DIR}/approval.cbor\"]" step_create_approval
run_step "invoke_approved" 6 "[\"${OUT_DIR}/approved_receipt.cbor\",\"${OUT_DIR}/approved_decision.json\"]" step_invoke_approved
run_step "audit_verify" 7 "[]" step_audit_verify

fcp-e2e --validate-log "${LOG_JSONL}"

echo "${SCRIPT_NAME} complete. Logs: ${LOG_JSONL}"
