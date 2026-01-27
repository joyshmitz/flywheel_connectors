#!/usr/bin/env bash
set -euo pipefail

SCRIPT_NAME="e2e_denial_path"
SEED="0xDEADBEEF"
ZONE="z:work"
CONNECTOR="fcp.test-echo"
OUT_DIR="${OUT_DIR:-./out/${SCRIPT_NAME}}"
LOG_JSONL="${LOG_JSONL:-${OUT_DIR}/${SCRIPT_NAME}.jsonl}"

EXPECTED_FAILURE=""
ACTUAL_FAILURE=""

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

details_json() {
  if [[ -z "${EXPECTED_FAILURE}" && -z "${ACTUAL_FAILURE}" ]]; then
    printf 'null'
    return 0
  fi
  printf '{"expected_failure":%s,"actual_failure":%s}' \
    "$(json_or_null "${EXPECTED_FAILURE}")" \
    "$(json_or_null "${ACTUAL_FAILURE}")"
}

log_step() {
  local step="$1"
  local step_number="$2"
  local result="$3"
  local duration_ms="$4"
  local artifacts_json="$5"
  local timestamp
  local correlation_id
  local details

  timestamp="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  correlation_id="$(correlation_id_for_step "${step_number}")"
  details="$(details_json)"

  mkdir -p "$(dirname "${LOG_JSONL}")"
  printf '{"timestamp":"%s","script":"%s","step":"%s","step_number":%s,"correlation_id":"%s","duration_ms":%s,"result":"%s","artifacts":%s,"details":%s}\n' \
    "${timestamp}" "${SCRIPT_NAME}" "${step}" "${step_number}" "${correlation_id}" "${duration_ms}" "${result}" "${artifacts_json}" "${details}" >> "${LOG_JSONL}"
}

run_step() {
  local step="$1"
  local step_number="$2"
  local artifacts_json="$3"
  local expected_failure="$4"
  shift 4

  local start_ms end_ms duration_ms rc
  EXPECTED_FAILURE="${expected_failure}"
  ACTUAL_FAILURE=""

  start_ms="$(now_ms)"
  set +e
  "$@"
  rc=$?
  set -e
  end_ms="$(now_ms)"
  duration_ms=$((end_ms - start_ms))

  if [[ ${rc} -eq 0 ]]; then
    if [[ -n "${EXPECTED_FAILURE}" ]]; then
      ACTUAL_FAILURE="${EXPECTED_FAILURE}"
    fi
    log_step "${step}" "${step_number}" "pass" "${duration_ms}" "${artifacts_json}"
  else
    ACTUAL_FAILURE="exit_code_${rc}"
    log_step "${step}" "${step_number}" "fail" "${duration_ms}" "${artifacts_json}"
    exit ${rc}
  fi
}

step_init() {
  fcp-harness init --nodes=3 --deterministic --seed "${SEED}"
}

step_install() {
  fcp install "${CONNECTOR}" --zone "${ZONE}"
}

step_invoke_without_token() {
  fcp-harness invoke \
    --connector="${CONNECTOR}" \
    --operation=echo \
    --args='{"message":"hello"}' \
    --expect-failure=FCP-2101 \
    --output="${OUT_DIR}/denial.cbor"
}

step_explain_denial() {
  fcp explain --receipt="${OUT_DIR}/denial.cbor" --output="${OUT_DIR}/decision.json"
  jq -e '.decision == "deny"' "${OUT_DIR}/decision.json" >/dev/null
  jq -e '.reason_code == "FCP-2101"' "${OUT_DIR}/decision.json" >/dev/null
  jq -e '.evidence | length > 0' "${OUT_DIR}/decision.json" >/dev/null
}

step_expired_token() {
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
}

step_wrong_zone() {
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
}

step_audit_tail() {
  fcp audit tail --zone "${ZONE}" --event-type=security.violation --limit=3
}

require_cmd fcp-harness
require_cmd fcp
require_cmd fcp-e2e
require_cmd jq

mkdir -p "${OUT_DIR}"

run_step "init" 1 "[]" "" step_init
run_step "install_connector" 2 "[]" "" step_install
run_step "invoke_without_token" 3 "[\"${OUT_DIR}/denial.cbor\"]" "FCP-2101" step_invoke_without_token
run_step "explain_denial" 4 "[\"${OUT_DIR}/decision.json\"]" "" step_explain_denial
run_step "expired_token" 5 "[\"${OUT_DIR}/expired_token.cbor\",\"${OUT_DIR}/expired_denial.cbor\"]" "FCP-2102" step_expired_token
run_step "wrong_zone" 6 "[\"${OUT_DIR}/wrong_zone_token.cbor\",\"${OUT_DIR}/zone_denial.cbor\"]" "FCP-3001" step_wrong_zone
run_step "audit_tail" 7 "[]" "" step_audit_tail

fcp-e2e --validate-log "${LOG_JSONL}"

echo "${SCRIPT_NAME} complete. Logs: ${LOG_JSONL}"
