E2E Log Schema (JSONL)
======================

This document defines the single structured logging schema used by:
- fcp-e2e harness logs (`crates/fcp-e2e`)
- shell-based E2E scripts (`scripts/e2e/*.sh`)

The goal is **machine-parseable, uniform logs** with minimal required fields and
clear compatibility between harness and script outputs.

Required Fields (All Logs)
--------------------------

- `timestamp` (string, RFC3339 UTC)
- `result` (string: `pass` | `fail`)
- `duration_ms` (u64)
- `correlation_id` (string, UUID)
- `test_name` OR `script` (non-empty string)
- `phase` OR `step` (non-empty string)

Optional Fields
---------------

- `level` (string: info|warn|error)
- `module` (string, e.g., `fcp-e2e`)
- `step_number` (u64)
- `assertions` (object):
  - `passed` (u64)
  - `failed` (u64)
- `artifacts` (array of strings)
- `context` (object; free-form for connector_id, zone_id, operation_id, etc.)
- `error_code` (string; stable FCP error code when `result=fail`)
- `details` (object; extra error metadata)

Compatibility Rules
-------------------

1. Harness logs use `test_name` + `phase`.
2. Script logs use `script` + `step`.
3. Both MUST include the required base fields above.
4. `result` is strictly `pass` or `fail` (no other values).
5. Any secrets in `context`/`details` are redacted by the harness.

Harness Example (fcp-e2e)
-------------------------

```json
{
  "timestamp": "2026-01-27T00:00:00Z",
  "level": "info",
  "test_name": "connector_happy_path",
  "module": "fcp-e2e",
  "phase": "execute",
  "correlation_id": "00000000-0000-4000-8000-000000000000",
  "result": "pass",
  "duration_ms": 12,
  "assertions": { "passed": 3, "failed": 0 },
  "context": { "zone_id": "z:work", "connector_id": "fcp.test-echo" }
}
```

Script Example (scripts/e2e/*.sh)
---------------------------------

```json
{
  "timestamp": "2026-01-27T00:00:00Z",
  "script": "e2e_happy_path",
  "step": "invoke",
  "step_number": 4,
  "correlation_id": "00000000-0000-4000-8000-000000000000",
  "duration_ms": 25,
  "result": "pass",
  "artifacts": ["receipt.cbor"]
}
```

Validator
---------

The validator lives in `crates/fcp-e2e/src/logging.rs` as:
- `validate_log_entry_value(value: &serde_json::Value)`
- `E2eLogEntry::validate()`

These checks enforce the required fields and minimal typing guarantees so
E2E logs are always parsable by downstream tooling.
