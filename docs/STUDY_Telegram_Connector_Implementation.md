# Study: Clawdbot Telegram Connector Implementation

**Bead**: `flywheel_connectors-w1g`
**Status**: Complete
**Date**: 2026-01-27

## Executive Summary

This document analyzes the Clawdbot Telegram connector implementation (TypeScript, grammY) to extract architecture, edge cases, and reusable patterns for FCP2 connectors. Key takeaways: (1) polling is wrapped in a supervised runner with backoff and update-offset persistence, (2) per-chat sequentialization and throttling are enforced by default, (3) message formatting is HTML-based with robust fallback to plain text, and (4) group/thread nuances (forum topics, group migrations, allowlists) are handled explicitly.

---

## 1. Architecture Diagram

```
┌──────────────────────────────────────────────────────────────────────┐
│                      Telegram Provider (Clawdbot)                    │
│                                                                      │
│  monitorTelegramProvider()                                           │
│  ┌────────────────────────────────────────────────────────────────┐  │
│  │ createTelegramBot() (grammY Bot)                               │  │
│  │ - apiThrottler() (rate-limit compliance)                        │  │
│  │ - sequentialize(getTelegramSequentialKey)                        │  │
│  │ - update dedupe (update_id/callback/message key)                 │  │
│  │ - update offset persistence (per account)                        │  │
│  └────────────────────────────────────────────────────────────────┘  │
│            │                               │                           │
│            │ poll (getUpdates)             │ webhook                   │
│            ▼                               ▼                           │
│   @grammyjs/runner                  webhookCallback(bot)              │
│   - concurrency = agent limit       - setWebhook()                     │
│   - retry policy                    - healthz endpoint                 │
│   - allowed_updates                 - diagnostics heartbeat            │
│                                                                      │
│  Message pipeline                                                     │
│   buildTelegramMessageContext -> dispatchTelegramMessage               │
│   - allowlist + pairing store                                         │
│   - mention gating + control commands                                 │
│   - forum thread routing + session keys                               │
│   - history/context enrichment                                        │
│                                                                      │
│  Outbound                                                             │
│   sendMessageTelegram()                                                │
│   - markdown->HTML rendering                                           │
│   - parse error fallback to plain text                                │
│   - caption split + follow-up text                                    │
│   - inline buttons (scoped)                                           │
│   - proxy/network config, retry policy                                │
└──────────────────────────────────────────────────────────────────────┘
```

---

## 2. Pattern Catalog

### P1: Supervised Polling with Update-Offset Persistence

**Location**: `src/telegram/monitor.ts`, `src/telegram/update-offset-store.ts`

**Pattern**:
- Long-polling uses `@grammyjs/runner` with retry/backoff.
- Update offsets are persisted per account to disk with atomic writes.
- 409 getUpdates conflict triggers backoff and retry.

**Why it matters**: Prevents duplicate processing after restarts and handles multi-instance conflicts cleanly.

**Reusability**: HIGH for polling connectors (Gmail, Slack RTM fallback, etc.).

---

### P2: Per-Chat Sequentialization + Throttling

**Location**: `src/telegram/bot.ts`

**Pattern**:
- `sequentialize(getTelegramSequentialKey)` enforces ordered handling per chat/topic.
- `apiThrottler()` applies rate limiting at API client layer.

**Why it matters**: Prevents reordering, avoids race conditions in stateful chat flows, and respects rate limits.

**Reusability**: HIGH for bidirectional chat connectors.

---

### P3: Robust HTML Rendering with Safe Fallback

**Location**: `src/telegram/format.ts`, `src/telegram/send.ts`

**Pattern**:
- Render markdown to Telegram HTML with escaping.
- If Telegram rejects HTML entities, fall back to plain text send.

**Why it matters**: Ensures message delivery even with malformed markup.

**Reusability**: HIGH for any platform with strict markup parsers.

---

### P4: Explicit Handling of Forum Topics and Threaded Replies

**Location**: `src/telegram/bot/helpers.ts`, `src/telegram/targets.ts`, `src/telegram/send.ts`

**Pattern**:
- Parse `message_thread_id` for forum topics.
- Thread params are passed only when provided to keep API calls clean.

**Why it matters**: Telegram forum topics behave differently from standard group chats; threading must be explicit.

**Reusability**: MEDIUM (maps to Slack threads, Discord threads, etc.).

---

### P5: Group Migration and Identifier Hygiene

**Location**: `src/telegram/group-migration.ts`, `src/telegram/targets.ts`

**Pattern**:
- Detect group id migrations (old chat id -> new -100... id) and update config maps.
- Normalize target formats (telegram:, tg:, group: prefixes).

**Why it matters**: Telegram group migrations break static IDs; without migration, allowlists and routing fail.

**Reusability**: MEDIUM for any platform with mutable identifiers.

---

### P6: Network Workarounds and Recoverable Error Detection

**Location**: `src/telegram/fetch.ts`, `src/telegram/network-errors.ts`, `src/telegram/network-config.ts`

**Pattern**:
- Node 22 Happy Eyeballs workaround (autoSelectFamily toggles).
- Centralized recoverable error classifier for polling/webhook/send.

**Why it matters**: Prevents flaky networking behavior and enables targeted retries.

**Reusability**: HIGH for any HTTP-based connector in Node runtimes.

---

## 3. Anti-Patterns / Risks

1. **State on Disk for Offsets**: Update offsets are persisted to local disk. This is fine for Telegram but conflicts with FCP's "authoritative state in mesh" principle. Use mesh-backed state for FCP2 connectors.
2. **Implicit Allow When No Allowlist**: `isSenderAllowed` returns true if no allowlist entries. For FCP2, default should be deny unless explicitly granted.
3. **Two bot.catch handlers**: Duplicate error handlers in `bot.ts` can lead to double logging; consolidate in FCP2 connector.
4. **Config-Driven Secrets**: Tokens are loaded from config/env files; FCP2 should avoid secrets on disk and prefer secret injection.

---

## 4. Reusable Components List

- **Update offset store** (atomic JSON file) -> adapt to mesh-backed state.
- **Dedupe cache** for updates (`createTelegramUpdateDedupe`).
- **Markdown-to-HTML rendering with escape + fallback**.
- **Inline buttons scope resolver** (allowlist / off / all).
- **Recoverable error classifier** for network retries.
- **Group migration utility** for mutable identifiers.

---

## 5. Comparison with Discord Connector (Clawdbot vs FCP Rust)

| Area | Telegram (Clawdbot) | Discord (FCP Rust) | Implication for FCP2 |
|------|---------------------|--------------------|----------------------|
| Transport | Polling (getUpdates) or webhook | Gateway WebSocket + REST | Telegram needs offset persistence; Discord needs resume + sequence tracking |
| Rate limiting | grammY throttler | Custom REST buckets | Provide shared rate-limit primitive in SDK |
| Ordering | per-chat sequentialize | gateway event order + userland handling | FCP2 should expose per-channel ordering hints |
| Threading | forum topics (`message_thread_id`) | threads/channels | Normalize threading in EventEnvelope metadata |
| Error handling | parse-mode fallback, network error classifier | WS reconnect + REST retry | Provide standardized retry taxonomy in SDK |
| Security | allowlist + pairing store | intents + permission checks | FCP2 must be default-deny + capability gated |

---

## 6. Edge Cases Worth Porting

- **409 getUpdates conflict**: treat as recoverable and backoff.
- **Duplicate updates**: dedupe by update_id, callback_query id, or chat+message.
- **Group migration**: old chat ID replaced by new -100... ID.
- **HTML parse errors**: fallback to plain text send.
- **Forum topics**: thread routing must pass `message_thread_id`.
- **Node 22 networking**: autoSelectFamily workaround.

---

## 7. Open Questions for FCP2

1. Should update offsets be stored as mesh objects (ConnectorState) instead of local files?
2. How should per-chat sequentialization be expressed in the SDK (policy hint vs runtime default)?
3. What is the canonical mapping for Telegram forum topics in FCP EventEnvelope metadata?
4. Can inline button scope be expressed via capability families instead of config?

---

## 8. Next Steps

- Map the above patterns to FCP2 SDK primitives and connector manifests.
- Define Telegram capability families and event schemas in `fcp_model_connectors_rust.md` if missing.
- Add tests for update dedupe + 409 conflict handling in the Rust Telegram connector.
