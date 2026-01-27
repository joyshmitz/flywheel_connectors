# AGENTS.md - Odoo v19 + FCP Integration Project

**Версія:** 1.0.0
**Дата:** 2026-01-27

---

## Призначення цього документа

Цей файл містить інструкції для AI coding agents (Claude, GPT, Codex, тощо), які працюватимуть над інтеграцією Odoo v19 з FCP (Flywheel Connector Protocol).

---

## Контекст проекту

### Що це за проект?

Створення **fcp-odoo connector** - адаптера, який дозволяє FCP mesh network взаємодіяти з Odoo v19 ERP системою, зокрема з модулем Quality Management (PDCA).

### Ключові репозиторії

| Репозиторій | Призначення |
|-------------|-------------|
| `flywheel_connectors` | FCP протокол та connectors |
| `odoov19` | Odoo v19 PDCA Quality Management |

### Статус проекту

- **FCP:** Draft (активна розробка)
- **fcp-odoo connector:** Research phase (ще не почато)
- **Odoo v19:** Production

---

## Критичні правила для AI Agents

### 1. Розуміння FCP Architecture

**ОБОВ'ЯЗКОВО прочитати перед початком:**
- `/FCP_Specification_V2.md` - Специфікація протоколу
- `/AGENTS.md` - Головний AGENTS.md flywheel_connectors
- `/docs/fcp_model_connectors_rust.md` - Гайд розробника connectors

**Ключові концепції, які ТРЕБА розуміти:**
- Zones (z:owner, z:private, z:work, z:community, z:public)
- Capabilities (криптографічні дозволи)
- OperationReceipt (ідемпотентність)
- ZoneCheckpoint (audit trail)
- Connector archetypes (Operational, Streaming, Bidirectional)

### 2. Розуміння Odoo v19 Quality Module

**ОБОВ'ЯЗКОВО прочитати:**
- `/Users/sd/github/odoo19/odoov19/EXPLAIN.md`
- `/Users/sd/github/odoo19/odoov19/docs/PRD.md`

**Ключові сутності:**
- QCP (Quality Control Point)
- Quality Check
- Quality Alert
- CAPA (Corrective and Preventive Action)

### 3. Naming Conventions

```rust
// Connector name
pub const CONNECTOR_NAME: &str = "odoo";

// Operation names (domain.entity.action)
"odoo.quality.qcp.list"
"odoo.quality.check.create"
"odoo.capa.draft.create"

// Capability names
"odoo.quality.read"
"odoo.quality.write"
"odoo.capa.draft"
"odoo.capa.approve"
```

### 4. Code Style

**Rust code ПОВИНЕН:**
- Використовувати `async/await` для I/O операцій
- Мати proper error handling (`Result<T, E>`)
- Включати documentation comments (`///`)
- Проходити `cargo clippy` без warnings
- Мати unit tests для всіх public функцій

**Приклад:**
```rust
/// Creates a draft CAPA document from a quality alert.
///
/// # Arguments
/// * `alert_id` - The Odoo ID of the source quality alert
/// * `analysis` - Root cause analysis content
///
/// # Returns
/// * `Ok(CapaResult)` - Successfully created CAPA draft
/// * `Err(OdooError)` - Failed to create CAPA
///
/// # Example
/// ```
/// let result = connector.create_capa_draft(12345, "Root cause...").await?;
/// ```
pub async fn create_capa_draft(
    &self,
    alert_id: u64,
    analysis: &str,
) -> Result<CapaResult, OdooError> {
    // Implementation
}
```

### 5. Security Rules

**ЗАБОРОНЕНО:**
- Hardcode credentials в коді
- Log sensitive data (passwords, API keys, tokens)
- Bypass capability checks
- Direct database access (тільки через Odoo API)

**ОБОВ'ЯЗКОВО:**
- Validate all input from Odoo API
- Use environment variables for credentials
- Check capabilities before operations
- Log audit events

### 6. Testing Requirements

**Кожен PR повинен включати:**
- Unit tests для нових функцій
- Integration tests (з mock Odoo server)
- Documentation updates

**Test structure:**
```
connectors/odoo/tests/
├── unit/
│   ├── auth_test.rs
│   ├── quality_test.rs
│   └── capa_test.rs
├── integration/
│   ├── mock_server.rs
│   └── scenarios/
│       ├── create_capa.rs
│       └── phase_transition.rs
└── fixtures/
    ├── quality_alert.json
    └── capa_draft.json
```

---

## Архітектура fcp-odoo Connector

### Файлова структура

```
connectors/odoo/
├── Cargo.toml
├── README.md
├── src/
│   ├── lib.rs              # Public API exports
│   ├── connector.rs        # Main Connector trait impl
│   ├── config.rs           # Configuration types
│   ├── auth.rs             # Odoo authentication
│   ├── client.rs           # HTTP client wrapper
│   ├── operations/
│   │   ├── mod.rs
│   │   ├── quality.rs      # QCP, Check, Alert ops
│   │   ├── capa.rs         # CAPA operations
│   │   ├── knowledge.rs    # KB operations
│   │   └── kpi.rs          # Metrics operations
│   ├── types/
│   │   ├── mod.rs
│   │   ├── quality.rs      # Quality domain types
│   │   ├── capa.rs         # CAPA types
│   │   └── common.rs       # Shared types
│   └── error.rs            # Error types
└── tests/
    └── ...
```

### Cargo.toml Template

```toml
[package]
name = "fcp-odoo"
version = "0.1.0"
edition = "2021"

[dependencies]
fcp-core = { path = "../../fcp-core" }
fcp-traits = { path = "../../fcp-traits" }

# Async runtime
tokio = { version = "1", features = ["full"] }

# HTTP client
reqwest = { version = "0.11", features = ["json", "rustls-tls"] }

# Serialization
serde = { version = "1", features = ["derive"] }
serde_json = "1"

# Error handling
thiserror = "1"
anyhow = "1"

# Logging
tracing = "0.1"

[dev-dependencies]
tokio-test = "0.4"
mockito = "1"
```

---

## Capability Mapping

### Zone → Capability Matrix

| Zone | Capabilities |
|------|-------------|
| `z:owner` | All capabilities |
| `z:private` | `odoo.capa.approve`, `odoo.accounting.read` |
| `z:work` | `odoo.quality.*`, `odoo.capa.draft`, `odoo.kb.*`, `odoo.kpi.read` |
| `z:community` | `odoo.quality.read`, `odoo.kb.read` |
| `z:public` | None (webhook receive only) |

### Capability Hierarchy

```
odoo.*                          (ALL)
├── odoo.quality.*              (All quality)
│   ├── odoo.quality.read       (Read QCP, Check, Alert)
│   └── odoo.quality.write      (Create/Update)
├── odoo.capa.*                 (All CAPA)
│   ├── odoo.capa.draft         (Draft operations)
│   └── odoo.capa.approve       (Approval, requires escalation)
├── odoo.kb.*                   (Knowledge Base)
│   ├── odoo.kb.read
│   └── odoo.kb.write
├── odoo.kpi.read               (Metrics, read-only)
└── odoo.accounting.read        (Financial, read-only, restricted)
```

---

## Типові помилки та як їх уникати

### Помилка 1: Ігнорування OperationReceipt

**Неправильно:**
```rust
// Просто викликаємо API
client.create_capa(data).await?;
```

**Правильно:**
```rust
// Перевіряємо ідемпотентність
let receipt = OperationReceipt::new(&params)?;
if let Some(existing) = self.check_receipt(&receipt).await? {
    return Ok(existing);
}
client.create_capa(data).await?;
self.store_receipt(receipt).await?;
```

### Помилка 2: Bypass Capability Check

**Неправильно:**
```rust
// Просто виконуємо операцію
async fn approve_capa(&self, id: u64) -> Result<()> {
    self.client.approve(id).await
}
```

**Правильно:**
```rust
async fn approve_capa(&self, ctx: &OperationContext, id: u64) -> Result<()> {
    // Перевіряємо capability
    ctx.require_capability("odoo.capa.approve")?;

    // Тільки після перевірки
    self.client.approve(id).await
}
```

### Помилка 3: Hardcoded Credentials

**ЗАБОРОНЕНО:**
```rust
const API_KEY: &str = "sk-abc123..."; // НІКОЛИ!
```

**Правильно:**
```rust
let api_key = std::env::var("FCP_ODOO_API_KEY")
    .map_err(|_| ConfigError::MissingCredential("FCP_ODOO_API_KEY"))?;
```

---

## Контакти та ресурси

### Документація

- FCP Specification: `/FCP_Specification_V2.md`
- Research Document: `/docs/research/ODOO_V19_FCP_INTEGRATION.md`
- Implementation Plan: `/docs/research/PLAN_FOR_ODOOv19_AND_FLYWHEEL.md`

### Existing Connectors (для reference)

Вивчіть існуючі connectors як приклади:
- `connectors/twitter/` - Приклад Bidirectional connector
- `connectors/telegram/` - Приклад Operational connector
- `connectors/anthropic/` - Приклад простого API connector

---

## Checklist для AI Agent

Перед кожним PR перевір:

- [ ] Код компілюється (`cargo build`)
- [ ] Clippy проходить (`cargo clippy -- -D warnings`)
- [ ] Тести проходять (`cargo test`)
- [ ] Documentation оновлена
- [ ] Capabilities правильно перевіряються
- [ ] OperationReceipt використовується для мутацій
- [ ] Credentials НЕ hardcoded
- [ ] Logging НЕ містить sensitive data

---

*Цей документ є частиною дослідження інтеграції Odoo v19 + FCP*
*Версія: 1.0.0 | Дата: 2026-01-27*
