# AGENTS.md - Odoo v19 + FCP Integration Project

**Версія:** 2.0.0
**Дата:** 2026-01-27

---

## Призначення цього документа

Цей файл містить інструкції для AI coding agents (Claude, GPT, Codex, тощо), які працюватимуть над інтеграцією Odoo v19 з FCP (Flywheel Connector Protocol).

---

## Контекст проекту

### Що це за проект?

Створення **fcp-odoo connector** - адаптера для взаємодії FCP mesh network з Odoo v19 ERP системою.

**Ключовий інсайт:** Odoo v19 Quality API - це **Enterprise Process Quality Framework**, не просто модуль якості виробництва. Контролює якість ВСІХ бізнес-процесів підприємства.

### Ключові репозиторії

| Репозиторій | Призначення |
|-------------|-------------|
| `flywheel_connectors` | FCP протокол та connectors |
| `odoov19` | Odoo v19 PDCA Quality Management |

### Статус проекту

- **FCP:** Draft (активна розробка)
- **fcp-odoo connector:** Research phase (v2.0)
- **Odoo v19:** Production

---

## Ключові концепції (MUST READ)

### 1. Process Decomposition Model

**Бізнес-процес НЕ є монолітом.** Декомпозиція:

```
Business Process = Σ(Operations) + Σ(Gates) + Σ(Decisions)

Operations:  атомарні дії (можуть бути Skills - автоматизовані)
Gates:       Quality Checks (авто) або Approvals (human)
Decisions:   Rule-based (авто) або Judgment (human)
```

**Візуалізація:**
```
[Operation] → [Gate] → [Operation] → [Gate] → [Decision]
     ↓           ↓           ↓           ↓          ↓
   Skill?    Quality     Skill?     Human      Rule or
  (auto)     Check      (auto)     Approval   Judgment?
```

### 2. Operations як Skills

**Skill** = атомарна, автоматизована операція:
- Тривалість: секунди/хвилини
- Stateless або мінімальний state
- Один виконавець (AI/система)
- Результат: Pass/Fail

**Business Process** = оркестрація skills + gates + human decisions

### 3. Policy Profiles

**Автоматизація залежить від типу підприємства:**

| Enterprise | Automation | Gates | Compliance |
|------------|------------|-------|------------|
| ФОП (спрощена) | 80-95% | 0-1 | Мінімальний |
| ТОВ (загальна) | 50-70% | 3-5 | Бухоблік, ЕЦП |
| ПАТ (публічне) | 30-50% | 7+ | Аудит, держконтроль |

### 4. Три виміри автоматизації

Для кожної Operation визнач:
1. **CAN** - технічно можливо автоматизувати?
2. **SHOULD** - compliance дозволяє?
3. **IS** - поточний стан

```
Automatable = CAN ∧ SHOULD ∧ ¬HAS_BLOCKING_GATE
```

---

## Критичні правила для AI Agents

### 1. Розуміння FCP Architecture

**ОБОВ'ЯЗКОВО прочитати:**
- `/FCP_Specification_V2.md` - Специфікація протоколу
- `/AGENTS.md` - Головний AGENTS.md flywheel_connectors
- `/docs/fcp_model_connectors_rust.md` - Гайд розробника

**Ключові концепції:**
- Zones (z:owner, z:private, z:work, z:community, z:public)
- Capabilities (криптографічні дозволи)
- OperationReceipt (ідемпотентність)
- ZoneCheckpoint (audit trail)

### 2. Розуміння Odoo v19 Quality API

**ОБОВ'ЯЗКОВО прочитати:**
- `/Users/sd/projects/odoov19/EXPLAIN.md` - PDCA система
- `/docs/research/ODOO_V19_FCP_INTEGRATION.md` - Дослідження v2.0

**Ключові сутності:**
- QCP (Quality Control Point) - для БУДЬ-ЯКОГО бізнес-процесу
- Quality Check - фактична перевірка
- Quality Alert - сигнал про відхилення
- CAPA - Corrective and Preventive Action
- SOP - Standard Operating Procedure (Knowledge Base)
- Phase Gate - Go/No-Go точка

### 3. Policy Profile Awareness

**При написанні коду ЗАВЖДИ враховуй:**
- Код має працювати для ВСІХ enterprise types
- Gates мають бути configurable через Policy Profile
- Не hardcode рішення про автоматизацію

```rust
// НЕПРАВИЛЬНО - hardcoded automation
async fn process_payment(&self) -> Result<()> {
    self.auto_record_income().await // Що якщо ТОВ?
}

// ПРАВИЛЬНО - policy-aware
async fn process_payment(&self, ctx: &Context) -> Result<()> {
    self.receive_payment().await?;

    if ctx.policy.requires_gate("accounting_entry") {
        return Ok(PendingGate::AccountingReview);
    }

    self.record_income().await
}
```

---

## Архітектура fcp-odoo Connector

### Файлова структура (v2.0)

```
connectors/odoo/
├── Cargo.toml
├── README.md
├── src/
│   ├── lib.rs                    # Public API
│   ├── connector.rs              # Main Connector trait
│   ├── config.rs                 # Configuration types
│   │
│   ├── policy_profiles/          # NEW: Enterprise profiles
│   │   ├── mod.rs
│   │   ├── profile.rs            # Profile trait
│   │   ├── fop_simplified.rs     # ФОП спрощена
│   │   ├── tov_general.rs        # ТОВ загальна
│   │   └── pat_public.rs         # ПАТ публічне
│   │
│   ├── decomposition/            # NEW: Process decomposition
│   │   ├── mod.rs
│   │   ├── operation.rs          # Operation/Skill types
│   │   ├── gate.rs               # Gate definitions
│   │   ├── decision.rs           # Decision points
│   │   └── patterns/             # Reusable patterns
│   │       ├── mod.rs
│   │       ├── capa_lifecycle.rs
│   │       ├── inventory_receiving.rs
│   │       └── payment_processing.rs
│   │
│   ├── operations/               # FCP Operations
│   │   ├── mod.rs
│   │   ├── quality.rs
│   │   ├── capa.rs
│   │   ├── knowledge.rs
│   │   ├── inventory.rs
│   │   └── kpi.rs
│   │
│   ├── auth.rs
│   ├── client.rs
│   ├── types/
│   │   └── ...
│   └── error.rs
└── tests/
    ├── unit/
    ├── integration/
    └── policy_profiles/          # NEW: Profile-specific tests
        ├── fop_test.rs
        ├── tov_test.rs
        └── pat_test.rs
```

### Naming Conventions

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

// Policy Profile names
"fop_simplified"
"tov_general"
"pat_public"

// Gate names
"gate.accounting_entry"
"gate.tax_classification"
"gate.quality_signoff"
```

---

## Capability Mapping по Policy Profiles

### ФОП (спрощена система)

```rust
// Максимальна автоматизація
capabilities! {
    auto_granted: [
        "odoo.quality.*",
        "odoo.capa.draft",
        "odoo.kb.read",
        "odoo.stock.*",
        "odoo.income.record",  // Книга доходів - auto!
    ],
    requires_human: [
        "odoo.capa.approve",   // Тільки approve
    ]
}
```

### ТОВ (загальна система)

```rust
// Баланс автоматизації та compliance
capabilities! {
    auto_granted: [
        "odoo.quality.read",
        "odoo.quality.write",
        "odoo.capa.draft",
        "odoo.kb.read",
        "odoo.stock.read",
    ],
    requires_human: [
        "odoo.capa.approve",
        "odoo.accounting.entry",  // Gate: бухгалтер
        "odoo.tax.classify",      // Gate: головбух
        "odoo.stock.accounting",  // Gate: облік
        "odoo.kb.sign",           // Gate: Sign
    ]
}
```

### ПАТ (публічне)

```rust
// Максимальні gates для compliance
capabilities! {
    auto_granted: [
        "odoo.quality.read",
        "odoo.kb.read",
        "odoo.kpi.read",
    ],
    requires_human: [
        "odoo.quality.write",     // Gate: QA review
        "odoo.capa.*",            // All CAPA operations
        "odoo.accounting.*",      // All accounting
        "odoo.stock.write",       // Gate: inventory control
        "odoo.kb.write",          // Gate: content review
        "odoo.audit.sign",        // Gate: auditor
        "odoo.board.approve",     // Gate: наглядова рада
    ]
}
```

---

## Code Patterns

### Pattern 1: Policy-Aware Operation

```rust
/// Operation that respects policy profile gates
pub async fn create_stock_move(
    &self,
    ctx: &OperationContext,
    data: StockMoveData,
) -> Result<StockMoveResult, OdooError> {
    // 1. Check base capability
    ctx.require_capability("odoo.stock.write")?;

    // 2. Execute the operation
    let stock_move = self.client.create_stock_move(&data).await?;

    // 3. Check if accounting gate is required by profile
    if ctx.policy.requires_gate("stock_accounting") {
        // Return pending state - human must approve
        return Ok(StockMoveResult::PendingGate {
            stock_move_id: stock_move.id,
            gate: "accounting_entry",
            required_role: "accountant",
        });
    }

    // 4. Auto-complete if no gate required (e.g., ФОП)
    self.client.confirm_stock_move(stock_move.id).await?;
    Ok(StockMoveResult::Completed(stock_move))
}
```

### Pattern 2: Decomposed Process

```rust
/// Process decomposition pattern
pub struct InventoryReceivingProcess {
    operations: Vec<Operation>,
    gates: Vec<Gate>,
    policy: PolicyProfile,
}

impl InventoryReceivingProcess {
    pub fn for_profile(profile: PolicyProfile) -> Self {
        let mut process = Self::base_process();

        match profile {
            PolicyProfile::FopSimplified => {
                // Remove accounting gate
                process.gates.retain(|g| g.name != "accounting_entry");
            }
            PolicyProfile::TovGeneral => {
                // Standard gates
            }
            PolicyProfile::PatPublic => {
                // Add extra gates
                process.gates.push(Gate::new("audit_review"));
                process.gates.push(Gate::new("board_notification"));
            }
        }

        process
    }
}
```

### Pattern 3: Gate Handler

```rust
/// Gate that requires human approval
#[derive(Debug)]
pub struct Gate {
    pub name: String,
    pub required_capability: String,
    pub required_role: String,
    pub timeout: Duration,
}

impl Gate {
    pub async fn check(&self, ctx: &OperationContext) -> GateResult {
        if ctx.has_capability(&self.required_capability) {
            // Capability granted - can proceed
            GateResult::Proceed
        } else {
            // Need human approval
            GateResult::Pending {
                gate: self.name.clone(),
                role: self.required_role.clone(),
                expires_at: Utc::now() + self.timeout,
            }
        }
    }
}
```

---

## Типові помилки

### Помилка 1: Hardcoded Automation Level

**НЕПРАВИЛЬНО:**
```rust
// Assumes ФОП level of automation
async fn receive_inventory(&self) -> Result<()> {
    self.create_stock_move().await?;
    self.update_inventory().await?;
    self.record_income().await?;  // What if ТОВ needs approval?
    Ok(())
}
```

**ПРАВИЛЬНО:**
```rust
async fn receive_inventory(&self, ctx: &Context) -> Result<ProcessState> {
    self.create_stock_move().await?;
    self.update_inventory().await?;

    // Check policy for next step
    match ctx.policy.next_step("record_income") {
        NextStep::Auto => {
            self.record_income().await?;
            Ok(ProcessState::Completed)
        }
        NextStep::Gate(gate) => {
            Ok(ProcessState::PendingGate(gate))
        }
    }
}
```

### Помилка 2: Ignoring Enterprise Type in Tests

**НЕПРАВИЛЬНО:**
```rust
#[test]
fn test_payment_processing() {
    // Only tests one scenario
    let result = process_payment(&data);
    assert!(result.is_ok());
}
```

**ПРАВИЛЬНО:**
```rust
#[test]
fn test_payment_processing_fop() {
    let ctx = Context::with_profile(PolicyProfile::FopSimplified);
    let result = process_payment(&ctx, &data);
    assert!(matches!(result, ProcessState::Completed));
}

#[test]
fn test_payment_processing_tov() {
    let ctx = Context::with_profile(PolicyProfile::TovGeneral);
    let result = process_payment(&ctx, &data);
    // ТОВ requires accounting gate
    assert!(matches!(result, ProcessState::PendingGate(_)));
}
```

### Помилка 3: Not Considering SOP as Skills Repository

**НЕПРАВИЛЬНО:**
```rust
// Hardcoded process steps
fn get_receiving_steps() -> Vec<Step> {
    vec![
        Step::new("check_documents"),
        Step::new("measure_temperature"),
        // ...
    ]
}
```

**ПРАВИЛЬНО:**
```rust
// Load from SOP/Knowledge Base
async fn get_receiving_steps(&self, ctx: &Context) -> Result<Vec<Step>> {
    let sop = self.kb.get_sop("receiving_process").await?;
    let steps = sop.to_operations(ctx.policy)?;
    Ok(steps)
}
```

---

## Checklist для AI Agent

### Перед кожним PR:

**Code Quality:**
- [ ] `cargo build` проходить
- [ ] `cargo clippy -- -D warnings` проходить
- [ ] `cargo test` проходить
- [ ] Documentation оновлена

**Policy Profile Awareness:**
- [ ] Код працює для всіх enterprise types (ФОП, ТОВ, ПАТ)
- [ ] Gates configurable через Policy Profile
- [ ] Тести покривають різні profiles

**FCP Compliance:**
- [ ] Capabilities перевіряються
- [ ] OperationReceipt для мутацій
- [ ] Credentials НЕ hardcoded
- [ ] Logging НЕ містить sensitive data

**Process Decomposition:**
- [ ] Operations атомарні та reusable
- [ ] Gates clearly defined
- [ ] Decisions documented

---

## Ресурси

| Document | Location |
|----------|----------|
| FCP Spec | `/FCP_Specification_V2.md` |
| Research v2.0 | `/docs/research/ODOO_V19_FCP_INTEGRATION.md` |
| Plan | `/docs/research/PLAN_FOR_ODOOv19_AND_FLYWHEEL.md` |
| Odoo PDCA | `/Users/sd/projects/odoov19/EXPLAIN.md` |

---

*Версія: 2.0.0 | Дата: 2026-01-27*
*Ключові зміни: Process Decomposition, Policy Profiles, Enterprise Types*
