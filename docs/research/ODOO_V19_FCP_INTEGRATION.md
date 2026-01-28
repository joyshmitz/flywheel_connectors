# Дослідження інтеграції Odoo v19 + FCP (Flywheel Connector Protocol)

**Версія:** 2.1.0
**Дата:** 2026-01-28
**Статус:** Дослідження (Research Phase)

---

## 1. Огляд проектів

### 1.1 FCP (Flywheel Connector Protocol)

**Призначення:** Mesh-native протокол для безпечних, розподілених операцій AI-асистентів.

**Три аксіоми:**
1. **Universal Fungibility** - Дані представлені як RaptorQ символи (fountain codes)
2. **Authenticated Mesh** - Всі вузли автентифіковані через Tailscale
3. **Explicit Authority** - Криптографічні ланцюги дозволів (capabilities)

**Ключові концепції:**

| Концепція | Опис |
|-----------|------|
| Zone | Криптографічна ізоляція (owner/private/work/community/public) |
| Capability | Криптографічний дозвіл на операцію |
| OperationReceipt | Вбудована ідемпотентність |
| ZoneCheckpoint | Незмінний, hash-linked аудит |
| Connector | Адаптер до зовнішнього сервісу |

**Рівні довіри зон:**
```
z:owner     = 100  (повний контроль)
z:private   = 80   (особисті дані)
z:work      = 60   (робочі операції)
z:community = 40   (командна робота)
z:public    = 20   (публічні API)
```

### 1.2 Odoo v19 Quality API - Enterprise Process Quality Framework

**Призначення:** Система управління якістю **ВСІХ бізнес-процесів підприємства** на основі циклу Plan-Do-Check-Act.

**Ключовий інсайт:** Quality API - це НЕ тільки "якість продукції". Це платформа контролю якості будь-яких бізнес-процесів:

```
┌─────────────────────────────────────────────────────────────┐
│                Quality Control Points (КТЯ)                  │
├─────────────────────────────────────────────────────────────┤
│  Виробництво     │  Логістика      │  Фінанси              │
│  - Температура   │  - Цілісність   │  - Reconciliation     │
│  - Вологість     │  - Терміни      │  - Валідація даних    │
│  - Специфікація  │  - Документи    │  - Compliance checks  │
├─────────────────────────────────────────────────────────────┤
│  HR/Процеси      │  IT/Інтеграції  │  Compliance           │
│  - Onboarding    │  - API health   │  - Audit trail        │
│  - Training      │  - Data quality │  - Policy adherence   │
└─────────────────────────────────────────────────────────────┘
```

**Основні сутності:**

| Сутність | Опис |
|----------|------|
| Quality Control Point (QCP/КТЯ) | Точка контролю в БУДЬ-ЯКОМУ бізнес-процесі |
| Quality Check | Фактична перевірка/вимірювання |
| Quality Alert | Сигнал про відхилення від норми |
| CAPA | Corrective and Preventive Action |
| SOP | Standard Operating Procedure (Knowledge Base) |
| Phase Gate | Go/No-Go точка переходу між фазами |

**Ключові метрики:**
- **FPY** (First Pass Yield) - % що пройшло з першого разу
- **MTTR** (Mean Time To Repair) - Середній час усунення проблеми
- **CAPA Efficacy** - Ефективність коригувальних дій (повтори ≤15%)
- **SPC** (Statistical Process Control) - Статистичний контроль процесів

---

## 2. Ключова концепція: Декомпозиція бізнес-процесів

### 2.1 Процес = Operations + Gates + Decisions

Замість типізації процесів ("автоматичний" vs "ручний"), використовуємо **декомпозицію**:

```
Business Process = Σ(Operations) + Σ(Gates) + Σ(Decisions)

Operations:  атомарні дії (можуть бути Skills - автоматизовані)
Gates:       Quality Checks (авто) або Approvals (human)
Decisions:   Rule-based (авто) або Judgment (human)
```

**Візуалізація:**

```
┌─────────────────────────────────────────────────────────────┐
│              Business Process (Orchestration)                │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│   [Operation] → [Gate] → [Operation] → [Gate] → [Decision]  │
│       ↓           ↓           ↓           ↓          ↓      │
│     Skill?    Quality     Skill?     Human      Rule or     │
│    (auto)     Check      (auto)     Approval   Judgment?    │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### 2.2 Три виміри автоматизації

```
                    ┌─────────────────────┐
                    │   CAN be automated  │ ← Технічна можливість
                    │   (Potential)       │
                    └─────────────────────┘
                              │
                              ▼
                    ┌─────────────────────┐
                    │ SHOULD be automated │ ← Compliance / Policy
                    │   (Allowed)         │
                    └─────────────────────┘
                              │
                              ▼
                    ┌─────────────────────┐
                    │   IS automated      │ ← Поточний стан
                    │   (Current)         │
                    └─────────────────────┘
```

**Automation Ratio:**
```
Automation Ratio = Σ(Automatable Operations) / Σ(All Operations)

Де "Automatable" = CAN ∧ SHOULD ∧ ¬HAS_BLOCKING_GATE
```

### 2.3 Operations як Skills

**Ключовий інсайт:** Окремі операції в бізнес-процесі можуть бути реалізовані як **Skills** - атомарні, автоматизовані дії:

| Характеристика | Operation/Skill | Business Process |
|----------------|-----------------|------------------|
| Тривалість | Секунди/хвилини | Години/дні/тижні |
| State | Stateless або мінімальний | Складний state machine |
| Актори | Один (AI/система) | Багато (різні ролі) |
| Результат | Pass/Fail | Метрики, KPI |
| Еволюція | Версіонування | Змінює себе через CAPA |

**SOP (Standard Operating Procedure)** - найближче до Skills repository:
- Документована послідовність кроків
- Чіткі inputs/outputs
- Версіонується через Sign
- "Викликається" оператором або системою

---

## 3. Policy Profiles: Автоматизація залежить від типу підприємства

### 3.1 Enterprise Types та Compliance

Система розрахована на різні типи підприємств з різними вимогами:

```
┌─────────────────────────────────────────────────────────────┐
│                    Enterprise Type                          │
├─────────────────┬─────────────────┬─────────────────────────┤
│      ФОП        │      ТОВ        │    Інші (ПАТ, ДП...)   │
│  (спрощена)     │   (загальна)    │                        │
├─────────────────┼─────────────────┼─────────────────────────┤
│ Compliance:     │ Compliance:     │ Compliance:            │
│ - Мінімальний   │ - Бухоблік      │ - Аудит                │
│ - Книга доходів │ - Податкові     │ - Держконтроль         │
│ - 1-2 група     │   накладні      │ - Публічна звітність   │
│                 │ - Підписи ЕЦП   │ - Наглядова рада       │
├─────────────────┼─────────────────┼─────────────────────────┤
│ Automation:     │ Automation:     │ Automation:            │
│ HIGH (80-95%)   │ MEDIUM (50-70%) │ LOW (30-50%)           │
│                 │                 │                        │
│ Gates: 0-1      │ Gates: 3-5      │ Gates: 7+              │
│ Human: мін      │ Human: середній │ Human: максимум        │
└─────────────────┴─────────────────┴─────────────────────────┘
```

### 3.2 Приклад: Один процес - різна автоматизація

**Процес: "Прийняти оплату від клієнта"**

```yaml
# ФОП (спрощена система, 2 група)
process: receive_payment
enterprise_type: FOP_simplified
decomposition:
  - operation: receive_notification    # Skill ✓
  - operation: validate_amount         # Skill ✓
  - operation: match_invoice           # Skill ✓
  - operation: record_income           # Skill ✓ (Книга доходів)
  - gate: none
automation_ratio: 100%

# ТОВ (загальна система оподаткування)
process: receive_payment
enterprise_type: TOV_general
decomposition:
  - operation: receive_notification    # Skill ✓
  - operation: validate_amount         # Skill ✓
  - operation: match_invoice           # Skill ✓
  - gate: reconciliation_review        # Human (бухгалтер)
  - operation: create_accounting_entry # Skill ✓
  - gate: tax_classification           # Human (головбух)
  - operation: record_tax_liability    # Skill ✓
  - gate: period_close_review          # Human (фін.директор)
automation_ratio: ~55%
```

### 3.3 FCP Capabilities по Policy Profile

```toml
# Profile: FOP_simplified
[capabilities.auto_granted]
odoo.payment.receive = true
odoo.payment.record = true
odoo.income.record = true

[capabilities.requires_human]
# Мінімум gates

# Profile: TOV_general
[capabilities.auto_granted]
odoo.payment.receive = true
odoo.payment.validate = true

[capabilities.requires_human]
odoo.accounting.entry = true     # Gate: бухгалтер
odoo.tax.classify = true         # Gate: головбух
odoo.period.close = true         # Gate: фін.директор

# Profile: PAT_public
[capabilities.auto_granted]
odoo.payment.receive = true

[capabilities.requires_human]
odoo.payment.validate = true     # Gate: контролер
odoo.accounting.entry = true     # Gate: бухгалтер
odoo.tax.classify = true         # Gate: головбух
odoo.audit.sign = true           # Gate: аудитор
odoo.board.approve = true        # Gate: наглядова рада
```

---

## 4. Патерни декомпозиції типових процесів

### 4.1 Quality Alert → CAPA Lifecycle

```yaml
process: quality_alert_to_capa
phases:
  - name: Detection
    operations:
      - operation: detect_deviation      # Skill (auto QCP check)
      - operation: create_alert          # Skill
      - operation: classify_severity     # Skill (rule-based)
    gates: []

  - name: Analysis
    operations:
      - operation: gather_context        # Skill (fetch related data)
      - operation: ai_root_cause         # Skill (AI analysis)
      - operation: draft_capa            # Skill (AI draft)
    gates:
      - gate: human_review_analysis      # Human (QA engineer)

  - name: Planning
    operations:
      - operation: define_actions        # Human input
      - operation: assign_owners         # Human input
      - operation: set_deadlines         # Human input
    gates:
      - gate: capa_approval              # Human (QA manager)

  - name: Execution
    operations:
      - operation: track_progress        # Skill (status updates)
      - operation: notify_deadlines      # Skill
    gates:
      - gate: completion_verification    # Human (QA engineer)

  - name: Verification
    operations:
      - operation: measure_effectiveness # Skill (KPI calculation)
      - operation: update_sop            # Human input
    gates:
      - gate: sop_sign_off               # Human (Sign approval)
      - gate: capa_closure               # Human (QA manager)

automation_by_enterprise:
  FOP_simplified: 75%   # Менше gates
  TOV_general: 60%      # Стандартний flow
  PAT_public: 45%       # Додаткові compliance gates
```

### 4.2 Inventory Receiving (Приймання на склад)

```yaml
process: inventory_receiving
decomposition:
  # Phase 1: Документи
  - operation: receive_documents         # Skill
  - operation: validate_documents        # Skill
  - gate: document_approval              # ФОП: skip, ТОВ: Human

  # Phase 2: Фізична перевірка
  - operation: create_qcp_checks         # Skill
  - operation: record_measurements       # Skill (IoT/manual)
  - gate: quality_decision               # Rule-based or Human

  # Phase 3: Облік
  - operation: create_stock_move         # Skill
  - operation: update_inventory          # Skill
  - gate: accounting_entry               # ФОП: skip, ТОВ: Human

automation_by_enterprise:
  FOP_simplified: 90%
  TOV_general: 65%
  PAT_public: 50%
```

### 4.3 Таблиця автоматизації по процесах

| Процес | ФОП | ТОВ | ПАТ | Ключова різниця |
|--------|-----|-----|-----|-----------------|
| Прийняття оплати | 100% | 55% | 40% | Бухпроводки, податки |
| Quality Alert→CAPA | 75% | 60% | 45% | Compliance gates |
| Приймання на склад | 90% | 65% | 50% | Документообіг |
| Відвантаження | 85% | 55% | 40% | ТТН, податкові |
| Закупівля | 80% | 45% | 30% | Договори, тендери |
| Нарахування ЗП | N/A | 35% | 25% | ПДФО, ЄСВ, звіти |
| Інвентаризація | 70% | 45% | 35% | Комісія, акти |
| SOP Publication | 60% | 50% | 40% | Sign workflow |

---

## 5. Архітектура fcp-odoo Connector

### 5.1 Структура модуля (на основі існуючих connectors)

**Референс:** `connectors/anthropic/` — найповніший приклад bidirectional connector.

```
flywheel_connectors/
└── connectors/
    └── odoo/
        ├── Cargo.toml
        ├── src/
        │   ├── main.rs               # Entry point: JSON-RPC protocol loop
        │   ├── connector.rs          # OdooConnector impl FcpConnector trait
        │   ├── client.rs             # Odoo JSON-2 API HTTP client
        │   ├── types.rs              # Odoo-specific types
        │   ├── error.rs              # Error handling
        │   ├── policy_profiles/      # Enterprise profiles
        │   │   ├── mod.rs
        │   │   ├── fop_simplified.rs
        │   │   ├── tov_general.rs
        │   │   └── pat_public.rs
        │   ├── operations/
        │   │   ├── mod.rs
        │   │   ├── quality.rs        # QCP, Quality Check, Alert
        │   │   ├── capa.rs           # CAPA operations
        │   │   ├── knowledge.rs      # KB/SOP operations
        │   │   ├── inventory.rs      # Stock operations
        │   │   └── kpi.rs            # Metrics/KPI
        │   ├── decomposition/        # Process decomposition
        │   │   ├── mod.rs
        │   │   ├── patterns.rs       # Reusable patterns
        │   │   └── gates.rs          # Gate definitions
        │   └── ratelimit.rs          # Rate limit pool definitions
        └── tests/
```

### 5.1.1 FcpConnector Trait Implementation

**Путь референсу:** `crates/fcp-core/src/connector.rs:22-94`

```rust
#[async_trait]
pub trait FcpConnector: Send + Sync {
    fn id(&self) -> &ConnectorId;
    async fn configure(&mut self, config: Value) -> FcpResult<()>;
    async fn handshake(&mut self, req: HandshakeRequest) -> FcpResult<HandshakeResponse>;
    async fn health(&self) -> HealthSnapshot;
    fn metrics(&self) -> ConnectorMetrics;
    async fn shutdown(&mut self, req: ShutdownRequest) -> FcpResult<()>;
    fn introspect(&self) -> Introspection;
    fn rate_limits(&self) -> RateLimitDeclarations;
    async fn invoke(&self, req: InvokeRequest) -> FcpResult<InvokeResponse>;
    async fn simulate(&self, req: SimulateRequest) -> FcpResult<SimulateResponse>;
    // ... subscribe, unsubscribe, ack, nack
}
```

### 5.1.2 Protocol Loop Pattern

**Путь референсу:** `connectors/anthropic/src/main.rs:36-119`

```rust
fn run_fcp_loop() -> Result<()> {
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    let mut connector = OdooConnector::new();

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;

    for line in stdin.lock().lines() {
        let request: Value = serde_json::from_str(&line?)?;
        let method = request["method"].as_str().unwrap_or("");

        let result = runtime.block_on(async {
            match method {
                "configure" => connector.handle_configure(request["params"].clone()).await,
                "handshake" => connector.handle_handshake(request["params"].clone()).await,
                "invoke" => connector.handle_invoke(request["params"].clone()).await,
                // ...
            }
        });

        writeln!(stdout, "{}", serde_json::to_string(&result)?)?;
    }
    Ok(())
}
```

### 5.2 Connector Configuration з Policy Profile

**Файл:** `~/.fcp/connectors/odoo.toml`

```toml
# Odoo v19 Connector Configuration

[connector]
name = "odoo"
version = "0.2.0"
zone = "z:work"
archetypes = ["RequestResponse", "Bidirectional"]  # Per fcp-manifest archetypes

[enterprise]
# Enterprise type визначає policy profile
type = "TOV_general"  # FOP_simplified | TOV_general | PAT_public | custom
tax_system = "general"  # simplified | general

[credentials]
# JSON-2 API (Odoo v19 recommended)
url = "https://odoo.example.com"
database = "production"
api_key = "${FCP_ODOO_API_KEY}"  # Bearer token for Authorization header

[options]
timeout_secs = 60
max_retries = 3

# Rate limits (використовує fcp-sdk/ratelimit)
[rate_limits.pools]
quality_read = { requests_per_minute = 100, enforcement = "hard" }
quality_write = { requests_per_minute = 30, enforcement = "hard" }
capa_operations = { requests_per_minute = 20, enforcement = "soft" }

# Capabilities автоматично визначаються policy profile
# Можна override для кастомізації:
[capabilities.override]
# odoo.custom.operation = true
```

### 5.2.1 Odoo JSON-2 API Client

**HTTP Client pattern** (референс: `connectors/anthropic/src/client.rs`):

```rust
pub struct OdooClient {
    http: reqwest::Client,
    base_url: String,
    database: String,
    api_key: String,
}

impl OdooClient {
    /// Call Odoo JSON-2 API
    /// Endpoint: POST /json/2/{model}/{method}
    pub async fn call<T: DeserializeOwned>(
        &self,
        model: &str,
        method: &str,
        args: Value,
    ) -> Result<T, OdooError> {
        let url = format!("{}/json/2/{}/{}", self.base_url, model, method);

        let response = self.http
            .post(&url)
            .header("Authorization", format!("bearer {}", self.api_key))
            .header("X-Odoo-Database", &self.database)
            .json(&json!({ "params": args }))
            .send()
            .await?;

        let result: OdooResponse<T> = response.json().await?;
        result.into_result()
    }
}
```

### 5.3 Operations Map

| Domain | Operation | Capability | Can be Skill? |
|--------|-----------|------------|---------------|
| **Quality** | `quality.qcp.list` | `odoo.quality.read` | Yes |
| | `quality.qcp.get` | `odoo.quality.read` | Yes |
| | `quality.check.create` | `odoo.quality.write` | Yes |
| | `quality.alert.create` | `odoo.quality.write` | Yes |
| | `quality.alert.classify` | `odoo.quality.write` | Yes (rule-based) |
| **CAPA** | `capa.draft.create` | `odoo.capa.draft` | Yes (AI) |
| | `capa.draft.update` | `odoo.capa.draft` | Yes |
| | `capa.submit` | `odoo.capa.draft` | Yes |
| | `capa.approve` | `odoo.capa.approve` | **No** (human gate) |
| | `capa.verify` | `odoo.capa.verify` | Partial |
| **Knowledge** | `kb.search` | `odoo.kb.read` | Yes |
| | `kb.article.get` | `odoo.kb.read` | Yes |
| | `kb.article.draft` | `odoo.kb.write` | Yes (AI) |
| | `kb.article.publish` | `odoo.kb.sign` | **No** (Sign gate) |
| **Inventory** | `stock.receive` | `odoo.stock.write` | Yes |
| | `stock.move.create` | `odoo.stock.write` | Yes |
| | `stock.accounting` | `odoo.accounting.entry` | Profile-dependent |
| **KPI** | `kpi.fpy.get` | `odoo.kpi.read` | Yes |
| | `kpi.mttr.get` | `odoo.kpi.read` | Yes |
| | `kpi.dashboard` | `odoo.kpi.read` | Yes |

### 5.4 Інтеграція з новими FCP модулями (upstream v2.1)

#### 5.4.1 Rate Limiting (`fcp-sdk/ratelimit`)

**Путь:** `crates/fcp-sdk/src/ratelimit.rs`

```rust
use fcp_sdk::ratelimit::{RateLimitTracker, RateLimitError};

impl OdooConnector {
    fn rate_limits(&self) -> RateLimitDeclarations {
        RateLimitDeclarations {
            pools: vec![
                RateLimitPool {
                    id: "quality_read".into(),
                    config: RateLimitConfig {
                        requests_per_minute: 100,
                        burst: 10,
                    },
                    enforcement: RateLimitEnforcement::Hard,
                },
                RateLimitPool {
                    id: "quality_write".into(),
                    config: RateLimitConfig {
                        requests_per_minute: 30,
                        burst: 5,
                    },
                    enforcement: RateLimitEnforcement::Hard,
                },
            ],
        }
    }

    async fn invoke(&self, req: InvokeRequest) -> FcpResult<InvokeResponse> {
        // Rate limit check before Odoo API call
        let pool_id = self.get_pool_for_operation(&req.operation);
        self.rate_tracker.try_consume(&pool_id)?;

        // Proceed with Odoo call
        self.client.call(...).await
    }
}
```

#### 5.4.2 Lifecycle Management (`fcp-core/lifecycle`)

**Путь:** `crates/fcp-core/src/lifecycle.rs`

```rust
use fcp_core::lifecycle::{LifecycleState, LifecycleRecord, CanaryPolicy};

// Connector lifecycle states:
// Pending → Installing → Canary → Production
//                          ↓
//                     RolledBack

// Canary policy для Odoo connector
let canary_policy = CanaryPolicy {
    traffic_percentage: 10,        // 10% traffic initially
    duration_secs: 3600,           // 1 hour canary period
    success_threshold: 0.99,       // 99% success rate required
    auto_promote: true,            // Auto-promote if healthy
};
```

#### 5.4.3 Runtime Supervision (`fcp-sdk/runtime`)

**Путь:** `crates/fcp-sdk/src/runtime.rs`

```rust
use fcp_sdk::runtime::{SupervisorConfig, HealthTracker};

let supervisor_config = SupervisorConfig {
    base_backoff_ms: 1000,           // 1s initial backoff
    max_backoff_ms: 60000,           // 60s max backoff
    jitter_enabled: true,
    max_consecutive_failures: 5,
    cooldown_after_failure_ms: 300000, // 5min cooldown
    heartbeat_interval_ms: 30000,      // 30s heartbeat
};

// Health tracking for Odoo connection
let health_tracker = HealthTracker::new();
health_tracker.record_success();  // After successful API call
health_tracker.record_failure();  // After failed API call
```

#### 5.4.4 Fork Detection (`fcp-core/connector_state`)

**Путь:** `crates/fcp-core/src/connector_state.rs`

**Use case:** Multi-site Odoo deployments з синхронізацією Quality Alerts.

```rust
use fcp_core::connector_state::{ConnectorStateModel, CrdtType};

// For multi-site Odoo sync
let state_model = ConnectorStateModel::Crdt {
    crdt_type: CrdtType::LwwMap,  // Last-write-wins for alert state
};

// Fork detection pauses connector until resolved
// Higher lease_seq wins deterministically
```

---

## 6. Сценарії використання

### 6.1 Сценарій: AI генерує CAPA документ

**Потік:**
```
1. Quality Alert виявлено (auto або manual)
2. AI читає alert + контекст (odoo.quality.read)
3. AI аналізує root cause
4. AI створює draft CAPA (odoo.capa.draft)
5. Human reviewer затверджує (gate: capa.approve)
6. CAPA виконується, метрики збираються
7. Human верифікує ефективність (gate: capa.verify)
```

**FCP Request:**
```json
{
  "zone": "z:work",
  "connector": "odoo",
  "operation": "capa.draft.create",
  "policy_profile": "TOV_general",
  "params": {
    "alert_id": 12345,
    "root_cause_analysis": "...",
    "corrective_actions": ["..."],
    "preventive_actions": ["..."]
  }
}
```

### 6.2 Сценарій: Phase Gate Review (F1 → F2)

**Потік:**
```
1. Система збирає метрики (auto)
   - FPY ≥ 98%? ✓
   - 5 критичних КТЯ активні? ✓
   - SOP підписані? ✓
2. Створюється Phase Gate Review request
3. ZoneCheckpoint фіксує стан
4. Quorum підписує (human gate)
5. Перехід до F2 або повернення на доопрацювання
```

**ZoneCheckpoint:**
```json
{
  "checkpoint": {
    "zone": "z:work",
    "sequence": 142,
    "type": "phase_gate",
    "phase_transition": {
      "from": "F1_foundation",
      "to": "F2_deployment"
    },
    "metrics": {
      "fpy": 98.3,
      "critical_qcp_active": 5,
      "sop_signed": true
    },
    "quorum": {
      "required": 3,
      "signatures": ["qa_manager", "ops_lead", "compliance"]
    }
  }
}
```

### 6.3 Сценарій: Автоматизоване приймання (ФОП)

**Потік для ФОП (максимальна автоматизація):**
```
1. Товар прибуває
2. QCP checks виконуються (IoT sensors або manual input)
3. Всі checks PASS → auto stock.receive
4. Auto inventory update
5. Auto income record (Книга доходів)
6. Done - 0 human gates
```

**Потік для ТОВ (з gates):**
```
1. Товар прибуває
2. QCP checks виконуються
3. [GATE] Document verification (бухгалтер)
4. Checks PASS → stock.receive
5. [GATE] Quality sign-off (QA)
6. Inventory update
7. [GATE] Accounting entry (головбух)
8. Done - 3 human gates
```

---

## 7. Проблеми, які вирішує інтеграція

### 7.1 AI Safety через Capabilities

**Без FCP:** Python middleware на кожен endpoint

**З FCP:** Policy Profile визначає capabilities автоматично:
```
Enterprise: TOV_general
Zone: z:work
→ Auto-granted: odoo.quality.*, odoo.capa.draft, odoo.kb.read
→ Requires gate: odoo.accounting.*, odoo.kb.sign, odoo.capa.approve
```

### 7.2 Flexibility через Policy Profiles

Той самий код, різна поведінка:
- ФОП: мінімум gates, максимум automation
- ТОВ: баланс automation + compliance
- ПАТ: максимум gates, audit trail

### 7.3 Ідемпотентність через OperationReceipt

Вбудована на рівні протоколу - не потрібна окрема реалізація.

### 7.4 Audit Trail через ZoneCheckpoint

Phase Gates автоматично створюють immutable checkpoints з quorum signatures.

---

## 8. Технічні вимоги

### 8.1 Odoo v19 API Requirements (ФАКТИ)

**Офіційно підтримувані API:**

| API | Статус | Endpoint | Рекомендація |
|-----|--------|----------|--------------|
| **JSON-2 API** | Новий, рекомендований | `/json/2/<model>/<method>` | **ВИКОРИСТОВУВАТИ** |
| XML-RPC | DEPRECATED | `/xmlrpc`, `/xmlrpc/2` | НЕ використовувати |
| JSON-RPC | DEPRECATED | `/jsonrpc` | НЕ використовувати |

**ВАЖЛИВО:** XML-RPC та JSON-RPC будуть **ВИДАЛЕНІ в Odoo 20** (осінь 2026).

**GraphQL:** Офіційного GraphQL API в Odoo v19 **НЕ ІСНУЄ**. Модуль `fcp-graphql` не застосовний для Odoo connector.

**Автентифікація:**
- API Keys через `Authorization: bearer {API_KEY}` HTTP заголовок
- Ключі генеруються: Preferences > Account Security > New API Key
- OAuth2 підтримується для Google, Azure
- Заголовок `X-Odoo-Database` потрібен для multi-database серверів

**Обмеження:** Зовнішній API доступний тільки на **Custom pricing plans** Odoo.

**Динамічна документація:** Endpoint `/doc` генерує документацію всіх доступних моделей та методів.

### 8.2 FCP Requirements

**Базові:**
- Tailscale mesh membership
- Rust stable toolchain (2024 edition)
- Policy Profile configuration

**Нові модулі з upstream (v2.1):**

| Модуль | Призначення | Застосування для Odoo |
|--------|-------------|----------------------|
| `fcp-sdk/ratelimit` | Rate limiting pools | Захист Odoo API від перевантаження |
| `fcp-sdk/runtime` | Supervisor, health tracking | Управління станом connector |
| `fcp-core/lifecycle` | State machine (Canary→Production) | Безпечний rollout |
| `fcp-core/connector_state` | Fork detection, CRDT | Multi-site Odoo sync |

### 8.3 Enterprise-specific

| Enterprise Type | Additional Requirements |
|-----------------|------------------------|
| ФОП | Книга доходів API |
| ТОВ | Бухгалтерський облік API, ЕЦП |
| ПАТ | Audit API, Board approval workflow |

---

## 9. Оцінка складності

| Компонент | Складність | Час |
|-----------|------------|-----|
| Basic connector | Низька | 2-3 дні |
| Policy Profiles system | Середня | 3-4 дні |
| Quality operations | Середня | 3-5 днів |
| CAPA operations | Середня | 3-5 днів |
| Process decomposition engine | Висока | 5-7 днів |
| Gate system | Середня | 3-4 дні |
| KB/SOP operations | Низька | 2-3 дні |
| KPI operations | Середня | 3-4 дні |
| Integration tests | Середня | 3-5 днів |
| **Всього** | | **~4-5 тижнів** |

---

## 10. Питання для подальшого дослідження

### 10.1 Архітектура та декомпозиція

1. **Як визначати межі між Operations в процесі?**
   - Atomic transaction boundary?
   - Single responsibility?
   - Reusability across processes?

2. **Як моделювати conditional gates?**
   - Gate required тільки якщо amount > threshold?
   - Dynamic gate assignment based on risk?

3. **Як версіонувати Process Decomposition patterns?**
   - SOP-like versioning?
   - Migration між версіями?

### 10.2 Policy Profiles

4. **Як обробляти hybrid enterprises?**
   - ФОП з найманими працівниками
   - ТОВ на спрощеній системі

5. **Як кастомізувати profiles під специфіку галузі?**
   - Харчова промисловість (HACCP)
   - Фармацевтика (GMP)
   - IT послуги

6. **Як мігрувати між profiles?**
   - ФОП → ТОВ при зростанні
   - Історичні дані, audit trail

### 10.3 Skills та автоматизація

7. **Які Operations найкраще підходять для повної автоматизації?**
   - IoT sensor readings
   - Document validation (OCR + rules)
   - KPI calculations

8. **Як визначити "точку неповернення" для автоматизації?**
   - Коли Operation НЕ може бути Skill?
   - Legal requirements
   - Risk threshold

9. **Як Odoo v19 AI Agents інтегруються з FCP Skills?**
   - Odoo AI Agent = FCP Skill?
   - Orchestration layer?

### 10.4 Compliance та аудит

10. **Як забезпечити audit trail при зміні Policy Profile?**

11. **Як обробляти regulatory changes?**
    - Нові вимоги до звітності
    - Зміни в податковому законодавстві

12. **Як документувати automation decisions для аудиторів?**

---

## 11. Посилання та ресурси

### FCP Documentation (flywheel_connectors)
- `crates/fcp-core/src/connector.rs` — FcpConnector trait definition
- `crates/fcp-core/src/lifecycle.rs` — Lifecycle state machine
- `crates/fcp-core/src/connector_state.rs` — State management, fork detection
- `crates/fcp-sdk/src/ratelimit.rs` — Rate limiting
- `crates/fcp-sdk/src/runtime.rs` — Supervisor, health tracking
- `crates/fcp-manifest/src/lib.rs` — Manifest structure (99KB)

### Existing Connectors (референс)
- `connectors/anthropic/` — **Головний референс** (bidirectional, повна реалізація)
- `connectors/discord/` — Bidirectional connector
- `connectors/telegram/` — Operational connector
- `connectors/twitter/` — Bidirectional connector
- `connectors/openai/` — API connector

### Odoo v19 Official Documentation
- [External JSON-2 API](https://www.odoo.com/documentation/19.0/developer/reference/external_api.html) — **Рекомендований API**
- [External RPC API](https://www.odoo.com/documentation/19.0/developer/reference/external_rpc_api.html) — DEPRECATED
- [Quality Module](https://www.odoo.com/documentation/19.0/applications/inventory_and_mrp/quality.html)
- [ORM Changelog](https://www.odoo.com/documentation/19.0/developer/reference/backend/orm/changelog.html)

### Важливі факти
- **GraphQL:** Офіційно НЕ підтримується в Odoo v19
- **XML-RPC/JSON-RPC:** Будуть видалені в Odoo 20 (осінь 2026)
- **JSON-2 API:** Єдиний рекомендований спосіб інтеграції

---

## 12. Change Log

| Дата | Версія | Зміни |
|------|--------|-------|
| 2026-01-27 | 1.0.0 | Початкове дослідження |
| 2026-01-27 | 2.0.0 | Process Decomposition, Policy Profiles, Enterprise Types |
| 2026-01-28 | 2.1.0 | Інтеграція upstream модулів, факти про Odoo API, архітектура на основі існуючих connectors |

---

*Документ оновлено: 2026-01-28*
*Версія: 2.1.0*
*Ключові зміни: Odoo JSON-2 API (факт), інтеграція fcp-sdk/ratelimit, fcp-core/lifecycle, connector pattern з anthropic референсу*
