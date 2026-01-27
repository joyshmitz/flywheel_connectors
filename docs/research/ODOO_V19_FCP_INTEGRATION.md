# Дослідження інтеграції Odoo v19 + FCP (Flywheel Connector Protocol)

**Версія:** 2.0.0
**Дата:** 2026-01-27
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

### 5.1 Структура модуля

```
fcp-connectors/
└── connectors/
    └── odoo/
        ├── Cargo.toml
        ├── src/
        │   ├── lib.rs
        │   ├── connector.rs          # Головний connector
        │   ├── policy_profiles/      # NEW: Enterprise profiles
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
        │   ├── decomposition/        # NEW: Process decomposition
        │   │   ├── mod.rs
        │   │   ├── patterns.rs       # Reusable patterns
        │   │   └── gates.rs          # Gate definitions
        │   ├── auth.rs
        │   └── types.rs
        └── tests/
```

### 5.2 Connector Configuration з Policy Profile

**Файл:** `~/.fcp/connectors/odoo.toml`

```toml
# Odoo v19 Connector Configuration

[connector]
name = "odoo"
version = "0.2.0"
zone = "z:work"
archetypes = ["Operational", "Bidirectional"]

[enterprise]
# NEW: Enterprise type визначає policy profile
type = "TOV_general"  # FOP_simplified | TOV_general | PAT_public | custom
tax_system = "general"  # simplified | general

[credentials]
url = "https://odoo.example.com"
database = "production"
api_key = "${FCP_ODOO_API_KEY}"

[options]
timeout_secs = 60
max_retries = 3

# Capabilities автоматично визначаються policy profile
# Можна override для кастомізації:
[capabilities.override]
# odoo.custom.operation = true
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

### 8.1 Odoo API Requirements

- JSON-RPC або XML-RPC доступ
- API ключ або OAuth2
- Права доступу до quality, stock, knowledge models

### 8.2 FCP Requirements

- Tailscale mesh membership
- Rust nightly toolchain
- Policy Profile configuration

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

### FCP Documentation
- `/FCP_Specification_V2.md` - Специфікація протоколу
- `/docs/fcp_model_connectors_rust.md` - Гайд розробника
- `/AGENTS.md` - AI agent guidelines

### Odoo v19 Documentation
- `/Users/sd/projects/odoov19/EXPLAIN.md` - PDCA система
- `/Users/sd/projects/odoov19/docs/PRD.md` - PRD
- Odoo Quality: https://www.odoo.com/documentation/19.0/

### Existing Connectors
- `connectors/twitter/` - Bidirectional connector
- `connectors/telegram/` - Operational connector
- `connectors/anthropic/` - API connector

---

*Документ оновлено: 2026-01-27*
*Версія: 2.0.0*
*Ключові зміни: Process Decomposition model, Policy Profiles, Enterprise Types*
