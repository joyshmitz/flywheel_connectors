# Дослідження інтеграції Odoo v19 + FCP (Flywheel Connector Protocol)

**Версія:** 1.0.0
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

### 1.2 Odoo v19 PDCA Quality Management System

**Призначення:** Система управління якістю на основі циклу Plan-Do-Check-Act.

**Основні сутності:**

| Сутність | Опис |
|----------|------|
| Quality Control Point (QCP) | Точка контролю якості |
| Quality Check | Перевірка якості |
| Quality Alert | Сигнал про проблему якості |
| CAPA | Corrective and Preventive Action |

**Ключові метрики:**
- **FPY** (First Pass Yield) - Відсоток продукції, що пройшла з першого разу
- **MTTR** (Mean Time To Repair) - Середній час усунення дефекту
- **CAPA Efficacy** - Ефективність коригувальних дій
- **SPC** (Statistical Process Control) - Статистичний контроль процесів

---

## 2. Проблеми, які вирішує інтеграція

### 2.1 Проблема: AI безпека (AI Safety)

**Без FCP:**
```python
# Odoo v19 - Python middleware
class AIMiddleware:
    def process(self, request):
        if request.is_ai_generated:
            if request.touches_financial_records:
                raise SecurityError("AI cannot modify financial data")
```

**З FCP:**
```
Zone: z:work (рівень 60)
Capability: odoo.quality.* (дозволено)
Capability: odoo.accounting.* (НЕ видано) ← автоматично заблоковано
```

**Перевага:** Безпека на рівні протоколу, не потрібен Python middleware.

### 2.2 Проблема: Ідемпотентність

**Без FCP:**
```python
# Потрібна власна логіка
def create_capa_safe(data, idempotency_key):
    existing = CAPA.search([('external_id', '=', idempotency_key)])
    if existing:
        return existing
    return CAPA.create(data)
```

**З FCP:**
```json
{
  "operation": "odoo.capa.create",
  "receipt": {
    "request_hash": "sha256:abc123...",
    "idempotency_key": "capa-2026-001"
  }
}
```

**Перевага:** Вбудована ідемпотентність через OperationReceipt.

### 2.3 Проблема: AI Governance (Policy-as-Code)

**Без FCP:**
```python
# Кожен endpoint потребує перевірки
@api.route('/api/capa')
def create_capa():
    policy = PolicyEngine.check('capa.create', request.user)
    if not policy.allowed:
        return 403
```

**З FCP:**
```toml
# Одноразове налаштування capabilities
[capabilities]
required = ["odoo.capa.draft"]
optional = ["odoo.capa.approve"]  # потребує escalation
```

**Перевага:** Декларативні дозволи замість імперативного коду.

### 2.4 Проблема: Phase Gates (Аудит переходів)

**Без FCP:**
```python
# Власна реалізація audit trail
class PhaseTransition(models.Model):
    from_phase = fields.Selection(...)
    to_phase = fields.Selection(...)
    approved_by = fields.Many2one(...)
    timestamp = fields.Datetime(...)
```

**З FCP:**
```
ZoneCheckpoint {
  sequence: 42,
  hash: "sha256:...",
  previous_hash: "sha256:...",
  quorum_signatures: [...],
  operations: [...]
}
```

**Перевага:** Незмінний, hash-linked audit trail з кворумними підписами.

---

## 3. Архітектура fcp-odoo Connector

### 3.1 Структура модуля

```
fcp-connectors/
└── connectors/
    └── odoo/
        ├── Cargo.toml
        ├── src/
        │   ├── lib.rs
        │   ├── connector.rs      # Головний connector
        │   ├── operations/
        │   │   ├── mod.rs
        │   │   ├── quality.rs    # QCP, Quality Check, Alert
        │   │   ├── capa.rs       # CAPA operations
        │   │   ├── knowledge.rs  # KB operations
        │   │   └── kpi.rs        # Metrics/KPI
        │   ├── auth.rs           # Odoo authentication
        │   └── types.rs          # Odoo-specific types
        └── tests/
            ├── integration.rs
            └── fixtures/
```

### 3.2 Connector Configuration

**Файл:** `~/.fcp/connectors/odoo.toml`

```toml
# Odoo v19 Connector Configuration
# Connector ID: odoo:erp:v19

[connector]
name = "odoo"
version = "0.1.0"
zone = "z:work"

archetypes = ["Operational", "Bidirectional"]

[credentials]
# Odoo server URL
url = "https://odoo.example.com"

# Database name
database = "production"

# API key or user credentials
api_key = "${FCP_ODOO_API_KEY}"
# OR
# username = "admin"
# password = "${FCP_ODOO_PASSWORD}"

[options]
# Request timeout in seconds
timeout_secs = 60

# Retry settings
max_retries = 3
retry_delay_secs = 5

# Rate limiting
requests_per_minute = 60

[capabilities]
# Quality domain
required = [
    "odoo.quality.read",      # Read QCPs, Checks, Alerts
]
optional = [
    "odoo.quality.write",     # Create/update quality records
    "odoo.capa.draft",        # Draft CAPA documents
    "odoo.capa.approve",      # Approve CAPA (requires z:private)
    "odoo.kb.read",           # Read Knowledge Base
    "odoo.kb.write",          # Write to Knowledge Base
    "odoo.kpi.read",          # Read metrics/KPIs
    "odoo.accounting.read",   # Financial data (restricted)
]
```

### 3.3 Operations Map

| Domain | Operation | Capability | Description |
|--------|-----------|------------|-------------|
| **Quality** | `quality.qcp.list` | `odoo.quality.read` | Список QCP |
| | `quality.qcp.get` | `odoo.quality.read` | Деталі QCP |
| | `quality.check.create` | `odoo.quality.write` | Створити перевірку |
| | `quality.alert.create` | `odoo.quality.write` | Створити alert |
| **CAPA** | `capa.list` | `odoo.capa.draft` | Список CAPA |
| | `capa.create_draft` | `odoo.capa.draft` | Чернетка CAPA |
| | `capa.submit` | `odoo.capa.draft` | Подати на розгляд |
| | `capa.approve` | `odoo.capa.approve` | Затвердити CAPA |
| **Knowledge** | `kb.search` | `odoo.kb.read` | Пошук в KB |
| | `kb.article.get` | `odoo.kb.read` | Отримати статтю |
| | `kb.article.create` | `odoo.kb.write` | Створити статтю |
| **KPI** | `kpi.fpy.get` | `odoo.kpi.read` | First Pass Yield |
| | `kpi.mttr.get` | `odoo.kpi.read` | Mean Time To Repair |
| | `kpi.spc.chart` | `odoo.kpi.read` | SPC графіки |

---

## 4. Сценарії використання

### 4.1 Сценарій: AI генерує CAPA документ

**Потік:**
```
1. Quality Alert виявлено в Odoo
2. AI-асистент через FCP читає alert (odoo.quality.read)
3. AI аналізує root cause
4. AI створює draft CAPA (odoo.capa.draft)
5. Human reviewer затверджує (поза FCP або через z:private)
6. CAPA записується в Odoo
```

**FCP Request:**
```json
{
  "zone": "z:work",
  "connector": "odoo",
  "operation": "capa.create_draft",
  "params": {
    "alert_id": 12345,
    "root_cause_analysis": "...",
    "corrective_actions": ["..."],
    "preventive_actions": ["..."],
    "idempotency_key": "capa-alert-12345-v1"
  }
}
```

**FCP Response:**
```json
{
  "status": "success",
  "receipt": {
    "request_hash": "sha256:...",
    "connector": "odoo",
    "operation": "capa.create_draft",
    "timestamp": "2026-01-27T10:30:00Z"
  },
  "result": {
    "capa_id": 789,
    "state": "draft",
    "requires_approval": true
  }
}
```

### 4.2 Сценарій: Privabank webhook через FCP

**Потік:**
```
1. Privabank надсилає payment notification
2. FCP webhook connector приймає (z:public)
3. FCP валідує підпис Privabank
4. FCP forwards до Odoo connector (z:work)
5. Odoo створює payment record
6. FCP НЕ дозволяє modify account balance (немає capability)
```

**Конфігурація зон:**
```
z:public  → webhook.receive (Privabank notification)
    ↓ (capability grant)
z:work    → odoo.payment.create (запис платежу)
    ✗ (no capability)
z:work    → odoo.accounting.modify (ЗАБЛОКОВАНО)
```

### 4.3 Сценарій: Phase Gate Review з Checkpoint

**Потік:**
```
1. CAPA готова до переходу "Do → Check"
2. Створюється ZoneCheckpoint
3. Quorum (3 з 5) підписує checkpoint
4. Phase transition записується
5. Checkpoint hash стає immutable
```

**ZoneCheckpoint Structure:**
```json
{
  "checkpoint": {
    "zone": "z:work",
    "sequence": 142,
    "hash": "sha256:a1b2c3...",
    "previous_hash": "sha256:x9y8z7...",
    "timestamp": "2026-01-27T14:00:00Z",
    "quorum": {
      "required": 3,
      "signatures": [
        {"signer": "node-1", "sig": "ed25519:..."},
        {"signer": "node-2", "sig": "ed25519:..."},
        {"signer": "node-3", "sig": "ed25519:..."}
      ]
    },
    "operations": [
      {
        "type": "phase_transition",
        "capa_id": 789,
        "from": "do",
        "to": "check",
        "approved_by": ["user:alice", "user:bob", "user:carol"]
      }
    ]
  }
}
```

---

## 5. Порівняння: З FCP vs Без FCP

| Аспект | Без FCP | З FCP |
|--------|---------|-------|
| **AI Safety** | Python middleware на кожен endpoint | Криптографічні capabilities |
| **Ідемпотентність** | Власна реалізація | Вбудований OperationReceipt |
| **Audit Trail** | Власна таблиця логів | ZoneCheckpoint (immutable) |
| **Policy Enforcement** | Розсіяний по коду | Централізовані capabilities |
| **Phase Gates** | Кастомні state machines | Zone transitions + checkpoints |
| **Integration** | REST API + middleware | Unified connector interface |
| **Scalability** | Vertical (один сервер) | Horizontal (mesh network) |

---

## 6. Технічні вимоги до реалізації

### 6.1 Odoo API Requirements

- **XML-RPC** або **JSON-RPC** доступ
- API ключ або OAuth2 credentials
- Права доступу до quality models
- Доступ до Knowledge Base API

### 6.2 FCP Requirements

- Tailscale mesh membership
- Rust nightly toolchain
- RaptorQ codec support
- Zone key generation

### 6.3 Security Requirements

- TLS 1.3 для Odoo API
- Tailscale peer authentication
- Capability chains validation
- Audit log retention (30+ днів)

---

## 7. Оцінка складності реалізації

| Компонент | Складність | Час (орієнтовно) |
|-----------|------------|------------------|
| Basic connector scaffold | Низька | 2-3 дні |
| Odoo authentication | Середня | 2-3 дні |
| Quality operations | Середня | 3-5 днів |
| CAPA operations | Середня | 3-5 днів |
| KB integration | Низька | 2-3 дні |
| KPI operations | Середня | 3-4 дні |
| Phase gate checkpoints | Висока | 5-7 днів |
| Integration tests | Середня | 3-5 днів |
| **Всього** | | **~3-4 тижні** |

---

## 8. Ризики та обмеження

### 8.1 Технічні ризики

| Ризик | Ймовірність | Вплив | Мітигація |
|-------|-------------|-------|-----------|
| Odoo API зміни в v19 | Середня | Високий | Version detection, adapter pattern |
| Performance bottleneck | Низька | Середній | Async operations, batching |
| Tailscale availability | Низька | Високий | Fallback modes, graceful degradation |

### 8.2 Обмеження FCP (поточний стан)

- **Статус:** Draft (не production-ready)
- **API стабільність:** Може змінюватись
- **Документація:** В процесі
- **Тестування:** Потребує розширення

### 8.3 Обмеження Odoo v19

- Новий реліз, можливі breaking changes
- Quality module може мати undocumented behavior
- API rate limits можуть впливати на throughput

---

## 9. Наступні кроки

### 9.1 Короткострокові (1-2 тижні)

1. [ ] Створити базовий scaffold для fcp-odoo connector
2. [ ] Реалізувати Odoo authentication (API key)
3. [ ] Імплементувати `quality.qcp.list` operation
4. [ ] Написати unit tests

### 9.2 Середньострокові (3-4 тижні)

1. [ ] Повний набір Quality operations
2. [ ] CAPA draft/submit operations
3. [ ] Integration tests з mock Odoo server
4. [ ] Документація capabilities

### 9.3 Довгострокові (1-2 місяці)

1. [ ] Phase Gate checkpoints integration
2. [ ] Knowledge Base operations
3. [ ] KPI/metrics operations
4. [ ] Production hardening
5. [ ] Performance optimization

---

## 10. Питання для подальшого дослідження

### 10.1 Архітектурні питання

1. **Як найкраще мапити Odoo user roles на FCP capabilities?**
   - One-to-one mapping?
   - Role hierarchies?
   - Dynamic capability grants?

2. **Як обробляти Odoo workflows через FCP zones?**
   - Один zone на workflow state?
   - Capability escalation при переході?

3. **Як інтегрувати Odoo ir.attachment з RaptorQ symbols?**
   - Конвертація при upload/download?
   - Streaming для великих файлів?

4. **Чи потрібен окремий connector для Odoo v19 Quality vs інших модулів?**
   - Monolithic connector?
   - Micro-connectors (odoo-quality, odoo-accounting, etc.)?

### 10.2 Безпекові питання

5. **Як захистити Odoo credentials в FCP config?**
   - Environment variables?
   - Secrets manager integration?
   - HSM support?

6. **Як валідувати Odoo API responses для запобігання injection?**
   - Input sanitization?
   - Schema validation?

7. **Як обробляти capability revocation для active sessions?**
   - Immediate termination?
   - Graceful timeout?

### 10.3 Операційні питання

8. **Як моніторити fcp-odoo connector health?**
   - Prometheus metrics?
   - Health check endpoints?
   - Alerting rules?

9. **Як обробляти Odoo downtime?**
   - Queue operations?
   - Retry policies?
   - Circuit breaker?

10. **Як синхронізувати state між Odoo та FCP audit logs?**
    - Event sourcing?
    - Periodic reconciliation?

### 10.4 Бізнес питання

11. **Які Odoo модулі крім Quality потребують FCP integration?**
    - Inventory?
    - Manufacturing?
    - Accounting (read-only)?

12. **Як версіонувати fcp-odoo connector відносно Odoo releases?**
    - Semver alignment?
    - Compatibility matrix?

13. **Чи потрібна multi-tenancy підтримка (кілька Odoo instances)?**
    - Connector per instance?
    - Routing через config?

### 10.5 Тестування

14. **Як створити test fixtures для Odoo Quality module?**
    - Mock server?
    - Docker Odoo instance?
    - Record/replay?

15. **Як тестувати ZoneCheckpoint quorum без повної mesh?**
    - Simulated nodes?
    - Test mode flags?

---

## 11. Посилання та ресурси

### 11.1 FCP Documentation

- `/FCP_Specification_V2.md` - Авторитетна специфікація протоколу
- `/docs/RFC_Mesh_Native_Protocol_V2.md` - RFC mesh-native протоколу
- `/docs/fcp_model_connectors_rust.md` - Гайд розробника connectors
- `/AGENTS.md` - Гайдлайни для AI coding agents

### 11.2 Odoo v19 Documentation

- `/Users/sd/github/odoo19/odoov19/EXPLAIN.md` - Пояснення PDCA системи
- `/Users/sd/github/odoo19/odoov19/docs/PRD.md` - Product Requirements Document
- Odoo Quality Module: https://www.odoo.com/documentation/19.0/applications/inventory_and_mrp/quality.html

### 11.3 Existing FCP Connectors (для reference)

- `connectors/twitter/` - Twitter/X connector implementation
- `connectors/telegram/` - Telegram Bot API connector
- `connectors/anthropic/` - Anthropic Claude API connector
- `connectors/openai/` - OpenAI API connector

---

*Документ створено: 2026-01-27*
*Автор: Claude Code Assistant*
*Проект: flywheel_connectors / odoo v19 integration research*
