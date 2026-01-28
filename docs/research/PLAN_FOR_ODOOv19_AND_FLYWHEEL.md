# PLAN: Odoo v19 + Flywheel Connectors Integration

**Версія:** 2.1.0
**Дата оновлення:** 2026-01-28
**Статус:** Planning Phase

---

## Executive Summary

Цей документ описує план інтеграції Odoo v19 з FCP (Flywheel Connector Protocol) через створення `fcp-odoo` connector.

**Ключові інсайти v2.0:**
- Odoo v19 Quality API = **Enterprise Process Quality Framework** (не тільки виробництво)
- **Process Decomposition:** Operations + Gates + Decisions
- **Policy Profiles:** Автоматизація залежить від типу підприємства (ФОП/ТОВ/ПАТ)
- **Operations як Skills:** Атомарні, автоматизовані дії

**Мета:** Забезпечити безпечну, policy-aware взаємодію AI-асистентів з Odoo v19.

---

## 1. Фази проекту

### Phase 0: Research & Discovery ✅ ЗАВЕРШЕНО
**Тривалість:** 1-2 тижні
**Статус:** Завершено (v2.0)

| Завдання | Статус |
|----------|--------|
| Вивчити FCP архітектуру | ✅ |
| Вивчити Odoo v19 Quality API | ✅ |
| Розробити Process Decomposition model | ✅ NEW |
| Визначити Policy Profiles | ✅ NEW |
| Визначити capability mapping | ✅ |
| Ідентифікувати ризики | ✅ |

**Deliverables:**
- [x] `ODOO_V19_FCP_INTEGRATION.md` v2.0
- [x] `AGENTS_ODOO_FCP.md` v2.0
- [x] `PLAN_FOR_ODOOv19_AND_FLYWHEEL.md` v2.0

---

### Phase 1: Foundation + Policy Profiles
**Тривалість:** 2-3 тижні
**Статус:** Planned

#### 1.1 Project Scaffold

| Завдання | Пріоритет | Оцінка |
|----------|-----------|--------|
| Створити `connectors/odoo/` structure | High | 1 день |
| Налаштувати Cargo.toml | High | 0.5 дня |
| Імплементувати базовий Connector trait | High | 2 дні |
| Створити config types з enterprise type | High | 1 день |

#### 1.2 Policy Profiles System (NEW)

| Завдання | Пріоритет | Оцінка |
|----------|-----------|--------|
| Створити PolicyProfile trait | High | 1 день |
| Імплементувати FopSimplified profile | High | 1 день |
| Імплементувати TovGeneral profile | High | 1 день |
| Імплементувати PatPublic profile | Medium | 1 день |
| Написати profile tests | High | 1 день |

**Acceptance Criteria:**
- [ ] `cargo build` проходить
- [ ] Connector приймає enterprise type в config
- [ ] Gates визначаються Policy Profile
- [ ] Тести для всіх трьох profiles

#### 1.3 Odoo Authentication (JSON-2 API)

**ФАКТ:** Odoo v19 рекомендує JSON-2 API. XML-RPC/JSON-RPC deprecated (видалення в Odoo 20).

| Завдання | Пріоритет | Оцінка |
|----------|-----------|--------|
| Імплементувати Bearer token auth | High | 1 день |
| Підтримка `X-Odoo-Database` header | High | 0.5 дня |
| Написати auth tests | High | 1 день |

#### 1.4 JSON-2 API Client

**Endpoint:** `POST /json/2/{model}/{method}`

| Завдання | Пріоритет | Оцінка |
|----------|-----------|--------|
| Створити OdooClient struct (референс: anthropic/client.rs) | High | 1 день |
| Імплементувати JSON-2 API calls | High | 2 дні |
| Інтегрувати `fcp-sdk/ratelimit` | High | 1 день |
| Додати retry logic з backoff | Medium | 1 день |

#### 1.5 Rate Limiting Integration (NEW)

**Модуль:** `fcp-sdk/ratelimit`

| Завдання | Пріоритет | Оцінка |
|----------|-----------|--------|
| Визначити rate limit pools | High | 0.5 дня |
| Інтегрувати RateLimitTracker | High | 1 день |
| Тести rate limiting | Medium | 0.5 дня |

---

### Phase 2: Process Decomposition Engine (NEW)
**Тривалість:** 2 тижні
**Статус:** Planned

#### 2.1 Core Decomposition Types

| Завдання | Пріоритет | Оцінка |
|----------|-----------|--------|
| Створити Operation type | High | 1 день |
| Створити Gate type | High | 1 день |
| Створити Decision type | High | 1 день |
| Створити Process orchestrator | High | 2 дні |

#### 2.2 Gate System

| Завдання | Пріоритет | Оцінка |
|----------|-----------|--------|
| Gate registry | High | 1 день |
| Gate state machine | High | 2 дні |
| Human approval workflow | High | 2 дні |
| Gate timeout handling | Medium | 1 день |

**Acceptance Criteria:**
- [ ] Operations can be marked as Skills (auto)
- [ ] Gates stop execution until approved
- [ ] Different profiles have different gates
- [ ] Gate state persists across requests

---

### Phase 3: Quality Operations
**Тривалість:** 2 тижні
**Статус:** Planned

#### 3.1 Quality Read Operations

| Operation | Capability | Skill? | Оцінка |
|-----------|------------|--------|--------|
| `quality.qcp.list` | `odoo.quality.read` | Yes | 1 день |
| `quality.qcp.get` | `odoo.quality.read` | Yes | 0.5 дня |
| `quality.check.list` | `odoo.quality.read` | Yes | 1 день |
| `quality.alert.list` | `odoo.quality.read` | Yes | 1 день |
| `quality.alert.get` | `odoo.quality.read` | Yes | 0.5 дня |

#### 3.2 Quality Write Operations (Policy-Aware)

| Operation | Capability | ФОП | ТОВ | ПАТ |
|-----------|------------|-----|-----|-----|
| `quality.check.create` | `odoo.quality.write` | Auto | Auto | Gate |
| `quality.alert.create` | `odoo.quality.write` | Auto | Auto | Gate |
| `quality.alert.classify` | `odoo.quality.write` | Auto | Auto | Gate |

**Acceptance Criteria:**
- [ ] All read operations work as Skills
- [ ] Write operations respect Policy Profile
- [ ] ПАТ profile requires QA review gate

---

### Phase 4: CAPA Operations
**Тривалість:** 2 тижні
**Статус:** Planned

#### 4.1 CAPA Lifecycle (Decomposed)

```yaml
process: capa_lifecycle
operations:
  - draft.create      # Skill (AI)
  - draft.update      # Skill
  - submit            # Skill
  - approve           # Gate (always human)
  - execute           # Mixed
  - verify            # Gate (human)
  - close             # Gate (human)
```

| Operation | ФОП Gates | ТОВ Gates | ПАТ Gates |
|-----------|-----------|-----------|-----------|
| Create draft | 0 | 0 | 1 (QA review) |
| Submit | 0 | 0 | 1 (manager) |
| Approve | 1 | 1 | 2 (QA + director) |
| Verify | 1 | 1 | 2 (QA + auditor) |
| Close | 0 | 1 | 2 (manager + compliance) |

---

### Phase 5: Knowledge Base & KPI
**Тривалість:** 1-2 тижні
**Статус:** Planned

#### 5.1 SOP as Skills Repository (NEW)

| Завдання | Пріоритет | Оцінка |
|----------|-----------|--------|
| SOP to Operations converter | High | 2 дні |
| SOP versioning integration | Medium | 1 день |
| Sign workflow integration | Medium | 2 дні |

#### 5.2 KPI Operations

| Operation | Capability | Skill? |
|-----------|------------|--------|
| `kpi.fpy.get` | `odoo.kpi.read` | Yes |
| `kpi.mttr.get` | `odoo.kpi.read` | Yes |
| `kpi.automation_ratio` | `odoo.kpi.read` | Yes (NEW) |

---

### Phase 6: Advanced Features & Upstream Integration
**Тривалість:** 2-3 тижні
**Статус:** Future

#### 6.1 ZoneCheckpoint for Phase Gates

| Завдання | Пріоритет | Оцінка |
|----------|-----------|--------|
| Phase Gate → ZoneCheckpoint mapping | High | 3 дні |
| Quorum signature per enterprise type | High | 3 дні |
| Checkpoint verification | High | 2 дні |

#### 6.2 Enterprise Type Migration

| Завдання | Пріоритет | Оцінка |
|----------|-----------|--------|
| ФОП → ТОВ migration path | Medium | 2 дні |
| Audit trail preservation | High | 2 дні |
| Gate backfill strategy | Medium | 1 день |

#### 6.3 Lifecycle Management Integration (NEW)

**Модуль:** `fcp-core/lifecycle`

| Завдання | Пріоритет | Оцінка |
|----------|-----------|--------|
| Інтегрувати LifecycleState machine | Medium | 2 дні |
| Canary deployment для Odoo connector | Medium | 2 дні |
| Auto-rollback on health failure | Medium | 1 день |

#### 6.4 Multi-site Odoo Sync (NEW)

**Модуль:** `fcp-core/connector_state` (fork detection)

| Завдання | Пріоритет | Оцінка |
|----------|-----------|--------|
| CRDT state model для Quality Alerts | Low | 3 дні |
| Fork detection handling | Low | 2 дні |
| Resolution strategy | Low | 2 дні |

---

## 2. Milestones

### Milestone 1: MVP with Policy Profiles
**Target:** +5-6 тижнів
**Scope:**
- Basic connector with Policy Profiles
- Quality read/write operations
- Gate system working

**Success Criteria:**
- [ ] Same operation behaves differently for ФОП vs ТОВ
- [ ] Gates properly pause execution
- [ ] Tests cover all three profiles

### Milestone 2: Full CAPA with Decomposition
**Target:** +9-10 тижнів
**Scope:**
- Complete CAPA lifecycle
- Process decomposition engine
- SOP integration

**Success Criteria:**
- [ ] AI can create CAPA draft (Skill)
- [ ] Approval gates work per profile
- [ ] SOP defines process steps

### Milestone 3: Production Ready
**Target:** +12-14 тижнів
**Scope:**
- ZoneCheckpoints for phase gates
- Enterprise migration support
- Full documentation

**Success Criteria:**
- [ ] End-to-end PDCA with proper gates
- [ ] Audit trail complete
- [ ] Migration ФОП→ТОВ tested

---

## 3. Architecture Decisions

### 3.1 Decisions Made

| Decision | Choice | Rationale |
|----------|--------|-----------|
| **Odoo API** | JSON-2 API | Офіційно рекомендований, RPC deprecated |
| **GraphQL** | НЕ використовувати | Офіційно не підтримується Odoo v19 |
| Process model | Decomposition | Flexibility per enterprise type |
| Automation control | Policy Profiles | Compliance requirements vary |
| Gate persistence | Database | State survives restarts |
| SOP integration | As Skills source | Single source of truth |
| **Rate limiting** | fcp-sdk/ratelimit | Upstream модуль, готовий до використання |
| **Lifecycle** | fcp-core/lifecycle | Canary deployments, health tracking |
| **Connector pattern** | anthropic референс | JSON-RPC protocol loop, BaseConnector |

### 3.2 Closed Questions (v2.1)

| Question | Decision | Rationale |
|----------|----------|-----------|
| Який API використовувати? | JSON-2 API | XML-RPC/JSON-RPC deprecated, видалення в Odoo 20 |
| Чи використовувати fcp-graphql? | НІ | Odoo не має GraphQL API |
| Connector base | BaseConnector | З fcp-core, референс anthropic connector |

### 3.3 Open Questions

| Question | Options | Decision By |
|----------|---------|-------------|
| Gate timeout default | 24h / 48h / configurable | Phase 2 |
| Hybrid enterprise handling | Strict / Flexible | Phase 1 |
| Profile switching runtime | Allowed / Restart required | Phase 1 |
| Multi-site sync strategy | CRDT / Lease-based | Phase 6 |

---

## 4. Automation Matrix by Enterprise Type

### Таблиця процесів

| Процес | ФОП | ТОВ | ПАТ |
|--------|-----|-----|-----|
| **Quality Check** | 95% | 80% | 60% |
| **Quality Alert** | 90% | 75% | 55% |
| **CAPA Lifecycle** | 75% | 60% | 45% |
| **Inventory Receiving** | 90% | 65% | 50% |
| **Payment Processing** | 100% | 55% | 40% |
| **SOP Publication** | 60% | 50% | 40% |

### Таблиця gates

| Gate Type | ФОП | ТОВ | ПАТ |
|-----------|-----|-----|-----|
| QA Review | - | Optional | Required |
| Accounting Entry | - | Required | Required |
| Tax Classification | - | Required | Required |
| Manager Approval | - | Some | Most |
| Director Approval | - | - | Required |
| Auditor Sign-off | - | - | Required |
| Board Notification | - | - | Some |

---

## 5. Testing Strategy

### 5.1 Profile-Specific Tests

```
tests/
├── policy_profiles/
│   ├── fop_simplified/
│   │   ├── quality_test.rs      # No gates
│   │   ├── capa_test.rs         # Minimal gates
│   │   └── payment_test.rs      # Full auto
│   ├── tov_general/
│   │   ├── quality_test.rs
│   │   ├── capa_test.rs         # Standard gates
│   │   └── accounting_test.rs   # Gate required
│   └── pat_public/
│       ├── quality_test.rs      # Extra gates
│       ├── capa_test.rs         # Many gates
│       └── audit_test.rs        # Audit gates
└── cross_profile/
    ├── migration_test.rs        # ФОП → ТОВ
    └── consistency_test.rs      # Same data, different gates
```

### 5.2 Test Coverage Goals

| Component | Target |
|-----------|--------|
| Policy Profiles | 95% |
| Gate System | 90% |
| Operations | 85% |
| Integration | 80% |

---

## 6. Risk Management

### 6.1 Updated Risks

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| Profile complexity | Medium | Medium | Start with 3 core profiles |
| Gate state corruption | Low | High | Transaction-based state |
| Enterprise type mismatch | Medium | Medium | Validation at startup |
| Regulatory changes | Medium | High | Profile versioning |

### 6.2 Contingency

**If profile system too complex:**
- Start with ФОП only (simplest)
- Add ТОВ in phase 2
- ПАТ in phase 3

**If gate system performance issues:**
- In-memory cache for active gates
- Async gate state updates

---

## 7. Progress Tracker

```
Phase 0: Research     [████████████████████] 100% ✅
Phase 1: Foundation   [                    ]   0%
Phase 2: Decomposition[                    ]   0%
Phase 3: Quality      [                    ]   0%
Phase 4: CAPA         [                    ]   0%
Phase 5: KB & KPI     [                    ]   0%
Phase 6: Advanced     [                    ]   0%
```

---

## 8. Change Log

| Date | Version | Change |
|------|---------|--------|
| 2026-01-27 | 1.0.0 | Initial plan |
| 2026-01-27 | 2.0.0 | Added Process Decomposition, Policy Profiles, Enterprise Types |
| 2026-01-28 | 2.1.0 | JSON-2 API (факт), upstream модулі integration, architecture decisions |

---

## 9. Next Actions

### Immediate (цей тиждень):
1. [ ] Review updated plan
2. [ ] Decide on hybrid enterprise handling
3. [ ] Create `connectors/odoo/` scaffold (референс: `connectors/anthropic/`)

### Short-term (наступні 2 тижні):
1. [ ] Implement OdooClient з JSON-2 API
2. [ ] Integrate `fcp-sdk/ratelimit`
3. [ ] Implement Policy Profile system
4. [ ] First working operation with profile-aware behavior

---

## 10. Flywheel Connectors Ecosystem (v2.1)

### Доступні crates (25 штук)

| Crate | Використання для Odoo |
|-------|----------------------|
| **fcp-core** | FcpConnector trait, BaseConnector, lifecycle, connector_state |
| **fcp-sdk** | ratelimit, runtime supervision, prelude |
| **fcp-manifest** | Manifest parsing, validation |
| **fcp-crypto** | Capability verification |
| **fcp-cbor** | CBOR encoding |
| **fcp-testkit** | Testing utilities |

### Референс connectors

| Connector | Корисність |
|-----------|-----------|
| **anthropic** | Головний референс: повна реалізація, JSON-RPC loop, client pattern |
| discord | Bidirectional events |
| telegram | Operational |

---

*Plan updated: 2026-01-28*
*Version: 2.1.0*
*Key changes: JSON-2 API decision, upstream modules integration, flywheel ecosystem overview*
