# PLAN: Odoo v19 + Flywheel Connectors Integration

**Версія:** 1.0.0
**Дата створення:** 2026-01-27
**Статус:** Planning Phase

---

## Executive Summary

Цей документ описує план інтеграції Odoo v19 PDCA Quality Management System з FCP (Flywheel Connector Protocol) через створення спеціалізованого `fcp-odoo` connector.

**Мета:** Забезпечити безпечну, аудитовану взаємодію AI-асистентів з Odoo v19, зокрема з модулем управління якістю.

---

## 1. Фази проекту

### Phase 0: Research & Discovery (ПОТОЧНА)
**Тривалість:** 1-2 тижні
**Статус:** В процесі

| Завдання | Статус | Відповідальний |
|----------|--------|----------------|
| Вивчити FCP архітектуру | Завершено | - |
| Вивчити Odoo v19 Quality API | Завершено | - |
| Створити research документацію | Завершено | - |
| Визначити capability mapping | Завершено | - |
| Ідентифікувати ризики | Завершено | - |

**Deliverables:**
- [x] `ODOO_V19_FCP_INTEGRATION.md` - Research document
- [x] `AGENTS_ODOO_FCP.md` - AI agent guidelines
- [x] `PLAN_FOR_ODOOv19_AND_FLYWHEEL.md` - This document

---

### Phase 1: Foundation
**Тривалість:** 1-2 тижні
**Статус:** Planned

#### 1.1 Project Scaffold

| Завдання | Пріоритет | Оцінка |
|----------|-----------|--------|
| Створити `connectors/odoo/` structure | High | 1 день |
| Налаштувати Cargo.toml з dependencies | High | 0.5 дня |
| Імплементувати базовий Connector trait | High | 2 дні |
| Створити config types | Medium | 1 день |

**Acceptance Criteria:**
- [ ] `cargo build` проходить без помилок
- [ ] `cargo test` проходить (базові тести)
- [ ] Connector реєструється в FCP registry

#### 1.2 Odoo Authentication

| Завдання | Пріоритет | Оцінка |
|----------|-----------|--------|
| Імплементувати API key auth | High | 1 день |
| Імплементувати session auth (опціонально) | Low | 2 дні |
| Написати auth tests | High | 1 день |

**Acceptance Criteria:**
- [ ] Успішна автентифікація з тестовим Odoo
- [ ] Proper error handling для invalid credentials
- [ ] Credentials НЕ логуються

#### 1.3 HTTP Client Wrapper

| Завдання | Пріоритет | Оцінка |
|----------|-----------|--------|
| Створити Odoo client struct | High | 1 день |
| Імплементувати JSON-RPC calls | High | 2 дні |
| Додати retry logic | Medium | 1 день |
| Додати rate limiting | Medium | 1 день |

**Acceptance Criteria:**
- [ ] Successful API calls to Odoo
- [ ] Automatic retries on transient failures
- [ ] Rate limiting prevents 429 errors

---

### Phase 2: Quality Operations
**Тривалість:** 2-3 тижні
**Статус:** Planned

#### 2.1 Quality Read Operations

| Operation | Capability | Пріоритет | Оцінка |
|-----------|------------|-----------|--------|
| `quality.qcp.list` | `odoo.quality.read` | High | 1 день |
| `quality.qcp.get` | `odoo.quality.read` | High | 0.5 дня |
| `quality.check.list` | `odoo.quality.read` | High | 1 день |
| `quality.alert.list` | `odoo.quality.read` | High | 1 день |
| `quality.alert.get` | `odoo.quality.read` | High | 0.5 дня |

**Acceptance Criteria:**
- [ ] All operations return correct data
- [ ] Proper pagination support
- [ ] Capability checks enforced

#### 2.2 Quality Write Operations

| Operation | Capability | Пріоритет | Оцінка |
|-----------|------------|-----------|--------|
| `quality.check.create` | `odoo.quality.write` | High | 2 дні |
| `quality.check.update` | `odoo.quality.write` | Medium | 1 день |
| `quality.alert.create` | `odoo.quality.write` | High | 2 дні |

**Acceptance Criteria:**
- [ ] OperationReceipt for all mutations
- [ ] Idempotency via receipt checking
- [ ] Proper validation of inputs

#### 2.3 Integration Tests

| Завдання | Пріоритет | Оцінка |
|----------|-----------|--------|
| Створити mock Odoo server | High | 2 дні |
| Написати integration tests | High | 3 дні |
| Створити test fixtures | Medium | 1 день |

---

### Phase 3: CAPA Operations
**Тривалість:** 2 тижні
**Статус:** Planned

#### 3.1 CAPA Draft Operations

| Operation | Capability | Пріоритет | Оцінка |
|-----------|------------|-----------|--------|
| `capa.list` | `odoo.capa.draft` | High | 1 день |
| `capa.get` | `odoo.capa.draft` | High | 0.5 дня |
| `capa.draft.create` | `odoo.capa.draft` | High | 2 дні |
| `capa.draft.update` | `odoo.capa.draft` | Medium | 1 день |
| `capa.submit` | `odoo.capa.draft` | High | 1 день |

**Acceptance Criteria:**
- [ ] Draft CAPA creation from Quality Alert
- [ ] State machine transitions work correctly
- [ ] Audit trail created

#### 3.2 CAPA Approval (Restricted)

| Operation | Capability | Пріоритет | Оцінка |
|-----------|------------|-----------|--------|
| `capa.approve` | `odoo.capa.approve` | Medium | 2 дні |
| `capa.reject` | `odoo.capa.approve` | Medium | 1 день |

**Notes:**
- Потребує zone escalation (z:work → z:private)
- Може потребувати human-in-the-loop

---

### Phase 4: Knowledge Base & KPI
**Тривалість:** 1-2 тижні
**Статус:** Planned

#### 4.1 Knowledge Base Operations

| Operation | Capability | Пріоритет | Оцінка |
|-----------|------------|-----------|--------|
| `kb.search` | `odoo.kb.read` | Medium | 1 день |
| `kb.article.get` | `odoo.kb.read` | Medium | 0.5 дня |
| `kb.article.create` | `odoo.kb.write` | Low | 2 дні |

#### 4.2 KPI/Metrics Operations

| Operation | Capability | Пріоритет | Оцінка |
|-----------|------------|-----------|--------|
| `kpi.fpy.get` | `odoo.kpi.read` | Medium | 1 день |
| `kpi.mttr.get` | `odoo.kpi.read` | Medium | 1 день |
| `kpi.dashboard` | `odoo.kpi.read` | Low | 2 дні |

---

### Phase 5: Advanced Features
**Тривалість:** 2-3 тижні
**Статус:** Future

#### 5.1 ZoneCheckpoint Integration

| Завдання | Пріоритет | Оцінка |
|----------|-----------|--------|
| Phase transition checkpoints | High | 3-5 днів |
| Quorum signature collection | High | 3-5 днів |
| Checkpoint verification | High | 2-3 дні |

#### 5.2 Webhook Support

| Завдання | Пріоритет | Оцінка |
|----------|-----------|--------|
| Incoming webhook handler | Medium | 2 дні |
| Odoo event subscriptions | Medium | 2 дні |
| Event routing to zones | Medium | 2 дні |

---

## 2. Milestones

### Milestone 1: MVP (Phase 1-2)
**Target:** +4-5 тижнів від старту
**Scope:**
- Basic connector working
- Quality read/write operations
- Integration tests passing

**Success Criteria:**
- [ ] `fcp connector test odoo` succeeds
- [ ] Can list QCPs from Odoo
- [ ] Can create Quality Check via FCP

### Milestone 2: CAPA Support (Phase 3)
**Target:** +7-8 тижнів від старту
**Scope:**
- Full CAPA lifecycle (draft → submit)
- Approval workflow (restricted)

**Success Criteria:**
- [ ] AI can create CAPA draft from alert
- [ ] State transitions logged
- [ ] Approval requires escalation

### Milestone 3: Full Feature Set (Phase 4-5)
**Target:** +10-12 тижнів від старту
**Scope:**
- KB integration
- KPI dashboards
- Phase gate checkpoints

**Success Criteria:**
- [ ] End-to-end PDCA cycle support
- [ ] ZoneCheckpoints for phase transitions
- [ ] Production-ready documentation

---

## 3. Технічні рішення

### 3.1 Architecture Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Odoo API | JSON-RPC | Standard, well-documented |
| Auth method | API Key first | Simplest, most secure |
| Async runtime | Tokio | Standard for Rust async |
| HTTP client | Reqwest | Feature-rich, async support |
| Serialization | Serde | De-facto standard |

### 3.2 Open Questions

| Question | Options | Decision Needed By |
|----------|---------|-------------------|
| Single vs multi-connector? | Monolithic / Micro | Phase 1 start |
| Mock server approach | Mockito / Docker Odoo | Phase 2 start |
| Capability granularity | Fine / Coarse | Phase 1 |

---

## 4. Ресурси

### 4.1 Required Skills

- Rust (intermediate+)
- FCP protocol knowledge
- Odoo API knowledge
- Async programming

### 4.2 Documentation

| Document | Location | Purpose |
|----------|----------|---------|
| FCP Spec | `/FCP_Specification_V2.md` | Protocol reference |
| Connector Guide | `/docs/fcp_model_connectors_rust.md` | Development guide |
| Odoo PDCA | `/Users/sd/github/odoo19/odoov19/EXPLAIN.md` | Domain knowledge |
| Research | `/docs/research/ODOO_V19_FCP_INTEGRATION.md` | Integration analysis |

### 4.3 External Dependencies

| Dependency | Purpose | Risk |
|------------|---------|------|
| Odoo v19 API | Target system | API changes |
| Tailscale | Mesh network | Service availability |
| FCP core | Protocol implementation | Breaking changes |

---

## 5. Ризик-менеджмент

### 5.1 Risk Register

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| Odoo API breaking changes | Medium | High | Version detection, adapter pattern |
| FCP spec changes | Medium | Medium | Track upstream, adapt quickly |
| Performance issues | Low | Medium | Profiling, optimization |
| Security vulnerabilities | Low | High | Security review, audits |

### 5.2 Contingency Plans

**If Odoo API changes:**
- Implement version detection
- Maintain compatibility layer
- Document minimum supported version

**If FCP spec changes:**
- Monitor CHANGELOG
- Allocate time for updates
- Use feature flags for new capabilities

---

## 6. Definition of Done

### For each operation:
- [ ] Implementation complete
- [ ] Unit tests passing
- [ ] Integration tests passing
- [ ] Documentation updated
- [ ] Capability checks enforced
- [ ] OperationReceipt used (for mutations)
- [ ] Error handling complete
- [ ] Logging appropriate (no sensitive data)

### For each phase:
- [ ] All operations in phase complete
- [ ] Code review passed
- [ ] All tests green
- [ ] Documentation reviewed
- [ ] Demo to stakeholders

---

## 7. Наступні дії (Immediate Actions)

### Сьогодні / Завтра:
1. [ ] Review this plan
2. [ ] Confirm Phase 0 complete
3. [ ] Set up development environment

### Цей тиждень:
1. [ ] Create `connectors/odoo/` scaffold
2. [ ] Implement basic Connector trait
3. [ ] Set up test infrastructure

### Наступний тиждень:
1. [ ] Implement Odoo authentication
2. [ ] Create HTTP client wrapper
3. [ ] First working API call to Odoo

---

## 8. Tracking

### Progress Tracker

```
Phase 0: Research     [████████████████████] 100%
Phase 1: Foundation   [                    ]   0%
Phase 2: Quality      [                    ]   0%
Phase 3: CAPA         [                    ]   0%
Phase 4: KB & KPI     [                    ]   0%
Phase 5: Advanced     [                    ]   0%
```

### Change Log

| Date | Version | Change |
|------|---------|--------|
| 2026-01-27 | 1.0.0 | Initial plan created |

---

## 9. Контакти

### Project Resources

| Resource | Location |
|----------|----------|
| Research Docs | `/docs/research/` |
| FCP Connectors | `/connectors/` |
| User Guides | `/docs/guides/` |

### Related Projects

| Project | Repository |
|---------|------------|
| FCP Core | `flywheel_connectors` |
| Odoo v19 | `odoov19` |

---

*Plan created: 2026-01-27*
*Status: Active Planning*
*Next review: After Phase 1 completion*
