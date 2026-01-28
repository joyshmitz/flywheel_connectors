# FCP Research Documents

Цей каталог містить документацію досліджень та планування інтеграцій FCP.

---

## Odoo v19 Integration Research

| Документ | Опис |
|----------|------|
| [ODOO_V19_FCP_INTEGRATION.md](ODOO_V19_FCP_INTEGRATION.md) | Повне дослідження інтеграції Odoo v19 + FCP |
| [AGENTS_ODOO_FCP.md](AGENTS_ODOO_FCP.md) | Інструкції для AI coding agents |
| [PLAN_FOR_ODOOv19_AND_FLYWHEEL.md](PLAN_FOR_ODOOv19_AND_FLYWHEEL.md) | План реалізації fcp-odoo connector |

---

## Статус досліджень

| Тема | Статус | Версія | Дата оновлення |
|------|--------|--------|----------------|
| Odoo v19 + FCP Integration | Research Complete | v2.1.0 | 2026-01-28 |

---

## Ключові факти (v2.1)

| Питання | Відповідь |
|---------|-----------|
| Odoo v19 API | **JSON-2 API** (рекомендований) |
| XML-RPC/JSON-RPC | DEPRECATED, видалення в Odoo 20 |
| GraphQL в Odoo | **НЕ існує** офіційно |
| Connector референс | `connectors/anthropic/` |
| Rate limiting | `fcp-sdk/ratelimit` |
| Lifecycle | `fcp-core/lifecycle` |

---

## Як використовувати

### Для дослідників:
1. Почніть з `ODOO_V19_FCP_INTEGRATION.md` - повний аналіз
2. Перегляньте питання для дослідження в кінці документа

### Для AI agents:
1. Прочитайте `AGENTS_ODOO_FCP.md` перед початком роботи
2. Дотримуйтесь правил та conventions

### Для планування:
1. `PLAN_FOR_ODOOv19_AND_FLYWHEEL.md` містить roadmap
2. Відстежуйте progress у секції Tracking

---

*Останнє оновлення: 2026-01-28*
