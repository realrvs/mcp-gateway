# ADR-0006: Observability stack для MCP Gateway

- **Status:** Accepted
- **Date:** 2026-09-24
- **Deciders:** Roman Sokolov (Architect)
- **Tags:** `observability`, `sre`, `operations`, `otel`, `finops`

---

## Context

MCP Gateway — точка входа для трафика AI-агентов к LLM и MCP-серверам.
Каждый запрос проходит через **8 middleware-слоёв** (auth, tenant, rate limit,
PII, breaker, audit, upstream, response) и взаимодействует с **5 внешними
системами** (Redis, PostgreSQL, Vault, SPIRE, LLM APIs).

Без полноценной observability невозможно ответить на вопросы:

```
    ┌──────────────────────────────────────────────────────────────┐
    │                                                              │
    │  Operational:                                                │
    │  • Почему тенант "acme" жалуется на latency?                 │
    │  • Какой компонент деградирует первым?                       │
    │  • Когда последний раз был инцидент и что его вызвало?       │
    │  • Соответствует ли SLA по контракту?                        │
    │                                                              │
    │  Business:                                                   │
    │  • Сколько стоит каждый tenant в час?                        │
    │  • Какой агент тратит больше всех?                           │
    │  • Что произошло с costs после релиза X?                     │
    │  • Какой процент запросов редактируется PII?                 │
    │                                                              │
    │  Reliability:                                                │
    │  • Мы укладываемся в SLO?                                    │
    │  • Какой error budget остался?                               │
    │  • С какой скоростью его тратим (burn rate)?                 │
    │  • Когда нужно freeze feature-релизов?                       │
    │                                                              │
    │  Security:                                                   │
    │  • Попадают ли PII в outgoing LLM-запросы?                   │
    │  • Есть ли аномальные паттерны (возможная атака)?            │
    │  • Кто и когда обращался к secrets?                          │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

**Существующий стек (из SLO.md и Capacity Planning):**

- Prometheus — метрики (RED + USE)
- Grafana — dashboards
- Loki — structured logs (планируется)
- OpenTelemetry — трейсы (упомянуто, но не детализировано)

**Чего не хватает:**

1. **Unified instrumentation** — как именно мы генерируем данные?
   OpenTelemetry SDK vs Prometheus client vs custom.
2. **LLM-specific observability** — Langfuse для prompts/responses/costs.
3. **Consistency между сигналами** — единый trace_id, единый tenant_id,
   единые labels.
4. **Cost attribution per agent** (не только per tenant).
5. **Incident replay** — воспроизведение инцидента по trace_id.
6. **Sampling strategy** — 100% трафика невозможно (cost + volume).
7. **Retention policy** — сколько хранить, что архивировать, где.

---

## Decision

**Используем unified observability stack** на базе **OpenTelemetry**,
с тремя pillars (metrics, logs, traces) + LLM-specific layer (Langfuse)
+ cost attribution layer.

### Архитектура

```
    ┌───────────────────────────────────────────────────────────────────┐
    │                                                                    │
    │                    MCP Gateway (Go)                                │
    │                                                                    │
    │   ┌──────────────────────────────────────────────────────────┐    │
    │   │                                                            │    │
    │   │   OpenTelemetry SDK                                        │    │
    │   │   ├── trace.Span (per request)                             │    │
    │   │   ├── metric.Meter (RED + USE)                             │    │
    │   │   ├── log.Logger (structured)                              │    │
    │   │   └── Baggage: tenant_id, agent_id, request_id             │    │
    │   │                                                            │    │
    │   └────────────────────┬───────────────────────────────────────┘    │
    │                        │                                            │
    │                        │ OTLP/gRPC                                  │
    │                        │ (собрано одним exporter'ом)                │
    │                        │                                            │
    └────────────────────────┼────────────────────────────────────────────┘
                             │
                             ▼
    ┌───────────────────────────────────────────────────────────────────┐
    │                                                                    │
    │                OpenTelemetry Collector                             │
    │                (sidecar или DaemonSet)                             │
    │                                                                    │
    │   ┌──────────────┐  ┌──────────────┐  ┌──────────────┐            │
    │   │  Receivers   │  │  Processors  │  │  Exporters   │            │
    │   ├──────────────┤  ├──────────────┤  ├──────────────┤            │
    │   │  OTLP/gRPC   │→ │  batch       │→ │  prometheus  │→ Prometheus│
    │   │  OTLP/HTTP   │  │  memory_lim  │  │  loki        │→ Loki      │
    │   │              │  │  attributes  │  │  otlp        │→ Tempo     │
    │   │              │  │  tail_sampling│ │  langfuse    │→ Langfuse  │
    │   │              │  │  transform   │  │              │            │
    │   └──────────────┘  └──────────────┘  └──────────────┘            │
    │                                                                    │
    └───────────────────────────────────────────────────────────────────┘
                             │
        ┌────────────────────┼────────────────────┬────────────────┐
        │                    │                    │                │
        ▼                    ▼                    ▼                ▼
    ┌──────────┐        ┌──────────┐        ┌──────────┐      ┌──────────┐
    │Prometheus│        │  Loki    │        │  Tempo   │      │Langfuse  │
    │          │        │          │        │          │      │(LLM-     │
    │• metrics │        │• logs    │        │• traces  │      │ specific)│
    │• 15d     │        │• 7d      │        │• 30d     │      │• prompts │
    │  retention│       │  retention│       │  retention│     │• costs   │
    └────┬─────┘        └────┬─────┘        └────┬─────┘      └────┬─────┘
         │                   │                   │                  │
         └───────────────────┼───────────────────┴──────────────────┘
                             │
                             ▼
                    ┌──────────────────┐
                    │    Grafana       │
                    │                  │
                    │ • Unified UI     │
                    │ • Dashboards     │
                    │ • Explore        │
                    │ • Alerting       │
                    └──────────────────┘
                             │
                             ▼
                    ┌──────────────────┐
                    │  Alertmanager    │
                    │                  │
                    │ • Routing        │
                    │ • Silencing      │
                    │ • Escalation     │
                    └──────────────────┘
```

### Three Pillars

```
    ┌──────────────────────────────────────────────────────────────┐
    │                                                              │
    │  1. METRICS (Prometheus)                                     │
    │                                                              │
    │  Источник: OpenTelemetry SDK → collector → prometheus        │
    │             exporter                                          │
    │                                                              │
    │  Формат: OpenMetrics (prometheus-compatible)                 │
    │                                                              │
    │  Категории метрик:                                           │
    │                                                              │
    │  • RED (per method × tenant)                                 │
    │    - mcp_requests_total{method, tenant, status}              │
    │    - mcp_request_duration_seconds{method, tenant}            │
    │    - mcp_errors_total{method, tenant, error_type}            │
    │                                                              │
    │  • USE (infra)                                               │
    │    - mcp_goroutines                                          │
    │    - mcp_memory_bytes                                        │
    │    - mcp_redis_latency_seconds                               │
    │    - mcp_postgres_write_duration_seconds                     │
    │                                                              │
    │  • Business (FinOps + SLO)                                   │
    │    - mcp_llm_tokens_total{tenant, agent, provider, model,    │
    │      direction}                                              │
    │    - mcp_llm_cost_rub_total{tenant, agent, provider, model}  │
    │    - mcp_audit_verify_runs_total{result}                     │
    │    - mcp_pii_redacted_total{tenant, type}                    │
    │    - mcp_cache_hits_total{tenant}                            │
    │                                                              │
    │  Retention: 15 дней (Prometheus local)                       │
    │  Long-term: Thanos / VictoriaMetrics (TBD)                   │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘

    ┌──────────────────────────────────────────────────────────────┐
    │                                                              │
    │  2. LOGS (Loki)                                              │
    │                                                              │
    │  Источник: OpenTelemetry SDK → collector → loki exporter     │
    │                                                              │
    │  Формат: structured JSON                                     │
    │                                                              │
    │  Обязательные поля:                                          │
    │                                                              │
    │  {                                                           │
    │    "timestamp": "2026-09-24T10:30:00.123Z",                  │
    │    "level": "info|warn|error",                               │
    │    "message": "...",                                         │
    │    "trace_id": "abc123...",                                  │
    │    "span_id": "def456...",                                   │
    │    "tenant_id": "acme",                                      │
    │    "agent_id": "agent-x",                                    │
    │    "request_id": "req-789",                                  │
    │    "method": "tools/call",                                   │
    │    "outcome": "allow|deny|error",                            │
    │    "duration_ms": 1234                                       │
    │  }                                                           │
    │                                                              │
    │  Запрещено логировать:                                       │
    │  • PII (emails, SSN, IBAN, ФИО) — только через redaction     │
    │  • API keys                                                  │
    │  • JWT tokens                                                │
    │  • Raw prompts/responses (только в Langfuse)                 │
    │                                                              │
    │  Labels (для индексации):                                    │
    │  tenant_id, level, method, outcome                           │
    │                                                              │
    │  Retention: 7 дней (Loki)                                    │
    │  Archive: S3 (90 дней) для compliance                        │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘

    ┌──────────────────────────────────────────────────────────────┐
    │                                                              │
    │  3. TRACES (Tempo)                                           │
    │                                                              │
    │  Источник: OpenTelemetry SDK → collector → otlp exporter     │
    │                                                              │
    │  Формат: OTLP (OpenTelemetry Protocol)                       │
    │                                                              │
    │  Span hierarchy:                                             │
    │                                                              │
    │  mcp.request (root span)                                     │
    │  ├── auth.validate (mTLS + SPIFFE)                           │
    │  ├── auth.jwt_validate                                       │
    │  ├── tenant.resolve                                          │
    │  ├── ratelimit.check                                         │
    │  │   └── redis.eval (Lua script)                             │
    │  ├── pii.detect                                              │
    │  │   └── pii.mask                                            │
    │  ├── breaker.execute                                         │
    │  │   └── upstream.call                                       │
    │  │       └── llm.request (если upstream = LLM)               │
    │  ├── pii.unmask                                              │
    │  └── audit.write                                             │
    │      └── postgres.insert                                     │
    │                                                              │
    │  Span attributes (обязательные):                             │
    │  • tenant.id                                                 │
    │  • agent.id (если применимо)                                 │
    │  • mcp.method                                                │
    │  • mcp.outcome                                               │
    │  • upstream.name                                             │
    │  • upstream.status_code                                      │
    │  • pii.redacted_count                                        │
    │  • breaker.state (closed|half-open|open)                     │
    │  • llm.tokens.input                                          │
    │  • llm.tokens.output                                         │
    │  • llm.cost_rub                                              │
    │                                                              │
    │  Sampling:                                                   │
    │  • Head-based: 100% для errors, 10% для success              │
    │  • Tail-based (в collector): 100% для медленных (>SLO),      │
    │    100% для 5xx, 10% для остальных                           │
    │                                                              │
    │  Retention: 30 дней (Tempo)                                  │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

### LLM-specific layer (Langfuse)

```
    ┌──────────────────────────────────────────────────────────────┐
    │                                                              │
    │  Langfuse — observability для LLM                            │
    │                                                              │
    │  Зачем отдельный компонент:                                  │
    │                                                              │
    │  • Prometheus метрики — числовые (aggregated)                │
    │  • Tempo трейсы — span tree (структура)                      │
    │  • Loki логи — сообщения (текст)                             │
    │                                                              │
    │  Langfuse — что НЕ покрывают три pillars:                    │
    │  • Prompt versioning (какая версия промпта использована)     │
    │  • Full prompt/response (для отладки и A/B testing)          │
    │  • LLM-specific metrics (tokens, cost, quality scores)       │
    │  • Evaluation (human-in-the-loop feedback)                   │
    │  • Prompt A/B testing (см. ADR-0009)                         │
    │                                                              │
    │  Что трекаем:                                                │
    │                                                              │
    │  Trace (per LLM call):                                       │
    │  • tenant_id                                                 │
    │  • agent_id                                                  │
    │  • prompt_template_id + version                              │
    │  • model (GigaChat-Pro, YandexGPT, Ollama)                   │
    │  • input_tokens, output_tokens                               │
    │  • cost_rub                                                  │
    │  • latency_ms                                                │
    │  • status (success|error)                                    │
    │  • trace_id (link to Tempo)                                  │
    │                                                              │
    │  PII handling:                                               │
    │  • Prompts хранятся ТОЛЬКО в redacted виде                   │
    │  • Placeholders <EMAIL_1>, <PHONE_2> (см. ADR-0006 TBD)      │
    │  • Retention: 30 дней                                        │
    │  • Access: RBAC, audit log всех reads                        │
    │                                                              │
    │  Deployment:                                                 │
    │  • Self-hosted (docker-compose локально, K8s в prod)         │
    │  • PostgreSQL + ClickHouse backend                           │
    │  • S3 для blob storage (prompts)                             │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

### Cost attribution layer

```
    ┌──────────────────────────────────────────────────────────────┐
    │                                                              │
    │  Cost attribution per tenant × agent                         │
    │                                                              │
    │  Проблема: один tenant = много агентов.                      │
    │  Нужно понимать, КАКОЙ агент тратит деньги.                  │
    │                                                              │
    │  Решение:                                                    │
    │                                                              │
    │  1. agent_id как обязательный атрибут (см. ADR-0010 TBD)     │
    │                                                              │
    │  2. Метрики:                                                 │
    │     mcp_llm_cost_rub_total{tenant, agent, provider, model}   │
    │     mcp_llm_tokens_total{tenant, agent, provider, model,     │
    │       direction}                                             │
    │                                                              │
    │  3. Grafana dashboards:                                      │
    │     • Top-N агентов по стоимости                             │
    │     • Cost trend per tenant/agent                            │
    │     • Cost vs budget per tenant                              │
    │     • Anomaly detection (rule-based)                         │
    │                                                              │
    │  4. Alerting:                                                │
    │     • Tenant cost > 100% budget → warning                    │
    │     • Tenant cost > 150% budget → critical                   │
    │     • Agent cost > 3x baseline за час → warning              │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

### Unified context propagation

```
    ┌──────────────────────────────────────────────────────────────┐
    │                                                              │
    │  Ключевое: один trace_id сквозь все сигналы                  │
    │                                                              │
    │  HTTP Request                                                │
    │  ├── X-Request-ID: req-789 (если клиент передал)             │
    │  ├── traceparent: 00-abc123-def456-01 (W3C)                  │
    │  │                                                           │
    │  ▼                                                           │
    │  context.Context                                             │
    │  ├── trace_id = abc123 (OTel)                                │
    │  ├── span_id = def456 (OTel)                                 │
    │  ├── tenant_id = acme (ADR-0004)                             │
    │  ├── agent_id = agent-x (ADR-0010 TBD)                       │
    │  ├── request_id = req-789                                    │
    │  │                                                           │
    │  ▼                                                           │
    │  Каждый сигнал содержит эти атрибуты:                        │
    │                                                              │
    │  • Metric: labels {tenant, agent, method, ...}               │
    │  • Log: fields {trace_id, span_id, tenant_id, agent_id, ...} │
    │  • Trace: span attributes {tenant.id, agent.id, ...}         │
    │  • Langfuse: metadata {trace_id, tenant_id, agent_id}        │
    │                                                              │
    │  Это позволяет:                                              │
    │  • Из метрики → в трейс (drill-down)                         │
    │  • Из трейса → в логи (по trace_id)                          │
    │  • Из лога → в Langfuse (по trace_id)                        │
    │  • Из алерта → в конкретный запрос                           │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

---

## Rationale

### Почему OpenTelemetry, а не нативные SDK

```
    ┌──────────────────────────────────────────────────────────────┐
    │                                                              │
    │  Альтернативы:                                               │
    │                                                              │
    │  1. Нативные SDK:                                            │
    │     • Prometheus client_golang (metrics)                     │
    │     • zerolog/zap (logs)                                     │
    │     • jaeger-client-go (traces)                              │
    │                                                              │
    │  2. OpenTelemetry SDK (наш выбор)                            │
    │                                                              │
    │  Почему OTel выигрывает:                                     │
    │                                                              │
    │  ✅ Единый SDK для всех трёх pillars                         │
    │     — один dependency вместо трёх                            │
    │     — один exporter вместо трёх                              │
    │                                                              │
    │  ✅ Vendor-neutral                                            │
    │     — можно переехать с Prometheus на VictoriaMetrics        │
    │       без изменения кода                                     │
    │     — можно добавить Datadog/New Relic как второй backend    │
    │                                                              │
    │  ✅ Context propagation из коробки                            │
    │     — trace_id автоматически в logs, metrics, spans          │
    │     — не нужно вручную прокидывать                            │
    │                                                              │
    │  ✅ Collector как центральная точка                           │
    │     — sampling, filtering, enrichment в одном месте          │
    │     — не нужно в приложении                                  │
    │                                                              │
    │  ✅ Индустриальный стандарт (CNCF)                            │
    │     — совместим с любым современным backend                  │
    │                                                              │
    │  Минусы OTel:                                                │
    │  ❌ Больше boilerplate, чем у нативных SDK                   │
    │  ❌ Меньше фич, чем у специализированных (пока)              │
    │  ❌ Молодой (breaking changes в 1.0 → stable)                │
    │                                                              │
    │  Вывод: минусы приемлемы, плюсы критичны.                    │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

### Почему self-hosted, а не SaaS (Datadog, New Relic)

```
    ┌──────────────────────────────────────────────────────────────┐
    │                                                              │
    │  Datadog / New Relic:                                        │
    │                                                              │
    │  ✅ Zero ops — managed, обновления, scaling                  │
    │  ✅ Богатые фичи — APM, RUM, synthetics                      │
    │  ✅ Быстрый старт                                             │
    │                                                              │
    │  ❌ Очень дорого: ~$15-30/host/месяц + custom metrics        │
    │     Для 10 pods + 5 services = $10k-20k/месяц                │
    │  ❌ Vendor lock-in                                            │
    │  ❌ Данные вне периметра (compliance risk для 152-ФЗ)        │
    │                                                              │
    │  Self-hosted:                                                │
    │                                                              │
    │  ✅ Стоимость ~10x ниже ($1k-2k/месяц infra)                 │
    │  ✅ Данные внутри периметра (152-ФЗ, GDPR)                   │
    │  ✅ Полный контроль                                          │
    │  ❌ Операционная нагрузка (обновления, scaling)              │
    │  ❌ Меньше фич                                               │
    │                                                              │
    │  Для enterprise в регулируемой среде (наша целевая            │
    │  аудитория) self-hosted — обязательное требование.           │
    │                                                              │
    │  Гибридный подход:                                           │
    │  • Self-hosted для compliance-critical данных (audit, PII)   │
    │  • SaaS для агрегированных метрик (возможно)                 │
    │                                                              │
    │  Выбор: полностью self-hosted для PoC и production.          │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

### Почему Langfuse, а не кастомное решение

```
    ┌──────────────────────────────────────────────────────────────┐
    │                                                              │
    │  Задача: трекать LLM-specific данные (prompts, tokens,       │
    │  costs, A/B testing, evals).                                 │
    │                                                              │
    │  Вариант 1: Собственное решение                              │
    │  • Своя БД для prompts                                       │
    │  • Свои UI для дашбордов                                     │
    │  • Свои SDK для integration                                  │
    │  • Своя A/B testing логика                                   │
    │  • Свои evals                                                │
    │                                                              │
    │  Оценка: 3-6 месяцев разработки + поддержка.                 │
    │                                                              │
    │  Вариант 2: Langfuse (наш выбор)                             │
    │  • Open-source, self-hosted                                  │
    │  • Уже в стеке (agentic-orchestration-platform)              │
    │  • SDK для Go, Python, JS                                    │
    │  • Встроенный A/B testing                                    │
    │  • Встроенные evals                                          │
    │  • Встроенный prompt versioning                              │
    │  • Интеграция с OTel (trace_id propagation)                  │
    │                                                              │
    │  Оценка: 2-3 дня на интеграцию.                              │
    │                                                              │
    │  Альтернативы Langfuse:                                      │
    │  • Helicone — SaaS, менее гибкий                             │
    │  • Phoenix (Arize) — больше для ML, менее для LLM ops        │
    │  • LangSmith — SaaS, vendor lock (LangChain)                 │
    │  • Собственное — не оправдано                                │
    │                                                              │
    │  Выбор: Langfuse.                                             │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

### Почему tail-based sampling, а не head-based

```
    ┌──────────────────────────────────────────────────────────────┐
    │                                                              │
    │  Head-based sampling (в приложении):                         │
    │  • Решение о sample принимается ДО обработки запроса         │
    │  • Просто: if rand() < 0.1 { sample }                        │
    │  • Проблема: не знаем, будет ли запрос ошибкой               │
    │  • Errors могут быть sampled out — теряем диагностику        │
    │                                                              │
    │  Tail-based sampling (в collector):                          │
    │  • Решение принимается ПОСЛЕ обработки                       │
    │  • Collector видит: latency, status, errors                  │
    │  • Правила:                                                  │
    │    - 100% для errors (5xx)                                   │
    │    - 100% для медленных (>SLO p99)                           │
    │    - 100% для конкретных tenant_id (support tickets)         │
    │    - 10% для остальных                                       │
    │  • Минус: collector должен буферизовать все traces           │
    │                                                              │
    │  Для нашего профиля:                                         │
    │  • Объём: ~8.6M calls/day = 100 RPS                          │
    │  • Traces: ~10 spans/call = 1000 spans/sec                   │
    │  • Размер: ~2 KB/span = 2 MB/sec = 172 GB/day                │
    │  • Retention 30 дней = 5 TB                                  │
    │                                                              │
    │  С tail sampling (10%):                                      │
    │  • 17 GB/day = 500 GB за 30 дней                             │
    │  • Экономия 10x по storage                                   │
    │                                                              │
    │  Выбор: tail-based в OTel Collector.                          │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

---

## Consequences

### Positive

- **Unified instrumentation** — один SDK, один exporter, единый контекст.
- **Сквозной trace_id** — drill-down между метрикой, логом, трейсом.
- **LLM-specific insights** — Langfuse даёт то, что не покрывают три pillars.
- **Cost attribution per agent** — FinOps на уровне отдельного агента.
- **Compliance-ready** — данные внутри периметра, retention controlled.
- **Vendor-neutral** — можно мигрировать между backends без изменения кода.
- **Стоимость ~10x ниже SaaS** — экономия $100k+/год.
- **Incident replay** — воспроизведение инцидента по trace_id.

### Negative

- **Операционная сложность** — 5 компонентов (Prometheus, Loki, Tempo,
  Langfuse, OTel Collector) вместо SaaS.
- **Storage costs** — 5 TB/30 дней для traces (без sampling), ~500 GB с
  sampling. S3 archive для compliance.
- **OTel maturity** — breaking changes в SDK случаются (но stable с 2023).
- **Boilerplate** — OpenTelemetry требует больше кода, чем native SDK.
- **Langfuse dependency** — требует PostgreSQL + ClickHouse (больше
  инфраструктуры).
- **Sampling trade-off** — 10% sample может пропустить редкие проблемы.

### Neutral

- **Retention policy** — разные retention для разных сигналов
  (7d logs, 15d metrics, 30d traces).
- **Alerting сложнее** — Alertmanager конфигурация требует времени.
- **Grafana dashboards** — много, но общие шаблоны работают.

---

## Failure modes

### OTel Collector недоступен

```
    ┌──────────────────────────────────────────────────────────────┐
    │                                                              │
    │  Симптом: gateway не может экспортировать телеметрию         │
    │                                                              │
    │  Причины:                                                    │
    │  • Collector down (crash, OOM, network)                      │
    │  • Collector под нагрузкой (backpressure)                    │
    │  • Misconfiguration                                          │
    │                                                              │
    │  Поведение gateway:                                          │
    │  • SDK buffer'ит данные в памяти (до 1000 spans/logs)        │
    │  • При переполнении buffer'а — drop (не block)               │
    │  • Circuit breaker на exporter (не влияет на бизнес-логику)  │
    │  • Fail-open — gateway продолжает работать                   │
    │                                                              │
    │  ⚠️ Критично: observability НЕ должна ронять gateway         │
    │                                                              │
    │  Detection:                                                  │
    │  • Алерт: mcp_gateway_otel_export_errors_total > 0           │
    │  • Алерт: mcp_gateway_otel_buffer_dropped_total > 0          │
    │  • Метрика: otelcol_receiver_refused_spans                   │
    │                                                              │
    │  Recovery:                                                   │
    │  • Collector auto-restart (K8s deployment)                   │
    │  • Gateway автоматически переподключается                    │
    │  • Потеря данных за окно downtime (приемлемо)                │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

### Prometheus недоступен (scrape fails)

```
    ┌──────────────────────────────────────────────────────────────┐
    │                                                              │
    │  Симптом: метрики не собираются                              │
    │                                                              │
    │  Влияние:                                                    │
    │  • Grafana dashboards показывают gaps                        │
    │  • Алерты не срабатывают (нет данных)                        │
    │  • SLO расчёты приостановлены                                │
    │                                                              │
    │  ⚠️ Gateway продолжает работать (metrics — pull model)       │
    │                                                              │
    │  Detection:                                                  │
    │  • Алерт: up{job="mcp-gateway"} == 0 > 2m                    │
    │  • Алерт: prometheus_tsdb_head_samples_appended_total        │
    │           rate == 0                                          │
    │                                                              │
    │  Mitigation:                                                 │
    │  • Prometheus HA (2 instances, Thanos для dedup)             │
    │  • Long-term storage в Thanos/VictoriaMetrics                │
    │  • Gateway не зависит от Prometheus для работы               │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

### Langfuse недоступен

```
    ┌──────────────────────────────────────────────────────────────┐
    │                                                              │
    │  Симптом: LLM traces не сохраняются                          │
    │                                                              │
    │  Влияние:                                                    │
    │  • Нет данных для A/B testing (ADR-0009)                     │
    │  • Нет детальных prompts/responses для отладки               │
    │  • Cost tracking задерживается (но не теряется — метрики     │
    │    в Prometheus работают независимо)                         │
    │                                                              │
    │  ⚠️ Gateway продолжает работать (async export)               │
    │                                                              │
    │  Mitigation:                                                 │
    │  • SDK buffer + retry с exponential backoff                  │
    │  • Fallback: логировать в Loki (structured) без Langfuse     │
    │  • Cost tracking через Prometheus метрики (не зависит        │
    │    от Langfuse)                                              │
    │                                                              │
    │  Detection:                                                  │
    │  • Алерт: langfuse_ingestion_errors_total > 0                │
    │  • Алерт: langfuse_health_check == 0 > 5m                    │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

### Disk full на Tempo/Loki

```
    ┌──────────────────────────────────────────────────────────────┐
    │                                                              │
    │  Симптом: traces/logs не пишутся                             │
    │                                                              │
    │  Причины:                                                    │
    │  • Retention слишком долгий                                  │
    │  • Volume выше ожидаемого                                    │
    │  • Sampling не работает                                      │
    │                                                              │
    │  Mitigation:                                                 │
    │  • Disk usage alert: >80% → warning, >90% → critical         │
    │  • Auto-delete oldest data при 90% (retention config)        │
    │  • S3 backend для long-term (Thanos, Loki S3)                │
    │  • Aggressive sampling при приближении к лимиту              │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

### PII leak в traces/logs

```
    ┌──────────────────────────────────────────────────────────────┐
    │                                                              │
    │  Симптом: PII обнаружены в Loki/Tempo/Langfuse               │
    │                                                              │
    │  ⚠️ КРИТИЧНО — compliance violation                          │
    │                                                              │
    │  Причины:                                                    │
    │  • Разработчик логирует raw args                             │
    │  • Span attribute содержит prompt без redaction              │
    │  • Ошибка в PII detection                                    │
    │                                                              │
    │  Mitigation (defense in depth):                              │
    │  1. Sanitization hook в OTel SDK (обязательный)              │
    │     — автоматическая redaction перед export                  │
    │  2. PII detection в collector (второй слой)                  │
    │  3. Periodic scan логов на PII patterns (third layer)        │
    │  4. RBAC на Loki/Tempo — только SRE, audit log reads         │
    │                                                              │
    │  Detection:                                                  │
    │  • Алерт: pii_in_logs_detected_total > 0                     │
    │  • Critical incident → freeze + investigation                │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

---

## Alternatives considered

### Alternative 1: Datadog / New Relic (SaaS)

**Плюсы:**
- Zero ops, managed.
- Богатые фичи.
- Быстрый старт.

**Минусы:**
- $10k-20k/месяц для нашего объёма.
- Vendor lock-in.
- Данные вне периметра (152-ФЗ risk).

**Решение:** отклонено. Compliance требует self-hosted.

### Alternative 2: Native SDKs (Prometheus client + zap + jaeger-client)

**Плюсы:**
- Меньше boilerplate.
- Больше контроля.
- Зрелые библиотеки.

**Минусы:**
- Три разных SDK вместо одного.
- Нет unified context propagation.
- Сложнее мигрировать между backends.

**Решение:** отклонено. OTel даёт unified подход.

### Alternative 3: ELK stack (Elasticsearch + Logstash + Kibana)

**Плюсы:**
- Мощный поиск.
- Большое community.
- Зрелый.

**Минусы:**
- Тяжёлый (Elasticsearch требователен к ресурсам).
- Дорогой (~$5k/месяц за кластер).
- Overkill для нашего объёма.
- Loki проще и дешевле для логов.

**Решение:** отклонено. Loki + Grafana достаточно.

### Alternative 4: Jaeger вместо Tempo

**Плюсы:**
- Зрелый, от CNCF.
- Хорошая поддержка.

**Минусы:**
- Elasticsearch/Cassandra backend (тяжело).
- Не интегрирован с Grafana так же хорошо.
- Tempo роднее для Grafana stack.

**Решение:** отклонено. Tempo — часть Grafana LGTM stack.

### Alternative 5: Собственное observability решение

**Плюсы:**
- Полный контроль.
- Идеальная интеграция с нашим стеком.

**Минусы:**
- 3-6 месяцев разработки.
- Поддержка навсегда.
- Изобретение велосипеда.

**Решение:** отклонено. OTel + Grafana + Langfuse покрывают все нужды.

### Alternative 6: Head-based sampling только

**Плюсы:**
- Просто (решение в приложении).
- Меньше нагрузка на collector.

**Минусы:**
- Errors могут быть sampled out.
- Нет 100% coverage медленных запросов.
- Потеря диагностики в worst moment.

**Решение:** отклонено. Tail-based sampling в collector обязателен.

---

## Action items

Задачи, вытекающие из этого ADR:

- [ ] **OTel SDK integration** — интегрировать `go.opentelemetry.io/otel`
  в gateway:
  - TracerProvider с OTLP exporter
  - MeterProvider с OTLP exporter
  - LoggerProvider с OTLP exporter (Go 1.21+ slog bridge)
  - Resource attributes: service.name, service.version, tenant.environment
  - Context propagation: W3C traceparent

- [ ] **OTel Collector deployment** — развернуть в K8s:
  - Deployment + ConfigMap с pipeline
  - Receivers: otlp (gRPC + HTTP)
  - Processors: batch, memory_limiter, attributes, tail_sampling
  - Exporters: prometheus, loki, otlp (Tempo), langfuse
  - Health checks: livenessProbe, readinessProbe

- [ ] **Prometheus setup**:
  - ServiceMonitor для scrape gateway + collector
  - Recording rules для SLO (см. docs/reliability/slo.md)
  - Alerting rules (см. раздел 9 blueprint.md)
  - Retention: 15 дней local
  - Remote write в Thanos/VictoriaMetrics (future)

- [ ] **Loki setup**:
  - Deployment + S3 backend
  - Retention: 7 дней
  - Structured logs (JSON parser в config)
  - Labels: tenant_id, level, method, outcome

- [ ] **Tempo setup**:
  - Deployment + S3 backend
  - Retention: 30 дней
  - Metrics generator (span metrics → Prometheus)
  - Service graph (service dependencies)

- [ ] **Langfuse setup**:
  - Deployment: PostgreSQL + ClickHouse + S3
  - SDK integration в gateway (Go SDK)
  - Trace linking: langfuse_trace_id ↔ otel_trace_id
  - RBAC: read access для SRE, audit log всех reads

- [ ] **Sanitization hook** — обязательный перед export:
  - PII detection в span attributes
  - PII detection в log fields
  - Автоматическая redaction (замена на <EMAIL_1>)
  - Unit tests для hook

- [ ] **Grafana dashboards**:
  - Overview (RED + SLO)
  - Per-tenant (rate, latency, cost)
  - FinOps (cost per agent, top-N)
  - Dependencies (Redis, Postgres, Vault, SPIRE, LLM)
  - Traces Explorer (drill-down по trace_id)
  - Logs Explorer (grep по tenant_id)

- [ ] **Alertmanager setup**:
  - Routing: critical → PagerDuty, warning → Slack
  - Silencing rules (maintenance windows)
  - Escalation policies
  - Integration: runbook links в alerts

- [ ] **Incident replay CLI** — `mcp-gateway replay`:
  - Input: trace_id
  - Fetch trace из Tempo
  - Fetch logs из Loki (по trace_id)
  - Fetch LLM data из Langfuse (по trace_id)
  - Output: unified timeline
  - Возможность re-run с теми же входами

- [ ] **Documentation**:
  - `docs/observability/README.md` — overview
  - `docs/observability/dashboards.md` — как читать
  - `docs/observability/alerts.md` — что делать
  - `docs/observability/cost-tracking.md` — FinOps
  - `docs/reliability/runbook.md` — обновить с observability

- [ ] **Load testing observability**:
  - Проверить throughput OTel Collector при 10k RPS
  - Проверить storage growth (per signal)
  - Проверить sampling accuracy

---

## References

- [OpenTelemetry Specification](https://opentelemetry.io/docs/specs/otel/)
- [OpenTelemetry Go SDK](https://opentelemetry.io/docs/languages/go/)
- [OpenTelemetry Collector](https://opentelemetry.io/docs/collector/)
- [W3C Trace Context](https://www.w3.org/TR/trace-context/)
- [Grafana LGTM Stack](https://grafana.com/oss/)
- [Prometheus Best Practices](https://prometheus.io/docs/practices/)
- [Loki Best Practices](https://grafana.com/docs/loki/latest/best-practices/)
- [Tempo Documentation](https://grafana.com/docs/tempo/latest/)
- [Langfuse Documentation](https://langfuse.com/docs)
- [Google SRE Book: Monitoring](https://sre.google/sre-book/monitoring-distributed-systems/)
- [Google SRE Workbook: Alerting](https://sre.google/workbook/alerting-on-slos/)
- [Tail-based Sampling in OTel](https://opentelemetry.io/docs/concepts/sampling/)
- [NIST SP 800-92: Log Management](https://csrc.nist.gov/publications/detail/sp/800-92/final)

---

## Related ADRs

- [ADR-0001: SPIFFE/SPIRE для mTLS](0001-use-spiffe-for-mtls.md) — SPIFFE ID в span attributes
- [ADR-0002: HMAC hash-chain для audit log](0002-hmac-hash-chain-for-audit.md) — audit verify metrics
- [ADR-0003: Redis для rate limiting](0003-redis-for-rate-limiting.md) — rate limit metrics
- [ADR-0004: tenant_id в context](0004-tenant-id-in-context.md) — tenant_id в spans, logs, metrics
- [ADR-0005: gobreaker для circuit breaker](0005-circuit-breaker-library-choice.md) — breaker state metrics
- [ADR-0007: Prompt A/B testing via Langfuse](0007-prompt-ab-testing.md) (TBD) — использует Langfuse из этого ADR
- [ADR-0009: Cost attribution per agent](0009-cost-attribution-per-agent.md) (TBD) — использует metrics layer из этого ADR