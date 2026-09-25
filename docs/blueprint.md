# MCP Gateway: Production Blueprint

- **Status:** Living Document
- **Version:** 3.0
- **Last Updated:** 2026-09-25
- **Author:** Roman Sokolov (Architect)
- **Audience:** Architects, CTO, InfoSec, SRE, Product Owners, Finance

---

## Содержание

1. [Проблема и контекст](#1-проблема-и-контекст)
2. [Целевая архитектура](#2-целевая-архитектура)
3. [Ключевые архитектурные решения](#3-ключевые-архитектурные-решения)
4. [Безопасность и compliance](#4-безопасность-и-compliance)
5. [Надёжность и SLO](#5-надёжность-и-slo)
6. [Multi-tenancy](#6-multi-tenancy)
7. [FinOps и Unit Economics](#7-finops-и-unit-economics)
8. [Deployment](#8-deployment)
9. [Observability](#9-observability)
10. [Roadmap и ограничения](#10-roadmap-и-ограничения)
11. [Ссылки](#11-ссылки)

---

## 1. Проблема и контекст

### 1.1. Что такое MCP Gateway

**MCP Gateway** — это корпоративный шлюз для трафика протокола
**Model Context Protocol (MCP)**. MCP — открытый стандарт,
позволяющий AI-агентам (Claude Desktop, IDE-плагины, кастомные
агенты) вызывать инструменты и читать ресурсы у внешних сервисов.

```
    ┌──────────────┐    MCP     ┌──────────────┐    MCP     ┌──────────────┐
    │              │  (JSON-RPC │              │            │              │
    │  AI Agent    │ ────────► │ MCP Gateway  │ ─────────► │ MCP Server   │
    │  (client)    │  2.0/SSE)  │              │            │  (tools,     │
    │              │            │              │            │  resources)  │
    └──────────────┘            └──────────────┘            └──────────────┘
                                       │
                                       │ HTTPS
                                       ▼
                                ┌──────────────┐
                                │  LLM API     │
                                │  (GigaChat,  │
                                │  YandexGPT,  │
                                │  Ollama)     │
                                └──────────────┘
```

### 1.2. Почему PoC недостаточно

Первая версия gateway (PoC) решала базовую задачу: проксирование
MCP-запросов от клиента к upstream. Она **работала в тестах**, но
при попытке внедрения в enterprise упиралась в **пять проблем**:

```
    ┌──────────────────────────────────────────────────────────────┐
    │  Проблема 1: Безопасность                                    │
    ├──────────────────────────────────────────────────────────────┤
    │                                                              │
    │  PoC: самоподписанные сертификаты, нет проверки identity     │
    │                                                              │
    │  В production:                                               │
    │  • Нужна mTLS с проверяемой identity workload'ов             │
    │  • Identity должна быть переносима между средами             │
    │  • Автоматическая ротация сертификатов без рестарта          │
    │                                                              │
    │  Решение: SPIFFE/SPIRE (ADR-0001)                            │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘

    ┌──────────────────────────────────────────────────────────────┐
    │  Проблема 2: Compliance                                      │
    ├──────────────────────────────────────────────────────────────┤
    │                                                              │
    │  PoC: plain text логи, без PII redaction                     │
    │                                                              │
    │  В production:                                               │
    │  • PII не должны покидать периметр                           │
    │  • Каждое действие — в audit log                             │
    │  • Audit log не должен быть подделываемым                    │
    │  • Соответствие 152-ФЗ, GDPR, PCI DSS, HIPAA                 │
    │                                                              │
    │  Решение: HMAC hash-chain (ADR-0002) + PII redaction         │
    │  (ADR-0009) + Key management (ADR-0010)                      │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘

    ┌──────────────────────────────────────────────────────────────┐
    │  Проблема 3: Изоляция тенантов                               │
    ├──────────────────────────────────────────────────────────────┤
    │                                                              │
    │  PoC: один глобальный rate limit, один upstream              │
    │                                                              │
    │  В production:                                               │
    │  • Несколько тенантов с разными квотами                      │
    │  • Noisy neighbor не должен ронять других                    │
    │  • Per-tenant circuit breaker                                │
    │  • Изоляция audit log и метрик                               │
    │                                                              │
    │  Решение: tenant_id в context (ADR-0004) + per-tenant        │
    │  rate limit (ADR-0003) + per-tenant breaker (ADR-0005)       │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘

    ┌──────────────────────────────────────────────────────────────┐
    │  Проблема 4: Наблюдаемость                                   │
    ├──────────────────────────────────────────────────────────────┤
    │                                                              │
    │  PoC: логи в stdout, нет метрик                              │
    │                                                              │
    │  В production:                                               │
    │  • SLI/SLO для каждой подсистемы                             │
    │  • Метрики per tenant × method                               │
    │  • Distributed tracing                                       │
    │  • Алерты на деградацию                                      │
    │                                                              │
    │  Решение: SLO (раздел 5) + unified observability             │
    │  stack (ADR-0006)                                            │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘

    ┌──────────────────────────────────────────────────────────────┐
    │  Проблема 5: FinOps и LLM-Ops                                │
    ├──────────────────────────────────────────────────────────────┤
    │                                                              │
    │  PoC: нет учёта затрат, нет управления промптами             │
    │                                                              │
    │  В production:                                               │
    │  • Каждый вызов LLM стоит денег (₽/1k токенов)               │
    │  • Нужен per-tenant AND per-agent billing                    │
    │  • Нужны лимиты для контроля затрат                          │
    │  • Промпты эволюционируют — нужен A/B testing                │
    │  • Деградация промпта должна откатываться автоматически      │
    │                                                              │
    │  Решение: Cost attribution per agent (ADR-0008) +            │
    │  Prompt A/B testing (ADR-0007)                               │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

### 1.3. Целевая аудитория

MCP Gateway предназначен для:

- **Enterprise-компаний**, внедряющих AI-агентов в регулируемой среде.
- **Банков и финансовых организаций** (152-ФЗ, PCI DSS).
- **Госсектора** (152-ФЗ, требования ФСТЭК).
- **Медицины** (HIPAA-аналог в РФ — 323-ФЗ).
- **SaaS-платформ**, предоставляющих агентные сервисы клиентам.

---

## 2. Целевая архитектура

### 2.1. C4 Context (уровень 1)

```
    ┌──────────────────────────────────────────────────────────────┐
    │                                                              │
    │                       ┌─────────────────┐                    │
    │                       │                 │                    │
    │                       │   AI Client     │                    │
    │                       │   (Claude       │                    │
    │                       │    Desktop,     │                    │
    │                       │    IDE plugin,  │                    │
    │                       │    custom agent)│                    │
    │                       │                 │                    │
    │                       └────────┬────────┘                    │
    │                                │                             │
    │                                │ MCP over mTLS               │
    │                                │ (SPIFFE SVID)               │
    │                                │                             │
    │                                ▼                             │
    │   ┌────────────────────────────────────────────────────┐     │
    │   │                                                    │     │
    │   │              MCP Gateway                           │     │
    │   │                                                    │     │
    │   │   Единая точка входа для AI-агентов.               │     │
    │   │   Управляет identity, rate limit, audit, PII,      │     │
    │   │   circuit breaker, multi-tenancy, cost tracking.   │     │
    │   │                                                    │     │
    │   └────┬──────────────┬──────────────┬─────────────────┘     │
    │        │              │              │                       │
    │        │              │              │                       │
    │        ▼              ▼              ▼                       │
    │   ┌─────────┐   ┌──────────┐   ┌──────────┐                 │
    │   │ LLM API │   │ MCP      │   │ Legacy   │                 │
    │   │ (Giga-  │   │ Servers  │   │ Systems  │                 │
    │   │  Chat,  │   │ (tools,  │   │ (1C, SAP,│                 │
    │   │ Yandex, │   │ resources│   │  ЕИС)    │                 │
    │   │ Ollama) │   │ )        │   │          │                 │
    │   └─────────┘   └──────────┘   └──────────┘                 │
    │                                                              │
    │   External dependencies:                                     │
    │   • SPIFFE/SPIRE  — identity                                 │
    │   • Redis         — rate limit, breaker state                │
    │   • PostgreSQL    — audit log                                │
    │   • OpenBao       — HMAC keys, API keys, secrets             │
    │   • S3 (WORM)     — root hash publication                    │
    │   • Prometheus    — metrics                                  │
    │   • Langfuse      — LLM observability                        │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

### 2.2. C4 Container (уровень 2)

```
    ┌───────────────────────────────────────────────────────────────────┐
    │                                                                    │
    │   MCP Gateway (Go, distroless container)                          │
    │                                                                    │
    │   ┌──────────────────────────────────────────────────────────┐    │
    │   │                                                          │    │
    │   │                   HTTP/2 Server                           │    │
    │   │                   (Streamable HTTP + SSE)                 │    │
    │   │                                                          │    │
    │   └────────────────────────┬─────────────────────────────────┘    │
    │                            │                                       │
    │   ┌────────────────────────▼─────────────────────────────────┐    │
    │   │                                                          │    │
    │   │              Middleware Pipeline                         │    │
    │   │                                                          │    │
    │   │   1. mTLS + SPIFFE        [ADR-0001]                     │    │
    │   │   2. JWT validation                                       │    │
    │   │   3. Tenant Resolver       [ADR-0004]                    │    │
    │   │   4. Agent Resolver        [ADR-0008]                    │    │
    │   │   5. Rate Limiter          [ADR-0003]                    │    │
    │   │   6. Prompt Resolver       [ADR-0007]                    │    │
    │   │   7. PII Redactor          [ADR-0009]                    │    │
    │   │   8. Circuit Breaker       [ADR-0005]                    │    │
    │   │   9. Audit Logger          [ADR-0002]                    │    │
    │   │  10. Cost Recorder         [ADR-0008]                    │    │
    │   │  11. Upstream Client                                      │    │
    │   │                                                          │    │
    │   └────────────────────────┬─────────────────────────────────┘    │
    │                            │                                       │
    │   ┌────────────────────────┼──────────────────────────────────┐   │
    │   │                        │                                  │   │
    │   │  ┌──────────────┐  ┌───▼──────────┐  ┌────────────────┐  │   │
    │   │  │  MCP         │  │  Upstream    │  │  Audit         │  │   │
    │   │  │  Protocol    │  │  Registry    │  │  Writer        │  │   │
    │   │  │  Handlers    │  │              │  │  (single-writer│  │   │
    │   │  │              │  │              │  │   batching)    │  │   │
    │   │  └──────────────┘  └──────────────┘  └────────────────┘  │   │
    │   │                                                            │   │
    │   │  ┌──────────────┐  ┌──────────────┐  ┌────────────────┐  │   │
    │   │  │  Breaker     │  │  Rate        │  │  PII           │  │   │
    │   │  │  Registry    │  │  Limiter     │  │  Detector      │  │   │
    │   │  │              │  │              │  │  (regex+NER)   │  │   │
    │   │  └──────────────┘  └──────────────┘  └────────────────┘  │   │
    │   │                                                            │   │
    │   │  ┌──────────────┐  ┌──────────────┐  ┌────────────────┐  │   │
    │   │  │  Prompt      │  │  Cost        │  │  OpenBao       │  │   │
    │   │  │  Resolver    │  │  Recorder    │  │  Client        │  │   │
    │   │  │  (Langfuse)  │  │              │  │                │  │   │
    │   │  └──────────────┘  └──────────────┘  └────────────────┘  │   │
    │   │                                                            │   │
    │   └────────────────────────┬───────────────────────────────────┘   │
    │                            │                                       │
    └────────────────────────────┼───────────────────────────────────────┘
                                 │
        ┌────────────┬───────────┼────────────┬─────────────┬─────────┐
        │            │           │            │             │         │
        ▼            ▼           ▼            ▼             ▼         ▼
    ┌────────┐  ┌────────┐  ┌────────┐  ┌────────┐  ┌──────────┐ ┌───────┐
    │ Redis  │  │Postgres│  │OpenBao │  │SPIRE   │  │ S3       │ │Lang-  │
    │        │  │        │  │        │  │Agent   │  │ (WORM)   │ │fuse   │
    │ • rate │  │ • audit│  │ • HMAC │  │        │  │ • root   │ │       │
    │   limit│  │   log  │  │   keys │  │ • SVID │  │   hash   │ │ • LLM │
    │ • CB   │  │        │  │ • API  │  │        │  │   publi- │ │   obs │
    │   state│  │        │  │   keys │  │        │  │   cation │ │       │
    └────────┘  └────────┘  └────────┘  └────────┘  └──────────┘ └───────┘
```

### 2.3. C4 Container with Cost Annotations

Та же C4 Container диаграмма, но с аннотациями стоимости на каждом
компоненте. Позволяет **быстро увидеть, где деньги** и **принимать
архитектурные решения с учётом цены**.

**Baseline для расчёта:** 100 RPS sustained, ~8.6M calls/day,
~260M calls/month, средний call = 2k input + 500 output tokens,
модель GigaChat Pro.

```
    ┌───────────────────────────────────────────────────────────────────────┐
    │                                                                        │
    │   MCP Gateway — C4 Container with Cost Annotations                     │
    │   Baseline: 100 RPS, ~260M calls/month                                 │
    │                                                                        │
    │   ┌──────────────────────────────────────────────────────────────┐     │
    │   │                                                                │     │
    │   │   Client Side                        Cost: 0 ₽ (клиент платит) │     │
    │   │                                                                │     │
    │   │   ┌──────────────────┐                                         │     │
    │   │   │   AI Client      │                                         │     │
    │   │   └────────┬─────────┘                                         │     │
    │   │            │                                                   │     │
    │   │            │ mTLS (SPIFFE SVID)                                │     │
    │   │            │ Cost: 0 ₽ (бесплатно)                              │     │
    │   │            │                                                   │     │
    │   └────────────┼───────────────────────────────────────────────────┘     │
    │                │                                                        │
    │                ▼                                                        │
    │   ┌──────────────────────────────────────────────────────────────┐     │
    │   │                                                                │     │
    │   │   Gateway (Zone 1: DMZ)                                       │     │
    │   │                                                                │     │
    │   │   ┌──────────────────────────────────────────────────────┐    │     │
    │   │   │                                                        │    │     │
    │   │   │   MCP Gateway (Go)                                     │    │     │
    │   │   │                                                        │    │     │
    │   │   │   ┌────────────────────────────────────────────────┐ │    │     │
    │   │   │   │  Middleware Pipeline                            │ │    │     │
    │   │   │   │                                                 │ │    │     │
    │   │   │   │  • mTLS + SPIFFE ............ 0 ₽               │ │    │     │
    │   │   │   │  • JWT validation ........... 0 ₽               │ │    │     │
    │   │   │   │  • Tenant/Agent resolver .... 0 ₽               │ │    │     │
    │   │   │   │  • Rate limiter ............. 0 ₽ (Redis ниже)  │ │    │     │
    │   │   │   │  • Prompt resolver .......... 0 ₽ (Langfuse)    │ │    │     │
    │   │   │   │  • PII redaction ............ 0 ₽ (CPU-bound)   │ │    │     │
    │   │   │   │  • Circuit breaker .......... 0 ₽ (in-memory)   │ │    │     │
    │   │   │   │  • Audit logger ............. 0 ₽ (Postgres)    │ │    │     │
    │   │   │   │  • Cost recorder ............ 0 ₽ (Prometheus)  │ │    │     │
    │   │   │   │  • Upstream client .......... 0 ₽               │ │    │     │
    │   │   │   │                                                 │ │    │     │
    │   │   │   └────────────────────────────────────────────────┘ │    │     │
    │   │   │                                                        │    │     │
    │   │   │   Compute Cost:                                        │    │     │
    │   │   │   • 2 vCPU / 4 GB RAM per pod                          │    │     │
    │   │   │   • 2-10 pods (HPA on CPU + inflight_requests)         │    │     │
    │   │   │   • ~4,500 ₽/pod/месяц                                 │    │     │
    │   │   │   • Среднее: 5 pods × 4,500 = 22,500 ₽/месяц           │    │     │
    │   │   │   • Per 1M calls: ~2.5 ₽                               │    │     │
    │   │   │                                                        │    │     │
    │   │   │   % от общего: ~0.007%                                 │    │     │
    │   │   │   ⚠ Пренебрежимо мало                                  │    │     │
    │   │   │                                                        │    │     │
    │   │   └──────────────────────────────────────────────────────┘    │     │
    │   │                                                                │     │
    │   └────────────────────────┬───────────────────────────────────────┘     │
    │                            │                                            │
    │                            │ mTLS                                       │
    │                            │                                            │
    │   ┌────────────────────────┼───────────────────────────────────────┐    │
    │   │                        │                                       │    │
    │   │   Backend (Zone 2)     │                                       │    │
    │   │                        ▼                                       │    │
    │   │   ┌──────────────────┐  ┌──────────────────┐  ┌────────────┐   │    │
    │   │   │                  │  │                  │  │            │   │    │
    │   │   │   Redis          │  │   PostgreSQL     │  │  OpenBao   │   │    │
    │   │   │                  │  │                  │  │            │   │    │
    │   │   │   HA, 2 GB,      │  │   HA, 100 GB,    │  │  HA, 3     │   │    │
    │   │   │   4 vCPU         │  │   2 vCPU, 8 GB   │  │  nodes     │   │    │
    │   │   │                  │  │                  │  │  (Raft)    │   │    │
    │   │   │   ~19,000 ₽/мес  │  │   ~45,000 ₽/мес  │  │ ~30,000 ₽/ │   │    │
    │   │   │                  │  │                  │  │   мес      │   │    │
    │   │   │   Per 1M calls:  │  │   Per 1M calls:  │  │            │   │    │
    │   │   │   ~0.13 ₽        │  │   ~6 ₽           │  │  Fixed:    │   │    │
    │   │   │                  │  │                  │  │  ~0.009%   │   │    │
    │   │   │   % total:       │  │   % total:       │  │            │   │    │
    │   │   │   ~0.006%        │  │   ~0.014%        │  │            │   │    │
    │   │   │                  │  │                  │  │            │   │    │
    │   │   └──────────────────┘  └──────────────────┘  └────────────┘   │    │
    │   │                                                                │    │
    │   │   ┌──────────────────┐  ┌──────────────────┐                   │    │
    │   │   │                  │  │                  │                   │    │
    │   │   │   S3 WORM        │  │   SPIRE Server   │                   │    │
    │   │   │   (root hash)    │  │   (identity)     │                   │    │
    │   │   │                  │  │                  │                   │    │
    │   │   │   ~37,500 ₽/мес  │  │   ~25,000 ₽/мес  │                   │    │
    │   │   │   % total:       │  │   Fixed:         │                   │    │
    │   │   │   ~0.011%        │  │   ~0.008%        │                   │    │
    │   │   │                  │  │                  │                   │    │
    │   │   └──────────────────┘  └──────────────────┘                   │    │
    │   │                                                                │    │
    │   │   ┌──────────────────────────────────────────────────────┐    │    │
    │   │   │                                                        │    │    │
    │   │   │   Observability Stack                                  │    │    │
    │   │   │   (Prometheus + Grafana + Loki + Tempo + Langfuse)     │    │    │
    │   │   │                                                        │    │    │
    │   │   │   • ~50,000-120,000 ₽/месяц (managed)                  │    │    │
    │   │   │   • Fixed: ~0.02%                                      │    │    │
    │   │   │                                                        │    │    │
    │   │   └──────────────────────────────────────────────────────┘    │    │
    │   │                                                                │    │
    │   └────────────────────────┬───────────────────────────────────────┘    │
    │                            │                                            │
    │                            │ HTTPS + API key                            │
    │                            │ Cost: egress ~560 ₽ / 1M calls             │
    │                            │                                            │
    │   ┌────────────────────────┼───────────────────────────────────────┐    │
    │   │                        │                                       │    │
    │   │   Upstream (Zone 3)    ▼                                       │    │
    │   │                                                                │    │
    │   │   ┌──────────────────┐  ┌──────────────────┐  ┌────────────┐   │    │
    │   │   │                  │  │                  │  │            │   │    │
    │   │   │   GigaChat       │  │   YandexGPT      │  │  Ollama    │   │    │
    │   │   │   (Pro/Max/Lite) │  │   (Pro/Lite)     │  │ (self-     │   │    │
    │   │   │                  │  │                  │  │  hosted)   │   │    │
    │   │   │   ⚠️ 99.5% всей  │  │                  │  │            │   │    │
    │   │   │   стоимости!     │  │                  │  │  Альтерна- │   │    │
    │   │   │                  │  │                  │  │  тива:     │   │    │
    │   │   │   Pro:           │  │   Pro:           │  │  ~0.6 ₽/   │   │    │
    │   │   │   1.25 ₽/call    │  │   2.00 ₽/call    │  │  call      │   │    │
    │   │   │                  │  │                  │  │            │   │    │
    │   │   │   Max:           │  │   Lite:          │  │  GPU       │   │    │
    │   │   │   1.63 ₽/call    │  │   0.50 ₽/call    │  │  ~300 ₽/   │   │    │
    │   │   │                  │  │                  │  │  час       │   │    │
    │   │   │   Lite:          │  │                  │  │            │   │    │
    │   │   │   0.16 ₽/call    │  │                  │  │  Требует   │   │    │
    │   │   │                  │  │                  │  │  ML ops    │   │    │
    │   │   │   % total:       │  │   % total:       │  │            │   │    │
    │   │   │   ~99.5%         │  │   зависит от mix │  │  % total:  │   │    │
    │   │   │   ⚠️ КРИТИЧНО    │  │                  │  │  ~0.05%    │   │    │
    │   │   └──────────────────┘  └──────────────────┘  └────────────┘   │    │
    │   │                                                                │    │
    │   └────────────────────────────────────────────────────────────────┘    │
    │                                                                        │
    └───────────────────────────────────────────────────────────────────────┘
```

#### Cost summary table

```
    ┌──────────────────────────┬─────────────────┬─────────────┬──────────┐
    │ Component                │ ₽/месяц         │ ₽/1M calls  │ % total  │
    ├──────────────────────────┼─────────────────┼─────────────┼──────────┤
    │                          │                 │             │          │
    │ LLM API (GigaChat Pro)   │ ~325,000,000 ₽  │ 1,250,000 ₽ │ 99.50%   │
    │ Networking (egress)      │ ~145,000 ₽      │ ~560 ₽      │ 0.045%   │
    │ PostgreSQL (HA)          │ ~45,000 ₽       │ ~6 ₽        │ 0.014%   │
    │ S3 (WORM archive)        │ ~37,500 ₽       │ ~0.6 ₽      │ 0.011%   │
    │ Observability Stack      │ ~50,000-120,000 ₽│ fixed      │ 0.02%    │
    │ OpenBao (HA)             │ ~30,000 ₽       │ fixed       │ 0.009%   │
    │ SPIRE Server (HA)        │ ~25,000 ₽       │ fixed       │ 0.008%   │
    │ Gateway compute          │ ~22,500 ₽       │ ~2.5 ₽      │ 0.007%   │
    │ Redis (HA)               │ ~19,000 ₽       │ ~0.13 ₽     │ 0.006%   │
    ├──────────────────────────┼─────────────────┼─────────────┼──────────┤
    │ TOTAL                    │ ~325,700,000 ₽  │ 1,250,570 ₽ │ 100%     │
    └──────────────────────────┴─────────────────┴─────────────┴──────────┘
```

#### Cost-driven architecture decisions

```
    ┌──────────────────────────────────────────────────────────────┐
    │                                                              │
    │  ✅ Высокий ROI (делать):                                     │
    │                                                              │
    │  • Model routing (Lite vs Pro) ............. ROI ~320,000%   │
    │  • Prompt optimization ..................... ROI ~65,000%    │
    │  • Batch API для async ..................... ROI ~25,000%    │
    │  • Response caching ........................ ROI ~19,000%    │
    │                                                              │
    ├──────────────────────────────────────────────────────────────┤
    │                                                              │
    │  ❌ Низкий ROI (не делать):                                   │
    │                                                              │
    │  • Переписать gateway на Rust ............... ROI ~0.75%/год │
    │  • Оптимизировать PII regex ................. ROI ~4.8%/год  │
    │  • Уменьшить PostgreSQL hot storage ......... ROI ~12%/год   │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

### 2.4. Поток запроса tools/call

```
    ┌─────────────────────────────────────────────────────────────┐
    │                                                             │
    │   1. Client → Gateway                                       │
    │      ├─ mTLS handshake (SPIFFE SVID)                        │
    │      └─ POST /mcp  { "method": "tools/call", ... }          │
    │                                                             │
    │   2. mTLS + SPIFFE validation          [ADR-0001]           │
    │      ├─ Проверка SVID (подпись, TTL, trust domain)          │
    │      ├─ Извлечение SPIFFE ID                                │
    │      └─ Проверка против SPIFFE ID allowlist                 │
    │                                                             │
    │   3. JWT validation                                         │
    │      ├─ Проверка подписи (JWKS от IdP)                      │
    │      ├─ Проверка exp, nbf, iss, aud                         │
    │      └─ Извлечение claim tenant_id                          │
    │                                                             │
    │   4. Tenant Resolver                   [ADR-0004]           │
    │      ├─ tenant_id из JWT (приоритет)                        │
    │      ├─ Валидация против allowlist                          │
    │      ├─ Проверка: SPIFFE ID авторизован для tenant_id       │
    │      └─ tenant.WithID(ctx, tenant_id)                       │
    │                                                             │
    │   5. Agent Resolver                    [ADR-0008]           │
    │      ├─ agent_id из JWT claim (приоритет)                   │
    │      ├─ Fallback: X-Agent-ID header                         │
    │      ├─ Fallback: "unknown" + warning metric                │
    │      └─ agent.WithID(ctx, agent_id)                         │
    │                                                             │
    │   6. Rate Limit check                  [ADR-0003]           │
    │      ├─ Key: rl:{tenant}:tools_call:60s                     │
    │      ├─ Lua: ZREMRANGEBYSCORE + PEXPIRE + ZCARD + ZADD      │
    │      ├─ allowed=1 → continue, allowed=0 → 429 + Retry-After │
    │      └─ Headers: X-RateLimit-Limit/Remaining/Reset          │
    │                                                             │
    │   7. Prompt Resolver                   [ADR-0007]           │
    │      ├─ Fetch prompt from Langfuse (cache TTL 5m)           │
    │      ├─ A/B split: hash(tenant, agent, request_id) % 100    │
    │      ├─ Select label: "prod-a" or "prod-b"                  │
    │      └─ Compile prompt with variables                       │
    │                                                             │
    │   8. PII Redaction                     [ADR-0009]           │
    │      ├─ Layer 1: Regex (email, phone, SSN, IBAN, card)      │
    │      ├─ Layer 2: NER (Person, Location, Organization)       │
    │      ├─ Layer 3: Custom per-tenant patterns                 │
    │      ├─ Mask: <EMAIL_1>, <PERSON_2>                         │
    │      └─ Store mapping in request-scoped memory              │
    │                                                             │
    │   9. Circuit Breaker check             [ADR-0005]           │
    │      ├─ Key: {tenant}:{upstream}                            │
    │      ├─ State: closed → allow, open → 503, half-open → N    │
    │      └─ Retry (3x exponential backoff) внутри breaker'а     │
    │                                                             │
    │  10. Upstream call                                          │
    │      ├─ HTTPS to LLM API / MCP server                       │
    │      ├─ Timeout: context.WithTimeout(ctx, 30s)              │
    │      └─ Response: stream or JSON                            │
    │                                                             │
    │  11. PII Unmask                                             │
    │      ├─ Reverse mapping <EMAIL_1> → original                │
    │      └─ Streaming-safe: overlap buffer 256 bytes            │
    │                                                             │
    │  12. Cost Recorder                     [ADR-0008]           │
    │      ├─ Extract tokens from LLM response                    │
    │      ├─ Compute cost по pricing config                      │
    │      ├─ Record mcp_llm_cost_rub_total{tenant, agent, ...}   │
    │      └─ Update budget metrics                                │
    │                                                             │
    │  13. Audit Log                         [ADR-0002]           │
    │      ├─ Entry: {Seq, Timestamp, TenantID, AgentID, Actor,   │
    │      │          Action, Resource, Outcome, Hash, HMAC}      │
    │      ├─ HMAC key from OpenBao (ADR-0010)                    │
    │      └─ Single-writer batching → Postgres                   │
    │                                                             │
    │  14. Response → Client                                      │
    │      ├─ HTTP 200 + stream/JSON                              │
    │      └─ Headers: X-RateLimit-*, X-Request-ID, traceparent   │
    │                                                             │
    └─────────────────────────────────────────────────────────────┘
```

### 2.5. Слои доверия (Trust Boundaries)

```
    ┌──────────────────────────────────────────────────────────────┐
    │                                                              │
    │  Zone 0: Untrusted Internet                                  │
    │  ────────────────────────────                                │
    │                                                              │
    │  • AI Client (может быть compromised)                        │
    │                                                              │
    │  Trust boundary: mTLS + SPIFFE SVID                          │
    │                                                              │
    ├──────────────────────────────────────────────────────────────┤
    │                                                              │
    │  Zone 1: DMZ (Gateway)                                       │
    │  ─────────────────────                                       │
    │                                                              │
    │  • MCP Gateway pods (distroless, non-root)                   │
    │  • SPIRE Agent (sidecar или DaemonSet)                       │
    │  • PII NER sidecar (Natasha, gRPC)                           │
    │                                                              │
    │  Trust boundary: mTLS + AppRole к backend                    │
    │                                                              │
    ├──────────────────────────────────────────────────────────────┤
    │                                                              │
    │  Zone 2: Backend (Internal)                                  │
    │  ──────────────────────────                                  │
    │                                                              │
    │  • Redis (rate limit + breaker state)                        │
    │  • PostgreSQL (audit log)                                    │
    │  • OpenBao (HMAC keys, API keys, secrets)                    │
    │  • SPIRE Server (identity issuance)                          │
    │  • Prometheus (metrics scrape)                               │
    │  • Langfuse (LLM observability)                              │
    │                                                              │
    │  Trust boundary: HTTPS + mTLS к upstream                     │
    │                                                              │
    ├──────────────────────────────────────────────────────────────┤
    │                                                              │
    │  Zone 3: Upstream (External, UNTRUSTED)                      │
    │  ───────────────────────────────────────                     │
    │                                                              │
    │  • LLM API (GigaChat, YandexGPT, Ollama)                     │
    │  • MCP Servers (tools, resources)                            │
    │  • Legacy Systems (1C, SAP, ЕИС)                             │
    │                                                              │
    │  ⚠ Responses considered UNTRUSTED INPUT (prompt injection)   │
    │                                                              │
    │  Trust boundary: HTTPS + API key + rate limit + breaker      │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

---

## 3. Ключевые архитектурные решения

Все ключевые решения зафиксированы в **Architecture Decision Records (ADR)**.
Каждый ADR описывает контекст, решение, обоснование, последствия и
рассмотренные альтернативы.

### 3.1. Сводная таблица ADR

```
    ┌──────┬─────────────────────────────┬─────────────────────────────┐
    │ ADR  │ Тема                        │ Ключевое решение            │
    ├──────┼─────────────────────────────┼─────────────────────────────┤
    │ 0001 │ Identity / mTLS             │ SPIFFE/SPIRE                │
    │      │                             │ • SVID через Workload API   │
    │      │                             │ • Attestation через K8s SA  │
    │      │                             │ • Автоматическая ротация    │
    │      │                             │ • Federation для внешних    │
    ├──────┼─────────────────────────────┼─────────────────────────────┤
    │ 0002 │ Audit log                   │ HMAC hash-chain             │
    │      │                             │ • SHA-256 цепочка           │
    │      │                             │ • HMAC-SHA256 (ключ в       │
    │      │                             │   OpenBao)                  │
    │      │                             │ • Canonical serialization   │
    │      │                             │ • Single-writer batching    │
    │      │                             │ • Off-site root hash (S3)   │
    ├──────┼─────────────────────────────┼─────────────────────────────┤
    │ 0003 │ Rate limiting               │ Redis + sliding window      │
    │      │                             │ • Lua-скрипт для атомарности│
    │      │                             │ • Per-tenant × per-method   │
    │      │                             │ • Fail-open/closed per tier │
    ├──────┼─────────────────────────────┼─────────────────────────────┤
    │ 0004 │ Multi-tenancy               │ tenant_id в context.Context │
    │      │                             │ • Типизированный TenantID   │
    │      │                             │ • Приватный ключ контекста  │
    │      │                             │ • Двойная проверка          │
    │      │                             │   (JWT + SPIFFE ID)         │
    ├──────┼─────────────────────────────┼─────────────────────────────┤
    │ 0005 │ Circuit breaker             │ gobreaker per-tenant        │
    │      │                             │ • Per-tenant × per-upstream │
    │      │                             │ • Retry внутри breaker'а    │
    │      │                             │ • 4xx не считается failure  │
    ├──────┼─────────────────────────────┼─────────────────────────────┤
    │ 0006 │ Observability               │ Unified observability stack │
    │      │                             │ • OpenTelemetry (unified)   │
    │      │                             │ • Prometheus (metrics)      │
    │      │                             │ • Loki (logs)               │
    │      │                             │ • Tempo (traces)            │
    │      │                             │ • Langfuse (LLM-specific)   │
    │      │                             │ • Tail-based sampling       │
    ├──────┼─────────────────────────────┼─────────────────────────────┤
    │ 0007 │ Prompt A/B testing          │ Langfuse + labels           │
    │      │                             │ • Prompt versioning         │
    │      │                             │ • Deterministic hash split  │
    │      │                             │ • Auto-rollback             │
    │      │                             │ • LLM-as-a-Judge            │
    ├──────┼─────────────────────────────┼─────────────────────────────┤
    │ 0008 │ Cost attribution            │ Per (tenant, agent)         │
    │      │                             │ • agent_id в метриках       │
    │      │                             │ • Grafana dashboards        │
    │      │                             │ • Rule-based anomaly        │
    │      │                             │ • Auto-throttle             │
    ├──────┼─────────────────────────────┼─────────────────────────────┤
    │ 0009 │ PII redaction               │ Multi-layer pipeline        │
    │      │                             │ • Regex (structured PII)    │
    │      │                             │ • NER (unstructured)        │
    │      │                             │ • Custom per-tenant rules   │
    │      │                             │ • Reversible placeholders   │
    │      │                             │ • Streaming-safe unmask     │
    ├──────┼─────────────────────────────┼─────────────────────────────┤
    │ 0010 │ Key management              │ OpenBao (MPL 2.0)           │
    │      │                             │ • AppRole auth              │
    │      │                             │ • RBAC policies             │
    │      │                             │ • HMAC rotation 90 дней     │
    │      │                             │ • Sealed backup в S3        │
    │      │                             │ • Incident response         │
    └──────┴─────────────────────────────┴─────────────────────────────┘
```

### 3.2. Статус ADR

```
    ┌──────┬─────────────────────────────┬─────────────────────────────┐
    │ ADR  │ Тема                        │ Статус                      │
    ├──────┼─────────────────────────────┼─────────────────────────────┤
    │ 0001 │ Identity / mTLS             │ ✅ Accepted                 │
    │ 0002 │ Audit log                   │ ✅ Accepted                 │
    │ 0003 │ Rate limiting               │ ✅ Accepted                 │
    │ 0004 │ Multi-tenancy               │ ✅ Accepted                 │
    │ 0005 │ Circuit breaker             │ ✅ Accepted                 │
    │ 0006 │ Observability stack         │ ✅ Accepted                 │
    │ 0007 │ Prompt A/B testing          │ 🚧 In Progress              │
    │ 0008 │ Cost attribution per agent  │ 🚧 In Progress              │
    │ 0009 │ PII redaction               │ 📋 Planned                  │
    │ 0010 │ Key management (OpenBao)    │ 📋 Planned                  │
    └──────┴─────────────────────────────┴─────────────────────────────┘

    Примечание: ADR-0007 и ADR-0008 помечены «In Progress»,
    потому что их реализация требует интеграции с Langfuse (ADR-0006).
    ADR-0009 и ADR-0010 — «Planned», реализация в Phase 3 Roadmap.
```

### 3.3. Почему именно эти решения

Каждое решение принято с учётом **индустриальных стандартов** и
**enterprise-требований**:

- **SPIFFE** — стандарт CNCF, используется в production Google,
  Uber, Bloomberg, HashiCorp.
- **HMAC hash-chain** — соответствие NIST SP 800-92, принимается
  аудиторами PCI DSS.
- **Redis + Lua** — стандарт rate limiting (Cloudflare, Stripe,
  GitHub).
- **context.Context** — идиоматичен для Go, рекомендован Google.
- **gobreaker** — используется в production Sony, Mercari, LINE.
- **OpenTelemetry** — стандарт CNCF для observability.
- **Langfuse** — open-source LLM observability, self-hosted.
- **OpenBao** — MPL 2.0, Linux Foundation governance, fork Vault.

**Дополнительные принципы:**

```
    ┌──────────────────────────────────────────────────────────────┐
    │                                                              │
    │  • Open source first — избегаем vendor lock                  │
    │    (OpenBao вместо Vault из-за BSL 1.1)                      │
    │  • Zero PII to LLM — defense in depth для compliance         │
    │  • Cost transparency — FinOps на уровне (tenant, agent)      │
    │  • Safe prompt evolution — A/B testing + auto-rollback       │
    │  • Unified observability — один trace_id сквозь все сигналы  │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

Все решения **обоснованы в ADR** с рассмотрением альтернатив. Это
отличает enterprise-архитектуру от PoC-решений «по вкусу».

---

## 4. Безопасность и compliance

### 4.1. Модель угроз (краткая версия)

Полная STRIDE-модель — в `docs/security/threat-model.md`.

```
    ┌──────────────────────────────────────────────────────────────┐
    │  Активы (что защищаем):                                      │
    ├──────────────────────────────────────────────────────────────┤
    │                                                              │
    │  • PII в промптах (emails, телефоны, SSN, IBAN, ФИО)         │
    │  • API-ключи upstream (GigaChat, YandexGPT)                  │
    │  • HMAC-ключи audit log                                      │
    │  • SPIFFE SVID (сертификаты identity)                        │
    │  • Tenant config (rate limits, upstream endpoints)           │
    │  • Agent config (budgets, throttling rules)                  │
    │  • Audit log (кто, когда, что сделал)                        │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘

    ┌──────────────────────────────────────────────────────────────┐
    │  Угрозы (по STRIDE) — 25 идентифицировано:                   │
    ├──────────────────────────────────────────────────────────────┤
    │                                                              │
    │  S — Spoofing (4)                                            │
    │    S-01: Подмена SPIFFE ID                                   │
    │    S-02: Подмена JWT                                         │
    │    S-03: Подмена tenant_id / agent_id                        │
    │    S-04: Подмена gateway под'а                               │
    │                                                              │
    │  T — Tampering (6)                                           │
    │    T-01: MITM modification                                   │
    │    T-02: SQL injection + audit tampering                     │
    │    T-03: Audit log tampering (DBA)                           │
    │    T-04: Redis state tampering                               │
    │    T-05: S3 root hash tampering                              │
    │    T-06: MITM on upstream                                    │
    │                                                              │
    │  R — Repudiation (2)                                         │
    │    R-01: Repudiation of action                               │
    │    R-02: Repudiation of config change                        │
    │                                                              │
    │  I — Information Disclosure (7)                              │
    │    I-01: PII leak to LLM                                     │
    │    I-02: API key leakage                                     │
    │    I-03: Cross-tenant data access                            │
    │    I-04: PII leak through logs                               │
    │    I-05: Memory dump extraction                              │
    │    I-06: Prompt Injection (indirect) — AI-specific           │
    │    I-07: LLM Response Poisoning                              │
    │                                                              │
    │  D — Denial of Service (4)                                   │
    │    D-01: Noisy neighbor                                      │
    │    D-02: Cascading failure                                   │
    │    D-03: ReDoS                                               │
    │    D-04: Slowloris + reconnection storm                      │
    │                                                              │
    │  E — Elevation of Privilege (4)                              │
    │    E-01: Cross-tenant escalation                             │
    │    E-02: Container escape                                    │
    │    E-03: ServiceAccount compromise                           │
    │    E-04: OpenBao privilege escalation                        │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

### 4.2. Защита от угроз (связь с ADR)

```
    ┌──────────────────┬──────────────────────────────────────────┐
    │ Угроза           │ Митигация                                │
    ├──────────────────┼──────────────────────────────────────────┤
    │ S-01, S-02       │ ADR-0001: SPIFFE/SPIRE + JWT validation  │
    │ S-03             │ ADR-0004 + ADR-0008: X-Tenant-ID только  │
    │                  │ в dev, agent_id из JWT                    │
    │ S-04             │ ADR-0001: WorkloadAttestor + image SHA   │
    │ T-01, T-06       │ ADR-0001: mTLS TLS 1.3                   │
    │ T-02             │ ADR-0002: parameterized queries + RLS    │
    │ T-03             │ ADR-0002 + ADR-0010: HMAC + OpenBao      │
    │ T-04             │ Redis AUTH + NetworkPolicy               │
    │ T-05             │ ADR-0002: S3 Object Lock COMPLIANCE      │
    │ R-01             │ ADR-0002: подпись actor (SPIFFE ID)      │
    │ R-02             │ GitOps + audit config changes            │
    │ I-01             │ ADR-0009: PII redaction pipeline         │
    │ I-02             │ ADR-0010: OpenBao + no-log               │
    │ I-03, E-01       │ ADR-0004: tenant_id isolation + allowlist│
    │ I-04             │ No-log policy + periodic scan            │
    │ I-05             │ ulimit -c 0 + MLOCK + zeroing buffers    │
    │ I-06             │ FGA/OPA + tool allowlist + output check  │
    │ I-07             │ Certificate pinning + schema validation  │
    │ D-01             │ ADR-0003: per-tenant rate limiting       │
    │ D-02             │ ADR-0005: per-tenant circuit breaker     │
    │ D-03             │ RE2 (no backtracking)                    │
    │ D-04             │ ReadTimeout + IdleTimeout + backoff      │
    │ E-02             │ Distroless + PodSecurityStandards        │
    │ E-03             │ automountServiceAccountToken: false      │
    │ E-04             │ ADR-0010: OpenBao AppRole + RBAC         │
    └──────────────────┴──────────────────────────────────────────┘
```

### 4.3. Compliance mapping

```
    ┌──────────────────────────────────────────────────────────────┐
    │  152-ФЗ (РФ, персональные данные)                            │
    ├──────────────────────────────────────────────────────────────┤
    │                                                              │
    │  • Ст. 18.1 — согласие на обработку ПДн → tenant config     │
    │  • Ст. 19 — меры защиты:                                     │
    │    - mTLS (ADR-0001)                                         │
    │    - шифрование в transit                                    │
    │    - audit log (ADR-0002)                                    │
    │    - PII redaction (ADR-0009)                                │
    │    - key management (ADR-0010, OpenBao)                      │
    │  • Ст. 22 — уведомление РКН → процедура (TBD)                │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘

    ┌──────────────────────────────────────────────────────────────┐
    │  GDPR (EU, General Data Protection Regulation)               │
    ├──────────────────────────────────────────────────────────────┤
    │                                                              │
    │  • Art. 5 — принципы обработки → PII redaction (ADR-0009)    │
    │  • Art. 25 — privacy by design → архитектурное решение       │
    │  • Art. 30 — Records of Processing → audit log (ADR-0002)    │
    │  • Art. 32 — security of processing → mTLS + audit + PII     │
    │  • Art. 33 — breach notification → incident response (TBD)   │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘

    ┌──────────────────────────────────────────────────────────────┐
    │  PCI DSS v4.0 (Payment Card Industry)                        │
    ├──────────────────────────────────────────────────────────────┤
    │                                                              │
    │  • Req. 3 — защита cardholder data → PII redaction           │
    │  • Req. 3.5 — защита ключей:                                 │
    │    - HMAC keys в OpenBao (ADR-0010)                          │
    │    - Rotation 90 дней                                        │
    │    - Sealed backup                                           │
    │  • Req. 3.6 — управление ключами:                            │
    │    - RBAC policies в OpenBao                                 │
    │    - Audit log всех доступов                                 │
    │  • Req. 4 — шифрование при передаче → mTLS (ADR-0001)        │
    │  • Req. 7 — need-to-know access → tenant isolation (ADR-0004)│
    │  • Req. 8 — идентификация → JWT + SPIFFE                     │
    │  • Req. 10 — logging and monitoring:                         │
    │    - 10.2 — audit trail                                      │
    │    - 10.3 — record audit trail entries                       │
    │    - 10.5 — secure audit trails (hash-chain)                 │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘

    ┌──────────────────────────────────────────────────────────────┐
    │  HIPAA (US, Health Insurance Portability and Accountability) │
    ├──────────────────────────────────────────────────────────────┤
    │                                                              │
    │  • §164.308 — administrative safeguards                      │
    │  • §164.312(a) — access control → tenant isolation           │
    │  • §164.312(b) — audit controls → hash-chain audit           │
    │  • §164.312(c) — integrity → HMAC                            │
    │  • §164.312(d) — person authentication → SPIFFE + JWT        │
    │  • §164.312(e) — transmission security → mTLS                │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘

    ┌──────────────────────────────────────────────────────────────┐
    │  NIST SP 800-207 (Zero Trust)                                │
    ├──────────────────────────────────────────────────────────────┤
    │                                                              │
    │  • §2.1 — все источники недоверенные → mTLS на всех границах│
    │  • §2.1 — per-request authentication → JWT + SPIFFE          │
    │  • §3.1 — dynamic policy → per-tenant config                 │
    │  • §3.2 — continuous monitoring → rate limit + breaker       │
    │  • §3.3 — least privilege → tenant isolation + RBAC          │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

### 4.4. Security best practices

```
    ┌──────────────────────────────────────────────────────────────┐
    │  Принципы (12-factor + NIST SP 800-207 Zero Trust):         │
    ├──────────────────────────────────────────────────────────────┤
    │                                                              │
    │  • Zero Trust: не доверять сети, проверять каждый запрос     │
    │  • Least Privilege: минимальные права у каждой компоненты    │
    │  • Defense in Depth: несколько слоёв защиты                  │
    │  • Fail-Secure: при сомнениях — отклонять запрос             │
    │  • Immutable Infrastructure: distroless, non-root            │
    │  • Secret Management: OpenBao для ключей                     │
    │  • No Secrets in Code: секреты только через env / OpenBao    │
    │  • No PII in Logs: логи без PII, redaction прежде всего      │
    │  • Audit Everything: все security-события в audit log        │
    │  • Open Source First: избегаем vendor lock-in                │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

---

## 5. Надёжность и SLO

### 5.1. SLI / SLO

Детальные SLO — в `docs/reliability/slo.md`. Ключевые показатели:

```
    ┌──────────────────────────────────────────────────────────────┐
    │  Availability                                                │
    ├──────────────────────────────────────────────────────────────┤
    │                                                              │
    │  SLI: доля успешных запросов (2xx/3xx) / все запросы         │
    │  Измерение: rate(mcp_requests_total{status!~"5.."}[5m])      │
    │  Окно: 30 дней                                               │
    │                                                              │
    │  SLO: 99.9% (43.2 мин downtime / месяц)                      │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘

    ┌──────────────────────────────────────────────────────────────┐
    │  Latency                                                     │
    ├──────────────────────────────────────────────────────────────┤
    │                                                              │
    │  SLI: p99 latency для tools/call                             │
    │  Измерение: histogram mcp_request_duration_seconds          │
    │                                                              │
    │  SLO:                                                        │
    │  • Без upstream LLM: p99 < 2s                                │
    │  • С upstream LLM:   p99 < 30s                               │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘

    ┌──────────────────────────────────────────────────────────────┐
    │  Error Budget Policy                                         │
    ├──────────────────────────────────────────────────────────────┤
    │                                                              │
    │  • Если budget исчерпан → freeze feature-релизов             │
    │  • Только bug fixes и reliability work                       │
    │  • Burn rate >14.4x за 5m → critical (page on-call)          │
    │  • Burn rate >2x за 1h → warning                             │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

### 5.2. SLO по тенантам

```
    ┌──────────────────────────────────────────────────────────────┐
    │  Tier         Availability   p99 (без LLM)   p99 (с LLM)    │
    ├──────────────────────────────────────────────────────────────┤
    │                                                              │
    │  Enterprise   99.95%         <1s             <20s            │
    │  Standard     99.9%          <2s             <30s            │
    │  Free         best-effort    <5s             <60s            │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

### 5.3. Resilience patterns

```
    ┌──────────────────────────────────────────────────────────────┐
    │  Комбинированная защита от отказов:                          │
    ├──────────────────────────────────────────────────────────────┤
    │                                                              │
    │  1. Rate Limiting (ADR-0003)                                 │
    │     └─ Защита от перегрузки и FinOps                          │
    │                                                              │
    │  2. Circuit Breaker (ADR-0005)                               │
    │     └─ Защита от каскадных отказов                            │
    │                                                              │
    │  3. Retry с exponential backoff                              │
    │     └─ Внутри breaker'а, только idempotent операции           │
    │                                                              │
    │  4. Timeout (context.WithTimeout)                            │
    │     └─ Везде: Redis 50ms, upstream 30s                        │
    │                                                              │
    │  5. Bulkhead (semaphore)                                     │
    │     └─ Ограничение concurrency per tenant                     │
    │                                                              │
    │  6. Fallback                                                 │
    │     └─ Cached response или degraded mode                      │
    │                                                              │
    │  7. Auto-throttle (ADR-0008)                                 │
    │     └─ Автоматическое снижение rate при budget overrun        │
    │                                                              │
    │  8. Auto-rollback prompts (ADR-0007)                         │
    │     └─ Откат промпта при деградации метрик                    │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

---

## 6. Multi-tenancy

### 6.1. Модель изоляции

```
    ┌──────────────────────────────────────────────────────────────┐
    │                                                              │
    │  Tenant — организационная единица (клиент, команда,         │
    │           пользователь) со своими:                           │
    │                                                              │
    │  • Rate limits (ADR-0003)                                    │
    │  • Upstream endpoints (разные LLM провайдеры)                │
    │  • PII policy (GDPR vs HIPAA vs PCI DSS)                     │
    │  • Circuit breaker state (ADR-0005)                          │
    │  • Audit log (изолирован по tenant_id)                       │
    │  • Billing (FinOps per tenant)                               │
    │  • Authorized SPIFFE IDs (какие workload'ы могут обращаться) │
    │                                                              │
    │  Внутри tenant'а может быть много AGENT'ов:                  │
    │  • Каждый агент имеет свой agent_id                          │
    │  • Cost attribution per agent (ADR-0008)                     │
    │  • Budget per agent                                          │
    │  • Auto-throttle per agent при overrun                       │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

### 6.2. Изоляция по слоям

```
    ┌──────────────────────────────────────────────────────────────┐
    │                                                              │
    │   Layer       Isolation mechanism                            │
    │   ───────     ────────────────────────────────────           │
    │                                                              │
    │   Identity    SPIFFE ID namespace + JWT tenant_id claim      │
    │   Agent       agent_id в JWT claim / header (ADR-0008)       │
    │   Context     tenant_id в context.Context (ADR-0004)         │
    │   Rate limit  Key: rl:{tenant}:method:window (ADR-0003)      │
    │   Breaker     Key: {tenant}:{upstream} (ADR-0005)            │
    │   Audit       Column tenant_id + RLS (ADR-0002)              │
    │   PII         Policy per tenant (ADR-0009)                   │
    │   Prompt      A/B split per tenant/agent (ADR-0007)          │
    │   Cost        Label tenant+agent в metrics (ADR-0008)        │
    │   Upstream    Registry: tenant → endpoint mapping            │
    │   Metrics     Labels tenant, agent в Prometheus              │
    │   Logs        Structured logging с tenant_id, agent_id       │
    │   Traces      Span attributes tenant.id, agent.id            │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

### 6.3. Cross-tenant защита

**Двойная проверка** (defense in depth):

```
    ┌──────────────────────────────────────────────────────────────┐
    │                                                              │
    │  1. JWT claim tenant_id                                      │
    │     └─ Подписан IdP, нельзя подменить                        │
    │                                                              │
    │  2. SPIFFE ID → tenant_id mapping                            │
    │     └─ Workload (под, сервис) авторизован для конкретного    │
    │        tenant_id через allowlist в конфиге                   │
    │                                                              │
    │  Оба должны совпасть → запрос разрешён                       │
    │  Иначе → 403 Forbidden + security alert + audit              │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

### 6.4. Пример конфигурации тенантов

```yaml
tenants:
  - id: "acme"
    tier: "enterprise"
    authorized_spiffe_ids:
      - "spiffe://mcp-gateway.local/ns/acme/sa/*"
    upstreams:
      llm:
        provider: "gigachat"
        model: "GigaChat-Pro"
        endpoint: "https://gigachat.devices.sberbank.ru/api/v1"
      tools:
        - "https://mcp.acme.internal"
    pii_policy: "strict"
    rate_limit:
      tools_call:
        limit: 1000
        window: "60s"
      tools_list:
        limit: 5000
        window: "60s"
      redis_failure_mode: "fail-closed"
    circuit_breaker:
      max_requests: 3
      interval: "30s"
      timeout: "60s"
    agents:
      - id: "agent-customer-support"
        budget_rub_per_hour: 5000
      - id: "agent-code-reviewer"
        budget_rub_per_hour: 50000
      - id: "agent-internal-tools"
        budget_rub_per_hour: 500000

  - id: "globex"
    tier: "standard"
    authorized_spiffe_ids:
      - "spiffe://mcp-gateway.local/ns/globex/sa/*"
    upstreams:
      llm:
        provider: "yandex"
        model: "YandexGPT-Pro"
        endpoint: "https://llm.api.cloud.yandex.net/foundationModels/v1"
    pii_policy: "gdpr"
    rate_limit:
      tools_call:
        limit: 100
        window: "60s"
      redis_failure_mode: "fail-open"
```

---

## 7. FinOps и Unit Economics

### 7.1. Ключевые цифры

```
    ┌──────────────────────────────────────────────────────────────┐
    │                                                              │
    │  Baseline: 100 RPS, ~260M calls/month                        │
    │                                                              │
    │  Cost per 1M MCP calls (GigaChat Pro): ~1,250,570 ₽          │
    │  Monthly cost (260M calls): ~325,700,000 ₽                   │
    │                                                              │
    │  Распределение:                                              │
    │  • LLM API:          99.50%  ⚠️ (вне контроля архитектора)   │
    │  • Networking:       0.045%                                  │
    │  • Observability:    0.020%                                  │
    │  • PostgreSQL:       0.014%                                  │
    │  • S3 WORM:          0.011%                                  │
    │  • OpenBao:          0.009%                                  │
    │  • SPIRE Server:     0.008%                                  │
    │  • Gateway compute:  0.007%                                  │
    │  • Redis:            0.006%                                  │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

### 7.2. Ключевые выводы

```
    ┌──────────────────────────────────────────────────────────────┐
    │                                                              │
    │  1. LLM = 99.5% стоимости. Все архитектурные решения         │
    │     нужно оценивать через призму влияния на LLM-вызовы.      │
    │                                                              │
    │  2. Инфраструктура (Redis, Postgres, OpenBao, SPIRE) —        │
    │     менее 0.1% стоимости. Не оптимизировать в первую         │
    │     очередь, если работает.                                  │
    │                                                              │
    │  3. Gateway compute — 0.007%. Переписывание на Rust          │
    │     даст <0.01% экономии. Не делать.                         │
    │                                                              │
    │  4. Главные levers FinOps:                                    │
    │     • Caching (30% savings, LOW complexity)                  │
    │     • Model routing (70% savings, MEDIUM complexity)         │
    │     • Prompt optimization (20% savings, LOW)                 │
    │     • Batch API (50% on async, LOW)                          │
    │                                                              │
    │  5. Combined optimization: ~77% savings vs baseline          │
    │     • 1,250,000 ₽ → 284,000 ₽ per 1M calls                   │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

### 7.3. Per-tenant cost model

```
    ┌──────────────────────────────────────────────────────────────┐
    │                                                              │
    │  ┌─────────────┬────────────┬──────────────┬──────────────┐ │
    │  │ Tier        │ Rate limit │ Volume/месяц │ Cost/месяц   │ │
    │  ├─────────────┼────────────┼──────────────┼──────────────┤ │
    │  │ Enterprise  │ 1000/min   │ 10M calls    │ ~12.5M ₽     │ │
    │  │ Standard    │ 100/min    │ 1M calls     │ ~1.25M ₽     │ │
    │  │ Free        │ 10/min     │ 100k calls   │ ~125k ₽      │ │
    │  └─────────────┴────────────┴──────────────┴──────────────┘ │
    │                                                              │
    │  Pricing strategy (пример):                                  │
    │  • Enterprise: 15M ₽/месяц (20% margin)                      │
    │  • Standard: 1.5M ₽/месяц (20% margin)                       │
    │  • Free: 0 ₽ (loss leader для adoption)                      │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

### 7.4. Сравнение с альтернативами

```
    ┌──────────────────────────────────────────────────────────────┐
    │                                                              │
    │  Cost per 1M MCP calls — сравнение подходов:                 │
    │                                                              │
    │  ┌────────────────────────────┬──────────────┬─────────────┐│
    │  │ Approach                   │ ₽/1M calls   │ Notes       ││
    │  ├────────────────────────────┼──────────────┼─────────────┤│
    │  │ No caching, GigaChat Pro   │ 1,250,000 ₽  │ baseline    ││
    │  │ + response caching (30%)   │ 875,000 ₽    │ -30%        ││
    │  │ + model routing (Lite)     │ 375,000 ₽    │ -70%        ││
    │  │ + prompt optimization      │ 312,500 ₽    │ -75%        ││
    │  │ + batch API                │ 218,750 ₽    │ -82.5%      ││
    │  │ + local Ollama (large vol) │ 62,500 ₽     │ -95%        ││
    │  └────────────────────────────┴──────────────┴─────────────┘│
    │                                                              │
    │  → Оптимизация LLM costs = biggest FinOps lever              │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

### 7.5. Cost attribution per agent

Полный анализ — в ADR-0008. Ключевые цифры:

```
    ┌──────────────────────────────────────────────────────────────┐
    │                                                              │
    │  Cost breakdown per tenant (пример: 10M calls/month):        │
    │                                                              │
    │  Tenant "acme" — total: ~12.5M ₽/месяц                       │
    │                                                              │
    │  ├── agent-internal-tools      :  ~9.5M ₽  (76%)             │
    │  ├── agent-code-reviewer       :  ~2.0M ₽  (16%)             │
    │  ├── agent-customer-support    :  ~0.8M ₽  (6%)              │
    │  └── agent-data-analyst        :  ~0.2M ₽  (2%)              │
    │                                                              │
    │  Без agent-level attribution — невозможно понять:            │
    │  • Кто тратит больше всех                                     │
    │  • Где аномалия                                               │
    │  • Кого throttle при overrun                                  │
    │                                                              │
    │  С agent-level attribution — возможно:                       │
    │  • Auto-throttle на конкретного агента                        │
    │  • Notify tenant: "ваш agent-X тратит 76% бюджета"           │
    │  • Optimize prompts per agent (ADR-0007)                     │
    │                                                              │
    │  Alerting:                                                   │
    │  • W-08: Agent cost >100% budget → warning                   │
    │  • C-08: Agent cost >150% budget → critical (auto-throttle)  │
    │  • C-09: Agent cost anomaly (>3x baseline) → critical        │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

### 7.6. Cost-driven decisions (ROI ranking)

```
    ┌──────────────────────────────────────────────────────────────┐
    │                                                              │
    │  ✅ Высокий ROI (делать):                                     │
    │                                                              │
    │  • Model routing (Lite vs Pro) ............. ROI ~320,000%   │
    │  • Prompt optimization ..................... ROI ~65,000%    │
    │  • Batch API для async ..................... ROI ~25,000%    │
    │  • Response caching ........................ ROI ~19,000%    │
    │                                                              │
    ├──────────────────────────────────────────────────────────────┤
    │                                                              │
    │  ❌ Низкий ROI (не делать):                                   │
    │                                                              │
    │  • Переписать gateway на Rust ............... ROI ~0.75%/год │
    │  • Оптимизировать PII regex ................. ROI ~4.8%/год  │
    │  • Уменьшить PostgreSQL hot storage ......... ROI ~12%/год   │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

---

## 8. Deployment

### 8.1. Kubernetes deployment

```
    ┌──────────────────────────────────────────────────────────────┐
    │                                                              │
    │  Namespace: mcp-gateway                                      │
    │                                                              │
    │  ┌──────────────────────────────────────────────────────┐   │
    │  │                                                      │   │
    │  │   Deployment: mcp-gateway                            │   │
    │  │   Replicas: 2-10 (HPA on CPU + custom metric)        │   │
    │  │                                                      │   │
    │  │   ┌────────────┐  ┌────────────┐  ┌────────────┐    │   │
    │  │   │ Pod 1      │  │ Pod 2      │  │ Pod N      │    │   │
    │  │   │            │  │            │  │            │    │   │
    │  │   │ gateway    │  │ gateway    │  │ gateway    │    │   │
    │  │   │ +spire-    │  │ +spire-    │  │ +spire-    │    │   │
    │  │   │  agent     │  │  agent     │  │  agent     │    │   │
    │  │   │  sidecar   │  │  sidecar   │  │  sidecar   │    │   │
    │  │   │ +NER       │  │ +NER       │  │ +NER       │    │   │
    │  │   │  sidecar   │  │  sidecar   │  │  sidecar   │    │   │
    │  │   └────────────┘  └────────────┘  └────────────┘    │   │
    │  │                                                      │   │
    │  │   Security:                                          │   │
    │  │   • runAsNonRoot: true                               │   │
    │  │   • readOnlyRootFilesystem: true                     │   │
    │  │   • drop ALL capabilities                            │   │
    │  │   • seccompProfile: RuntimeDefault                   │   │
    │  │                                                      │   │
    │  │   Probes:                                            │   │
    │  │   • livenessProbe: /healthz                          │   │
    │  │   • readinessProbe: /readyz (SVID + OpenBao + Redis) │   │
    │  │   • startupProbe: initial delay 30s                  │   │
    │  │                                                      │   │
    │  │   NetworkPolicy:                                     │   │
    │  │   • ingress: только от ingress-controller            │   │
    │  │   • egress: allowlist (Redis, Postgres, OpenBao,     │   │
    │  │     SPIRE Server, Langfuse, LLM API, MCP servers)    │   │
    │  │                                                      │   │
    │  └──────────────────────────────────────────────────────┘   │
    │                                                              │
    │  External services (managed):                                │
    │  • Redis (Sentinel / Cluster)                                │
    │  • PostgreSQL (HA, managed)                                  │
    │  • OpenBao (HA, 3 nodes, Raft)                               │
    │  • SPIRE Server                                              │
    │  • Langfuse (self-hosted)                                    │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

### 8.2. Helm chart структура

```
    deploy/helm/mcp-gateway/
    ├── Chart.yaml
    ├── values.yaml
    ├── values-production.yaml
    ├── values-dev.yaml
    └── templates/
        ├── _helpers.tpl
        ├── deployment.yaml
        ├── service.yaml
        ├── serviceaccount.yaml
        ├── configmap.yaml           # tenants.yaml, agents.yaml, policies
        ├── secret.yaml              # template only, ESO managed
        ├── hpa.yaml
        ├── pdb.yaml                 # pod disruption budget
        ├── networkpolicy.yaml
        ├── servicemonitor.yaml      # Prometheus operator
        └── serviceentry.yaml        # Istio (optional)
```

### 8.3. Secret management

```
    ┌──────────────────────────────────────────────────────────────┐
    │                                                              │
    │  External Secrets Operator (ESO)                             │
    │                                                              │
    │  ┌─────────────────┐         ┌────────────────────┐         │
    │  │  OpenBao        │  sync   │  K8s Secret        │         │
    │  │                 │ ──────► │                    │         │
    │  │  • HMAC keys    │         │  mcp-gateway-      │         │
    │  │  • API keys     │         │    secrets         │         │
    │  │  • DB creds     │         │                    │         │
    │  └─────────────────┘         └────────────────────┘         │
    │                                       │                      │
    │                                       │ mount                │
    │                                       ▼                      │
    │                              ┌────────────────────┐          │
    │                              │  Gateway pod       │          │
    │                              └────────────────────┘          │
    │                                                              │
    │  RBAC:                                                       │
    │  • mcp-gateway SA: read own secrets                          │
    │  • Нет прав на чтение чужих secrets                          │
    │  • Audit log всех доступов к secrets (OpenBao audit)         │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

### 8.4. Multi-cluster deployment

```
    ┌──────────────────────────────────────────────────────────────┐
    │                                                              │
    │  Cluster 1 (prod-ru)         Cluster 2 (prod-eu)             │
    │  ┌─────────────────┐         ┌─────────────────┐             │
    │  │ MCP Gateway     │         │ MCP Gateway     │             │
    │  │                 │         │                 │             │
    │  │ SPIFFE:         │         │ SPIFFE:         │             │
    │  │ trust-domain:   │◄────────┤ trust-domain:   │             │
    │  │ ru.example.com  │ SPIFFE  │ eu.example.com  │             │
    │  │                 │Federation│                │             │
    │  └─────────────────┘         └─────────────────┘             │
    │                                                              │
    │  Federation:                                                 │
    │  • Обмен trust bundles между SPIFFE-совместимыми серверами   │
    │  • Взаимная аутентификация workload'ов между кластерами      │
    │  • Единая identity для AI-агентов во всех регионах           │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

---

## 9. Observability

### 9.1. Three Pillars

```
    ┌──────────────────────────────────────────────────────────────┐
    │                                                              │
    │  Metrics (Prometheus)                                        │
    │  ────────────────────                                        │
    │                                                              │
    │  RED metrics:                                                │
    │  • Rate: mcp_requests_total{tenant, agent, method, status}   │
    │  • Errors: mcp_errors_total{tenant, method, error_type}      │
    │  • Duration: mcp_request_duration_seconds (histogram)        │
    │                                                              │
    │  USE metrics:                                                │
    │  • Utilization: cpu, memory                                  │
    │  • Saturation: goroutines, connection pool                   │
    │  • Errors: см. выше                                          │
    │                                                              │
    │  Business metrics:                                           │
    │  • llm_tokens_total{tenant, agent, provider, model}          │
    │  • llm_cost_rub_total{tenant, agent, provider, model}        │
    │  • rate_limit_denied_total{tenant, method}                   │
    │  • circuit_state{tenant, upstream}                           │
    │  • cache_hits_total{tenant}                                  │
    │  • pii_redacted_total{tenant, type}                          │
    │  • prompt_version_usage{name, version}                       │
    │  • agent_budget_used_pct{tenant, agent}                      │
    │                                                              │
    │  Logs (structured JSON → Loki)                               │
    │  ─────────────────────────────                               │
    │                                                              │
    │  • correlation_id = trace_id                                 │
    │  • tenant_id, agent_id, spiffe_id, method, outcome           │
    │  • БЕЗ PII (redaction до логирования)                        │
    │  • Уровни: debug, info, warn, error                          │
    │                                                              │
    │  Traces (OpenTelemetry → Tempo)                              │
    │  ──────────────────────────────                              │
    │                                                              │
    │  • Span на каждый MCP-вызов                                  │
    │  • Child spans: middleware, upstream call, audit write       │
    │  • Attributes: tenant.id, agent.id, mcp.method,              │
    │    upstream.name, pii.redacted_count, llm.cost_rub           │
    │  • W3C traceparent propagation                               │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

### 9.2. Dashboards

```
    ┌──────────────────────────────────────────────────────────────┐
    │  Grafana Dashboard: "MCP Gateway — Overview"                 │
    ├──────────────────────────────────────────────────────────────┤
    │                                                              │
    │  Row 1: Health                                               │
    │  • Request rate (per method)                                 │
    │  • Error rate (per status)                                   │
    │  • p50/p95/p99 latency                                       │
    │  • Availability (rolling 30d)                                │
    │                                                              │
    │  Row 2: Per-tenant                                           │
    │  • Top-N тенантов по request rate                            │
    │  • Rate limit hits/denials per tenant                        │
    │  • Circuit breaker state per tenant × upstream               │
    │                                                              │
    │  Row 3: Per-agent (ADR-0008)                                 │
    │  • Top-N agents by cost                                      │
    │  • Cost trend per agent                                      │
    │  • Budget vs actual per agent                                │
    │  • Anomaly detection heatmap                                 │
    │                                                              │
    │  Row 4: Dependencies                                         │
    │  • Redis latency / memory                                    │
    │  • PostgreSQL write latency                                  │
    │  • OpenBao request rate                                      │
    │  • SPIRE SVID TTL distribution                               │
    │  • Langfuse prompt fetch latency                             │
    │                                                              │
    │  Row 5: Business metrics                                     │
    │  • LLM tokens per tenant                                     │
    │  • LLM cost per tenant (FinOps)                              │
    │  • PII redacted per tenant × type                            │
    │  • Prompt version distribution                               │
    │  • Cache hit rate per tenant                                 │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

### 9.3. Алерты

```
    ┌──────────────────────────────────────────────────────────────┐
    │  Critical (page on-call):                                    │
    ├──────────────────────────────────────────────────────────────┤
    │                                                              │
    │  • Availability burn rate >14.4x за 5m                       │
    │  • Circuit open >10m для любого (tenant, upstream)           │
    │  • Audit verify failed (целостность нарушена)                │
    │  • OpenBao недоступен >2m                                    │
    │  • SPIRE agent недоступен >2m                                │
    │  • Redis недоступен >1m (для enterprise тенантов)            │
    │  • HMAC key rotation failed                                  │
    │  • Daily cost >2x baseline (FinOps spike)                    │
    │  • Agent cost >150% budget → auto-throttle                   │
    │  • Agent cost anomaly >3x baseline                           │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘

    ┌──────────────────────────────────────────────────────────────┐
    │  Warning (notify team):                                      │
    ├──────────────────────────────────────────────────────────────┤
    │                                                              │
    │  • Availability burn rate >2x за 1h                          │
    │  • Circuit open >1m                                          │
    │  • Rate limit denial rate >10% для тенанта                   │
    │  • p99 latency > SLO                                         │
    │  • Audit queue full                                          │
    │  • SVID TTL <15m                                             │
    │  • Breaker registry size anomaly                             │
    │  • Tenant cost >100% budget                                  │
    │  • Agent cost >100% budget                                   │
    │  • Cache hit rate <20%                                       │
    │  • HMAC key age >80 дней                                     │
    │  • Unknown agent_id rate >5%                                 │
    │  • PII detector false positive rate >5%                      │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

### 9.4. Prompt-level observability (ADR-0007)

```
    ┌──────────────────────────────────────────────────────────────┐
    │                                                              │
    │  Langfuse даёт:                                              │
    │                                                              │
    │  • Prompt versioning — какая версия использована             │
    │  • A/B testing — сравнение версий по метрикам                │
    │  • Cost per prompt version — оптимизация                     │
    │  • Latency per prompt version                                │
    │  • Quality scores (LLM-as-a-Judge)                           │
    │  • Offline experiments (на датасетах)                        │
    │                                                              │
    │  Integration с OTel:                                         │
    │  • langfuse.observation.type = "generation"                  │
    │  • langfuse.prompt.name = "system-prompt-tools-call"         │
    │  • langfuse.prompt.version = 2                               │
    │                                                              │
    │  Workflow:                                                    │
    │  1. Draft v3 в Langfuse                                      │
    │  2. Test на staging dataset                                  │
    │  3. Label v3 как "prod-b", split 10%                         │
    │  4. Monitor 24 часа                                          │
    │  5. Если OK → production; если не OK → auto-rollback         │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

---

## 10. Roadmap и ограничения

### 10.1. Roadmap

```
    ┌──────────────────────────────────────────────────────────────┐
    │                                                              │
    │  ✅ Phase 1: Foundation (Done)                               │
    │  ─────────────────────────────                               │
    │  • Структура репозитория (~60 файлов)                        │
    │  • 10 ADR (0001-0010)                                        │
    │  • Blueprint v3                                              │
    │  • Threat Model v2 (25 угроз)                                │
    │  • SLO.md                                                    │
    │  • Capacity Planning                                         │
    │  • Runbook.md                                                │
    │  • CI (GitHub Actions)                                       │
    │                                                              │
    │  🚧 Phase 2: Core (In Progress)                              │
    │  ──────────────────────────────                              │
    │  • MCP protocol handlers (initialize, tools/list, tools/call)│
    │  • Tenant middleware (ADR-0004)                              │
    │  • Agent resolver (ADR-0008)                                 │
    │  • Rate limiter с Lua (ADR-0003)                             │
    │  • Audit logger с HMAC hash-chain (ADR-0002)                 │
    │  • Circuit breaker (ADR-0005)                                │
    │  • SPIFFE integration (ADR-0001)                             │
    │  • OpenBao client (ADR-0010)                                 │
    │                                                              │
    │  📋 Phase 3: Security & Compliance                           │
    │  ───────────────────────────────────                         │
    │  • PII redaction pipeline (ADR-0009)                         │
    │  • Threat model review с InfoSec                             │
    │  • Key management runbook                                    │
    │  • Incident response runbook                                 │
    │  • Penetration testing                                       │
    │                                                              │
    │  📋 Phase 4: LLM-Ops                                         │
    │  ────────────────────                                        │
    │  • Prompt A/B testing via Langfuse (ADR-0007)                │
    │  • Cost attribution per agent (ADR-0008)                     │
    │  • Auto-rollback prompts                                     │
    │  • Grafana dashboards (Cost by Agent)                        │
    │  • LLM-as-a-Judge evaluation                                 │
    │                                                              │
    │  📋 Phase 5: Production Readiness                            │
    │  ────────────────────────────────                            │
    │  • Helm chart production-ready                               │
    │  • Multi-cluster deployment (SPIFFE Federation)              │
    │  • Disaster recovery procedures                              │
    │  • External security audit                                   │
    │  • Compliance certification (152-ФЗ, ISO 27001)              │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

### 10.2. Ограничения reference implementation

```
    ┌──────────────────────────────────────────────────────────────┐
    │                                                              │
    │  • Нет production hardening для конкретной инфраструктуры    │
    │    (требуется адаптация под заказчика)                       │
    │                                                              │
    │  • PII detection на regex + NER может давать false           │
    │    positives/negatives — требуется per-tenant tuning         │
    │                                                              │
    │  • Нет HA-конфигурации Redis/Postgres/OpenBao из коробки —   │
    │    предполагается managed-сервисы                            │
    │                                                              │
    │  • Multi-cluster deployment показан концептуально,           │
    │    требует адаптации под конкретный setup                    │
    │                                                              │
    │  • Нет admin UI — управление тенантами через YAML + reload   │
    │                                                              │
    │  • Benchmark не проводился на production-железе              │
    │    (цель: 10k RPS, p99 <10ms)                                │
    │                                                              │
    │  • Penetration testing не проводился                         │
    │                                                              │
    │  • Цены на LLM даны как reference, требуют проверки          │
    │    по актуальным прайс-листам                                │
    │                                                              │
    │  • FinOps-расчёты сделаны для baseline 100 RPS;              │
    │    при других нагрузках требуется пересчёт                    │
    │                                                              │
    │  • ADR-0007-0010 в статусе Planned/In Progress,              │
    │    реализация — Phase 3-4 Roadmap                            │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

### 10.3. Что делать перед production

```
    ┌──────────────────────────────────────────────────────────────┐
    │  Pre-production checklist:                                   │
    ├──────────────────────────────────────────────────────────────┤
    │                                                              │
    │  Security:                                                   │
    │  [ ] External security audit (pentest)                       │
    │  [ ] Threat model review с InfoSec                           │
    │  [ ] Key management procedures approved                      │
    │  [ ] Incident response playbooks written                     │
    │                                                              │
    │  Reliability:                                                │
    │  [ ] SLO defined и согласованы с бизнесом                    │
    │  [ ] Load testing на production-like workload                │
    │  [ ] Chaos engineering (убить Redis, OpenBao, upstream)      │
    │  [ ] Disaster recovery test                                  │
    │                                                              │
    │  Operations:                                                 │
    │  [ ] Runbooks для всех алертов                               │
    │  [ ] On-call rotation setup                                  │
    │  [ ] Dashboards и alerts в production                        │
    │  [ ] Capacity planning validated                             │
    │                                                              │
    │  Compliance:                                                 │
    │  [ ] Compliance mapping reviewed                             │
    │  [ ] Data flow diagrams approved                             │
    │  [ ] DPIA (Data Protection Impact Assessment)                │
    │  [ ] Regulatory notification procedures                      │
    │                                                              │
    │  FinOps:                                                     │
    │  [ ] Budget per tenant + agent согласован                    │
    │  [ ] Cost alerts настроены                                   │
    │  [ ] Optimization pipeline (caching, routing)                │
    │  [ ] Cost attribution per tenant + agent работает            │
    │                                                              │
    │  LLM-Ops:                                                    │
    │  [ ] Langfuse развёрнут                                       │
    │  [ ] Prompts версионированы                                   │
    │  [ ] A/B testing workflow документирован                      │
    │  [ ] Auto-rollback настроен                                   │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

---

## 11. Ссылки

### 11.1. Architecture Decision Records

```
    docs/adr/
    ├── 0001-use-spiffe-for-mtls.md
    ├── 0002-hmac-hash-chain-for-audit.md
    ├── 0003-redis-for-rate-limiting.md
    ├── 0004-tenant-id-in-context.md
    ├── 0005-circuit-breaker-library-choice.md
    ├── 0006-observability-stack.md
    ├── 0007-prompt-ab-testing.md
    ├── 0008-cost-attribution-per-agent.md
    ├── 0009-pii-redaction.md
    └── 0010-key-management.md
```

### 11.2. Дополнительная документация

```
    docs/
    ├── architecture/
    │   ├── overview.md           # C4 diagrams (детально)
    │   ├── trust-boundaries.md   # Trust boundaries (детально)
    │   └── data-flow.md          # Data flow (детально)
    ├── security/
    │   ├── threat-model.md       # STRIDE model (25 угроз)
    │   ├── compliance-mapping.md # 152-ФЗ, GDPR, PCI DSS, HIPAA
    │   ├── key-management.md     # Управление HMAC keys (ADR-0010)
    │   └── incident-response.md  # Runbook (TBD)
    ├── reliability/
    │   ├── slo.md                # SLI / SLO / error budget
    │   ├── capacity-planning.md  # FinOps, cost per 1M MCP calls
    │   └── runbook.md            # Ops runbook + incident replay
    └── blueprint.md              # Этот документ
```

### 11.3. Индустриальные стандарты и best practices

- [NIST SP 800-207: Zero Trust Architecture](https://csrc.nist.gov/publications/detail/sp/800-207/final)
- [NIST SP 800-57: Key Management](https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final)
- [NIST SP 800-92: Guide to Computer Security Log Management](https://csrc.nist.gov/publications/detail/sp/800-92/final)
- [SPIFFE Standard](https://spiffe.io/docs/latest/spiffe-about/overview/)
- [WIMSE IETF Working Group](https://datatracker.ietf.org/group/wimse/about/)
- [PCI DSS v4.0](https://www.pcisecuritystandards.org/)
- [GDPR](https://gdpr-info.eu/)
- [152-ФЗ](https://www.consultant.ru/document/cons_doc_LAW_61801/)
- [Google SRE Book](https://sre.google/sre-book/table-of-contents/)
- [OpenTelemetry Specification](https://opentelemetry.io/docs/specs/otel/)
- [OpenBao Documentation](https://openbao.org/)
- [Langfuse Documentation](https://langfuse.com/docs)
- [FinOps Foundation](https://www.finops.org/)

### 11.4. Связанные проекты

- [agentic-orchestration-platform](https://github.com/realrvs/agentic-orchestration-platform) — multi-agent платформа для enterprise
- [enterprise-agent-orchestration-blueprint](https://github.com/realrvs/enterprise-agent-orchestration-blueprint) — архитектурный blueprint

---

## Приложение A: Словарь терминов

```
    ┌──────────────────┬──────────────────────────────────────────┐
    │ Термин           │ Определение                              │
    ├──────────────────┼──────────────────────────────────────────┤
    │ ADR              │ Architecture Decision Record — документ,  │
    │                  │ фиксирующий архитектурное решение         │
    │ MCP              │ Model Context Protocol — открытый        │
    │                  │ стандарт для AI-агентов                  │
    │ SPIFFE           │ Secure Production Identity Framework     │
    │                  │ for Everyone — стандарт identity         │
    │ SVID             │ SPIFFE Verifiable Identity Document —    │
    │                  │ X.509 сертификат с SPIFFE ID в SAN       │
    │ SPIRE            │ SPIFFE Runtime Environment — реализация  │
    │                  │ SPIFFE                                   │
    │ HMAC             │ Hash-based Message Authentication Code — │
    │                  │ симметричная подпись                     │
    │ Tenant           │ Организационная единица (клиент, команда)│
    │ Agent            │ AI-приложение внутри tenant'а            │
    │ Circuit Breaker  │ Паттерн отказоустойчивости               │
    │ Rate Limiting    │ Ограничение частоты запросов             │
    │ SLO              │ Service Level Objective                  │
    │ SLI              │ Service Level Indicator                  │
    │ PII              │ Personally Identifiable Information      │
    │ FinOps           │ Управление затратами                     │
    │ ROI              │ Return on Investment                     │
    │ TCO              │ Total Cost of Ownership                  │
    │ OpenBao          │ Open-source fork HashiCorp Vault         │
    │ Langfuse         │ Open-source LLM observability            │
    │ OTel             │ OpenTelemetry                            │
    └──────────────────┴──────────────────────────────────────────┘
```

---

## Приложение B: Changelog

```
    ┌────────────┬──────────────┬──────────────────────────────────┐
    │ Version    │ Date         │ Changes                          │
    ├────────────┼──────────────┼──────────────────────────────────┤
    │ 1.0        │ 2026-09-23   │ Initial blueprint                │
    │            │              │ • 5 ADR included                 │
    │            │              │ • C4 diagrams                    │
    │            │              │ • Request flow for tools/call    │
    │            │              │ • Threat model summary           │
    │            │              │ • Compliance mapping             │
    │            │              │ • SLO summary                    │
    │            │              │                                  │
    │ 2.0        │ 2026-09-24   │ Major update:                    │
    │            │              │ • C4 Container with Cost         │
    │            │              │   Annotations                    │
    │            │              │ • FinOps раздел                  │
    │            │              │ • Российские LLM (RUB)           │
    │            │              │ • Threat model (25 угроз)        │
    │            │              │ • Compliance + NIST 800-207      │
    │            │              │                                  │
    │ 3.0        │ 2026-09-25   │ ADR-0006-0010 added:             │
    │            │              │ • ADR-0006 Observability stack   │
    │            │              │ • ADR-0007 Prompt A/B testing    │
    │            │              │ • ADR-0008 Cost per agent        │
    │            │              │ • ADR-0009 PII redaction         │
    │            │              │ • ADR-0010 Key mgmt (OpenBao)    │
    │            │              │ • Vault → OpenBao migration      │
    │            │              │ • Prompt-level observability     │
    │            │              │ • Cost attribution per agent     │
    │            │              │ • Roadmap Phase 4 (LLM-Ops)      │
    └────────────┴──────────────┴──────────────────────────────────┘
```

---

## Приложение C: Contributing

Это reference implementation. Для внесения изменений:

1. **Изменения архитектуры** → новый ADR или обновление существующего
2. **Изменения в blueprint** → PR с обоснованием
3. **Изменения в коде** → PR с tests + обновление ADR при необходимости

**Ключевой принцип:** каждое значимое решение фиксируется в ADR.
Blueprint — производный документ, ссылающийся на ADR.

