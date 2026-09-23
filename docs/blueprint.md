# MCP Gateway: Production Blueprint

- **Status:** Living Document
- **Version:** 1.0
- **Last Updated:** 2026-09-23
- **Author:** Roman Sokolov (Architect)
- **Audience:** Architects, CTO, InfoSec, SRE, Product Owners

---

## Содержание

1. [Проблема и контекст](#1-проблема-и-контекст)
2. [Целевая архитектура](#2-целевая-архитектура)
3. [Ключевые архитектурные решения](#3-ключевые-архитектурные-решения)
4. [Безопасность и compliance](#4-безопасность-и-compliance)
5. [Надёжность и SLO](#5-надёжность-и-slo)
6. [Multi-tenancy](#6-multi-tenancy)
7. [Deployment](#7-deployment)
8. [Observability](#8-observability)
9. [Roadmap и ограничения](#9-roadmap-и-ограничения)
10. [Ссылки](#10-ссылки)

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
                                │  (OpenAI,    │
                                │  Anthropic,  │
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
    │    (K8s, bare-metal, on-prem)                                │
    │  • Автоматическая ротация сертификатов без рестарта          │
    │                                                              │
    │  Решение: SPIFFE/SPIRE (см. ADR-0001)                        │
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
    │  Решение: HMAC hash-chain audit (ADR-0002) + PII redaction   │
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
    │  Решение: SLO (см. раздел 5) + Prometheus + OpenTelemetry    │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘

    ┌──────────────────────────────────────────────────────────────┐
    │  Проблема 5: FinOps                                          │
    ├──────────────────────────────────────────────────────────────┤
    │                                                              │
    │  PoC: нет учёта затрат на LLM                                │
    │                                                              │
    │  В production:                                               │
    │  • Каждый вызов LLM стоит денег ($/1k tokens)                │
    │  • Нужен per-tenant billing                                  │
    │  • Нужны лимиты для контроля затрат                          │
    │  • Стоимость на 1M MCP calls для capacity planning           │
    │                                                              │
    │  Решение: rate limiting per tenant (ADR-0003) + метрики      │
    │  usage per tenant × method                                   │
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
    │   │   circuit breaker, multi-tenancy.                  │     │
    │   │                                                    │     │
    │   └────┬──────────────┬──────────────┬─────────────────┘     │
    │        │              │              │                       │
    │        │              │              │                       │
    │        ▼              ▼              ▼                       │
    │   ┌─────────┐   ┌──────────┐   ┌──────────┐                 │
    │   │ LLM API │   │ MCP      │   │ Legacy   │                 │
    │   │ (OpenAI,│   │ Servers  │   │ Systems  │                 │
    │   │Anthropic│   │ (tools,  │   │ (1C, SAP,│                 │
    │   │ Ollama) │   │ resources│   │  ЕИС)    │                 │
    │   └─────────┘   └──────────┘   └──────────┘                 │
    │                                                              │
    │   External dependencies:                                     │
    │   • SPIFFE/SPIRE  — identity                                 │
    │   • Redis         — rate limit, breaker state                │
    │   • PostgreSQL    — audit log                                │
    │   • Vault         — HMAC keys, secrets                       │
    │   • S3 (WORM)     — root hash publication                    │
    │   • Prometheus    — metrics                                  │
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
    │   │   4. Rate Limiter          [ADR-0003]                    │    │
    │   │   5. PII Redactor          (TBD ADR-0006)                │    │
    │   │   6. Circuit Breaker       [ADR-0005]                    │    │
    │   │   7. Audit Logger          [ADR-0002]                    │    │
    │   │   8. Upstream Client                                      │    │
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
    │   │  │              │  │              │  │                │  │   │
    │   │  └──────────────┘  └──────────────┘  └────────────────┘  │   │
    │   │                                                            │   │
    │   └────────────────────────┬───────────────────────────────────┘   │
    │                            │                                       │
    └────────────────────────────┼───────────────────────────────────────┘
                                 │
        ┌────────────┬───────────┼────────────┬─────────────┐
        │            │           │            │             │
        ▼            ▼           ▼            ▼             ▼
    ┌────────┐  ┌────────┐  ┌────────┐  ┌────────┐  ┌──────────┐
    │ Redis  │  │Postgres│  │ Vault  │  │SPIRE   │  │ S3       │
    │        │  │        │  │        │  │Agent   │  │ (WORM)   │
    │ • rate │  │ • audit│  │ • HMAC │  │        │  │ • root   │
    │   limit│  │   log  │  │   keys │  │ • SVID │  │   hash   │
    │ • CB   │  │        │  │        │  │        │  │   publi- │
    │   state│  │        │  │        │  │        │  │   cation │
    └────────┘  └────────┘  └────────┘  └────────┘  └──────────┘
```

### 2.3. Поток запроса `tools/call`

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
    │   5. Rate Limit check                  [ADR-0003]           │
    │      ├─ Key: rl:{tenant}:tools_call:60s                     │
    │      ├─ Lua: ZREMRANGEBYSCORE + PEXPIRE + ZCARD + ZADD      │
    │      ├─ allowed=1 → continue, allowed=0 → 429 + Retry-After │
    │      └─ Headers: X-RateLimit-Limit/Remaining/Reset          │
    │                                                             │
    │   6. PII Redaction                     (TBD ADR-0006)       │
    │      ├─ Detect: email, phone, SSN, IBAN, credit card        │
    │      ├─ Mask: <EMAIL_1>, <PHONE_2>                          │
    │      └─ Store mapping in request-scoped memory              │
    │                                                             │
    │   7. Circuit Breaker check             [ADR-0005]           │
    │      ├─ Key: {tenant}:{upstream}                            │
    │      ├─ State: closed → allow, open → 503, half-open → N    │
    │      └─ Retry (3x exponential backoff) внутри breaker'а     │
    │                                                             │
    │   8. Upstream call                                          │
    │      ├─ HTTPS to LLM API / MCP server                       │
    │      ├─ Timeout: context.WithTimeout(ctx, 30s)              │
    │      └─ Response: stream or JSON                            │
    │                                                             │
    │   9. PII Unmask                                             │
    │      ├─ Reverse mapping <EMAIL_1> → original                │
    │      └─ Streaming-safe: overlap buffer 256 bytes            │
    │                                                             │
    │  10. Audit Log                         [ADR-0002]           │
    │      ├─ Entry: {Seq, Timestamp, TenantID, Actor,            │
    │      │          Action, Resource, Outcome, Hash, HMAC}      │
    │      ├─ HMAC = HMAC-SHA256(Key, Hash)                       │
    │      └─ Single-writer batching → Postgres                   │
    │                                                             │
    │  11. Response → Client                                      │
    │      ├─ HTTP 200 + stream/JSON                              │
    │      └─ Headers: X-RateLimit-*, X-Request-ID, traceparent   │
    │                                                             │
    └─────────────────────────────────────────────────────────────┘
```

### 2.4. Слои доверия (Trust Boundaries)

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
    │                                                              │
    │  Trust boundary: mTLS + JWT к backend                        │
    │                                                              │
    ├──────────────────────────────────────────────────────────────┤
    │                                                              │
    │  Zone 2: Backend (Internal)                                  │
    │  ──────────────────────────                                  │
    │                                                              │
    │  • Redis (rate limit + breaker state)                        │
    │  • PostgreSQL (audit log)                                    │
    │  • Vault (HMAC keys, secrets)                                │
    │  • SPIRE Server (identity issuance)                          │
    │  • Prometheus (metrics scrape)                               │
    │                                                              │
    │  Trust boundary: HTTPS + mTLS к upstream                     │
    │                                                              │
    ├──────────────────────────────────────────────────────────────┤
    │                                                              │
    │  Zone 3: Upstream (External)                                 │
    │  ───────────────────────────                                 │
    │                                                              │
    │  • LLM API (OpenAI, Anthropic, Ollama)                       │
    │  • MCP Servers (tools, resources)                            │
    │  • Legacy Systems (1C, SAP, ЕИС)                             │
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
    │      │                             │ • HMAC-SHA256 (ключ в Vault)│
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
    └──────┴─────────────────────────────┴─────────────────────────────┘
```

### 3.2. Связанные решения (запланированные ADR)

```
    ┌──────┬─────────────────────────────┬─────────────────────────────┐
    │ ADR  │ Тема                        │ Статус                      │
    ├──────┼─────────────────────────────┼─────────────────────────────┤
    │ 0006 │ PII redaction               │ TBD                         │
    │ 0007 │ MCP protocol transport      │ TBD                         │
    │ 0008 │ Observability stack         │ TBD                         │
    │ 0009 │ Deployment / Helm           │ TBD                         │
    └──────┴─────────────────────────────┴─────────────────────────────┘
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
    │  • API-ключи upstream (OpenAI, Anthropic)                    │
    │  • HMAC-ключи audit log                                      │
    │  • SPIFFE SVID (сертификаты identity)                        │
    │  • Tenant config (rate limits, upstream endpoints)           │
    │  • Audit log (кто, когда, что сделал)                        │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘

    ┌──────────────────────────────────────────────────────────────┐
    │  Угрозы (по STRIDE):                                         │
    ├──────────────────────────────────────────────────────────────┤
    │                                                              │
    │  S — Spoofing                                                │
    │    T-01: Подмена SPIFFE ID                                   │
    │    T-02: Подмена JWT                                         │
    │    T-03: Подмена tenant_id через X-Tenant-ID header          │
    │                                                              │
    │  T — Tampering                                               │
    │    T-04: Модификация audit log в БД (DBA)                    │
    │    T-05: Модификация root hash publication                   │
    │                                                              │
    │  R — Repudiation                                             │
    │    T-06: Отрицание факта вызова                              │
    │                                                              │
    │  I — Information Disclosure                                  │
    │    T-07: Утечка PII в upstream LLM                           │
    │    T-08: Cross-tenant data access                            │
    │    T-09: Утечка API-ключей в логах                           │
    │                                                              │
    │  D — Denial of Service                                       │
    │    T-10: Noisy neighbor (runaway loop)                       │
    │    T-11: Cascading failure при отказе upstream               │
    │                                                              │
    │  E — Elevation of Privilege                                  │
    │    T-12: Tenant A получает доступ к ресурсам Tenant B        │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

### 4.2. Защита от угроз (связь с ADR)

```
    ┌──────────────────┬──────────────────────────────────────────┐
    │ Угроза           │ Митигация                                │
    ├──────────────────┼──────────────────────────────────────────┤
    │ T-01, T-02       │ ADR-0001: SPIFFE/SPIRE + JWT validation  │
    │ T-03             │ ADR-0004: X-Tenant-ID только в dev       │
    │ T-04             │ ADR-0002: HMAC hash-chain + append-only  │
    │ T-05             │ ADR-0002: off-site root hash (S3 WORM)   │
    │ T-06             │ ADR-0002: подпись actor (SPIFFE ID)      │
    │ T-07             │ ADR-0006 (TBD): PII redaction pipeline   │
    │ T-08, T-12       │ ADR-0004: tenant_id isolation + allowlist│
    │ T-09             │ Secret management (Vault) + no-log policy│
    │ T-10             │ ADR-0003: per-tenant rate limiting       │
    │ T-11             │ ADR-0005: per-tenant circuit breaker     │
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
    │  • Ст. 22 — уведомление РКН → процедура (TBD)                │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘

    ┌──────────────────────────────────────────────────────────────┐
    │  GDPR (EU, General Data Protection Regulation)               │
    ├──────────────────────────────────────────────────────────────┤
    │                                                              │
    │  • Art. 5 — принципы обработки → PII redaction (ADR-0006)    │
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
    │  • Req. 4 — шифрование при передаче → mTLS (ADR-0001)        │
    │  • Req. 7 — need-to-know access → tenant isolation (ADR-0004)│
    │  • Req. 8 — идентификация пользователей → JWT + SPIFFE       │
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
    │  • Secret Management: Vault для ключей                       │
    │  • No Secrets in Code: секреты только через env / Vault      │
    │  • No PII in Logs: логи без PII, redaction прежде всего      │
    │  • Audit Everything: все security-события в audit log        │
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
    │   Context     tenant_id в context.Context (ADR-0004)         │
    │   Rate limit  Key: rl:{tenant}:method:window (ADR-0003)      │
    │   Breaker     Key: {tenant}:{upstream} (ADR-0005)            │
    │   Audit       Column tenant_id + RLS (ADR-0002)              │
    │   PII         Policy per tenant (ADR-0006 TBD)               │
    │   Upstream    Registry: tenant → endpoint mapping            │
    │   Metrics     Label tenant в Prometheus                      │
    │   Logs        Structured logging с tenant_id                 │
    │   Traces      Span attribute tenant.id                       │
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
        provider: "openai"
        endpoint: "https://api.openai.com/v1"
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

  - id: "globex"
    tier: "standard"
    authorized_spiffe_ids:
      - "spiffe://mcp-gateway.local/ns/globex/sa/*"
    upstreams:
      llm:
        provider: "anthropic"
        endpoint: "https://api.anthropic.com/v1"
    pii_policy: "gdpr"
    rate_limit:
      tools_call:
        limit: 100
        window: "60s"
      redis_failure_mode: "fail-open"
```

---

## 7. Deployment

### 7.1. Kubernetes deployment

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
    │  │   • readinessProbe: /readyz (SVID + Vault + Redis)   │   │
    │  │   • startupProbe: initial delay 30s                  │   │
    │  │                                                      │   │
    │  │   NetworkPolicy:                                     │   │
    │  │   • ingress: только от ingress-controller            │   │
    │  │   • egress: allowlist (Redis, Postgres, Vault,       │   │
    │  │     SPIRE Server, LLM API, MCP servers)              │   │
    │  │                                                      │   │
    │  └──────────────────────────────────────────────────────┘   │
    │                                                              │
    │  ┌──────────────────────────────────────────────────────┐   │
    │  │   DaemonSet: spire-agent                             │   │
    │  │   (если не sidecar)                                  │   │
    │  └──────────────────────────────────────────────────────┘   │
    │                                                              │
    │  External services (managed):                                │
    │  • Redis (Sentinel / Cluster)                                │
    │  • PostgreSQL (HA, managed)                                  │
    │  • Vault (HA)                                                │
    │  • SPIRE Server                                              │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

### 7.2. Helm chart структура

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
        ├── configmap.yaml           # tenants.yaml, policies
        ├── secret.yaml              # template only, ESO managed
        ├── hpa.yaml
        ├── pdb.yaml                 # pod disruption budget
        ├── networkpolicy.yaml
        ├── servicemonitor.yaml      # Prometheus operator
        └── serviceentry.yaml        # Istio (optional)
```

### 7.3. Secret management

```
    ┌──────────────────────────────────────────────────────────────┐
    │                                                              │
    │  External Secrets Operator (ESO)                             │
    │                                                              │
    │  ┌─────────────────┐         ┌────────────────────┐         │
    │  │  Vault          │  sync   │  K8s Secret        │         │
    │  │                 │ ──────► │                    │         │
    │  │  • HMAC keys    │         │  mcp-gateway-      │         │
    │  │  • JWT secrets  │         │    secrets         │         │
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
    │  • Audit log всех доступов к secrets (Vault audit)           │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

### 7.4. Multi-cluster deployment

```
    ┌──────────────────────────────────────────────────────────────┐
    │                                                              │
    │  Cluster 1 (prod-eu)         Cluster 2 (prod-ru)             │
    │  ┌─────────────────┐         ┌─────────────────┐             │
    │  │ MCP Gateway     │         │ MCP Gateway     │             │
    │  │                 │         │                 │             │
    │  │ SPIFFE:         │         │ SPIFFE:         │             │
    │  │ trust-domain:   │◄────────┤ trust-domain:   │             │
    │  │ eu.example.com  │ SPIFFE  │ ru.example.com  │             │
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

## 8. Observability

### 8.1. Three Pillars

```
    ┌──────────────────────────────────────────────────────────────┐
    │                                                              │
    │  Metrics (Prometheus)                                        │
    │  ────────────────────                                        │
    │                                                              │
    │  RED metrics:                                                │
    │  • Rate: mcp_requests_total{tenant,method,status}            │
    │  • Errors: mcp_errors_total{tenant,method,error_type}        │
    │  • Duration: mcp_request_duration_seconds (histogram)        │
    │                                                              │
    │  USE metrics:                                                │
    │  • Utilization: cpu, memory                                  │
    │  • Saturation: goroutines, connection pool                   │
    │  • Errors: см. выше                                          │
    │                                                              │
    │  Business metrics:                                           │
    │  • llm_tokens_total{tenant,provider}                         │
    │  • llm_cost_usd_total{tenant,provider}                       │
    │  • rate_limit_denied_total{tenant,method}                    │
    │  • circuit_state{tenant,upstream}                            │
    │                                                              │
    │  Logs (structured JSON → Loki)                               │
    │  ─────────────────────────────                               │
    │                                                              │
    │  • correlation_id = trace_id                                 │
    │  • tenant_id, spiffe_id, method, outcome                     │
    │  • БЕЗ PII (redaction до логирования)                        │
    │  • Уровни: debug, info, warn, error                          │
    │                                                              │
    │  Traces (OpenTelemetry → Jaeger/Tempo)                       │
    │  ─────────────────────────────────────                       │
    │                                                              │
    │  • Span на каждый MCP-вызов                                  │
    │  • Child spans: middleware, upstream call, audit write       │
    │  • Attributes: tenant.id, mcp.method, upstream.name,         │
    │    pii.redacted_count                                        │
    │  • W3C traceparent propagation                               │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

### 8.2. Dashboards

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
    │  Row 3: Dependencies                                         │
    │  • Redis latency / memory                                    │
    │  • PostgreSQL write latency                                  │
    │  • Vault request rate                                        │
    │  • SPIRE SVID TTL distribution                               │
    │                                                              │
    │  Row 4: Business metrics                                     │
    │  • LLM tokens per tenant                                     │
    │  • LLM cost per tenant (FinOps)                              │
    │  • Audit log write rate                                      │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

### 8.3. Алерты

```
    ┌──────────────────────────────────────────────────────────────┐
    │  Critical (page on-call):                                    │
    ├──────────────────────────────────────────────────────────────┤
    │                                                              │
    │  • Availability burn rate >14.4x за 5m                       │
    │  • Circuit open >10m для любого (tenant, upstream)           │
    │  • Audit verify failed (целостность нарушена)                │
    │  • Vault недоступен >2m                                      │
    │  • SPIRE agent недоступен >2m                                │
    │  • Redis недоступен >1m (для enterprise тенантов)            │
    │  • HMAC key rotation failed                                  │
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
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

---

## 9. Roadmap и ограничения

### 9.1. Roadmap

```
    ┌──────────────────────────────────────────────────────────────┐
    │                                                              │
    │  ✅ Phase 1: Foundation (Done)                               │
    │  ─────────────────────────────                               │
    │  • Структура репозитория                                     │
    │  • 5 ADR (0001-0005)                                         │
    │  • Blueprint                                                 │
    │  • CI (GitHub Actions)                                       │
    │                                                              │
    │  🚧 Phase 2: Core (In Progress)                              │
    │  ──────────────────────────────                              │
    │  • MCP protocol handlers (initialize, tools/list, tools/call)│
    │  • Tenant middleware (ADR-0004)                              │
    │  • Rate limiter с Lua (ADR-0003)                             │
    │  • Audit logger (ADR-0002)                                   │
    │  • Circuit breaker (ADR-0005)                                │
    │  • SPIFFE integration (ADR-0001)                             │
    │                                                              │
    │  📋 Phase 3: Security & Compliance                           │
    │  ───────────────────────────────────                         │
    │  • PII redaction pipeline (ADR-0006)                         │
    │  • Threat model + compliance mapping                         │
    │  • Key management runbook                                    │
    │  • Incident response runbook                                 │
    │  • Penetration testing                                       │
    │                                                              │
    │  📋 Phase 4: Operations                                      │
    │  ─────────────────────                                       │
    │  • SLO + error budget policy                                 │
    │  • Capacity planning + FinOps                                │
    │  • Grafana dashboards                                        │
    │  • Alerting rules                                            │
    │  • Load testing (k6)                                         │
    │                                                              │
    │  📋 Phase 5: Production Readiness                            │
    │  ────────────────────────────────                            │
    │  • Helm chart production-ready                               │
    │  • Multi-cluster deployment                                  │
    │  • Disaster recovery procedures                              │
    │  • Security audit (external)                                 │
    │  • Compliance certification (152-ФЗ, ISO 27001)              │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

### 9.2. Ограничения reference implementation

**Что НЕ реализовано в reference implementation:**

```
    ┌──────────────────────────────────────────────────────────────┐
    │                                                              │
    │  • Нет production hardening для конкретной инфраструктуры    │
    │    (требуется адаптация под заказчика)                       │
    │                                                              │
    │  • PII detection на regex-уровне может давать false          │
    │    positives/negatives — для production нужен NER +          │
    │    per-tenant правила                                        │
    │                                                              │
    │  • Нет HA-конфигурации Redis/Postgres из коробки —           │
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
    └──────────────────────────────────────────────────────────────┘
```

### 9.3. Что делать перед production

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
    │  [ ] Chaos engineering (убить Redis, Vault, upstream)        │
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
    └──────────────────────────────────────────────────────────────┘
```

---

## 10. Ссылки

### 10.1. Architecture Decision Records

```
    docs/adr/
    ├── 0001-use-spiffe-for-mtls.md
    ├── 0002-hmac-hash-chain-for-audit.md
    ├── 0003-redis-for-rate-limiting.md
    ├── 0004-tenant-id-in-context.md
    └── 0005-circuit-breaker-library-choice.md
```

### 10.2. Дополнительная документация

```
    docs/
    ├── architecture/
    │   ├── overview.md           # C4 diagrams (детально)
    │   ├── trust-boundaries.md   # Trust boundaries (детально)
    │   └── data-flow.md          # Data flow (детально)
    ├── security/
    │   ├── threat-model.md       # STRIDE model
    │   ├── compliance-mapping.md # 152-ФЗ, GDPR, PCI DSS, HIPAA
    │   ├── key-management.md     # Управление HMAC keys (TBD)
    │   └── incident-response.md  # Runbook (TBD)
    ├── reliability/
    │   ├── slo.md                # SLI / SLO / error budget
    │   ├── runbook.md            # Ops runbook
    │   └── capacity-planning.md  # FinOps, cost analysis (TBD)
    └── blueprint.md              # Этот документ
```

### 10.3. Индустриальные стандарты и best practices

- [NIST SP 800-207: Zero Trust Architecture](https://csrc.nist.gov/publications/detail/sp/800-207/final)
- [NIST SP 800-92: Guide to Computer Security Log Management](https://csrc.nist.gov/publications/detail/sp/800-92/final)
- [SPIFFE Standard](https://spiffe.io/docs/latest/spiffe-about/overview/)
- [WIMSE IETF Working Group](https://datatracker.ietf.org/group/wimse/about/)
- [PCI DSS v4.0](https://www.pcisecuritystandards.org/)
- [GDPR](https://gdpr-info.eu/)
- [152-ФЗ](https://www.consultant.ru/document/cons_doc_LAW_61801/)
- [Google SRE Book](https://sre.google/sre-book/table-of-contents/)
- [Martin Fowler: Circuit Breaker](https://martinfowler.com/bliki/CircuitBreaker.html)
- [The Twelve-Factor App](https://12factor.net/)

### 10.4. Связанные проекты

- [agentic-orchestration-platform](https://github.com/realrvs/agentic-orchestration-platform) — multi-agent платформа для enterprise
- [enterprise-agent-orchestration-blueprint](https://github.com/realrvs/enterprise-agent-orchestration-blueprint) — архитектурный blueprint
