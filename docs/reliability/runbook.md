# Operations Runbook: MCP Gateway

- **Status:** Living Document
- **Version:** 1.0
- **Last Updated:** 2026-09-25
- **Author:** Roman Sokolov (Architect)
- **Reviewers:** SRE, On-call Engineers, Engineering Leadership
- **Audience:** On-call Engineers, SRE, Incident Commanders

---

## Содержание

1. [Быстрый старт для дежурного](#1-быстрый-старт-для-дежурного)
2. [Диагностика по trace_id](#2-диагностика-по-trace_id)
3. [Runbook по алертам](#3-runbook-по-алертам)
4. [Incident replay](#4-incident-replay)
5. [Escalation matrix](#5-escalation-matrix)
6. [Communication plan](#6-communication-plan)
7. [Post-mortem template](#7-post-mortem-template)
8. [Периодические операции](#8-периодические-операции)
9. [Ревью и обновления](#9-ревью-и-обновления)

---

## 1. Быстрый старт для дежурного

### 1.1. Первые 5 минут после алерта

```
    ┌──────────────────────────────────────────────────────────────┐
    │                                                              │
    │  Шаг 1: Открыть dashboard                                    │
    │  ────────────────────────                                    │
    │                                                              │
    │  https://grafana.internal/d/mcp-gateway-overview             │
    │                                                              │
    │  Что смотреть:                                               │
    │  • Общая availability (SLO-1)                                │
    │  • Error rate (per method)                                   │
    │  • p50/p95/p99 latency                                       │
    │  • Circuit breaker states (per tenant × upstream)            │
    │  • Redis/Postgres/Vault health                               │
    │                                                              │
    ├──────────────────────────────────────────────────────────────┤
    │                                                              │
    │  Шаг 2: Определить severity                                  │
    │  ──────────────────────────                                  │
    │                                                              │
    │  🟢 P3 (info):      Error rate <1%, никого не затрагивает    │
    │  🟡 P2 (warning):   Error rate 1-5%, затронуты некоторые     │
    │  🟠 P1 (critical):  Error rate >5%, degradация для многих    │
    │  🔴 P0 (outage):    Полный отказ, все тенанты                │
    │                                                              │
    ├──────────────────────────────────────────────────────────────┤
    │                                                              │
    │  Шаг 3: Взять ownership                                      │
    │  ────────────────────────                                    │
    │                                                              │
    │  • #incident channel (Slack): написать "I'm on it"           │
    │  • Если P0/P1 — эскалировать по matrix (см. раздел 5)        │
    │  • Открыть incident в системе (Jira/Linear)                  │
    │                                                              │
    ├──────────────────────────────────────────────────────────────┤
    │                                                              │
    │  Шаг 4: Первичная диагностика                                │
    │  ─────────────────────────────                                │
    │                                                              │
    │  1. Определить симптом → найти в разделе 3                   │
    │  2. Следовать runbook для конкретного алерта                 │
    │  3. Если не помогает → escalation                            │
    │                                                              │
    ├──────────────────────────────────────────────────────────────┤
    │                                                              │
    │  Шаг 5: Коммуникация                                         │
    │  ─────────────────────                                       │
    │                                                              │
    │  • Клиенты: status page (если затронуты)                     │
    │  • Команда: #incident channel                                │
    │  • Руководство: если P0/P1                                   │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

### 1.2. Ключевые ссылки

```
    ┌──────────────────────────────────────────────────────────────┐
    │                                                              │
    │  Monitoring:                                                 │
    │  • Grafana:      https://grafana.internal/d/mcp-gateway      │
    │  • Prometheus:   https://prometheus.internal                 │
    │  • Alertmanager: https://alertmanager.internal               │
    │                                                              │
    │  Logs / Traces:                                              │
    │  • Loki:         https://grafana.internal/explore/loki       │
    │  • Tempo:        https://grafana.internal/explore/tempo      │
    │  • Langfuse:     https://langfuse.internal                   │
    │                                                              │
    │  Infra:                                                      │
    │  • K8s:          kubectl --context=prod-mcp                  │
    │  • Redis:        redis-cli -h redis.internal                 │
    │  • Postgres:     psql -h postgres.internal -U mcp_gateway    │
    │  • Vault:        vault.internal:8200 (AppRole)               │
    │                                                              │
    │  Docs:                                                       │
    │  • ADR:          github.com/realrvs/mcp-gateway/docs/adr     │
    │  • SLO:          github.com/realrvs/mcp-gateway/docs/        │
    │                  reliability/slo.md                          │
    │  • Threat Model: github.com/realrvs/mcp-gateway/docs/        │
    │                  security/threat-model.md                    │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

### 1.3. Полезные команды

```bash
# === Gateway ===
kubectl get pods -n mcp-gateway
kubectl logs -n mcp-gateway -l app=mcp-gateway --tail=100 -f
kubectl describe pod -n mcp-gateway <pod-name>

# === Health checks ===
curl -s https://mcp.internal/healthz   # liveness
curl -s https://mcp.internal/readyz    # readiness (SVID + Vault + Redis)

# === Metrics ===
curl -s https://mcp.internal/metrics | grep mcp_gateway
curl -s https://mcp.internal/metrics | grep circuit_state

# === Redis ===
redis-cli -h redis.internal INFO
redis-cli -h redis.internal --scan --pattern "rl:*" | head -20
redis-cli -h redis.internal ZCARD "rl:{acme}:tools_call:60s"

# === Postgres ===
psql -h postgres.internal -U mcp_gateway -c "SELECT count(*) FROM audit_log WHERE timestamp > NOW() - INTERVAL '1 hour';"
psql -h postgres.internal -U mcp_gateway -c "SELECT MAX(seq) FROM audit_log;"

# === Vault ===
vault status
vault kv get mcp-gateway/audit-hmac-key

# === Audit verification ===
mcp-gateway audit verify --from <seq_start> --to <seq_end>

# === Incident replay ===
mcp-gateway replay --trace-id <trace_id>
```

---

## 2. Диагностика по trace_id

### 2.1. Где взять trace_id

```
    ┌──────────────────────────────────────────────────────────────┐
    │                                                              │
    │  Источники trace_id:                                         │
    │                                                              │
    │  1. HTTP response header:                                    │
    │     X-Request-ID: abc123                                     │
    │     traceparent: 00-abc123-def456-01                         │
    │                                                              │
    │  2. Клиентский SDK:                                          │
    │     response.trace_id                                        │
    │                                                              │
    │  3. Grafana:                                                 │
    │     Клик по точке на графике → trace_id                       │
    │                                                              │
    │  4. Alertmanager:                                            │
    │     Alert содержит пример trace_id                            │
    │                                                              │
    │  5. Loki:                                                    │
    │     Поиск по tenant_id + timeframe → найти trace_id          │
    │                                                              │
    │  6. Langfuse:                                                │
    │     Filter by tenant/agent → trace_id                        │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

### 2.2. Unified diagnostics flow

```
    ┌──────────────────────────────────────────────────────────────┐
    │                                                              │
    │  Вход: trace_id = abc123                                     │
    │                                                              │
    │  Шаг 1: Trace в Tempo                                        │
    │  ──────────────────────                                      │
    │                                                              │
    │  Grafana → Explore → Tempo → Search by trace_id              │
    │                                                              │
    │  Что смотреть:                                               │
    │  • Span hierarchy (дерево вызовов)                           │
    │  • Duration per span                                         │
    │  • Errors (span с status=error)                              │
    │  • Attributes: tenant.id, mcp.method, upstream.name          │
    │                                                              │
    │  Шаг 2: Logs в Loki                                          │
    │  ──────────────────                                          │
    │                                                              │
    │  Grafana → Explore → Loki → Query:                           │
    │  {app="mcp-gateway"} |= "abc123"                             │
    │                                                              │
    │  Что смотреть:                                               │
    │  • Error messages                                            │
    │  • Stack traces                                              │
    │  • PII redaction events                                      │
    │                                                              │
    │  Шаг 3: Metrics в Prometheus                                 │
    │  ────────────────────────────                                │
    │                                                              │
    │  Grafana → Explore → Prometheus → Query:                     │
    │  mcp_requests_total{tenant="acme", method="tools/call"}      │
    │                                                              │
    │  Что смотреть:                                               │
    │  • Rate, errors, duration (RED) в момент инцидента           │
    │  • Аномалии (spikes)                                         │
    │                                                              │
    │  Шаг 4: Langfuse (LLM-specific)                              │
    │  ──────────────────────────────                              │
    │                                                              │
    │  Langfuse UI → Filter by trace_id                            │
    │                                                              │
    │  Что смотреть:                                               │
    │  • Prompt (redacted)                                         │
    │  • Response (redacted)                                       │
    │  • Tokens (input/output)                                     │
    │  • Cost (₽)                                                  │
    │  • Latency breakdown                                         │
    │  • Model version                                             │
    │                                                              │
    │  Шаг 5: Audit log                                            │
    │  ─────────────────                                           │
    │                                                              │
    │  psql -c "SELECT * FROM audit_log                            │
    │          WHERE metadata->>'trace_id' = 'abc123';"            │
    │                                                              │
    │  Что смотреть:                                               │
    │  • Кто (SPIFFE ID)                                           │
    │  • Что (action, resource)                                    │
    │  • Когда (timestamp)                                         │
    │  • Outcome (allow/deny/error)                                │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

### 2.3. Replay одной командой

```
    ┌──────────────────────────────────────────────────────────────┐
    │                                                              │
    │  mcp-gateway replay --trace-id abc123                        │
    │                                                              │
    │  Вывод:                                                      │
    │                                                              │
    │  ═══ Incident Replay: abc123 ═══                             │
    │                                                              │
    │  Time:    2026-09-25 10:30:00.123Z → 10:30:02.456Z (2.3s)    │
    │  Tenant:  acme                                               │
    │  Agent:   agent-x                                            │
    │  Method:  tools/call                                         │
    │  Outcome: error                                              │
    │                                                              │
    │  ─── Timeline ───                                            │
    │                                                              │
    │  [10:30:00.123] auth.validate       OK       12ms            │
    │  [10:30:00.135] tenant.resolve      OK       3ms             │
    │  [10:30:00.138] ratelimit.check     OK       5ms             │
    │  [10:30:00.143] pii.detect          OK       45ms            │
    │  [10:30:00.188] breaker.execute     ...                      │
    │  [10:30:00.190] upstream.call       ERROR    2268ms          │
    │  [10:30:02.458] breaker.trip        OPEN                     │
    │                                                              │
    │  ─── Error Details ───                                       │
    │                                                              │
    │  Upstream: gigachat-prod                                     │
    │  Error:    503 Service Unavailable                           │
    │  Message:  "upstream timeout after 2000ms"                   │
    │  Retries:  3 (all failed)                                    │
    │                                                              │
    │  ─── Impact ───                                              │
    │                                                              │
    │  • Breaker {acme:gigachat} → OPEN                            │
    │  • Subsequent requests to gigachat → 503 (fail-fast)         │
    │  • Error budget consumed: 0.5% (of 30-day budget)            │
    │                                                              │
    │  ─── Recommended Actions ───                                 │
    │                                                              │
    │  1. Check GigaChat status page                               │
    │  2. Verify network from gateway to GigaChat                  │
    │  3. If GigaChat healthy → reset breaker manually:            │
    │     mcp-gateway admin breaker reset --tenant acme            │
    │                                       --upstream gigachat    │
    │  4. Monitor for recurrence                                   │
    │                                                              │
    │  ═══════════════════════════════════════════                 │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

---

## 3. Runbook по алертам

### 3.1. Каталог алертов

```
    ┌──────────────────────────────────────────────────────────────┐
    │                                                              │
    │  Критические (page on-call):                                 │
    │                                                              │
    │  A-01: Availability burn rate >14.4x за 5m                   │
    │  A-02: Circuit breaker open >10m                             │
    │  A-03: Audit integrity failure                               │
    │  A-04: Vault недоступен >2m                                  │
    │  A-05: SPIRE agent недоступен >2m                            │
    │  A-06: Redis недоступен >1m (enterprise tenant)              │
    │  A-07: HMAC key rotation failed                              │
    │  A-08: Daily cost >2x baseline                               │
    │                                                              │
    │  Предупреждения (notify team):                               │
    │                                                              │
    │  W-01: Availability burn rate >2x за 1h                      │
    │  W-02: Circuit open >1m                                      │
    │  W-03: Rate limit denial rate >10% для tenant                │
    │  W-04: p99 latency > SLO                                     │
    │  W-05: Audit queue full                                      │
    │  W-06: SVID TTL <15m                                         │
    │  W-07: Breaker registry size anomaly                         │
    │  W-08: Tenant cost >100% budget                              │
    │  W-09: Cache hit rate <20%                                   │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

---

### A-01: Availability burn rate >14.4x за 5m

```
    ┌──────────────────────────────────────────────────────────────┐
    │                                                              │
    │  Что значит:                                                 │
    │  Error rate такой, что при сохранении темпа мы исчерпаем     │
    │  месячный error budget за ~2 дня.                            │
    │                                                              │
    │  Диагностика (5 минут):                                      │
    │                                                              │
    │  1. Открыть Grafana: MCP Gateway — Overview                  │
    │  2. Найти источник ошибок:                                   │
    │     • Per method (tools/call vs tools/list)                  │
    │     • Per tenant (кто больше страдает)                       │
    │     • Per status code (5xx vs 429 vs timeout)                │
    │                                                              │
    │  3. Быстрые команды:                                         │
    │     kubectl get pods -n mcp-gateway                          │
    │     kubectl logs -n mcp-gateway -l app=mcp-gateway --tail=100│
    │                                                              │
    │  4. Проверить зависимости:                                   │
    │     • Redis:    redis-cli -h redis.internal ping             │
    │     • Postgres: psql -h postgres.internal -c "SELECT 1"      │
    │     • Vault:    vault status                                 │
    │     • SPIRE:    kubectl get pods -n spire                    │
    │     • Upstream: curl -I https://gigachat.devices.sberbank.ru │
    │                                                              │
    │  Решение по симптомам:                                       │
    │                                                              │
    │  ┌────────────────────┬────────────────────────────────────┐ │
    │  │ Симптом            │ Действие                            │ │
    │  ├────────────────────┼────────────────────────────────────┤ │
    │  │                    │                                     │ │
    │  │ 5xx на всех тенантах│ 1. Проверить pod status             │ │
    │  │                    │ 2. Rolling restart если под завис    │ │
    │  │                    │ 3. Проверить ресурсы (CPU/mem)       │ │
    │  │                    │                                     │ │
    │  │ 5xx на одном тенанте│ 1. Проверить его config             │ │
    │  │                    │ 2. Проверить upstream для тенанта    │ │
    │  │                    │                                     │ │
    │  │ Timeouts           │ 1. Проверить upstream latency        │ │
    │  │                    │ 2. Увеличить timeout (если ок)       │ │
    │  │                    │ 3. Открыть breaker вручную           │ │
    │  │                    │                                     │ │
    │  │ 429 (rate limit)   │ 1. Это ОЖИДАЕМО, не error            │ │
    │  │                    │ 2. Проверить, что tenant не abuse    │ │
    │  │                    │                                     │ │
    │  │ 401/403            │ 1. Проверить SVID/SPIFFE             │ │
    │  │                    │ 2. Проверить JWT config              │ │
    │  │                    │                                     │ │
    │  └────────────────────┴────────────────────────────────────┘ │
    │                                                              │
    │  Эскалация:                                                  │
    │  • Если >15 минут без прогресса → SRE Lead                   │
    │  • Если затронуты enterprise тенанты → notify Customer       │
    │    Success + VP Engineering                                  │
    │  • Если подозрение на security → Security team               │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

---

### A-02: Circuit breaker open >10m

```
    ┌──────────────────────────────────────────────────────────────┐
    │                                                              │
    │  Что значит:                                                 │
    │  Breaker для конкретного (tenant, upstream) в состоянии OPEN │
    │  больше 10 минут. Значит upstream недоступен или деградировал.│
    │                                                              │
    │  Диагностика:                                                │
    │                                                              │
    │  1. Найти affected breaker:                                  │
    │     curl -s https://mcp.internal/metrics |                   │
    │       grep "circuit_state.*2"                                │
    │                                                              │
    │     Вывод: circuit_state{tenant="acme",upstream="gigachat"} 2│
    │                                                              │
    │  2. Проверить upstream напрямую:                             │
    │     curl -I https://gigachat.devices.sberbank.ru/api/v1      │
    │     curl -I https://llm.api.cloud.yandex.net/foundationModels│
    │                                                              │
    │  3. Проверить статус-страницы провайдеров:                   │
    │     • GigaChat: status.sber.ru                               │
    │     • YandexGPT: status.cloud.yandex.ru                      │
    │                                                              │
    │  4. Посмотреть ошибки в логах:                               │
    │     kubectl logs -n mcp-gateway -l app=mcp-gateway           │
    │       | grep "breaker\|upstream_error"                       │
    │                                                              │
    │  Решение:                                                    │
    │                                                              │
    │  ┌────────────────────────┬────────────────────────────────┐ │
    │  │ Симптом                │ Действие                        │ │
    │  ├────────────────────────┼────────────────────────────────┤ │
    │  │                        │                                 │ │
    │  │ Upstream down (внешне) │ 1. Связаться с провайдером       │ │
    │  │                        │ 2. Notify затронутых tenant'ов   │ │
    │  │                        │ 3. Fallback: switch на другую    │ │
    │  │                        │    модель (если есть)            │ │
    │  │                        │ 4. Ждать восстановления upstream │ │
    │  │                        │                                 │ │
    │  │ Upstream работает,     │ 1. Проверить isFailure класси-   │ │
    │  │ но breaker open        │    фикацию (4xx ≠ failure)       │ │
    │  │                        │ 2. Проверить network gateway     │ │
    │  │                        │ 3. Reset breaker вручную:        │ │
    │  │                        │    mcp-gateway admin breaker      │ │
    │  │                        │      reset --tenant acme          │ │
    │  │                        │      --upstream gigachat          │ │
    │  │                        │                                 │ │
    │  │ Breaker flapping       │ 1. Увеличить Interval (30s→60s)  │ │
    │  │                        │ 2. Увеличить Timeout (60s→120s)  │ │
    │  │                        │ 3. Уточнить ReadyToTrip thresholds│ │
    │  │                        │                                 │ │
    │  └────────────────────────┴────────────────────────────────┘ │
    │                                                              │
    │  Эскалация:                                                  │
    │  • Если затрагивает enterprise tenant >30m → notify VP      │
    │  • Если несколько breaker'ов одновременно → системная       │
    │    проблема, escalate к SRE Lead                             │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

---

### A-03: Audit integrity failure

```
    ┌──────────────────────────────────────────────────────────────┐
    │                                                              │
    │  ⚠️ КРИТИЧНО: возможная компрометация audit log              │
    │                                                              │
    │  Что значит:                                                 │
    │  Верификатор обнаружил нарушение HMAC hash-chain. Это        │
    │  означает, что записи могли быть изменены, удалены или       │
    │  пересчитаны с другим ключом.                                │
    │                                                              │
    │  ПЕРВОЕ ДЕЙСТВИЕ (0-2 минуты):                               │
    │                                                              │
    │  1. Немедленно freeze gateway:                               │
    │     kubectl patch deployment mcp-gateway -n mcp-gateway      │
    │       -p '{"spec":{"replicas":0}}'                           │
    │                                                              │
    │  2. НЕ трогать ничего в Postgres (следы!)                    │
    │                                                              │
    │  3. Уведомить:                                               │
    │     • Security team (немедленно)                             │
    │     • CISO                                                    │
    │     • On-call SRE Lead                                        │
    │     • VP Engineering                                          │
    │                                                              │
    │  4. Открыть P0 incident                                       │
    │                                                              │
    │  Диагностика (2-30 минут):                                   │
    │                                                              │
    │  1. Определить, где именно разрыв:                           │
    │     mcp-gateway audit verify --full --report-json > out.json │
    │                                                              │
    │  2. Сравнить с off-site root hashes (S3 Object Lock):        │
    │     aws s3 ls s3://mcp-audit-roots/ --recursive              │
    │                                                              │
    │  3. Проверить доступы:                                       │
    │     • Кто имел доступ к Postgres за последние 24ч            │
    │     • Были ли UPDATE/DELETE попытки (Postgres logs)          │
    │     • Кто имел доступ к Vault (HMAC keys)                    │
    │                                                              │
    │  4. Проверить backup:                                        │
    │     • Когда последний backup                                  │
    │     • Совпадает ли backup с off-site root hash               │
    │                                                              │
    │  Дальнейшие действия:                                        │
    │                                                              │
    │  ┌──────────────────────────┬──────────────────────────────┐ │
    │  │ Найдено                  │ Действие                      │ │
    │  ├──────────────────────────┼──────────────────────────────┤ │
    │  │                          │                               │ │
    │  │ Разрыв на конкретной     │ 1. Проверить запись по seq    │ │
    │  │ записи (1-2 seq)         │ 2. Сравнить с off-site         │ │
    │  │                          │ 3. Если подтверждён tampering  │ │
    │  │                          │    → incident response         │ │
    │  │                          │                               │ │
    │  │ Разрыв на многих записях │ 1. Полное расследование        │ │
    │  │                          │ 2. Forensics на БД             │ │
    │  │                          │ 3. Уведомление регулятора      │ │
    │  │                          │    (если требуется)            │ │
    │  │                          │                               │ │
    │  │ False positive           │ 1. Проверить key version        │ │
    │  │ (неверный ключ)          │ 2. Проверить Vault             │ │
    │  │                          │ 3. Восстановить правильный ключ│ │
    │  │                          │                               │ │
    │  └──────────────────────────┴──────────────────────────────┘ │
    │                                                              │
    │  Восстановление:                                             │
    │  • НЕ возобновлять gateway до полного расследования          │
    │  • Если false positive → reset breaker + restart             │
    │  • Если реальный tampering → восстановление из backup +      │
    │    forensics + notification                                  │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

---

### A-04: Vault недоступен >2m

```
    ┌──────────────────────────────────────────────────────────────┐
    │                                                              │
    │  Что значит:                                                 │
    │  Gateway не может читать HMAC-ключи или API-ключи.           │
    │                                                              │
    │  Последствия:                                                │
    │  • Новые запросы → 503 (fail-closed)                         │
    │  • Существующие соединения продолжают работать               │
    │                                                              │
    │  Диагностика:                                                │
    │                                                              │
    │  1. Проверить Vault:                                         │
    │     vault status                                             │
    │     curl -s https://vault.internal:8200/v1/sys/health        │
    │                                                              │
    │  2. Проверить connectivity:                                  │
    │     kubectl exec -it <gateway-pod> -- nc -zv vault.internal  │
    │       8200                                                   │
    │                                                              │
    │  3. Проверить логи Vault:                                    │
    │     kubectl logs -n vault -l app=vault --tail=100            │
    │                                                              │
    │  Решение:                                                    │
    │                                                              │
    │  ┌──────────────────────┬──────────────────────────────────┐ │
    │  │ Симптом              │ Действие                          │ │
    │  ├──────────────────────┼──────────────────────────────────┤ │
    │  │                      │                                   │ │
    │  │ Vault sealed         │ 1. Unseal через Vault operator    │ │
    │  │                      │ 2. Проверить auto-unseal          │ │
    │  │                      │                                   │ │
    │  │ Vault pod down       │ 1. kubectl get pods -n vault      │ │
    │  │                      │ 2. Restart если нужно             │ │
    │  │                      │ 3. Проверить HA (3 nodes)         │ │
    │  │                      │                                   │ │
    │  │ Network issue        │ 1. Проверить NetworkPolicy        │ │
    │  │                      │ 2. Проверить DNS                  │ │
    │  │                      │                                   │ │
    │  │ Auth failure         │ 1. Проверить AppRole role_id      │ │
    │  │                      │ 2. Проверить secret_id            │ │
    │  │                      │                                   │ │
    │  └──────────────────────┴──────────────────────────────────┘ │
    │                                                              │
    │  Эскалация:                                                  │
    │  • >5 минут → SRE Lead                                       │
    │  • >15 минут → VP Engineering + Customer Success             │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

---

### A-05: SPIRE agent недоступен >2m

```
    ┌──────────────────────────────────────────────────────────────┐
    │                                                              │
    │  Что значит:                                                 │
    │  Gateway не может получить или обновить SVID.                │
    │                                                              │
    │  Последствия:                                                │
    │  • Существующий SVID работает до истечения TTL (1 час)       │
    │  • Новые соединения → 503 (fail-closed)                      │
    │                                                              │
    │  Диагностика:                                                │
    │                                                              │
    │  1. Проверить SPIRE agent:                                   │
    │     kubectl get pods -n spire                                │
    │     kubectl logs -n spire -l app=spire-agent --tail=100      │
    │                                                              │
    │  2. Проверить SPIRE server:                                  │
    │     kubectl logs -n spire -l app=spire-server --tail=100     │
    │                                                              │
    │  3. Проверить SVID TTL:                                      │
    │     curl -s https://mcp.internal/metrics |                   │
    │       grep "spiffe_svid_ttl_seconds"                         │
    │                                                              │
    │  Решение:                                                    │
    │                                                              │
    │  • Если SPIRE agent crashed → auto-restart (DaemonSet)       │
    │  • Если SPIRE server down → manual restart + проверка HA     │
    │  • Если attestation failure → проверить WorkloadAttestor     │
    │    config + K8s SA + image SHA                               │
    │                                                              │
    │  ⚠️ При TTL <15m — окно для реакции критично мало            │
    │                                                              │
    │  Эскалация:                                                  │
    │  • >5 минут → SRE Lead                                       │
    │  • SVID TTL <15m → critical, все руки на палубу              │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

---

### A-06: Redis недоступен >1m (enterprise tenant)

```
    ┌──────────────────────────────────────────────────────────────┐
    │                                                              │
    │  Что значит:                                                 │
    │  Rate limiter не работает. Для enterprise tier — fail-closed,│
    │  значит все запросы → 503.                                   │
    │                                                              │
    │  Диагностика:                                                │
    │                                                              │
    │  1. Проверить Redis:                                         │
    │     redis-cli -h redis.internal ping                         │
    │     redis-cli -h redis.internal INFO                         │
    │                                                              │
    │  2. Проверить Sentinel (если HA):                            │
    │     redis-cli -h sentinel.internal -p 26379 sentinel masters │
    │                                                              │
    │  3. Проверить логи:                                          │
    │     kubectl logs -n redis -l app=redis --tail=100            │
    │                                                              │
    │  Решение:                                                    │
    │                                                              │
    │  ┌──────────────────────┬──────────────────────────────────┐ │
    │  │ Симптом              │ Действие                          │ │
    │  ├──────────────────────┼──────────────────────────────────┤ │
    │  │                      │                                   │ │
    │  │ Redis pod down       │ 1. Auto-restart (K8s)             │ │
    │  │                      │ 2. Если crash loop — проверить    │ │
    │  │                      │    memory/disk                    │ │
    │  │                      │                                   │ │
    │  │ Network issue        │ 1. Проверить NetworkPolicy        │ │
    │  │                      │ 2. Проверить DNS                  │ │
    │  │                      │                                   │ │
    │  │ Sentinel failover    │ 1. Проверить, что новый master    │ │
    │  │                      │    выбран                          │ │
    │  │                      │ 2. Gateway auto-reconnect         │ │
    │  │                      │                                   │ │
    │  │ Memory OOM           │ 1. Увеличить memory limits        │ │
    │  │                      │ 2. Проверить, что нет runaway     │ │
    │  │                      │    tenant'а                       │ │
    │  │                      │                                   │ │
    │  └──────────────────────┴──────────────────────────────────┘ │
    │                                                              │
    │  Fallback режим:                                             │
    │  • Standard/free tier — fail-open (продолжают работать)      │
    │  • Enterprise tier — fail-closed (503)                       │
    │  • Можно временно переключить enterprise в fail-open:        │
    │    mcp-gateway admin config set --tenant acme                │
    │      rate_limit.redis_failure_mode=fail-open                 │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

---

### A-07: HMAC key rotation failed

```
    ┌──────────────────────────────────────────────────────────────┐
    │                                                              │
    │  Что значит:                                                 │
    │  Плановая ротация HMAC-ключа (каждые 90 дней) не удалась.    │
    │                                                              │
    │  ⚠️ Не критично для работы — старый ключ продолжает          │
    │  использоваться. Но проблема должна быть решена до истечения │
    │  grace period.                                               │
    │                                                              │
    │  Диагностика:                                                │
    │                                                              │
    │  1. Проверить логи rotation job:                             │
    │     kubectl logs -n mcp-gateway job/hmac-rotation --tail=100 │
    │                                                              │
    │  2. Проверить Vault:                                         │
    │     vault kv list mcp-gateway/audit-hmac-key                 │
    │                                                              │
    │  3. Проверить права gateway SA на Vault:                     │
    │     vault policy read mcp-gateway-audit-key                  │
    │                                                              │
    │  Решение:                                                    │
    │                                                              │
    │  • Проверить connectivity к Vault                            │
    │  • Проверить RBAC policy                                     │
    │  • Manual rotation:                                          │
    │    mcp-gateway admin hmac rotate --force                     │
    │                                                              │
    │  ⚠️ Ключевое: НЕ удалять старый ключ после ротации —         │
    │  он нужен для верификации исторических записей.              │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

---

### A-08: Daily cost >2x baseline

```
    ┌──────────────────────────────────────────────────────────────┐
    │                                                              │
    │  Что значит:                                                 │
    │  Стоимость LLM за сутки превысила baseline в 2 раза.         │
    │  Возможные причины: runaway agent, DDoS, bug, изменение      │
    │  тарифов провайдера.                                         │
    │                                                              │
    │  Диагностика:                                                │
    │                                                              │
    │  1. Grafana → FinOps dashboard → Top-N agents by cost        │
    │                                                              │
    │  2. Быстрая проверка:                                        │
    │     curl -s https://mcp.internal/metrics |                   │
    │       grep mcp_llm_cost_rub_total | sort -k2 -n -r | head    │
    │                                                              │
    │  3. Определить аномального tenant/agent:                     │
    │     • Резкий рост requests                                   │
    │     • Резкий рост tokens per request                         │
    │     • Смена модели (Lite → Max)                              │
    │     • Retry storms                                            │
    │                                                              │
    │  Решение:                                                    │
    │                                                              │
    │  ┌──────────────────────┬──────────────────────────────────┐ │
    │  │ Причина              │ Действие                          │ │
    │  ├──────────────────────┼──────────────────────────────────┤ │
    │  │                      │                                   │ │
    │  │ Runaway agent        │ 1. Найти agent_id в метриках      │ │
    │  │                      │ 2. Блокировать:                    │ │
    │  │                      │    mcp-gateway admin tenant        │ │
    │  │                      │      block --tenant acme           │ │
    │  │                      │      --agent agent-x               │ │
    │  │                      │ 3. Notify tenant                   │ │
    │  │                      │                                   │ │
    │  │ Bug в gateway        │ 1. Проверить recent deploys       │ │
    │  │                      │ 2. Rollback если нужно            │ │
    │  │                      │                                   │ │
    │  │ DDoS / abuse         │ 1. Проверить rate limit metrics   │ │
    │  │                      │ 2. Увеличить throttling           │ │
    │  │                      │ 3. Security incident              │ │
    │  │                      │                                   │ │
    │  │ Смена тарифа         │ 1. Проверить статус провайдера    │ │
    │  │                      │ 2. Обновить FinOps model           │ │
    │  │                      │                                   │ │
    │  └──────────────────────┴──────────────────────────────────┘ │
    │                                                              │
    │  Эскалация:                                                  │
    │  • Cost >5x baseline → VP Engineering + Finance              │
    │  • Cost >10x baseline → C-level escalation                   │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

---

### W-01 — W-09: Warning alerts (краткая версия)

```
    ┌──────────────────────────────────────────────────────────────┐
    │                                                              │
    │  W-01: Burn rate >2x за 1h                                   │
    │  ────────────────────────────                                │
    │  → Отслеживать. Если тренд сохраняется → P2 (warning).       │
    │  → Проверить источник ошибок (как в A-01).                   │
    │                                                              │
    │  W-02: Circuit open >1m                                      │
    │  ─────────────────────────                                   │
    │  → Мониторить. Если >10m → A-02.                             │
    │  → Проверить upstream health.                                │
    │                                                              │
    │  W-03: Rate limit denial >10% для tenant                     │
    │  ────────────────────────────────────────                    │
    │  → Возможно, лимит слишком строгий.                          │
    │  → Связаться с tenant: нужен ли upgrade?                     │
    │  → Или: возможен abuse → security review.                    │
    │                                                              │
    │  W-04: p99 latency > SLO                                     │
    │  ────────────────────────                                    │
    │  → Найти медленные методы (tools/call?).                     │
    │  → Проверить upstream latency.                               │
    │  → Проверить CPU/mem gateway.                                │
    │                                                              │
    │  W-05: Audit queue full                                      │
    │  ─────────────────────                                       │
    │  → Writer не успевает.                                       │
    │  → Проверить Postgres latency.                               │
    │  → Увеличить batch size / pool.                              │
    │                                                              │
    │  W-06: SVID TTL <15m                                         │
    │  ────────────────────                                        │
    │  → Проверить SPIRE agent connectivity.                       │
    │  → Если TTL<5m → критично, escalate.                         │
    │                                                              │
    │  W-07: Breaker registry size anomaly                         │
    │  ───────────────────────────────────                         │
    │  → Возможно brute-force tenant_id.                           │
    │  → Проверить GC breaker'ов.                                  │
    │  → Валидация tenant_id перед созданием breaker'а.            │
    │                                                              │
    │  W-08: Tenant cost >100% budget                              │
    │  ──────────────────────────                                  │
    │  → Notify tenant.                                            │
    │  → Если >150% → auto-throttle.                               │
    │                                                              │
    │  W-09: Cache hit rate <20%                                   │
    │  ─────────────────────────                                   │
    │  → Проверить cache invalidation.                             │
    │  → Возможно, prompts не кешируются.                          │
    │  → Проверить TTL и cache keys.                               │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

---

## 4. Incident replay

### 4.1. Зачем нужен replay

```
    ┌──────────────────────────────────────────────────────────────┐
    │                                                              │
    │  Replay позволяет:                                           │
    │                                                              │
    │  • Понять, что произошло (post-mortem без догадок)           │
    │  • Воспроизвести инцидент для тестирования fix'а             │
    │  • Обучить команду на реальных кейсах                        │
    │  • Regression testing (не повторяется ли инцидент)           │
    │                                                              │
    │  Что сохраняется для replay:                                 │
    │                                                              │
    │  • Trace (Tempo, 30 дней)                                    │
    │  • Logs (Loki, 7 дней)                                       │
    │  • LLM prompts/responses (Langfuse, 30 дней, redacted)       │
    │  • Audit entry (Postgres, 1+ год)                            │
    │  • Metrics snapshot (Prometheus, 15 дней)                    │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

### 4.2. Как использовать

```bash
# 1. Replay по trace_id
mcp-gateway replay --trace-id abc123

# 2. Replay по request_id
mcp-gateway replay --request-id req-789

# 3. Replay по tenant + timeframe
mcp-gateway replay --tenant acme \
                   --from "2026-09-25T10:00:00Z" \
                   --to "2026-09-25T11:00:00Z" \
                   --out incident.json

# 4. Replay с экспортом
mcp-gateway replay --trace-id abc123 --format json > incident.json
mcp-gateway replay --trace-id abc123 --format markdown > incident.md

# 5. Test fix на инциденте
mcp-gateway replay --trace-id abc123 \
                   --replay-mode full \
                   --dry-run
```

### 4.3. Replay в post-mortem

```
    ┌──────────────────────────────────────────────────────────────┐
    │                                                              │
    │  Post-mortem template (см. раздел 7)                         │
    │                                                              │
    │  Ключевые секции, где используется replay:                   │
    │                                                              │
    │  1. Timeline:                                                │
    │     mcp-gateway replay --trace-id abc123 --format timeline   │
    │                                                              │
    │  2. Root cause:                                              │
    │     На основе unified trace + logs + Langfuse                │
    │                                                              │
    │  3. Impact:                                                  │
    │     На основе metrics snapshot + audit entries               │
    │                                                              │
    │  4. Action items:                                            │
    │     Regression test: replay после fix'а                      │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

---

## 5. Escalation matrix

```
    ┌──────────────────────────────────────────────────────────────┐
    │                                                              │
    │  Severity  │ First responder │ Escalate to      │ When       │
    │  ────────  │ ─────────────── │ ──────────────── │ ─────────  │
    │                                                              │
    │  🟢 P3     │ On-call SRE     │ —                │ —          │
    │  (info)    │                 │                  │            │
    │                                                              │
    │  🟡 P2     │ On-call SRE     │ Team Lead        │ >30 min    │
    │  (warn)    │                 │                  │ без прогресса│
    │                                                              │
    │  🟠 P1     │ On-call SRE     │ SRE Lead         │ Немедленно │
    │  (crit)    │ + Team Lead     │                  │            │
    │            │                 │ VP Engineering   │ >15 min    │
    │            │                 │ Customer Success │ Если client│
    │                                                              │
    │  🔴 P0     │ On-call SRE     │ SRE Lead         │ Немедленно │
    │  (outage)  │ + Team Lead     │                  │            │
    │            │                 │ VP Engineering   │ Немедленно │
    │            │                 │ CTO              │ >30 min    │
    │            │                 │ Customer Success │ Немедленно │
    │            │                 │ Security (если   │ Если       │
    │            │                 │  security)       │ security   │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

### 5.1. Ответственные роли

```
    ┌──────────────────────────────────────────────────────────────┐
    │                                                              │
    │  On-call SRE                                                 │
    │  • Первый responder                                          │
    │  • Диагностика по runbook                                    │
    │  • Фикс или эскалация                                        │
    │                                                              │
    │  Team Lead                                                   │
    │  • Поддержка on-call                                         │
    │  • Принятие решений по сложным инцидентам                    │
    │  • Коммуникация с командой                                   │
    │                                                              │
    │  SRE Lead                                                    │
    │  • Координация P1/P0                                          │
    │  • Принятие решений по rollback/deploy                       │
    │  • Связь с руководством                                       │
    │                                                              │
    │  VP Engineering                                              │
    │  • Эскалация P1/P0                                            │
    │  • Принятие бизнес-решений (приостановить сервис?)           │
    │                                                              │
    │  CTO                                                          │
    │  • P0 >30 min                                                │
    │  • Кризисный management                                       │
    │                                                              │
    │  Security Team                                               │
    │  • Все security-related инциденты                            │
    │  • Forensics, incident response                              │
    │                                                              │
    │  Customer Success                                            │
    │  • Коммуникация с затронутыми клиентами                      │
    │  • Обновления статуса                                         │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

---

## 6. Communication plan

### 6.1. Каналы коммуникации

```
    ┌──────────────────────────────────────────────────────────────┐
    │                                                              │
    │  Internal:                                                   │
    │  • #incident (Slack) — live updates                          │
    │  • #incident-postmortem — follow-up                          │
    │  • Email VP Eng / CTO — P0/P1 only                           │
    │                                                              │
    │  External:                                                   │
    │  • Status page (statuspage.io или аналог)                    │
    │  • Email затронутым клиентам (Customer Success)              │
    │  • Public post-mortem (для enterprise clients)               │
    │                                                              │
    │  Regulators:                                                 │
    │  • Роскомнадзор (152-ФЗ, при утечке ПДн)                     │
    │  • ЦБ РФ (для финансовых организаций)                        │
    │  • По требованию — в течение 24-72 часов                     │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

### 6.2. Update cadence

```
    ┌──────────────────────────────────────────────────────────────┐
    │                                                              │
    │  P0 (outage):                                                │
    │  • Status page: каждые 30 минут                              │
    │  • #incident: каждые 15 минут                                │
    │  • Затронутые клиенты: каждые 30 минут                       │
    │                                                              │
    │  P1 (critical):                                              │
    │  • Status page: каждые 2 часа                                │
    │  • #incident: каждые 30 минут                                │
    │                                                              │
    │  P2 (warning):                                               │
    │  • #incident: каждый час                                     │
    │                                                              │
    │  P3 (info):                                                  │
    │  • #incident: только при значимых изменениях                 │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

### 6.3. Шаблон сообщения

```
    ┌──────────────────────────────────────────────────────────────┐
    │                                                              │
    │  [STATUS UPDATE] MCP Gateway — <time UTC>                    │
    │                                                              │
    │  Severity: P0 / P1 / P2 / P3                                 │
    │  Status:   Investigating / Identified / Monitoring /         │
    │            Resolved                                          │
    │  Impact:   <что затронуто>                                   │
    │  ETA:      <оценка до fix>                                   │
    │  Updates:  <следующий апдейт через X минут>                  │
    │                                                              │
    │  Current situation:                                          │
    │  <описание>                                                  │
    │                                                              │
    │  Actions taken:                                              │
    │  • <action 1>                                                │
    │  • <action 2>                                                │
    │                                                              │
    │  Next steps:                                                 │
    │  • <next 1>                                                  │
    │  • <next 2>                                                  │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

---

## 7. Post-mortem template

```markdown
# Post-Mortem: <Incident Title>

- **Date:** YYYY-MM-DD
- **Severity:** P0 / P1 / P2 / P3
- **Duration:** X hours Y minutes
- **Author:** <name>
- **Status:** Draft / Final

## Summary

<2-3 предложения о том, что произошло>

## Impact

- **Users affected:** <N tenants / agents>
- **Requests affected:** <N total / N% of traffic>
- **Downtime:** <X minutes of degraded service>
- **Error budget consumed:** <N% of 30-day budget>
- **Financial impact:** <₽ estimated>

## Timeline

All times in UTC.

| Time | Event |
|------|-------|
| HH:MM | Alert fired (A-01: burn rate 14.4x) |
| HH:MM | On-call responded |
| HH:MM | Diagnostics started (trace_id abc123) |
| HH:MM | Root cause identified |
| HH:MM | Mitigation applied |
| HH:MM | Service restored |
| HH:MM | Monitoring confirmed stable |

## Root Cause

<Detailed analysis. Use `mcp-gateway replay --trace-id abc123` for exact timeline.>

## Detection

<How was the incident detected? Alert / customer report / manual? Why so long?>

## Response

<What went well? What could be better?>

## Contributing Factors

- <Factor 1>
- <Factor 2>

## Action Items

| Action | Owner | Deadline | Status |
|--------|-------|----------|--------|
| Add regression test | @sre | YYYY-MM-DD | Open |
| Update runbook | @sre | YYYY-MM-DD | Open |
| Improve alerting | @sre | YYYY-MM-DD | Open |

## Lessons Learned

<What did we learn? What will we do differently?>

## Appendix

- Trace: https://grafana.internal/explore/tempo?trace_id=abc123
- Logs: https://grafana.internal/explore/loki?query=...
- Metrics: https://grafana.internal/d/mcp-gateway?from=...&to=...
- Audit entries: SELECT * FROM audit_log WHERE ...
```

---

## 8. Периодические операции

### 8.1. Ежедневные

```
    ┌──────────────────────────────────────────────────────────────┐
    │                                                              │
    │  [ ] Проверить daily cost (FinOps dashboard)                 │
    │  [ ] Проверить SLO compliance                                │
    │  [ ] Проверить audit verify runs (должны быть success)       │
    │  [ ] Проверить broken alerts (silenced?)                     │
    │  [ ] Проверить audit queue size                              │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

### 8.2. Еженедельные

```
    ┌──────────────────────────────────────────────────────────────┐
    │                                                              │
    │  [ ] Review SLO weekly report                                │
    │  [ ] Review incidents (closed + open)                        │
    │  [ ] Check certificate expiry (SVID, TLS)                    │
    │  [ ] Check disk usage (Tempo, Loki, Postgres)                │
    │  [ ] Check Redis memory + evictions                          │
    │  [ ] Check Vault seal status                                 │
    │  [ ] Review rate limit denials per tenant                    │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

### 8.3. Ежемесячные

```
    ┌──────────────────────────────────────────────────────────────┐
    │                                                              │
    │  [ ] Review SLO monthly report                               │
    │  [ ] Cost review with Finance                                │
    │  [ ] Rotate on-call schedule                                 │
    │  [ ] Review incident trends                                  │
    │  [ ] Update runbook (based on incidents)                     │
    │  [ ] Test disaster recovery                                  │
    │  [ ] Review access permissions (RBAC)                        │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

### 8.4. Ежеквартальные

```
    ┌──────────────────────────────────────────────────────────────┐
    │                                                              │
    │  [ ] Review SLO targets                                      │
    │  [ ] Review threat model                                     │
    │  [ ] Review compliance mapping                               │
    │  [ ] Review ADR (any outdated?)                              │
    │  [ ] Capacity planning review                                │
    │  [ ] Key rotation (HMAC, если не auto)                       │
    │  [ ] External security review                                │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

---

## 9. Ревью и обновления

### 9.1. Расписание

```
    ┌──────────────────────────────────────────────────────────────┐
    │                                                              │
    │  • Ежемесячно — review based on incidents                    │
    │  • После крупного инцидента — обновление                     │
    │  • После релиза с новыми алертами — добавить runbook         │
    │  • Ежегодно — full review с SRE leadership                   │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

### 9.2. Ответственные

```
    ┌──────────────────────────────────────────────────────────────┐
    │                                                              │
    │  Owner:      SRE Lead                                        │
    │  Reviewers:  On-call engineers, Team Lead, Architect         │
    │  Approvers:  VP Engineering (для significant changes)        │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

### 9.3. Changelog

```
    ┌────────────┬──────────────┬──────────────────────────────────┐
    │ Version    │ Date         │ Changes                          │
    ├────────────┼──────────────┼──────────────────────────────────┤
    │ 1.0        │ 2026-09-25   │ Initial runbook                  │
    │            │              │ • Quick start                    │
    │            │              │ • 8 critical alert runbooks      │
    │            │              │ • 9 warning alert runbooks       │
    │            │              │ • Diagnostic by trace_id         │
    │            │              │ • Incident replay                │
    │            │              │ • Escalation matrix              │
    │            │              │ • Communication plan             │
    │            │              │ • Post-mortem template           │
    │            │              │ • Periodic operations            │
    └────────────┴──────────────┴──────────────────────────────────┘
```

---

## Приложение A: Полезные команды (cheat sheet)

```bash
# ═══ Health checks ═══
curl -s https://mcp.internal/healthz
curl -s https://mcp.internal/readyz
kubectl get pods -n mcp-gateway
kubectl logs -n mcp-gateway -l app=mcp-gateway --tail=100 -f

# ═══ Metrics ═══
curl -s https://mcp.internal/metrics | grep mcp_gateway
curl -s https://mcp.internal/metrics | grep circuit_state
curl -s https://mcp.internal/metrics | grep mcp_llm_cost

# ═══ Trace diagnostics ═══
mcp-gateway replay --trace-id abc123
mcp-gateway replay --trace-id abc123 --format json

# ═══ Redis ═══
redis-cli -h redis.internal ping
redis-cli -h redis.internal INFO
redis-cli -h redis.internal --scan --pattern "rl:*" | head -20

# ═══ Postgres ═══
psql -h postgres.internal -U mcp_gateway -c "SELECT count(*) FROM audit_log WHERE timestamp > NOW() - INTERVAL '1 hour';"
psql -h postgres.internal -U mcp_gateway -c "SELECT MAX(seq) FROM audit_log;"

# ═══ Audit verification ═══
mcp-gateway audit verify --from <seq_start> --to <seq_end>
mcp-gateway audit verify --full --report-json > report.json

# ═══ Breaker admin ═══
mcp-gateway admin breaker list
mcp-gateway admin breaker reset --tenant acme --upstream gigachat
mcp-gateway admin breaker reset --all

# ═══ Tenant admin ═══
mcp-gateway admin tenant block --tenant acme --agent agent-x
mcp-gateway admin tenant unblock --tenant acme --agent agent-x
mcp-gateway admin config set --tenant acme rate_limit.redis_failure_mode=fail-open

# ═══ Vault ═══
vault status
vault kv list mcp-gateway/
vault kv get mcp-gateway/audit-hmac-key

# ═══ Cost tracking ═══
curl -s https://mcp.internal/metrics | grep mcp_llm_cost_rub_total | sort -k2 -n -r | head

# ═══ Emergency freeze ═══
kubectl patch deployment mcp-gateway -n mcp-gateway -p '{"spec":{"replicas":0}}'
kubectl patch deployment mcp-gateway -n mcp-gateway -p '{"spec":{"replicas":3}}'
```

---

## Приложение B: Полезные ссылки

```
    ┌──────────────────────────────────────────────────────────────┐
    │                                                              │
    │  Documentation:                                              │
    │  • SLO:               docs/reliability/slo.md                │
    │  • Threat Model:      docs/security/threat-model.md          │
    │  • Capacity Planning: docs/reliability/capacity-planning.md  │
    │  • Blueprint:         docs/blueprint.md                      │
    │  • ADRs:              docs/adr/                              │
    │                                                              │
    │  External:                                                   │
    │  • Google SRE Book:   sre.google/sre-book/                   │
    │  • OTel Docs:         opentelemetry.io/docs/                 │
    │  • Grafana Docs:      grafana.com/docs/                      │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

