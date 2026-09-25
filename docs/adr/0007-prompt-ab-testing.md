# ADR-0007: Prompt A/B testing via Langfuse

- **Status:** In Progress
- **Date:** 2026-09-25
- **Deciders:** Roman Sokolov (Architect)
- **Tags:** `llm-ops`, `prompt-engineering`, `finops`, `reliability`, `observability`

---

## Context

MCP Gateway проксирует запросы AI-агентов к LLM. Каждый промпт, отправляемый в LLM, влияет на:

- **Качество ответа** — правильно ли агент решил задачу.
- **Стоимость** — количество input/output токенов (₽/call).
- **Latency** — время генерации ответа.
- **Compliance** — попадание PII в промпт.

**Проблема:** промпты эволюционируют, но их изменения не контролируются.

```
    ┌──────────────────────────────────────────────────────────────┐
    │                                                              │
    │  Типичный workflow без A/B testing:                          │
    │                                                              │
    │  1. Разработчик меняет промпт в коде                         │
    │  2. Deploy в production                                      │
    │  3. Молитва, что не сломается                                │
    │  4. Через неделю: "Почему cost вырос в 3 раза?"              │
    │  5. Rollback, но непонятно, что именно помогло               │
    │                                                              │
    │  Проблемы:                                                   │
    │  • Нет baseline для сравнения                                │
    │  • Нет изоляции переменных (изменили промпт + модель)        │
    │  • Нет метрик impact на cost/latency/quality                 │
    │  • Нет возможности canary deploy                             │
    │  • Rollback = новый deploy (медленно, рискованно)            │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

**Требуется:**

- **Версионирование промптов** — каждая версия имеет ID, можно вернуться.
- **A/B split** — часть трафика на версию A, часть на версию B.
- **Метрики impact** — cost, latency, quality per version.
- **Auto-rollback** — при деградации метрик откат автоматически.
- **Canary deploy** — сначала 1% трафика, потом 100%.

---

## Decision

**Используем Langfuse** для prompt management + A/B testing, интегрированный
с gateway через OTel (см. ADR-0006).

### Архитектура

```
    ┌───────────────────────────────────────────────────────────────────┐
    │                                                                    │
    │   MCP Gateway (Go)                                                 │
    │                                                                    │
    │   ┌──────────────────────────────────────────────────────────┐    │
    │   │                                                            │    │
    │   │   Prompt Resolver                                          │    │
    │   │   ├── Fetch prompt from Langfuse                           │    │
    │   │   ├── A/B split based on tenant/agent/request              │    │
    │   │   └── Inject into LLM request                              │    │
    │   │                                                            │    │
    │   └────────────────────┬───────────────────────────────────────┘    │
    │                        │                                            │
    │                        │ HTTPS                                      │
    │                        │ (cache TTL 5 min)                          │
    │                        ▼                                            │
    │   ┌──────────────────────────────────────────────────────────┐    │
    │   │                                                            │    │
    │   │   Langfuse Prompt Management                               │    │
    │   │   ├── Prompt "system-prompt-tools-call"                    │    │
    │   │   │   ├── v1 (label: prod-a) → 50% traffic                 │    │
    │   │   │   └── v2 (label: prod-b) → 50% traffic                 │    │
    │   │   ├── Prompt "system-prompt-tools-list"                    │    │
    │   │   │   └── v1 (label: prod) → 100% traffic                  │    │
    │   │   └── Prompt "pii-detection-instructions"                  │    │
    │   │       └── v1 (label: prod) → 100% traffic                  │    │
    │   │                                                            │    │
    │   └────────────────────┬───────────────────────────────────────┘    │
    │                        │                                            │
    │                        │ traces + metrics                           │
    │                        ▼                                            │
    │   ┌──────────────────────────────────────────────────────────┐    │
    │   │                                                            │    │
    │   │   Langfuse Analytics                                       │    │
    │   │   ├── Cost per prompt version                              │    │
    │   │   ├── Latency per prompt version                           │    │
    │   │   ├── Quality scores (LLM-as-a-Judge)                      │    │
    │   │   └── Regression detection                                 │    │
    │   │                                                            │    │
    │   └──────────────────────────────────────────────────────────┘    │
    │                                                                    │
    └───────────────────────────────────────────────────────────────────┘
```

### A/B split strategy

```
    ┌──────────────────────────────────────────────────────────────┐
    │                                                              │
    │  Split на уровне (tenant_id, agent_id, request_id):          │
    │                                                              │
    │  hash = SHA256(tenant_id || agent_id || request_id)          │
    │  bucket = hash % 100                                         │
    │                                                              │
    │  if bucket < 50:                                             │
    │      prompt = langfuse.get_prompt("name", label="prod-a")    │
    │  else:                                                       │
    │      prompt = langfuse.get_prompt("name", label="prod-b")    │
    │                                                              │
    │  Преимущества:                                               │
    │  • Deterministic — один и тот же запрос всегда одна версия   │
    │  • Consistent — один tenant всегда одна версия (если нужно)  │
    │  • Reproducible — можно повторить в replay                   │
    │                                                              │
    │  Конфигурация split:                                         │
    │  • 50/50 — классический A/B                                  │
    │  • 90/10 — canary deploy                                     │
    │  • 99/1 — smoke test новой версии                            │
    │  • 0/100 — полный rollback (без deploy)                      │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

### Метрики impact

```
    ┌──────────────────────────────────────────────────────────────┐
    │                                                              │
    │  Для каждой prompt version:                                  │
    │                                                              │
    │  Cost metrics:                                               │
    │  • avg_cost_per_call (₽)                                     │
    │  • total_cost_per_hour (₽)                                   │
    │  • cost_p50, cost_p99                                        │
    │                                                              │
    │  Latency metrics:                                            │
    │  • latency_p50, latency_p99 (ms)                             │
    │  • time_to_first_token (для streaming)                       │
    │                                                              │
    │  Quality metrics:                                            │
    │  • success_rate (2xx / total)                                │
    │  • retry_rate (сколько раз retry)                            │
    │  • LLM-as-a-Judge score (0-1)                                │
    │                                                              │
    │  Safety metrics:                                             │
    │  • pii_redacted_count (сколько PII обнаружено)               │
    │  • pii_false_positive_rate                                   │
    │                                                              │
    │  Business metrics:                                           │
    │  • task_completion_rate (если определена)                    │
    │  • user_satisfaction (если есть feedback)                    │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

### Auto-rollback

```
    ┌──────────────────────────────────────────────────────────────┐
    │                                                              │
    │  Триггеры для auto-rollback:                                 │
    │                                                              │
    │  • Cost per call > 1.5x baseline (за 15 минут)               │
    │  • Latency p99 > 2x baseline (за 15 минут)                   │
    │  • Success rate < 95% (за 5 минут)                           │
    │  • LLM-as-a-Judge score < 0.7 (за 30 минут)                  │
    │  • PII detection rate > 2x baseline                          │
    │                                                              │
    │  Действие:                                                   │
    │  mcp-gateway admin prompt rollback --name "system-prompt-    │
    │    tools-call" --to-version v1                               │
    │                                                              │
    │  Или автоматически через Langfuse webhook:                   │
    │  • Langfuse → Webhook → Gateway admin API                    │
    │  • Изменение label "prod-b" → "prod-a"                       │
    │  • Gateway перечитает prompt (cache TTL 5 min)               │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

### Prompt versioning

```
    ┌──────────────────────────────────────────────────────────────┐
    │                                                              │
    │  Langfuse Prompt Management:                                 │
    │                                                              │
    │  Prompt "system-prompt-tools-call":                          │
    │                                                              │
    │  ├── v1 (2026-09-01)                                         │
    │  │   label: [production, prod-a]                             │
    │  │   content: "You are a helpful assistant..."               │
    │  │                                                           │
    │  ├── v2 (2026-09-15)                                         │
    │  │   label: [prod-b]                                         │
    │  │   content: "You are a precise assistant..."               │
    │  │                                                           │
    │  └── v3 (2026-09-25, draft)                                  │
    │      label: [staging]                                        │
    │      content: "..."                                          │
    │                                                              │
    │  Workflow:                                                   │
    │  1. Draft v3 в Langfuse                                      │
    │  2. Test на staging dataset (LLM-as-a-Judge)                 │
    │  3. Label v3 как "prod-b", split 10%                         │
    │  4. Monitor 24 часа                                          │
    │  5. Если OK → label v3 как "production", удалить prod-a      │
    │  6. Если не OK → auto-rollback на prod-a                     │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

---

## Rationale

### Почему Langfuse, а не собственное решение

**Собственное решение:**

- Своя БД для prompt versions.
- Свой UI для сравнения.
- Свой A/B testing logic.
- Свои evals (LLM-as-a-Judge).
- Свои метрики.

**Оценка:** 3-6 месяцев разработки + поддержка.

**Langfuse:**

- Open-source, self-hosted.
- Уже в стеке (ADR-0006).
- Встроенный Prompt Management [citation:1].
- Встроенный A/B testing через labels [citation:1].
- Встроенные эксперименты через UI (Prompt Experiments) [citation:6][citation:7].
- Встроенные evals (LLM-as-a-Judge).
- SDK для Go (community-maintained) [citation:4][citation:11].
- Интеграция с OTel [citation:10].

**Оценка:** 2-3 дня на интеграцию.

**Решение:** Langfuse.

### Почему labels, а не feature flags

**Feature flags** (Unleash, LaunchDarkly):

- Мощные, но избыточные для prompts.
- Требуют отдельной инфраструктуры.
- Не интегрированы с LLM observability.

**Labels в Langfuse:**

- Простые: `prod-a`, `prod-b`, `production`, `staging`.
- Один источник правды (prompt + label + analytics).
- Zero extra infra (уже есть Langfuse).

**Решение:** labels.

### Почему deterministic hash split, а не random

**Random split:**

```go
if rand.Float64() < 0.5 {
    // prod-a
} else {
    // prod-b
}
```

**Проблема:** один и тот же запрос может попасть в разные версии при retry.
Это ломает:
- **Reproducibility** — replay даст другой результат.
- **Debugging** — сложно понять, какую версию видел пользователь.
- **Consistency** — один tenant может видеть разные версии.

**Deterministic hash split:**

```go
hash := sha256(tenantID + agentID + requestID)
bucket := hash[0] % 100
if bucket < 50 {
    // prod-a
} else {
    // prod-b
}
```

**Преимущества:**
- Один запрос → одна версия всегда.
- Replay воспроизводим.
- Debugging простой.

**Решение:** deterministic hash.

### Почему LLM-as-a-Judge, а не только метрики

**Числовые метрики** (cost, latency, success_rate) не измеряют **качество ответа**.

**Пример:**
- Prompt A: 100ms latency, 1000 токенов, 95% success.
- Prompt B: 200ms latency, 1500 токенов, 98% success.

Какой лучше? Метрики не отвечают. Нужен **quality score**.

**LLM-as-a-Judge** [citation:6][citation:7]:
- Отдельная LLM оценивает ответы по критериям (correctness, format, tone).
- Score 0-1.
- Автоматизировано, не требует human labeling.

**Решение:** LLM-as-a-Judge через Langfuse Evaluators.

### Почему auto-rollback, а не manual

**Manual rollback:**
- Требует on-call engineer.
- Задержка 5-30 минут.
- Человеческий фактор (забыли, ошиблись).

**Auto-rollback:**
- Мгновенно (Langfuse webhook → gateway admin API).
- Без участия человека.
- Consistent: всегда срабатывает.

**Риск:** false positive (auto-rollback при transient spike).

**Митигация:**
- Rolling window (15 минут) — сглаживает transient.
- Multiple triggers (cost + latency + success rate) — снижает false positive.
- Manual override — on-call может отменить auto-rollback.

**Решение:** auto-rollback с ручным override.

---

## Consequences

### Positive

- **Безопасная эволюция промптов** — canary deploy вместо big-bang.
- **Измеримый impact** — cost, latency, quality per version.
- **Auto-rollback** — деградация откатывается за минуты.
- **Reproducibility** — deterministic split для replay.
- **Zero extra infra** — Langfuse уже в стеке (ADR-0006).
- **Быстрый rollback** — смена label вместо deploy (95% быстрее) [citation:17].
- **A/B testing setup** — 10 минут через UI вместо дня кода [citation:17].
- **LLM-as-a-Judge** — автоматическая оценка качества.

### Negative

- **Langfuse dependency** — если Langfuse недоступен, prompts не загружаются.
  Митигация: cache TTL 5 минут + fallback на default prompts.
- **Cache invalidation** — после изменения prompt нужно ждать TTL или force refresh.
  Митигация: admin endpoint для force refresh.
- **Split complexity** — deterministic hash требует согласованности между
  gateway instances. Митигация: hash на request_id (не на instance state).
- **Auto-rollback risk** — false positive при transient spike.
  Митигация: rolling window + multiple triggers.
- **Storage costs** — Langfuse хранит prompts/responses (30 дней).
  Митигация: PII redaction перед сохранением (ADR-0006).

### Neutral

- **Prompt versioning** — новая дисциплина для команды. Требует обучения.
- **Metrics cardinality** — labels `prompt_version` увеличивают cardinality
  Prometheus. Митигация: только active versions в labels.
- **Go SDK** — community-maintained, не official [citation:4][citation:11].
  Митигация: fallback на REST API.

---

## Failure modes

### Langfuse недоступен

```
    ┌──────────────────────────────────────────────────────────────┐
    │                                                              │
    │  Симптом: gateway не может загрузить prompt                  │
    │                                                              │
    │  Поведение:                                                  │
    │  1. Cache hit (TTL 5 мин) → использовать закешированную версию│
    │  2. Cache miss → использовать default prompt из конфига      │
    │  3. Логировать warning + метрика                             │
    │                                                              │
    │  ⚠️ Gateway НЕ блокируется — fail-open для prompts           │
    │                                                              │
    │  Detection:                                                  │
    │  • Алерт: mcp_gateway_prompt_fetch_errors_total > 0          │
    │  • Алерт: mcp_gateway_prompt_cache_miss_total > threshold   │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

### Prompt не найден в Langfuse

```
    ┌──────────────────────────────────────────────────────────────┐
    │                                                              │
    │  Симптом: prompt name/label не существует                    │
    │                                                              │
    │  Причины:                                                    │
    │  • Опечатка в имени prompt                                   │
    │  • Label удалён                                              │
    │  • Prompt не создан                                          │
    │                                                              │
    │  Поведение:                                                  │
    │  • Fallback на default prompt                                │
    │  • Critical alert (это ошибка конфигурации)                  │
    │                                                              │
    │  Detection:                                                  │
    │  • Алерт: mcp_gateway_prompt_not_found_total > 0             │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

### Auto-rollback false positive

```
    ┌──────────────────────────────────────────────────────────────┐
    │                                                              │
    │  Симптом: auto-rollback сработал, но деградации не было      │
    │                                                              │
    │  Причины:                                                    │
    │  • Transient spike (upstream latency, network glitch)        │
    │  • Rolling window слишком короткое                           │
    │  • Single trigger без подтверждения                          │
    │                                                              │
    │  Митигация:                                                  │
    │  • Multiple triggers (cost + latency + success rate)         │
    │  • Rolling window 15 минут                                   │
    │  • Manual override (on-call может отменить)                  │
    │                                                              │
    │  Detection:                                                  │
    │  • Алерт: prompt_rollback_total > 2 за час                   │
    │  • Алерт: prompt_rollback_manual_override_total > 0          │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

### Split inconsistency между instances

```
    ┌──────────────────────────────────────────────────────────────┐
    │                                                              │
    │  Симптом: один и тот же запрос обрабатывается разными        │
    │  версиями prompt на разных gateway pods                      │
    │                                                              │
    │  Причины:                                                    │
    │  • Random split вместо deterministic hash                    │
    │  • Cache TTL рассинхронизирован                              │
    │                                                              │
    │  Митигация:                                                  │
    │  • Deterministic hash на (tenant_id || agent_id ||           │
    │    request_id)                                               │
    │  • Одинаковый cache TTL для всех pods                        │
    │  • Integration test: одинаковый hash на всех pods            │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

---

## Alternatives considered

### Alternative 1: Собственное решение для A/B testing

**Плюсы:**
- Полный контроль.
- Идеальная интеграция.

**Минусы:**
- 3-6 месяцев разработки.
- Поддержка навсегда.
- Не покрывает LLM-as-a-Judge.
- Не покрывает prompt versioning.

**Решение:** отклонено. Langfuse покрывает все нужды.

### Alternative 2: Feature flags (Unleash, LaunchDarkly)

**Плюсы:**
- Мощные.
- Много фич.

**Минусы:**
- Избыточные для prompts.
- Отдельная инфраструктура.
- Не интегрированы с LLM observability.

**Решение:** отклонено. Labels в Langfuse проще и интегрированнее.

### Alternative 3: Git-based prompt versioning

**Плюсы:**
- Prompts в git.
- Code review через PR.
- История.

**Минусы:**
- Deploy для изменения prompt.
- Нет A/B testing.
- Нет метрик per version.

**Решение:** отклонено. Git для prompts — медленно. Гибридный подход: prompts в Langfuse, версии ссылаются на git SHA.

### Alternative 4: Random split вместо deterministic hash

**Плюсы:**
- Проще.

**Минусы:**
- Один запрос → разные версии при retry.
- Replay не воспроизводим.
- Debugging сложен.

**Решение:** отклонено. Deterministic hash обязателен.

---

## Action items

Задачи, вытекающие из этого ADR:

- [ ] **Langfuse Prompt Management setup**:
  - Создать prompts в Langfuse UI
  - Определить labels: `production`, `prod-a`, `prod-b`, `staging`
  - Настроить Prompt Experiments для offline testing [citation:6][citation:7]

- [ ] **Gateway integration**:
  - Интегрировать Langfuse Go SDK (community-maintained) [citation:4][citation:11]
  - Или fallback на REST API (если SDK нестабилен)
  - Prompt Resolver с cache TTL 5 минут
  - Deterministic hash split

- [ ] **Metrics**:
  - `mcp_gateway_prompt_version_usage{name, version}` (counter)
  - `mcp_gateway_prompt_fetch_errors_total{name}` (counter)
  - `mcp_gateway_prompt_cache_miss_total{name}` (counter)
  - `mcp_gateway_prompt_not_found_total{name, label}` (counter)
  - `mcp_gateway_prompt_rollback_total{name}` (counter)

- [ ] **LLM-as-a-Judge**:
  - Настроить evaluator в Langfuse
  - Criteria: correctness, format, tone, safety
  - Score 0-1

- [ ] **Auto-rollback**:
  - Langfuse webhook → gateway admin API
  - Triggers: cost > 1.5x, latency > 2x, success rate < 95%
  - Rolling window 15 минут
  - Manual override

- [ ] **Admin endpoints**:
  - `mcp-gateway admin prompt list`
  - `mcp-gateway admin prompt refresh --name <name>`
  - `mcp-gateway admin prompt rollback --name <name> --to-version <v>`

- [ ] **Testing**:
  - Unit test: deterministic hash split
  - Integration test: Langfuse fetch + cache
  - Integration test: auto-rollback on degradation
  - Load test: 10k RPS с prompt fetch

- [ ] **Documentation**:
  - Обновить `docs/reliability/runbook.md` — prompt rollback procedures
  - Обновить `docs/blueprint.md` — A/B testing в capabilities
  - Guide для команды: workflow разработки prompts

---

## References

- [Langfuse: A/B Testing of LLM Prompts](https://python-sdk-v3.docs-snapshot.langfuse.com/docs/prompt-management/features/a-b-testing/)
- [Langfuse: Prompt Experiments via UI](https://langfuse.com/docs/evaluation/experiments/experiments-via-ui)
- [Langfuse: How to measure prompt performance](https://langfuse-docs-git-add-js-sdk-v4-docs-langfuse.vercel.app/faq/all/how-to-measure-prompt-performance)
- [Langfuse: community-maintained Go SDKs](https://github.com/langfuse/langfuse-examples)
- [Langfuse: OTel integration](https://raw.githubusercontent.com/trpc-group/trpc-agent-go/main/docs/mkdocs/en/observability.md)

---

## Related ADRs

- [ADR-0006: Observability stack](0006-observability-stack.md) — Langfuse входит в observability stack
- [ADR-0008: Cost attribution per agent](0008-cost-attribution-per-agent.md) (TBD) — использует метрики cost из A/B testing
- ADR-0009 (TBD): PII redaction — prompts хранятся в redacted виде