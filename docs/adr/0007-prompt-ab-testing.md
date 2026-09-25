# ADR-0007: Prompt A/B testing via Langfuse

- **Status:** In Progress
- **Date:** 2026-09-25
- **Deciders:** Roman Sokolov (Architect)
- **Tags:** `llm-ops`, `prompt-engineering`, `finops`, `reliability`, `observability`

---

## Context

MCP Gateway проксирует запросы AI-агентов к LLM. Каждый промпт, отправляемый
в LLM, влияет на:

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

## Implementation details

### Langfuse API contract

```
    ┌──────────────────────────────────────────────────────────────┐
    │                                                              │
    │  Authentication:                                             │
    │  • Basic Auth: public_key / secret_key                       │
    │  • Env: LANGFUSE_PUBLIC_KEY, LANGFUSE_SECRET_KEY             │
    │  • Base URL: LANGFUSE_BASE_URL (self-hosted или cloud)       │
    │                                                              │
    │  Endpoints (REST v2):                                        │
    │                                                              │
    │  1. GET /api/public/v2/prompts/{name}?label={label}          │
    │     Response:                                                │
    │     {                                                        │
    │       "name": "system-prompt-tools-call",                    │
    │       "version": 2,                                          │
    │       "type": "chat",                                        │
    │       "prompt": [                                            │
    │         {"role": "system", "content": "You are..."},         │
    │         {"role": "user", "content": "{{user_message}}"}      │
    │       ],                                                     │
    │       "labels": ["prod-b"],                                  │
    │       "config": {"model": "giga-chat-pro"}                   │
    │     }                                                        │
    │                                                              │
    │  2. POST /api/public/v2/prompts                              │
    │     Создать новую версию промпта                             │
    │                                                              │
    │  3. PATCH /api/public/v2/prompts/{name}/versions/{version}   │
    │     Обновить labels (для rollback)                           │
    │                                                              │
    │  4. POST /api/public/ingestion                               │
    │     Отправить traces (батчами)                               │
    │                                                              │
    │  5. GET /api/public/metrics                                  │
    │     Метрики для auto-rollback                                │
    │                                                              │
    │  6. Webhooks                                                 │
    │     • prompt.updated                                         │
    │     • prompt.label.changed                                   │
    │     Используется для cache invalidation                      │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

### Go structs

```go
// Prompt — представление промпта из Langfuse
type Prompt struct {
    Name    string                 `json:"name"`
    Version int                    `json:"version"`
    Type    string                 `json:"type"`   // "chat" | "text"
    Prompt  []Message              `json:"prompt"`
    Labels  []string               `json:"labels"`
    Config  map[string]interface{} `json:"config"`
    Tags    []string               `json:"tags,omitempty"`
}

// Message — сообщение в chat-промпте
type Message struct {
    Role    string `json:"role"`    // "system" | "user" | "assistant"
    Content string `json:"content"`
}

// ABConfig — конфигурация A/B эксперимента
type ABConfig struct {
    PromptName string // "system-prompt-tools-call"
    LabelA     string // "prod-a"
    LabelB     string // "prod-b"
    SplitPct   int    // 50 = 50% на A, 50% на B
}

// Client — клиент Langfuse с in-memory cache
type Client struct {
    baseURL    string
    publicKey  string
    secretKey  string
    httpClient *http.Client
    
    mu    sync.RWMutex
    cache map[string]*cacheEntry
}

type cacheEntry struct {
    prompt    *Prompt
    expiresAt time.Time
}
```

### OTel span attributes

```
    ┌──────────────────────────────────────────────────────────────┐
    │                                                              │
    │  КРИТИЧНО: attributes должны быть на GENERATION span,         │
    │  не на parent span.                                          │
    │                                                              │
    │  Обязательные attributes:                                    │
    │                                                              │
    │  • langfuse.observation.type = "generation"                  │
    │    ⚠️ Без него Langfuse игнорирует prompt linkage            │
    │                                                              │
    │  • langfuse.prompt.name = "system-prompt-tools-call"         │
    │  • langfuse.prompt.version = 2                               │
    │                                                              │
    │  GenAI semconv (OpenTelemetry):                              │
    │  • gen_ai.operation.name = "chat"                            │
    │  • gen_ai.request.model = "giga-chat-pro"                    │
    │  • gen_ai.usage.input_tokens = 2000                          │
    │  • gen_ai.usage.output_tokens = 500                          │
    │  • gen_ai.response.finish_reasons = ["stop"]                 │
    │                                                              │
    │  Custom attributes (наш gateway):                            │
    │  • tenant.id = "acme"                                        │
    │  • agent.id = "agent-x"                                      │
    │  • mcp.method = "tools/call"                                 │
    │  • pii.redacted_count = 2                                    │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

### Deterministic hash алгоритм

```go
func (c *ABConfig) SelectLabel(
    tenantID, agentID, requestID string,
) string {
    h := sha256.New()
    h.Write([]byte(tenantID))
    h.Write([]byte(":"))
    h.Write([]byte(agentID))
    h.Write([]byte(":"))
    h.Write([]byte(requestID))
    
    hash := h.Sum(nil)
    bucket := binary.BigEndian.Uint32(hash[:4]) % 100
    
    if int(bucket) < c.SplitPct {
        return c.LabelA
    }
    return c.LabelB
}
```

**Важно:** hash от `(tenant_id, agent_id, request_id)` — детерминированный.
Один запрос всегда одна версия. Replay воспроизводим.

### Rollout plan

```
    ┌──────────────────────────────────────────────────────────────┐
    │                                                              │
    │  Phase 1: Prompt versioning (без A/B) — 1 неделя             │
    │  ─────────────────────────────────────────────               │
    │  • Развернуть Langfuse                                       │
    │  • Создать prompts в Langfuse                                │
    │  • Интегрировать Prompt Resolver в gateway                   │
    │  • Заменить hardcoded prompts на dynamic fetch               │
    │  • Label: "production" для текущей версии                    │
    │                                                              │
    │  Phase 2: A/B split — 2 недели                               │
    │  ────────────────────────                                    │
    │  • Создать версию v2 с label "prod-b"                        │
    │  • Split 10% → monitor 1 неделя                              │
    │  • Если OK → split 50% → monitor 1 неделя                    │
    │  • Собрать метрики: cost, latency, quality                   │
    │                                                              │
    │  Phase 3: Auto-rollback — 1 неделя                           │
    │  ────────────────────────────                                │
    │  • Настроить Webhooks в Langfuse                             │
    │  • Реализовать Monitor в gateway                             │
    │  • Триггеры: cost > 1.5x, latency > 2x, success < 95%        │
    │  • Test с искусственной деградацией                          │
    │                                                              │
    │  Phase 4: LLM-as-a-Judge — 1 неделя                          │
    │  ────────────────────────────                                │
    │  • Настроить Evaluator в Langfuse                            │
    │  • Criteria: correctness, format, tone, safety               │
    │  • Score 0-1, автозапуск на каждый response                  │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

### Known limitations

```
    ┌──────────────────────────────────────────────────────────────┐
    │                                                              │
    │  1. Go SDK — community-maintained                            │
    │     ❌ Официального Go SDK от Langfuse нет                   │
    │     ⚠️ Community: github.com/git-hulk/langfuse-go            │
    │     ✅ Fallback: REST API (примеры в этом ADR)               │
    │     💡 Решение: обёртка над REST API + structs выше          │
    │                                                              │
    │  2. OTel prompt linkage — тонкости                           │
    │     ⚠️ Атрибуты должны быть на GENERATION span,              │
    │        не на parent                                            │
    │     ⚠️ Требуется langfuse.observation.type = "generation"    │
    │     💡 Тестировать через Langfuse UI: prompt должен           │
    │        появиться в trace                                       │
    │                                                              │
    │  3. Auto-rollback — кастомный код                            │
    │     ❌ Langfuse не делает auto-rollback из коробки           │
    │     ⚠️ Требуется Monitor (~300 строк Go)                     │
    │     💡 Или: Langfuse Webhooks + Gateway admin API            │
    │                                                              │
    │  4. Cache TTL vs rollback latency                            │
    │     ⚠️ Cache 5 минут = до 5 минут до применения rollback     │
    │     💡 Admin endpoint для force refresh:                     │
    │        mcp-gateway admin prompt refresh                      │
    │                                                              │
    │  5. Split consistency между pods                             │
    │     ⚠️ Deterministic hash обязателен (не random)             │
    │     💡 Hash от (tenant, agent, request_id), не от pod state  │
    │                                                              │
    │  6. Prompt Experiments — offline testing                     │
    │     ⚠️ Требует dataset с expected outputs                    │
    │     ⚠️ Требует LLM connection в Langfuse                     │
    │     💡 Setup: 1-2 дня на подготовку dataset                  │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

### Что из коробки vs кастомный код

```
    ┌─────────────────────────────┬──────────────────────────────┐
    │ Функция                     │ Реализация                   │
    ├─────────────────────────────┼──────────────────────────────┤
    │                             │                              │
    │ Prompt versioning           │ ✅ Langfuse из коробки       │
    │ Labels (prod-a/prod-b)      │ ✅ Langfuse из коробки       │
    │ A/B split (deterministic)   │ 🟡 Кастомный код (~100 строк)│
    │ Prompt fetch + cache        │ 🟡 Кастомный код (~150 строк)│
    │ OTel prompt linkage         │ 🟡 Span attributes (~50 строк)│
    │ Metrics (cost/latency)      │ ✅ Langfuse из коробки       │
    │ LLM-as-a-Judge              │ ✅ Langfuse Evaluators       │
    │ Offline Experiments         │ ✅ Langfuse Prompt Experiments│
    │ Auto-rollback               │ 🟡 Кастомный код (~300 строк)│
    │                             │                              │
    ├─────────────────────────────┼──────────────────────────────┤
    │ Итого кастомного кода       │ ~600 строк Go                │
    │ Итого из коробки Langfuse   │ 80% функциональности         │
    │                             │                              │
    └─────────────────────────────┴──────────────────────────────┘
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
- Встроенный Prompt Management.
- Встроенный A/B testing через labels.
- Встроенные эксперименты через UI (Prompt Experiments).
- Встроенные evals (LLM-as-a-Judge).
- SDK для Go (community-maintained).
- Интеграция с OTel.

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

**Числовые метрики** (cost, latency, success_rate) не измеряют **качество
ответа**.

**Пример:**

- Prompt A: 100ms latency, 1000 токенов, 95% success.
- Prompt B: 200ms latency, 1500 токенов, 98% success.

Какой лучше? Метрики не отвечают. Нужен **quality score**.

**LLM-as-a-Judge:**

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
- **Быстрый rollback** — смена label вместо deploy (95% быстрее).
- **A/B testing setup** — 10 минут через UI вместо дня кода.
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
- **Кастомный код** — ~600 строк Go для Prompt Resolver + Monitor.
  Митигация: обёртка над REST API + unit tests.

### Neutral

- **Prompt versioning** — новая дисциплина для команды. Требует обучения.
- **Metrics cardinality** — labels `prompt_version` увеличивают cardinality
  Prometheus. Митигация: только active versions в labels.
- **Go SDK** — community-maintained, не official.
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

**Решение:** отклонено. Git для prompts — медленно. Гибридный подход: prompts
в Langfuse, версии ссылаются на git SHA.

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
  - Развернуть Langfuse (docker-compose для dev, Helm для prod)
  - Создать prompts в Langfuse UI
  - Определить labels: `production`, `prod-a`, `prod-b`, `staging`
  - Настроить Prompt Experiments для offline testing

- [ ] **Gateway integration**:
  - Интегрировать Langfuse REST API (обёртка на Go)
  - Prompt Resolver с cache TTL 5 минут
  - Deterministic hash split
  - Fallback на default prompts при недоступности Langfuse

- [ ] **OTel span attributes**:
  - `langfuse.observation.type = "generation"`
  - `langfuse.prompt.name` + `langfuse.prompt.version`
  - Integration test: prompt появился в Langfuse UI

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
- [OpenTelemetry: GenAI Semantic Conventions](https://opentelemetry.io/docs/specs/semconv/gen-ai/)

---

## Related ADRs

- [ADR-0006: Observability stack](0006-observability-stack.md) — Langfuse входит в observability stack
- [ADR-0008: Cost attribution per agent](0008-cost-attribution-per-agent.md) (TBD) — использует метрики cost из A/B testing
- ADR-0009 (TBD): PII redaction — prompts хранятся в redacted виде