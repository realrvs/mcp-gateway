# ADR-0008: Cost attribution per agent

- **Status:** In Progress
- **Date:** 2026-09-25
- **Deciders:** Roman Sokolov (Architect)
- **Tags:** `finops`, `multi-tenancy`, `observability`, `reliability`, `cost`

---

## Context

MCP Gateway обслуживает **несколько тенантов**, и внутри каждого тенанта
может работать **много агентов** (AI-приложений, инструментов, интеграций).

Существующая FinOps-модель (см. `docs/reliability/capacity-planning.md`)
даёт cost per tenant, но этого **недостаточно**:

```
    ┌──────────────────────────────────────────────────────────────┐
    │                                                              │
    │  Проблема: один tenant = много агентов.                      │
    │                                                              │
    │  Пример: tenant "acme"                                       │
    │  ├── agent-customer-support    (100 calls/hour)              │
    │  ├── agent-code-reviewer       (500 calls/hour)              │
    │  ├── agent-data-analyst        (50 calls/hour)               │
    │  └── agent-internal-tools      (2000 calls/hour)  ⚠️         │
    │                                                              │
    │  Tenant видит один счёт: ~1.2M ₽/месяц                       │
    │  Непонятно:                                                   │
    │  • Какой агент тратит больше всех?                           │
    │  • Где аномалия (spike)?                                     │
    │  • Кого ограничить при превышении бюджета?                   │
    │  • Как аллоцировать cost внутри tenant'а?                    │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

**Требуется:**

- **Cost attribution per (tenant, agent)** — не только per tenant.
- **Cost per request** — микроуровень для аномалий.
- **Grafana dashboards** — Top-N агентов, trends, anomalies.
- **Alerting per agent** — на превышение baseline.
- **Auto-throttle** — при превышении бюджета.
- **Integration с A/B testing** (ADR-0007) — cost per prompt version × agent.

---

## Decision

**Расширяем FinOps-модель** через добавление `agent_id` как first-class
атрибута во все cost-метрики, с dashboards, alerting и auto-throttle.

### Архитектура

```
    ┌───────────────────────────────────────────────────────────────────┐
    │                                                                    │
    │   MCP Gateway (Go)                                                 │
    │                                                                    │
    │   ┌──────────────────────────────────────────────────────────┐    │
    │   │                                                            │    │
    │   │   Request Handler                                          │    │
    │   │   ├── Extract tenant_id (JWT claim)        [ADR-0004]      │    │
    │   │   ├── Extract agent_id (header/JWT/body)                   │    │
    │   │   ├── Fetch prompt (A/B split)             [ADR-0007]      │    │
    │   │   ├── Call LLM                                             │    │
    │   │   └── Record metrics (tenant + agent)                      │    │
    │   │                                                            │    │
    │   └────────────────────┬───────────────────────────────────────┘    │
    │                        │                                            │
    │                        │ OTLP                                       │
    │                        ▼                                            │
    │   ┌──────────────────────────────────────────────────────────┐    │
    │   │                                                            │    │
    │   │   Prometheus                                               │    │
    │   │   ├── mcp_llm_cost_rub_total{tenant, agent, provider,      │    │
    │   │   │                          model}                        │    │
    │   │   ├── mcp_llm_tokens_total{tenant, agent, direction}       │    │
    │   │   └── mcp_requests_total{tenant, agent, method, status}    │    │
    │   │                                                            │    │
    │   └────────────────────┬───────────────────────────────────────┘    │
    │                        │                                            │
    │                        ▼                                            │
    │   ┌──────────────────────────────────────────────────────────┐    │
    │   │                                                            │    │
    │   │   Grafana Dashboards                                       │    │
    │   │   ├── Top-N agents by cost                                 │    │
    │   │   ├── Cost trend per agent                                 │    │
    │   │   ├── Anomaly detection (rule-based)                       │    │
    │   │   └── Budget vs actual per agent                           │    │
    │   │                                                            │    │
    │   └────────────────────┬───────────────────────────────────────┘    │
    │                        │                                            │
    │                        ▼                                            │
    │   ┌──────────────────────────────────────────────────────────┐    │
    │   │                                                            │    │
    │   │   Alertmanager                                             │    │
    │   │   ├── Agent cost > 100% budget → warning                   │    │
    │   │   ├── Agent cost > 150% budget → critical                  │    │
    │   │   └── Agent cost > 3x baseline → anomaly warning           │    │
    │   │                                                            │    │
    │   └────────────────────┬───────────────────────────────────────┘    │
    │                        │                                            │
    │                        ▼                                            │
    │   ┌──────────────────────────────────────────────────────────┐    │
    │   │                                                            │    │
    │   │   Auto-throttle Controller                                 │    │
    │   │   ├── Watch alerts                                         │    │
    │   │   ├── Apply rate limit override                            │    │
    │   │   └── Notify tenant admin                                  │    │
    │   │                                                            │    │
    │   └──────────────────────────────────────────────────────────┘    │
    │                                                                    │
    └───────────────────────────────────────────────────────────────────┘
```

### Источники agent_id

```
    ┌──────────────────────────────────────────────────────────────┐
    │                                                              │
    │  Приоритеты (как для tenant_id в ADR-0004):                  │
    │                                                              │
    │  Priority  Source              When used                     │
    │  ────────  ──────────────────  ──────────────────────────    │
    │                                                              │
    │  1         JWT claim           Production. Всегда.            │
    │            "agent_id"          Подписан IdP, нельзя подменить.│
    │                                                              │
    │  2         HTTP header          Fallback. Полезно для         │
    │            "X-Agent-ID"         внутренних агентов,           │
    │                                 которых нет в IdP.            │
    │                                                              │
    │  3         Request body         Last resort. Требует          │
    │            "_meta.agent_id"     валидации: header не должен   │
    │                                 противоречить body.           │
    │                                                              │
    │  4         "unknown"            Fallback. Логируется          │
    │            (default)            как warning, используется     │
    │                                 для alerting.                 │
    │                                                              │
    │  ⚠️ Правило: если agent_id не извлечён → "unknown" +          │
    │  warning metric. Не блокируем запрос (в отличие от tenant).   │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

### Метрики

```
    ┌──────────────────────────────────────────────────────────────┐
    │                                                              │
    │  Primary metrics (per tenant × agent):                       │
    │                                                              │
    │  mcp_llm_cost_rub_total{                                     │
    │    tenant,              # "acme"                             │
    │    agent,               # "agent-x" или "unknown"            │
    │    provider,            # "gigachat" | "yandex" | "ollama"   │
    │    model,               # "GigaChat-Pro" | "YandexGPT-Lite"  │
    │    direction            # "input" | "output"                 │
    │  } → counter (₽)                                             │
    │                                                              │
    │  mcp_llm_tokens_total{                                       │
    │    tenant, agent, provider, model, direction                 │
    │  } → counter (tokens)                                        │
    │                                                              │
    │  mcp_requests_total{                                         │
    │    tenant, agent, method, status                             │
    │  } → counter (requests)                                      │
    │                                                              │
    │  Derived metrics:                                            │
    │                                                              │
    │  mcp_llm_cost_per_call_rub{tenant, agent} → histogram        │
    │    buckets: [0.01, 0.05, 0.1, 0.5, 1, 5, 10, 50, 100] ₽      │
    │                                                              │
    │  mcp_llm_cost_per_hour_rub{tenant, agent} → gauge            │
    │    (вычисляется через recording rules)                       │
    │                                                              │
    │  Budget metrics:                                             │
    │                                                              │
    │  mcp_agent_budget_rub{tenant, agent} → gauge                 │
    │    (из конфига, current budget)                              │
    │                                                              │
    │  mcp_agent_budget_used_pct{tenant, agent} → gauge            │
    │    (computed: current_hour_cost / budget * 100)              │
    │                                                              │
    │  Anomaly metrics:                                            │
    │                                                              │
    │  mcp_agent_cost_anomaly{tenant, agent} → gauge               │
    │    1 = anomaly detected, 0 = normal                          │
    │    (rule-based: >3x baseline за 1 час)                       │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

### Grafana dashboards

```
    ┌──────────────────────────────────────────────────────────────┐
    │  Dashboard: "MCP Gateway — Cost by Agent"                    │
    ├──────────────────────────────────────────────────────────────┤
    │                                                              │
    │  Row 1: Top-N agents by cost (текущий час)                   │
    │  ┌────────────────────────────────────────────────────────┐ │
    │  │ Tenant | Agent              | Cost ₽/hour | Budget %   │ │
    │  ├────────────────────────────────────────────────────────┤ │
    │  │ acme   | internal-tools     | 45,000     | 90%    ⚠️  │ │
    │  │ acme   | code-reviewer      | 12,500     | 25%        │ │
    │  │ acme   | customer-support   | 2,500      | 5%         │ │
    │  │ globex | data-analyst       | 8,000      | 40%        │ │
    │  └────────────────────────────────────────────────────────┘ │
    │                                                              │
    │  Row 2: Cost trend per agent (24h rolling)                   │
    │  • Time series: 5 top agents                                 │
    │  • Annotation: budget threshold                              │
    │  • Annotation: anomaly events                                │
    │                                                              │
    │  Row 3: Budget vs actual (per agent)                         │
    │  • Bar chart: current cost vs budget                         │
    │  • Color: green <80%, yellow 80-100%, red >100%              │
    │                                                              │
    │  Row 4: Anomaly detection                                    │
    │  • Heatmap: cost per minute per agent (last 6h)              │
    │  • Markers: detected anomalies                               │
    │                                                              │
    │  Row 5: Cost per prompt version (integration с ADR-0007)     │
    │  • Group by: tenant, agent, prompt_version                   │
    │  • Позволяет увидеть, какая версия промпта дороже            │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

### Alerting rules

```
    ┌──────────────────────────────────────────────────────────────┐
    │                                                              │
    │  W-08: Agent cost > 100% budget                              │
    │  ────────────────────────────────                            │
    │  expr: mcp_agent_budget_used_pct{tenant,agent} > 100         │
    │  for:  5m                                                    │
    │  labels: severity=warning                                    │
    │  annotations:                                                │
    │    summary: "Agent {{ $labels.agent }} exceeded budget"     │
    │    runbook: ".../runbook.md#w-08"                            │
    │                                                              │
    │  C-08: Agent cost > 150% budget                              │
    │  ────────────────────────────────                            │
    │  expr: mcp_agent_budget_used_pct{tenant,agent} > 150         │
    │  for:  2m                                                    │
    │  labels: severity=critical                                   │
    │  annotations:                                                │
    │    summary: "Agent {{ $labels.agent }} severely over budget" │
    │                                                              │
    │  C-09: Agent cost anomaly (>3x baseline)                     │
    │  ───────────────────────────────────────                     │
    │  expr:                                                       │
    │    (                                                         │
    │      rate(mcp_llm_cost_rub_total[5m])                        │
    │      /                                                       │
    │      avg_over_time(rate(mcp_llm_cost_rub_total[1h])[7d:1h])  │
    │    ) > 3                                                     │
    │  for:  5m                                                    │
    │  labels: severity=critical                                   │
    │  annotations:                                                │
    │    summary: "Agent {{ $labels.agent }} cost anomaly"        │
    │                                                              │
    │  W-10: Unknown agent_id rate >5%                             │
    │  ────────────────────────────────                            │
    │  expr:                                                       │
    │    (                                                         │
    │      sum(rate(mcp_llm_cost_rub_total{agent="unknown"}[5m]))  │
    │      /                                                       │
    │      sum(rate(mcp_llm_cost_rub_total[5m]))                   │
    │    ) > 0.05                                                  │
    │  for:  15m                                                   │
    │  labels: severity=warning                                    │
    │  annotations:                                                │
    │    summary: "Many requests without agent_id"                │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

### Auto-throttle

```
    ┌──────────────────────────────────────────────────────────────┐
    │                                                              │
    │  Триггеры для auto-throttle:                                 │
    │                                                              │
    │  • Agent cost > 150% budget за 5m → throttle до 50%          │
    │  • Agent cost > 200% budget за 5m → block agent              │
    │  • Anomaly detected (3x baseline) за 10m → throttle 75%      │
    │                                                              │
    │  Действие:                                                   │
    │                                                              │
    │  mcp-gateway admin agent throttle \                          │
    │    --tenant acme \                                           │
    │    --agent agent-x \                                         │
    │    --rate-limit 50%                                          │
    │                                                              │
    │  Или автоматически через Controller:                         │
    │                                                              │
    │  1. Watch Prometheus alerts (Alertmanager webhook)           │
    │  2. На триггер — вызвать gateway admin API                   │
    │  3. Применить override rate limit для (tenant, agent)        │
    │  4. Notify tenant admin (email + Slack)                      │
    │  5. Auto-remove throttle через 1 час (или manual)            │
    │                                                              │
    │  Конфигурация override:                                      │
    │                                                              │
    │  overrides:                                                  │
    │    - tenant: acme                                            │
    │      agent: agent-x                                          │
    │      rate_limit_pct: 50                                      │
    │      reason: "budget exceeded"                               │
    │      expires_at: 2026-09-25T12:00:00Z                        │
    │      created_by: "auto-throttle-controller"                  │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

---

## Implementation details

### Go structs

```go
// CostEvent — событие для cost attribution
type CostEvent struct {
    TenantID  string
    AgentID   string  // "unknown" если не извлечён
    Provider  string  // "gigachat" | "yandex" | "ollama"
    Model     string  // "GigaChat-Pro"
    
    InputTokens  int64
    OutputTokens int64
    
    CostRub       float64  // вычислено по прайсу
    InputCostRub  float64
    OutputCostRub float64
    
    Timestamp     time.Time
    RequestID     string
    TraceID       string
}

// AgentBudget — конфигурация бюджета агента
type AgentBudget struct {
    TenantID    string
    AgentID     string
    BudgetRub   float64  // budget per hour
    AlertAtPct  int      // 80 (warning)
    ThrottleAtPct int    // 150 (auto-throttle)
    BlockAtPct  int      // 200 (auto-block)
}

// AgentContext — agent_id извлекается как tenant_id (см. ADR-0004)
type AgentID string

func WithAgentID(ctx context.Context, id AgentID) context.Context
func AgentIDFromContext(ctx context.Context) (AgentID, bool)
```

### Метрики (Go)

```go
// Определения метрик
var (
    LLMCostRub = prometheus.NewCounterVec(
        prometheus.CounterOpts{
            Name: "mcp_llm_cost_rub_total",
            Help: "Total LLM cost in RUB per (tenant, agent, provider, model)",
        },
        []string{"tenant", "agent", "provider", "model", "direction"},
    )
    
    LLMTokens = prometheus.NewCounterVec(
        prometheus.CounterOpts{
            Name: "mcp_llm_tokens_total",
            Help: "Total LLM tokens per (tenant, agent, provider, model, direction)",
        },
        []string{"tenant", "agent", "provider", "model", "direction"},
    )
    
    AgentBudgetUsedPct = prometheus.NewGaugeVec(
        prometheus.GaugeOpts{
            Name: "mcp_agent_budget_used_pct",
            Help: "Agent budget used percent (current hour)",
        },
        []string{"tenant", "agent"},
    )
    
    AgentCostAnomaly = prometheus.NewGaugeVec(
        prometheus.GaugeOpts{
            Name: "mcp_agent_cost_anomaly",
            Help: "1 if agent cost anomaly detected, 0 otherwise",
        },
        []string{"tenant", "agent"},
    )
)

// RecordCost записывает cost event
func RecordCost(event *CostEvent) {
    LLMCostRub.WithLabelValues(
        event.TenantID,
        event.AgentID,
        event.Provider,
        event.Model,
        "input",
    ).Add(event.InputCostRub)
    
    LLMCostRub.WithLabelValues(
        event.TenantID,
        event.AgentID,
        event.Provider,
        event.Model,
        "output",
    ).Add(event.OutputCostRub)
    
    LLMTokens.WithLabelValues(
        event.TenantID,
        event.AgentID,
        event.Provider,
        event.Model,
        "input",
    ).Add(float64(event.InputTokens))
    
    LLMTokens.WithLabelValues(
        event.TenantID,
        event.AgentID,
        event.Provider,
        event.Model,
        "output",
    ).Add(float64(event.OutputTokens))
}
```

### Извлечение agent_id

```go
// AgentResolver middleware
func AgentResolver(jwtParser *JWTParser) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            ctx := r.Context()
            
            // Priority 1: JWT claim
            agentID, err := jwtParser.ExtractAgent(r)
            
            // Priority 2: X-Agent-ID header
            if err != nil || agentID == "" {
                agentID = AgentID(r.Header.Get("X-Agent-ID"))
            }
            
            // Priority 3: _meta.agent_id in body (validation)
            if agentID == "" {
                agentID = extractAgentFromBody(r)
            }
            
            // Fallback: "unknown"
            if agentID == "" {
                agentID = AgentID("unknown")
                metrics.UnknownAgentID.Inc()
            }
            
            ctx = WithAgentID(ctx, agentID)
            next.ServeHTTP(w, r.WithContext(ctx))
        })
    }
}
```

### Recording rules (Prometheus)

```yaml
groups:
  - name: mcp-gateway-cost
    interval: 30s
    rules:
      # Cost per hour per agent
      - record: mcp:llm_cost_per_hour_rub
        expr: |
          sum by (tenant, agent) (
            rate(mcp_llm_cost_rub_total[1h])
          ) * 3600

      # Budget used percent
      - record: mcp:agent_budget_used_pct
        expr: |
          100 * mcp:llm_cost_per_hour_rub
          / on(tenant, agent) group_left
          mcp_agent_budget_rub

      # Anomaly detection (3x baseline)
      - record: mcp:agent_cost_anomaly
        expr: |
          (
            mcp:llm_cost_per_hour_rub
            / 
            avg_over_time(mcp:llm_cost_per_hour_rub[7d])
          ) > 3
```

### Rollout plan

```
    ┌──────────────────────────────────────────────────────────────┐
    │                                                              │
    │  Phase 1: agent_id propagation — 1 неделя                    │
    │  ───────────────────────────────                             │
    │  • AgentResolver middleware                                  │
    │  • Извлечение из JWT claim                                   │
    │  • Fallback на header/body                                   │
    │  • Метрика unknown_agent_id                                  │
    │                                                              │
    │  Phase 2: Cost metrics per agent — 1 неделя                  │
    │  ────────────────────────────────                            │
    │  • Добавить agent label во все cost-метрики                  │
    │  • Recording rules для cost_per_hour                         │
    │  • Integration с ADR-0007 (prompt_version × agent)           │
    │                                                              │
    │  Phase 3: Dashboards — 3 дня                                 │
    │  ───────────────────────                                     │
    │  • Grafana dashboard "Cost by Agent"                         │
    │  • Top-N agents, trends, budget vs actual                    │
    │  • Anomaly heatmap                                           │
    │                                                              │
    │  Phase 4: Alerting — 3 дня                                   │
    │  ───────────────────                                         │
    │  • Alert rules (W-08, C-08, C-09, W-10)                      │
    │  • Alertmanager routing                                      │
    │  • Runbook sections                                          │
    │                                                              │
    │  Phase 5: Auto-throttle — 1 неделя                           │
    │  ────────────────────────────                                │
    │  • Controller (watch alerts)                                 │
    │  • Admin API для throttle                                    │
    │  • Notification tenant admin                                 │
    │  • Auto-remove через 1 час                                   │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

### Known limitations

```
    ┌──────────────────────────────────────────────────────────────┐
    │                                                              │
    │  1. agent_id extraction — не всегда надёжно                  │
    │     ⚠️ Если JWT не содержит agent_id, fallback на unknown    │
    │     ⚠️ Header может быть подменён (не безопастно)             │
    │     💡 Решение: JWT claim обязателен для production          │
    │                                                              │
    │  2. Cardinality — agent label умножает cardinality           │
    │     ⚠️ N тенантов × M агентов × K моделей × 2 directions      │
    │     💡 Митигация:                                            
    │        • Ограничить количество активных agent_id             │
    │        • Aggregation для неактивных (через recording rules)  │
    │        • Exemplars для sample-based analysis                 │
    │                                                              │
    │  3. Auto-throttle — риск false positive                      │
    │     ⚠️ Anomaly detection может сработать на transient        │
    │     💡 Митигация:                                            
    │        • Rolling window 15 минут                             │
    │        • Manual override                                     │
    │        • Multi-signal triggers                               │
    │                                                              │
    │  4. Budget configuration — per agent vs per tenant            │
    │     ⚠️ Нужен способ задавать budgets per (tenant, agent)     │
    │     💡 Формат: configs/budgets.yaml                          │
    │                                                              │
    │  5. Cost calculation — зависит от прайсов                    │
    │     ⚠️ Прайсы меняются (GigaChat, YandexGPT)                 │
    │     💡 Mitigation:                                            │
    │        • Config-driven pricing                               │
    │        • Periodic sync с провайдерами                        │
    │        • Alert на устаревшие прайсы (>30 дней)               │
    │                                                              │
    │  6. Агрегация для больших tenant'ов                          │
    │     ⚠️ 10k+ агентов × 100 тенантов = 1M series               │
    │     💡 Mitigation:                                            │
    │        • Aggregation для agents с cost <threshold            │
    │        • Tenant-level aggregation по умолчанию               │
    │        • Drill-down только по запросу                        │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

---

## Rationale

### Почему agent_id, а не только tenant_id

**Tenant-level cost** (уже есть в Capacity Planning):

- Общий счёт per tenant.
- Помогает для billing.
- Не помогает для оптимизации.

**Agent-level cost** (этот ADR):

- Видно, какой агент тратит больше всех.
- Можно обнаружить runaway agent.
- Можно аллоцировать cost внутри tenant'а.
- Можно таргетированно throttle.

**Решение:** agent_id как first-class атрибут.

### Почему Prometheus метрики, а не logs-based tracking

**Logs-based (Loki):**

- Каждый запрос — запись в log.
- Агрегация через LogQL.
- Дорого по storage (миллионы записей).
- Медленно для dashboards.

**Prometheus метрики:**

- Counter per (tenant, agent, provider, model, direction).
- Aggregation быстрая (PromQL).
- Cardinallity controlled.
- Интеграция с alerting из коробки.

**Решение:** Prometheus метрики.

### Почему rule-based anomaly detection, а не ML

**ML anomaly detection:**

- Требует обучения на исторических данных.
- Требует инфраструктуры (модели, retraining).
- Может давать false positives на новых паттернах.

**Rule-based (3x baseline):**

- Просто: `current > 3 * avg_over_time(7d)`.
- Работает из коробки.
- Прозрачно (можно объяснить почему сработало).
- Не требует инфраструктуры.

**Решение:** rule-based. ML — если понадобится (когда будет 100+ млн событий).

### Почему auto-throttle, а не auto-block

**Auto-block (полный запрет):**

- Жёстко.
- Может сломать работающий агент.
- Требует manual intervention для восстановления.

**Auto-throttle (снижение rate):**

- Мягче.
- Агент продолжает работать (медленнее).
- Даёт tenant'у время среагировать.
- Auto-remove через 1 час.

**Решение:** auto-throttle, auto-block только при >200% budget.

### Почему integration с ADR-0007 (A/B testing)

**Cost per agent сам по себе недостаточен.**

**Пример:**
- Agent X: cost вырос на 30%.
- Причины: prompt v2 дороже, или больше запросов, или модель изменилась.

**Integration с A/B testing:**
- Cost per (agent, prompt_version).
- Видно, какая версия промпта дороже.
- Можно auto-rollback на дешёвую версию.

**Решение:** cross-ADR integration.

---

## Consequences

### Positive

- **Granular cost attribution** — per (tenant, agent, provider, model).
- **Anomaly detection** — обнаружение runaway agents за минуты.
- **Auto-throttle** — защита от budget overrun.
- **Integration с A/B testing** — cost per prompt version.
- **Grafana dashboards** — Top-N, trends, heatmaps.
- **Rule-based** — просто, прозрачно, без ML.
- **Zero extra infra** — Prometheus уже в стеке.

### Negative

- **Cardinality growth** — agent label умножает number of series.
  Митигация: aggregation для неактивных, exemplars.
- **agent_id extraction complexity** — JWT + header + body fallback.
  Митигация: JWT claim обязателен для production.
- **Auto-throttle risk** — false positive при transient spike.
  Митигация: rolling window + manual override.
- **Budget configuration** — нужен способ задавать per agent.
  Митигация: configs/budgets.yaml.
- **Pricing drift** — прайсы провайдеров меняются.
  Митигация: config-driven pricing + sync.
- **Кастомный код** — ~500 строк Go для extraction + controller.

### Neutral

- **Alerting new alerts** — W-08, C-08, C-09, W-10.
- **Runbook sections** — новые процедуры для auto-throttle.
- **Budget governance** — tenant'ы должны определять budgets для своих агентов.

---

## Failure modes

### agent_id не извлекается

```
    ┌──────────────────────────────────────────────────────────────┐
    │                                                              │
    │  Симптом: agent_id = "unknown" в метриках                    │
    │                                                              │
    │  Причины:                                                    │
    │  • JWT не содержит agent_id claim                            │
    │  • Клиент не передал X-Agent-ID                              │
    │  • Bug в извлечении                                          │
    │                                                              │
    │  Поведение:                                                  │
    │  • Fallback на "unknown"                                     │
    │  • Warning metric (не блокирует запрос)                      │
    │  • Cost записывается в "unknown" bucket                      │
    │                                                              │
    │  Detection:                                                  │
    │  • Алерт W-10: unknown rate >5%                              │
    │                                                              │
    │  Mitigation:                                                 │
    │  • Notify tenant: "add agent_id to JWT"                      │
    │  • Документация для интеграции                               │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

### Cardinality explosion

```
    ┌──────────────────────────────────────────────────────────────┐
    │                                                              │
    │  Симптом: Prometheus тормозит, TSDB растёт                  │
    │                                                              │
    │  Причины:                                                    │
    │  • Много уникальных agent_id (например, UUID per request)    │
    │  • Много моделей × провайдеров × directions                  │
    │                                                              │
    │  Detection:                                                  │
    │  • Алерт: prometheus_tsdb_head_series > threshold            │
    │  • Алерт: scrape_duration_seconds > threshold                │
    │                                                              │
    │  Mitigation:                                                 │
    │  • Aggregation для agents с cost < threshold                 │
    │  • Dropping series с низким value                            │
    │  • Exemplars для sample-based analysis                       │
    │  • Ограничение на количество agent_id per tenant             │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

### Auto-throttle false positive

```
    ┌──────────────────────────────────────────────────────────────┐
    │                                                              │
    │  Симптом: агент throttled, но cost в норме                   │
    │                                                              │
    │  Причины:                                                    │
    │  • Transient spike (upstream latency, retry storm)           │
    │  • Anomaly detection сработал на legit burst                 │
    │                                                              │
    │  Detection:                                                  │
    │  • Алерт: prompt_rollback_manual_override_total > 0          │
    │  • Manual override через admin API                           │
    │                                                              │
    │  Mitigation:                                                 │
    │  • Rolling window 15 минут                                   │
    │  • Multiple triggers                                         │
    │  • Auto-remove через 1 час                                   │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

### Pricing drift

```
    ┌──────────────────────────────────────────────────────────────┐
    │                                                              │
    │  Симптом: cost в метриках не соответствует реальному счёту   │
    │                                                              │
    │  Причины:                                                    │
    │  • Провайдер поднял/снизил цены                              │
    │  • Не обновили config/pricing.yaml                           │
    │                                                              │
    │  Detection:                                                  │
    │  • Алерт: mcp_gateway_pricing_age_days > 30                  │
    │  • Monthly reconciliation с провайдером                      │
    │                                                              │    │  Mitigation:                                                 │
    │  • Config-driven pricing                                     │
    │  • Periodic sync (weekly)                                    │
    │  • Reconciliation script                                     │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

---

## Alternatives considered

### Alternative 1: Cost tracking через Langfuse (только)

**Плюсы:**
- Уже есть Langfuse (ADR-0006, ADR-0007).
- LLM-specific данные (tokens, cost, latency).

**Минусы:**
- Langfuse — не для real-time metric aggregation.
- Нет Prometheus alerting из коробки.
- Cardinality issues на больших объёмах.
- Не покрывает non-LLM operations.

**Решение:** отклонено как основной. Langfuse используется **дополнительно** для drill-down (trace-level).

### Alternative 2: Cost tracking через logs (Loki + LogQL)

**Плюсы:**
- Гибкий (любые поля).
- Retention controlled.
- Агрегация через LogQL.

**Минусы:**
- Дорого по storage (миллионы записей/час).
- Медленно для dashboards.
- Не предназначен для alerting на агрегатах.

**Решение:** отклонено. Prometheus метрики проще и эффективнее.

### Alternative 3: ML-based anomaly detection

**Плюсы:**
- Точнее на сложных паттернах.
- Адаптируется к сезонности.

**Минусы:**
- Требует инфраструктуры (обучение, retraining).
- False positives на новых паттернах.
- Непрозрачно (сложно объяснить почему сработало).

**Решение:** отклонено для v1. Возможно для v2 при объёме >100M events/day.

### Alternative 4: Auto-block вместо auto-throttle

**Плюсы:**
- Жёстко защищает от overrun.
- Проще реализовать.

**Минусы:**
- Может сломать работающий агент.
- Требует manual intervention.
- Overkill для transient spike.

**Решение:** отклонено. Auto-throttle мягче и безопаснее.

### Alternative 5: Per-request cost tracking без aggregation

**Плюсы:**
- Точность.
- Детальность.

**Минусы:**
- Cardinality explosion (N requests = N series).
- Дорого по storage.
- Не нужно для FinOps (достаточно hourly aggregates).

**Решение:** отклонено. Histogram + recording rules дают правильный баланс.

---

## Action items

Задачи, вытекающие из этого ADR:

- [ ] **agent_id propagation**:
  - AgentResolver middleware
  - Извлечение из JWT claim (priority 1)
  - Fallback на X-Agent-ID header (priority 2)
  - Fallback на _meta.agent_id body (priority 3)
  - Fallback на "unknown" + metric
  - Unit tests для всех приоритетов

- [ ] **Cost metrics**:
  - Расширить `mcp_llm_cost_rub_total` с agent label
  - Расширить `mcp_llm_tokens_total` с agent label
  - Добавить `mcp_agent_budget_used_pct` gauge
  - Добавить `mcp_agent_cost_anomaly` gauge
  - Recording rules для агрегатов

- [ ] **Budget configuration**:
  - `configs/budgets.yaml` формат
  - Loading + validation
  - Per (tenant, agent) budgets
  - Default budget for tenant

- [ ] **Grafana dashboards**:
  - Dashboard "Cost by Agent" (5 rows)
  - Top-N agents table
  - Cost trend time series
  - Budget vs actual bar chart
  - Anomaly heatmap
  - Cost per prompt_version (integration с ADR-0007)

- [ ] **Alerting**:
  - W-08: Agent cost >100% budget
  - C-08: Agent cost >150% budget
  - C-09: Anomaly >3x baseline
  - W-10: Unknown agent_id rate >5%
  - Alertmanager routing

- [ ] **Auto-throttle Controller**:
  - Watch Alertmanager webhook
  - Admin API для throttle
  - Config: configs/throttle-overrides.yaml
  - Auto-remove через 1 час
  - Notify tenant admin

- [ ] **Pricing management**:
  - `configs/pricing.yaml` — цены per provider × model
  - Sync script (weekly)
  - Alert на устаревшие прайсы (>30 дней)
  - Monthly reconciliation

- [ ] **Runbook updates**:
  - W-08 procedure
  - C-08 procedure
  - C-09 procedure (anomaly investigation)
  - W-10 procedure (unknown agent_id)
  - Auto-throttle manual override

- [ ] **Documentation**:
  - Обновить `docs/blueprint.md` — FinOps per agent в capabilities
  - Обновить `docs/reliability/capacity-planning.md` — agent-level
  - Guide для tenant'ов: как добавить agent_id в JWT

- [ ] **Testing**:
  - Unit test: agent extraction (all priorities)
  - Integration test: cost metrics per agent
  - Load test: cardinality при 10k agents
  - Alerting test: throttle triggers

---

## References

- [FinOps Foundation: Cost Allocation](https://www.finops.org/framework/capabilities/allocation/)
- [Prometheus: Best Practices — Cardinality](https://prometheus.io/docs/practices/instrumentation/#avoid-missing-metrics)
- [Prometheus: Recording Rules](https://prometheus.io/docs/prometheus/latest/configuration/recording_rules/)
- [Google SRE: Monitoring Distributed Systems](https://sre.google/sre-book/monitoring-distributed-systems/)
- [OpenTelemetry: GenAI Semantic Conventions](https://opentelemetry.io/docs/specs/semconv/gen-ai/)

---

## Related ADRs

- [ADR-0004: tenant_id в context.Context](0004-tenant-id-in-context.md) — agent_id извлекается аналогично tenant_id
- [ADR-0006: Observability stack](0006-observability-stack.md) — Prometheus + Grafana как база для cost tracking
- [ADR-0007: Prompt A/B testing via Langfuse](0007-prompt-ab-testing.md) — cost per prompt version × agent
- ADR-0009 (TBD): PII redaction — не влияет на cost tracking, но снижает cardinality (PII не в labels)