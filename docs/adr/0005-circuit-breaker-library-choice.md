# ADR-0005: gobreaker для per-tenant circuit breaker

- **Status:** Accepted
- **Date:** 2026-09-23
- **Deciders:** Roman Sokolov (Architect)
- **Tags:** `reliability`, `circuit-breaker`, `multi-tenancy`, `resilience`, `upstream`

---

## Context

MCP Gateway — прокси между AI-агентами (клиенты) и **upstream-сервисами**:
LLM-провайдеры (OpenAI, Anthropic, локальные Mistral/Ollama),
MCP-серверы с инструментами, legacy-системы (1С, SAP, ЕИС).

Каждый upstream-сервис может **отказывать**:

1. **Полный отказ** — сервис недоступен (сеть, DNS, TLS, 5xx).
2. **Частичный отказ** — сервис отвечает, но медленно (p99 > timeout)
   или возвращает 5xx на часть запросов.
3. **Rate limit** — upstream вернул `429`, quota исчерпана.
4. **Деградация** — сервис работает, но качество ответов упало
   (например, LLM возвращает мусор из-за перегрузки).

**Проблема без circuit breaker:**

```
    ┌──────────────────────────────────────────────────────────────┐
    │  Сценарий: upstream LLM API начал отказывать                 │
    ├──────────────────────────────────────────────────────────────┤
    │                                                              │
    │  t=0s   : upstream начал возвращать 500                      │
    │  t=1s   : 100 requests в полёте, все висят на timeout 30s    │
    │  t=5s   : 5000 requests в полёте, все висят                  │
    │  t=30s  : первые timeout'ы возвращаются, но уже новые        │
    │           5000 requests в полёте                             │
    │                                                              │
    │  Результат:                                                  │
    │  • Gateway исчерпал все goroutine'ы и connection pool        │
    │  • Клиенты получают timeout через 30 секунд ожидания         │
    │  • Восстановление upstream не помогает — backlog растёт      │
    │  • Каскадный отказ: gateway не может обслужить даже         │
    │    healthy tenants                                           │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

**Требуется circuit breaker** с поддержкой:

- **Per-tenant per-upstream** изоляция: падение upstream у тенанта A
  не должно открывать breaker для тенанта B.
- **Автоматическое восстановление**: half-open state, пробные запросы.
- **Метрики состояния** (closed / half-open / open) для observability.
- **Интеграция с retry**: retry только для idempotent операций.
- **Fail-fast при open**: клиент получает 503 за миллисекунды, а не
  за 30 секунд.
- **Fallback**: cached response, degraded mode, понятная ошибка.

---

## Decision

**Используем библиотеку [`sony/gobreaker`](https://github.com/sony/gobreaker)**
с обёрткой для per-tenant per-upstream изоляции.

### Состояния circuit breaker

```
    ┌──────────────────────────────────────────────────────────────┐
    │                                                              │
    │                    ┌─────────────┐                           │
    │                    │   CLOSED    │                           │
    │                    │             │                           │
    │                    │  Все запросы│                           │
    │                    │  проходят   │                           │
    │                    │  к upstream │                           │
    │                    └──────┬──────┘                           │
    │                           │                                  │
    │           Failures > threshold (ReadyToTrip)                 │
    │                           │                                  │
    │                           ▼                                  │
    │                    ┌─────────────┐                           │
    │                    │    OPEN     │                           │
    │                    │             │                           │
    │                    │  Все запросы│                           │
    │                    │  отклоняются│                           │
    │                    │  fail-fast  │                           │
    │                    └──────┬──────┘                           │
    │                           │                                  │
    │              Timeout expired (напр. 60s)                     │
    │                           │                                  │
    │                           ▼                                  │
    │                    ┌─────────────┐                           │
    │                    │  HALF-OPEN  │                           │
    │                    │             │                           │
    │                    │  N пробных  │                           │
    │                    │  запросов   │                           │
    │                    └──────┬──────┘                           │
    │                           │                                  │
    │              ┌────────────┴────────────┐                     │
    │              │                         │                     │
    │       Успех (>= M)              Ошибка (>= K)                │
    │              │                         │                     │
    │              ▼                         ▼                     │
    │       ┌─────────────┐           ┌─────────────┐              │
    │       │   CLOSED    │           │    OPEN     │              │
    │       │ (восстанов- │           │ (сбросить   │              │
    │       │  ление)     │           │  таймер)    │              │
    │       └─────────────┘           └─────────────┘              │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

### Параметры

```go
type BreakerSettings struct {
    // MaxRequests — сколько запросов пропускаем в HALF-OPEN
    // для проверки восстановления.
    MaxRequests uint32  // default: 3

    // Interval — окно в CLOSED, за которое считаем failures.
    // После Interval счётчики сбрасываются.
    Interval time.Duration  // default: 30s

    // Timeout — сколько времени держим OPEN до перехода в HALF-OPEN.
    Timeout time.Duration  // default: 60s

    // ReadyToTrip — функция, определяющая, когда переходить
    // из CLOSED в OPEN.
    ReadyToTrip func(counts gobreaker.Counts) bool
}

// Наш ReadyToTrip: срабатывает при 50% ошибок за >=10 запросов,
// ИЛИ при 5 подряд ошибок.
func readyToTrip(counts gobreaker.Counts) bool {
    if counts.Requests < 10 {
        return counts.ConsecutiveFailures >= 5
    }
    failureRatio := float64(counts.TotalFailures) / float64(counts.Requests)
    return failureRatio >= 0.5
}
```

**Обоснование параметров:**

| Параметр | Значение | Почему |
|----------|----------|--------|
| `MaxRequests` | 3 | Три пробных запроса в HALF-OPEN — достаточно, чтобы понять, восстановился ли upstream. Больше — риск снова положить его под нагрузкой. |
| `Interval` | 30s | Окно для расчёта failure rate. При 60s медленно реагируем на деградацию, при 10s слишком шумно. |
| `Timeout` | 60s | Время в OPEN. При 30s upstream может не успеть восстановиться, при 120s — слишком долго для клиентов. |
| `ReadyToTrip` | 50% при >=10 | Стандартный порог. 5 подряд ошибок — защита от «медленного старта». |

### Per-tenant per-upstream изоляция

**Ключевое решение:** breaker создаётся **на пару (tenant_id, upstream_name)**,
не глобально и не per-upstream.

```
    ┌──────────────────────────────────────────────────────────────┐
    │                                                              │
    │   Tenant "acme"              Tenant "globex"                 │
    │   ┌─────────────────┐        ┌─────────────────┐             │
    │   │ breake r:        │        │ breaker:        │             │
    │   │ acme:openai     │        │ globex:openai   │             │
    │   ├─────────────────┤        ├─────────────────┤             │
    │   │ acme:anthropic  │        │ globex:anthropic│             │
    │   ├─────────────────┤        ├─────────────────┤             │
    │   │ acme:1c         │        │ globex:1c       │             │
    │   └─────────────────┘        └─────────────────┘             │
    │                                                              │
    │   Каждый breaker независим.                                  │
    │                                                              │
    │   Падение openai у acme НЕ открывает breaker у globex.       │
    │                                                              │
    │   Даже если оба тенанта используют один upstream,            │
    │   их breaker'ы изолированы — потому что у них могут быть     │
    │   разные credentials, разные rate limits, разные SLA.        │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

**Почему не глобальный per-upstream breaker:**

- У тенантов **разные API-ключи** к upstream. Один тенант может
  исчерпать свою quota и получать `429`, а другой работает нормально.
  Глобальный breaker откроется для обоих — false positive.
- У тенантов **разные SLA**. Enterprise-тенант не должен страдать
  из-за проблем free-tier тенанта.
- **FinOps:** падение upstream у одного тенанта не должно останавливать
  billing для другого.

### Реестр breaker'ов

```go
package breaker

import (
    "sync"

    "github.com/sony/gobreaker"
)

type Registry struct {
    mu       sync.RWMutex
    breakers map[string]*gobreaker.CircuitBreaker  // key: "tenant:upstream"
    settings BreakerSettings
    metrics  *Metrics
}

func NewRegistry(settings BreakerSettings, metrics *Metrics) *Registry {
    return &Registry{
        breakers: make(map[string]*gobreaker.CircuitBreaker),
        settings: settings,
        metrics:  metrics,
    }
}

// Get возвращает breaker для (tenant, upstream), создавая его
// при первом обращении. Регистр потокобезопасен.
func (r *Registry) Get(tenantID, upstreamName string) *gobreaker.CircuitBreaker {
    key := tenantID + ":" + upstreamName

    // Fast path: read lock
    r.mu.RLock()
    cb, ok := r.breakers[key]
    r.mu.RUnlock()
    if ok {
        return cb
    }

    // Slow path: write lock, double-check
    r.mu.Lock()
    defer r.mu.Unlock()
    if cb, ok := r.breakers[key]; ok {
        return cb
    }

    cb = gobreaker.NewCircuitBreaker(gobreaker.Settings{
        Name:        key,
        MaxRequests: r.settings.MaxRequests,
        Interval:    r.settings.Interval,
        Timeout:     r.settings.Timeout,
        ReadyToTrip: r.settings.ReadyToTrip,
        OnStateChange: func(name string, from, to gobreaker.State) {
            r.metrics.RecordStateChange(tenantID, upstreamName, from, to)
        },
    })
    r.breakers[key] = cb
    return cb
}
```

### Использование

```go
func (h *Handler) CallUpstream(ctx context.Context, tenantID, upstreamName string) (*Response, error) {
    cb := h.breakerRegistry.Get(tenantID, upstreamName)

    result, err := cb.Execute(func() (any, error) {
        // Реальный вызов upstream
        return h.upstreamClient.Call(ctx, upstreamName)
    })

    if err != nil {
        // gobreaker возвращает ErrOpenState, если breaker открыт
        if errors.Is(err, gobreaker.ErrOpenState) {
            return nil, ErrUpstreamUnavailable
        }
        if errors.Is(err, gobreaker.ErrTooManyRequests) {
            return nil, ErrUpstreamBusy
        }
        return nil, err
    }

    return result.(*Response), nil
}
```

### Интеграция с retry

**Ключевое правило:** retry **внутри** или **вне** breaker?

```
    ┌──────────────────────────────────────────────────────────────┐
    │  Вариант A: retry ВНУТРИ breaker (ПРАВИЛЬНО)                 │
    ├──────────────────────────────────────────────────────────────┤
    │                                                              │
    │   cb.Execute(func() {                                        │
    │       for attempt := 1; attempt <= 3; attempt++ {            │
    │           resp, err := call()                                │
    │           if err == nil || !isRetryable(err) {               │
    │               return resp, err                               │
    │           }                                                  │
    │           sleep(backoff(attempt))                            │
    │       }                                                      │
    │       return nil, lastErr                                    │
    │   })                                                         │
    │                                                              │
    │   • Каждый retry учитывается в статистике breaker'а.         │
    │   • 3 неудачных retry = 3 failures для breaker'а.            │
    │   • Breaker правильно открывается при деградации.            │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘

    ┌──────────────────────────────────────────────────────────────┐
    │  Вариант B: retry ВНЕ breaker (НЕПРАВИЛЬНО)                  │
    ├──────────────────────────────────────────────────────────────┤
    │                                                              │
    │   for attempt := 1; attempt <= 3; attempt++ {                │
    │       result, err := cb.Execute(func() {                     │
    │           return call()                                      │
    │       })                                                     │
    │       if err == nil { return result, nil }                   │
    │       if errors.Is(err, gobreaker.ErrOpenState) {            │
    │           return nil, err  // не retry'им при open           │
    │       }                                                      │
    │       sleep(backoff(attempt))                                │
    │   }                                                          │
    │                                                              │
    │   • Каждый retry — отдельный «запрос» для breaker'а.         │
    │   • 3 retry = 3 failures (если все упали).                   │
    │   • То же поведение, но менее явное.                         │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

**Решение: retry внутри breaker** (Вариант A). Это даёт **атомарную
единицу работы** для breaker'а: «один вызов upstream с retry'ями».
Если все retry упали — breaker фиксирует один failure (не три).

**Исключение:** `ErrOpenState` **не retry'ится** — breaker уже открыт,
нет смысла пытаться.

### Какие ошибки считаются failure

```go
func isFailure(err error) bool {
    if err == nil {
        return false
    }

    // 4xx (кроме 429) — это НЕ failure upstream'а,
    // это ошибка клиента (невалидный запрос).
    // Breaker не должен открываться.
    var httpErr *HTTPError
    if errors.As(err, &httpErr) {
        if httpErr.StatusCode >= 400 && httpErr.StatusCode < 500 {
            // 429 — rate limit, считаем как failure
            if httpErr.StatusCode == 429 {
                return true
            }
            return false
        }
        // 5xx — failure upstream'а
        if httpErr.StatusCode >= 500 {
            return true
        }
    }

    // Сетевые ошибки (timeout, connection refused) — failure
    if errors.Is(err, context.DeadlineExceeded) ||
       errors.Is(err, context.Canceled) ||
       isNetworkError(err) {
        return true
    }

    return true  // по умолчанию — failure
}
```

**Обоснование:**

| Ошибка | Failure? | Почему |
|--------|----------|--------|
| `5xx` | ✅ Да | Upstream сломан |
| `429` | ✅ Да | Rate limit — это тоже деградация |
| `4xx` (кроме 429) | ❌ Нет | Клиент прислал невалидный запрос |
| Timeout | ✅ Да | Upstream не отвечает |
| Connection refused | ✅ Да | Upstream недоступен |
| TLS error | ✅ Да | Проблема с upstream'ом |

**Ключевая ошибка — считать `4xx` failure'ом.** Если клиент прислал
невалидный запрос 10 раз подряд, breaker откроется, и **весь тенант**
не сможет вызывать upstream. Это неправильно — `4xx` это проблема
клиента, не upstream.

### Метрики

Обязательные Prometheus-метрики:

```
    mcp_gateway_circuit_state{tenant,upstream}          gauge
        0 = closed, 1 = half-open, 2 = open

    mcp_gateway_circuit_requests_total{tenant,upstream,result}
        result = allowed | rejected | success | failure

    mcp_gateway_circuit_state_changes_total{tenant,upstream,from,to}

    mcp_gateway_circuit_open_duration_seconds{tenant,upstream}
        histogram — сколько времени breaker был в OPEN

    mcp_gateway_circuit_requests_in_flight{tenant,upstream}  gauge
```

**Алерты:**

```
    circuit_state == 2 (open) >1m
        → warning (upstream degraded)

    circuit_state == 2 (open) >10m
        → critical (upstream down)

    circuit_state_changes_total{from="closed",to="open"} > 3/hour
        → warning (flapping breaker)

    circuit_open_duration_seconds p99 > 5m
        → warning (upstream problems)
```

---

## Rationale

### Почему sony/gobreaker, а не альтернативы

**Рассмотренные библиотеки:**

| Библиотека | Плюсы | Минусы | Решение |
|-----------|-------|--------|---------|
| **sony/gobreaker** | Простой API, стабильная (используется в production Sony, Mercari), поддержка context, минимальные зависимости | Нет встроенного retry, нет per-key автоматизации | ✅ **Выбор** |
| **afex/hystrix-go** | Netflix Hystrix port, много возможностей | Заброшена (last commit 2018), нет context support, тяжёлая | ❌ Устарела |
| **rubyist/circuitbreaker** | Простой | Нет context, мало пользователей | ❌ Менее зрелая |
| **Собственная реализация** | Полный контроль | Много кода, легко ошибиться, нужны тесты | ❌ Overkill |

**Почему gobreaker:**

1. **Context support** — `Execute` принимает `context.Context` из
   коробки. Это критично для таймаутов и отмен.
2. **Стабильность** — библиотека используется в production Sony
   (PlayStation Store), Mercari, LINE. Миллиарды запросов.
3. **Простой API** — `Execute(fn)` и всё. Легко понять и использовать.
4. **Настраиваемые thresholds** — `ReadyToTrip` даёт полный контроль.
5. **OnStateChange callback** — удобно для метрик и алертов.
6. **Минимум зависимостей** — только stdlib.
7. **Active maintenance** — последний релиз 2023, active issues.

**Почему не hystrix-go:**

- Последний коммит — 2018. Библиотека **заброшена**.
- **Нет context support** — критично для Go 1.7+.
- Тяжёлая — тянет `afex/hystrix-go/hystrix/metric_collector`.
- Netflix Hystrix deprecated в 2018 (заменён на Resilience4j в Java).

**Почему не собственная реализация:**

- Circuit breaker — **обманчиво простая** концепция. Легко сделать
  неправильно:
  - Race conditions в state transitions.
  - Неверный подсчёт failures (когда сбрасывать счётчики).
  - Неправильная обработка context cancellation.
- gobreaker прошёл **тысячи production-сценариев**. Изобретать
  велосипед — тратить время на баги.

### Почему per-tenant per-upstream изоляция

**Ключевая проблема:** глобальный breaker (per-upstream) даёт
**false positive** для тенантов с разными credentials.

```
    ┌──────────────────────────────────────────────────────────────┐
    │  Сценарий: глобальный breaker per-upstream (СЛОМАН)          │
    ├──────────────────────────────────────────────────────────────┤
    │                                                              │
    │  Tenant A (free tier) исчерпал свою quota в OpenAI.          │
    │  Все запросы → 429.                                          │
    │                                                              │
    │  Глобальный breaker openai открывается.                      │
    │                                                              │
    │  Tenant B (enterprise) пытается вызвать openai —             │
    │  получает 503, потому что breaker открыт.                    │
    │                                                              │
    │  Хотя у B своя quota, свой API key, всё в порядке.           │
    │                                                              │
    │  Потеря enterprise-клиента. Потеря revenue.                  │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

**Per-tenant per-upstream breaker решает это:**

- Breaker для `(A, openai)` открывается → A получает 503.
- Breaker для `(B, openai)` остаётся **closed** → B работает.

**Компромисс:** больше breaker'ов в памяти. При 100 тенантах × 5
upstream'ов = 500 breaker'ов. Каждый ~200 байт → 100 KB. Приемлемо.

### Почему retry внутри breaker

**Альтернатива:** retry снаружи breaker'а.

**Проблема:** если retry снаружи, каждый retry считается **отдельным
запросом** для breaker'а. При `MaxRequests=3` в half-open 1 неудачный
вызов с 3 retry'ями исчерпает весь half-open budget → breaker
вернётся в OPEN. Хотя это была **одна** попытка восстановления.

**Решение:** retry внутри `cb.Execute()`. Breaker видит **один**
вызов (с внутренними retry'ями) и фиксирует один результат.

```
    Правильно:
    cb.Execute(func() {
        // 3 retry'я внутри
        // Результат: success или failure (один)
    })

    Результат для breaker:
    • Успех → 1 success
    • Провал (все retry упали) → 1 failure
    • Не 3 failure (как было бы с retry снаружи)
```

### Почему 4xx не считается failure

**Классическая ошибка:** считать все ошибки failure'ами для breaker'а.

**Проблема:** клиент присылает невалидные запросы (например, баг
в агенте). Upstream отвечает `400 Bad Request` 100 раз подряд.
Breaker открывается → **все запросы тенанта** получают 503, хотя
upstream работает нормально.

**Решение:** `4xx` (кроме `429`) — это ошибка **клиента**, не upstream'а.
Breaker не должен на неё реагировать.

**Исключение `429`:** rate limit — это **деградация upstream'а**.
Если upstream говорит «слишком много запросов», это сигнал, что нужно
снизить нагрузку → breaker открывается, чтобы дать upstream передохнуть.

### Почему не bulkhead pattern вместо breaker

**Bulkhead** (ограничение concurrency) — complementary паттерн, не
замена:

- **Bulkhead:** ограничивает количество одновременных запросов
  (например, 10 concurrent к upstream). Защита от исчерпания
  ресурсов.
- **Circuit breaker:** полностью блокирует запросы при деградации.
  Защита от каскадного отказа.

**Решение:** используем **оба**. Bulkhead через `golang.org/x/sync/semaphore`
ограничивает concurrency, breaker защищает от каскада. Это
дополняющие, не конкурирующие механизмы.

---

## Consequences

### Positive

- **Защита от каскадного отказа** — падение upstream не роняет gateway.
- **Fail-fast** — клиент получает 503 за миллисекунды, а не за 30s timeout.
- **Per-tenant изоляция** — проблемы у одного тенанта не влияют на других.
- **Автоматическое восстановление** — half-open state с пробными запросами.
- **Наблюдаемость** — метрики состояния breaker'а для dashboards и алертов.
- **Минимум зависимостей** — одна библиотека, ~500 строк кода.
- **Production-tested** — gobreaker используется Sony, Mercari, LINE.

### Negative

- **Память** — при 100 тенантах × 5 upstream = 500 breaker'ов.
  ~100 KB. Приемлемо, но растёт линейно с числом тенантов.
- **Сложность настройки** — параметры (`MaxRequests`, `Interval`,
  `Timeout`, `ReadyToTrip`) требуют тюнинга под workload. Дефолты
  подходят не всегда.
- **False positives** — при агрессивных настройках breaker может
  открываться на transient-проблемах (например, DNS-glitch).
- **Нет автоматической очистки** — breaker'ы для удалённых тенантов
  остаются в памяти. Митигация: TTL + periodic GC.
- **Клиенты не могут игнорировать** — если breaker открыт, клиент
  получает 503. Нужна документация для клиентов, что делать.

### Neutral

- **Не входит в SLO** — если upstream отказал, это не считается
  нарушением SLA gateway'я (при условии, что gateway вернул 503
  быстро, а не висел 30s).
- **Метрики** — обязательны для observability, но не критичны для
  работы.
- **Тестирование** — нужны unit-тесты для state transitions,
  integration-тесты с симуляцией отказа upstream.

---

## Failure modes

### Breaker остаётся в OPEN из-за false positive

```
    ┌──────────────────────────────────────────────────────────────┐
    │  Симптом: upstream работает, но breaker открыт               │
    ├──────────────────────────────────────────────────────────────┤
    │                                                              │
    │  Возможные причины:                                          │
    │  • Слишком агрессивные настройки (ReadyToTrip срабатывает    │
    │    при 2 failures)                                           │
    │  • Ошибки 4xx считаются failure'ами (см. выше)               │
    │  • Transient DNS glitch → 5 подряд ошибок → breaker open     │
    │                                                              │
    │  Действия:                                                   │
    │  1. Проверить circuit_state метрику                          │
    │  2. Проверить логи upstream'а (работает ли)                  │
    │  3. Проверить isFailure — правильно ли классифицируются      │
    │     ошибки                                                    │
    │  4. Настроить ReadyToTrip мягче                              │
    │  5. Ручной reset breaker'а (admin endpoint)                  │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

**Митигация:** admin endpoint `/admin/circuit/reset?tenant=X&upstream=Y`
для ручного сброса.

### Breaker flapping

```
    ┌──────────────────────────────────────────────────────────────┐
    │  Симптом: breaker часто переключается CLOSED ↔ OPEN          │
    ├──────────────────────────────────────────────────────────────┤
    │                                                              │
    │  Метрика: circuit_state_changes_total > 10/hour              │
    │                                                              │
    │  Причины:                                                    │
    │  • Upstream нестабилен (intermittent failures)               │
    │  • Timeout слишком короткий → false failures                 │
    │  • Interval слишком короткий → stale counters                │
    │                                                              │
    │  Действия:                                                   │
    │  1. Увеличить Interval (сгладить статистику)                 │
    │  2. Увеличить Timeout (не дёргать upstream)                  │
    │  3. Настроить ReadyToTrip на более строгий порог             │
    │  4. Если upstream действительно нестабилен — эскалация       │
    │     к провайдеру                                             │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

### Утечка breaker'ов

```
    ┌──────────────────────────────────────────────────────────────┐
    │  Симптом: mcp_gateway_breaker_registry_size растёт           │
    ├──────────────────────────────────────────────────────────────┤
    │                                                              │
    │  Причины:                                                    │
    │  • Создание breaker'а для удалённых тенантов                 │
    │  • Динамические upstream names (с параметрами в ключе)       │
    │  • Опционально: brute-force атака на разные tenant_id        │
    │                                                              │
    │  Митигация:                                                  │
    │  • TTL для неактивных breaker'ов (30 дней)                   │
    │  • Periodic GC (удалять breaker'ы, где last_used > TTL)      │
    │  • Валидация tenant_id против allowlist до создания breaker'а│
    │  • Метрика breaker_registry_size с алертом на аномалии       │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

### Breaker блокирует legitimate traffic

```
    ┌──────────────────────────────────────────────────────────────┐
    │  Симптом: клиенты получают 503, хотя upstream работает       │
    ├──────────────────────────────────────────────────────────────┤
    │                                                              │
    │  Причины:                                                    │
    │  • Другой тенант положил upstream (но у нас per-tenant,      │
    │    значит не должно быть)                                    │
    │  • Один тенант исчерпал quota → breaker open → все           │
    │    последующие запросы 503                                   │
    │                                                              │
    │  Это ОЖИДАЕМОЕ поведение:                                    │
    │  • Breaker защищает upstream от перегрузки                   │
    │  • Тенант должен увидеть Retry-After и подождать             │
    │                                                              │
    │  Что делать:                                                 │
    │  • Вернуть Retry-After: <seconds_until_half_open>            │
    │  • Документировать в API docs                                │
    │  • Для enterprise — fallback на cached response              │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

### Отсутствие метрик

```
    ┌──────────────────────────────────────────────────────────────┐
    │  Симптом: breaker открыт, никто не знает                     │
    ├──────────────────────────────────────────────────────────────┤
    │                                                              │
    │  Причины:                                                    │
    │  • OnStateChange callback не настроен                        │
    │  • Метрики не эмитятся в Prometheus                          │
    │  • Алерты не настроены                                       │
    │                                                              │
    │  Митигация:                                                  │
    │  • Обязательная эмиссия circuit_state{tenant,upstream}       │
    │  • Алерт: state == open >1m                                  │
    │  • Dashboard: топ-N открытых breaker'ов                      │
    │  • Integration test: проверить, что метрика эмитится         │
    │    при изменении состояния                                   │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

---

## Alternatives considered

### Alternative 1: afex/hystrix-go

Netflix Hystrix port на Go.

**Плюсы:**
- Много возможностей (bulkhead, fallback, dashboard).
- Знакомый API для тех, кто работал с Hystrix в Java.

**Минусы:**
- **Заброшена** — последний коммит 2018.
- **Нет context support** — критично для Go.
- Тяжёлая — тянет metrics collector.
- Netflix Hystrix **deprecated** в 2018.

**Решение:** отклонено. Мертвый проект.

### Alternative 2: Собственная реализация

**Плюсы:**
- Полный контроль над поведением.
- Нет внешних зависимостей.
- Можно оптимизировать под конкретный workload.

**Минусы:**
- **Легко ошибиться** — race conditions, state transitions.
- Нужны свои тесты (state machine, concurrency).
- Время на разработку и поддержку.
- gobreaker уже решает эту задачу.

**Решение:** отклонено. Not invented here не оправдан.

### Alternative 3: Resilience4j-style (Java port)

**Плюсы:**
- Современный подход (замена Hystrix).
- Больше фич (bulkhead, retry, time limiter).

**Минусы:**
- **Нет зрелого Go port'а** — есть отдельные библиотеки, но
  менее популярные.
- Избыточен для наших задач.
- Много концепций для изучения командой.

**Решение:** отклонено. gobreaker проще и достаточен.

### Alternative 4: Bulkhead только (без breaker)

**Плюсы:**
- Проще — ограничение concurrency.
- Защита от исчерпания ресурсов.

**Минусы:**
- **Не защищает от каскада** — при полном отказе upstream все
  запросы висят до timeout.
- Не даёт fail-fast поведения.
- Клиенты получают timeout вместо быстрого 503.

**Решение:** отклонено. Bulkhead — дополнение, не замена.

### Alternative 5: Rate limiting только (без breaker)

**Плюсы:**
- Уже есть (см. ADR-0003).
- Защита от перегрузки.

**Минусы:**
- **Не реагирует на отказ upstream** — rate limit ограничивает
  нагрузку, но не блокирует запросы при полном отказе.
- Клиенты продолжают получать 500/timeout.

**Решение:** отклонено. Rate limit и breaker — complementary.

### Alternative 6: Глобальный breaker per-upstream

**Плюсы:**
- Меньше breaker'ов в памяти.
- Проще в management.

**Минусы:**
- **False positives** для тенантов с разными credentials.
- **Не изолирует** tenant A от tenant B.
- Потеря enterprise-клиентов при проблемах free-tier.

**Решение:** отклонено. Per-tenant per-upstream обязательна.

---

## Action items

Задачи, вытекающие из этого ADR:

- [ ] **Пакет `internal/breaker`** — реализовать:
  - `Registry` с map[tenant:upstream] → *gobreaker.CircuitBreaker
  - `Get(tenantID, upstreamName) *gobreaker.CircuitBreaker`
  - Потокобезопасность (RWMutex + double-check)
  - `isFailure(err)` — классификация ошибок (4xx vs 5xx)
  - Unit-тесты с race detector
- [ ] **Интеграция с retry** — реализовать retry **внутри**
  `cb.Execute`:
  - Exponential backoff с jitter
  - `isRetryable(err)` — только для idempotent errors
  - Max 3 retry'я
- [ ] **Метрики** — Prometheus:
  - `mcp_gateway_circuit_state{tenant,upstream}` (gauge)
  - `mcp_gateway_circuit_requests_total{tenant,upstream,result}`
  - `mcp_gateway_circuit_state_changes_total{tenant,upstream,from,to}`
  - `mcp_gateway_circuit_open_duration_seconds` (histogram)
  - `mcp_gateway_breaker_registry_size` (gauge)
- [ ] **OnStateChange callback** — эмитить метрики и логировать
  переходы:
  ```go
  OnStateChange: func(name string, from, to gobreaker.State) {
      logger.Warn("circuit state change",
          "tenant", tenantID,
          "upstream", upstreamName,
          "from", from.String(),
          "to", to.String())
      metrics.RecordStateChange(tenantID, upstreamName, from, to)
  }
  ```
- [ ] **Алерты** — добавить в `docs/reliability/runbook.md`:
  - `circuit_state == 2` (open) >1m → warning
  - `circuit_state == 2` (open) >10m → critical
  - `circuit_state_changes_total` rate >10/hour для одного breaker'а → warning
  - `breaker_registry_size` аномалии → warning
- [ ] **Admin endpoint** — `/admin/circuit/reset?tenant=X&upstream=Y`:
  - Ручной сброс breaker'а в CLOSED
  - RBAC: только admin role
  - Audit log (см. ADR-0002)
- [ ] **GC breaker'ов** — periodic cleanup:
  - TTL 30 дней для неактивных breaker'ов
  - Метрика удалённых breaker'ов
- [ ] **Integration test** — сценарии:
  - Upstream отказывает → breaker открывается
  - Tenant A fails, Tenant B unaffected
  - Retry внутри breaker работает корректно
  - 4xx не считается failure'ом
  - 429 считается failure'ом
  - Timeout recovery (OPEN → HALF-OPEN → CLOSED)
- [ ] **Dashboard** — Grafana:
  - Топ-N открытых breaker'ов
  - State changes over time
  - Requests rejected by breaker (per tenant)
- [ ] **Документация** — для клиентов:
  - Что делать при 503 от breaker
  - Заголовок `Retry-After` при open
  - Fallback стратегии (cached response, degraded mode)

---

## References

- [Martin Fowler: Circuit Breaker](https://martinfowler.com/bliki/CircuitBreaker.html)
- [Microsoft: Circuit Breaker Pattern](https://learn.microsoft.com/en-us/azure/architecture/patterns/circuit-breaker)
- [sony/gobreaker](https://github.com/sony/gobreaker)
- [Netflix Hystrix: Deprecation](https://github.com/Netflix/Hystrix#hystrix-status)
- [Resilience4j](https://resilience4j.readme.io/)
- [Google SRE Book: Handling Overload](https://sre.google/sre-book/handling-overload/)
- [Release It! (Michael Nygard) — Circuit Breaker, Bulkhead](https://pragprog.com/titles/mnee2/release-it-second-edition/)
- [RFC 7231: Retry-After header](https://datatracker.ietf.org/doc/html/rfc7231#section-7.1.3)

---

## Related ADRs

- [ADR-0001: SPIFFE/SPIRE для mTLS](0001-use-spiffe-for-mtls.md) — не влияет на breaker, но используется для идентификации
- [ADR-0002: HMAC hash-chain для audit log](0002-hmac-hash-chain-for-audit.md) — state changes логируются в audit
- [ADR-0003: Redis для rate limiting](0003-redis-for-rate-limiting.md) — rate limit + breaker = complementary защита
- [ADR-0004: tenant_id в context](0004-tenant-id-in-context.md) — tenant_id — ключ для per-tenant breaker'ов
- ADR-0006 (TBD): PII redaction — вызывается перед upstream, работает с breaker