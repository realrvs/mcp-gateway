# ADR-0004: Сквозной tenant_id через context.Context

- **Status:** Accepted
- **Date:** 2026-09-23
- **Deciders:** Roman Sokolov (Architect)
- **Tags:** `multi-tenancy`, `architecture`, `context`, `security`, `isolation`

---

## Context

MCP Gateway обслуживает **несколько тенантов одновременно** — разных
клиентов (организаций, команд, пользователей), каждый со своими:

- **Rate limits** (см. ADR-0003) — per-tenant квоты на вызовы LLM.
- **Upstream-эндпоинты** — тенант A может использовать один LLM
  провайдер, тенант B — другой.
- **PII policy** — разные правила редактирования PII (GDPR vs HIPAA
  vs PCI DSS).
- **Audit isolation** — записи audit log помечаются tenant_id (см.
  ADR-0002), и тенант **не должен** видеть записи других тенантов.
- **Circuit breaker state** — падение upstream у тенанта A не должно
  открывать breaker для тенанта B (см. ADR-0005).
- **Billing** — использование LLM учитывается per tenant для FinOps.

**Ключевая проблема:** `tenant_id` — это **сквозной атрибут запроса**,
который нужен **всем** подсистемам gateway. Без чёткого механизма
распространения возможны:

1. **Потеря tenant_id** на каком-то этапе → атрибуция к «дефолтному»
   тенанту, утечка данных, неверный rate limit.
2. **Подмена tenant_id** злоумышленником → cross-tenant access,
   обход лимитов, доступ к чужим данным.
3. **Несогласованность** — в одном слое видим tenant A, в другом —
   tenant B (например, из-за race condition или неверного propagate).
4. **Сложность тестирования** — без явного контракта каждый модуль
   извлекает tenant_id по-своему.

**Требуется:**
- **Единый источник истины** для tenant_id на протяжении всего
  жизненного цикла запроса.
- **Криптографическая привязка** tenant_id к аутентифицированному
  субъекту (нельзя подменить заголовком).
- **Компиляционная защита** — модуль, которому нужен tenant_id,
  должен **явно** его требовать, а не получать «может быть nil».
- **Изоляция** — tenant A **не может** получить доступ к ресурсам
  tenant B, даже при ошибке в коде.

---

## Decision

**Используем `context.Context`** как единственный механизм передачи
`tenant_id` по стеку вызовов, с **типизированным ключом** и **обязательной
валидацией** на входе.

### Тип и ключ

```go
package tenant

// TenantID — типизированный идентификатор тенанта.
// Использование отдельного типа (а не string) даёт compile-time защиту
// от случайной передачи произвольной строки.
type TenantID string

// ctxKey — приватный тип ключа контекста.
// Приватный тип предотвращает коллизии с ключами из других пакетов.
type ctxKey struct{}

// WithID возвращает новый context с tenant_id.
// Используется ТОЛЬКО в middleware после успешной аутентификации.
func WithID(ctx context.Context, id TenantID) context.Context {
    return context.WithValue(ctx, ctxKey{}, id)
}

// FromContext извлекает tenant_id из контекста.
// Возвращает (id, true) если tenant_id присутствует и валиден,
// (zero, false) в противном случае.
func FromContext(ctx context.Context) (TenantID, bool) {
    id, ok := ctx.Value(ctxKey{}).(TenantID)
    return id, ok && id != ""
}

// MustFromContext — вариант для случаев, когда tenant_id гарантирован
// (например, в handler'ах, вызываемых только после middleware).
// Паникует, если tenant_id отсутствует — это programming error,
// а не runtime-ситуация.
func MustFromContext(ctx context.Context) TenantID {
    id, ok := FromContext(ctx)
    if !ok {
        panic("tenant_id missing from context — middleware not applied")
    }
    return id
}
```

### Распространение по стеку

```
    ┌──────────────────────────────────────────────────────────────┐
    │                                                              │
    │   HTTP Request                                               │
    │   ├── mTLS (SPIFFE SVID)             [ADR-0001]              │
    │   ├── Authorization: Bearer <JWT>                            │
    │   └── X-Tenant-ID: <optional, dev only>                      │
    │                                                              │
    │           │                                                  │
    │           ▼                                                  │
    │   ┌───────────────────────────┐                              │
    │   │  Auth Middleware          │                              │
    │   │  (валидация JWT, SVID)    │                              │
    │   └───────────┬───────────────┘                              │
    │               │                                              │
    │               ▼                                              │
    │   ┌───────────────────────────┐                              │
    │   │  Tenant Resolver          │                              │
    │   │  Middleware               │                              │
    │   │                           │                              │
    │   │  1. Извлечь tenant_id из  │                              │
    │   │     JWT claim (приоритет) │                              │
    │   │  2. Fallback: X-Tenant-ID │                              │
    │   │     (только dev)          │                              │
    │   │  3. Валидация против      │                              │
    │   │     allowlist тенантов    │                              │
    │   │  4. Проверить, что SVID   │                              │
    │   │     имеет право на этот   │                              │
    │   │     tenant_id             │                              │
    │   │  5. Положить в ctx        │                              │
    │   └───────────┬───────────────┘                              │
    │               │                                              │
    │               ▼                                              │
    │   ┌───────────────────────────────────────────────┐          │
    │   │  context.Context c tenant_id                   │          │
    │   └───────────┬───────────────────────────────────┘          │
    │               │                                              │
    │       ┌───────┼────────────┬────────────┬────────────┐       │
    │       │       │            │            │            │       │
    │       ▼       ▼            ▼            ▼            ▼       │
    │   ┌─────┐ ┌─────┐      ┌─────┐      ┌─────┐      ┌─────┐   │
    │   │ RL  │ │Audit│      │ PII │      │ CB  │      │MCP  │   │
    │   │     │ │     │      │     │      │     │      │     │   │
    │   │ ADR-│ │ ADR-│      │ ADR-│      │ ADR-│      │ ADR-│   │
    │   │ 0003│ │ 0002│      │ 0009│      │ 0005│      │ 0006│   │
    │   └─────┘ └─────┘      └─────┘      └─────┘      └─────┘   │
    │       │       │            │            │            │       │
    │       └───────┴────────────┴────────────┴────────────┘       │
    │                            │                                 │
    │                            ▼                                 │
    │                    Upstream LLM Call                         │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

### Источники tenant_id (по приоритету)

```
    ┌──────────────────────────────────────────────────────────────┐
    │  Priority │ Source              │ When used                  │
    ├───────────┼─────────────────────┼────────────────────────────┤
    │                                                              │
    │    1      │ JWT claim           │ Production. Всегда.        │
    │           │ "tenant_id"         │ Подписан IdP, нельзя       │
    │           │                     │ подменить.                 │
    │                                                              │
    │    2      │ X-Tenant-ID header  │ Local dev / testing only.  │
    │           │                     │ Отключено в production.    │
    │                                                              │
    │    3      │ SPIFFE ID mapping   │ Опционально: маппинг       │
    │           │ (config)            │ SPIFFE ID → tenant_id.     │
    │           │                     │ Используется, если клиент  │
    │           │                     │ не может выдать JWT        │
    │           │                     │ (например, internal agent).│
    │                                                              │
    │    4      │ (default fallback)  │ ОТСУТСТВУЕТ. Запрос        │
    │           │                     │ отклоняется с 401.         │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

**Ключевое правило:** если tenant_id не извлечён ни из одного
источника → запрос **отклоняется** с `401 Unauthorized`.
**Никаких дефолтных тенантов** — это security-anti-pattern.

### Пример middleware

```go
package tenant

import (
    "context"
    "errors"
    "net/http"
)

var (
    ErrMissingTenant = errors.New("tenant_id not found in request")
    ErrInvalidTenant = errors.New("tenant_id not in allowlist")
    ErrUnauthorized  = errors.New("SPIFFE ID not authorized for tenant")
)

func Middleware(
    jwtParser *JWTParser,
    allowlist *Allowlist,
    spiffeAuth *SPIFFEAuthz,
    isDev bool,
) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            ctx := r.Context()

            // 1. JWT claim (production, приоритет)
            tenantID, err := jwtParser.ExtractTenant(r)
            if err != nil && isDev {
                // 2. Fallback: X-Tenant-ID header (только dev)
                tenantID = TenantID(r.Header.Get("X-Tenant-ID"))
            }

            if tenantID == "" {
                http.Error(w, "missing tenant", http.StatusUnauthorized)
                return
            }

            // 3. Валидация против allowlist
            if !allowlist.Contains(tenantID) {
                http.Error(w, "invalid tenant", http.StatusForbidden)
                return
            }

            // 4. Проверка авторизации: SPIFFE ID → tenant_id
            spiffeID := spiffeAuth.FromContext(ctx)
            if !spiffeAuth.IsAuthorizedFor(spiffeID, tenantID) {
                http.Error(w, "forbidden", http.StatusForbidden)
                return
            }

            // 5. Положить в context
            ctx = WithID(ctx, tenantID)
            next.ServeHTTP(w, r.WithContext(ctx))
        })
    }
}
```

### Дальнейшее использование

Каждая подсистема **обязана** извлекать tenant_id из контекста
**явно**:

```go
func (h *ToolCallHandler) Handle(ctx context.Context, req *ToolCallRequest) (*Response, error) {
    tenantID := tenant.MustFromContext(ctx)  // паника, если нет

    // Rate limit (ADR-0003)
    if err := h.rateLimiter.Check(ctx, tenantID, "tools_call"); err != nil {
        return nil, err
    }

    // PII redaction (ADR-0009)
    redacted, err := h.piiRedactor.Redact(ctx, tenantID, req.Args)
    if err != nil {
        return nil, err
    }

    // Circuit breaker (ADR-0005)
    upstream := h.upstreamRegistry.Get(tenantID)
    result, err := h.breaker.Execute(ctx, tenantID, upstream, func() (any, error) {
        return h.callUpstream(ctx, upstream, redacted)
    })
    if err != nil {
        return nil, err
    }

    // Audit (ADR-0002)
    h.audit.Log(ctx, AuditEntry{
        TenantID: string(tenantID),
        Actor:    spiffeAuth.FromContext(ctx),
        Action:   "tools/call",
        Outcome:  "allow",
    })

    return result, nil
}
```

**Ключевые правила:**

1. **Никаких глобальных переменных** — tenant_id только через context.
2. **Никаких параметров функции** `tenantID string` — это ломает
   propagate через middleware и легко забывается.
3. **`MustFromContext` в handler'ах** — паника при отсутствии. Это
   лучше, чем тихо обработать запрос без tenant_id.
4. **`FromContext` в middleware** — мягкая проверка, чтобы
   возвращать 401, а не паниковать.

---

## Rationale

### Почему context.Context, а не явный параметр

**Альтернатива:** передавать `tenantID` параметром во все функции:

```go
func (h *Handler) Handle(ctx context.Context, tenantID string, req *Request) (*Response, error)
```

**Проблемы:**

1. **Забывание** — при добавлении нового слоя легко пропустить
   параметр. Компилятор подскажет, только если сигнатура изменится.
2. **Сигнатуры разрастаются** — при добавлении tenant-scoped фич
   (`user_id`, `request_id`, `trace_id`) параметры плодятся.
3. **Не работает с `context.Context`** — стандартные библиотеки
   (`database/sql`, `http.Client`, OpenTelemetry) принимают только
   context. Пришлось бы конвертировать туда-обратно.
4. **Не даёт «сквозной» guarantee** — middleware не может
   автоматически добавить параметр во все downstream-вызовы.

**`context.Context` — стандарт индустрии** для request-scoped данных
в Go (рекомендован Google, используется во всех крупных проектах:
Kubernetes, gRPC, Prometheus, etcd).

### Почему приватный ключ контекста

```go
// ПЛОХО:
type ctxKey string
const TenantIDKey ctxKey = "tenant_id"

// Другая библиотека может использовать то же самое:
const TenantIDKey2 = "tenant_id"  // ← конфликт
```

**Проблема:** если ключ — экспортируемая строка, две разные
библиотеки могут использовать одинаковый ключ → коллизия. Одна
перезапишет другую.

**Решение:** приватный тип `ctxKey struct{}`. Он **не экспортируется**,
никто кроме нашего пакета не может создать значение того же типа.
Коллизии исключены.

**Ключ не должен быть строкой:** `context.WithValue(ctx, "tenant_id", ...)`
работает, но это anti-pattern. Go vet предупреждает об этом.

### Почему типизированный TenantID, а не string

```go
// ПЛОХО:
func WithID(ctx context.Context, id string) context.Context
func FromContext(ctx context.Context) (string, bool)

// ХОРОШО:
func WithID(ctx context.Context, id TenantID) context.Context
func FromContext(ctx context.Context) (TenantID, bool)
```

**Преимущества:**

1. **Compile-time защита** — нельзя случайно передать произвольную
   строку (например, `user_id` вместо `tenant_id`).
2. **Самодокументируемость** — сигнатура `WithID(ctx, TenantID("acme"))`
   явно показывает намерение.
3. **Возможность добавить методы** — `TenantID.Validate()`,
   `TenantID.Normalize()`, `TenantID.Redacted()` (для логов).

### Почему не глобальная переменная / goroutine-local

**Goroutine-local storage** (через `runtime.SetFinalizer` или
библиотеки типа `gls`) технически возможен, но:

- **Не идиоматичен для Go** — противоречит явной передаче контекста.
- **Ломает concurrent-модель** — при `go func()` внутри обработки
  goroutine-local не наследуется.
- **Не работает с `context.Context`** — стандартные библиотеки
  не знают о goroutine-local.
- **Скрывает зависимости** — трудно понять, кто использует tenant_id.

**`context.Context` — единственный правильный способ** для
request-scoped данных в Go.

### Почему обязательная валидация против allowlist

**Проблема:** JWT подписан IdP, но `tenant_id` в нём может быть
**любым** — IdP не знает, какие тенанты обслуживает gateway.

**Пример атаки:**

1. Злоумышленник получает JWT от IdP с `tenant_id: "acme"` (свой
   тенант, легитимно).
2. Меняет claim на `tenant_id: "victim-corp"`.
3. JWT **невалиден** — подпись не сойдётся. ✓ Защита работает.

**Но** если IdP позволяет создавать JWT с произвольным tenant_id
(например, через self-service registration), то злоумышленник может
зарегистрировать `tenant_id: "victim-corp"` в IdP и получить
валидный JWT.

**Митигация:** gateway проверяет tenant_id против **своего** allowlist
(независимого от IdP). Если `victim-corp` не зарегистрирован в
gateway — запрос отклоняется с `403`.

**Дополнительно:** SPIFFE ID (ADR-0001) должен быть **авторизован**
для конкретного tenant_id. Например:

```yaml
tenants:
  - id: "acme"
    authorized_spiffe_ids:
      - "spiffe://mcp-gateway.local/ns/acme/sa/*"
  - id: "globex"
    authorized_spiffe_ids:
      - "spiffe://mcp-gateway.local/ns/globex/sa/*"
```

Это даёт **двойную защиту:** JWT (кто пользователь) + SPIFFE ID
(какой workload). Оба должны совпасть с tenant_id.

---

## Consequences

### Positive

- **Единый механизм** — tenant_id передаётся одним способом через
  весь стек.
- **Compile-time защита** — типизированный `TenantID` предотвращает
  путаницу.
- **Явные зависимости** — модуль, которому нужен tenant_id, явно
  вызывает `tenant.FromContext(ctx)`.
- **Тестируемость** — можно подставить любой tenant_id в тесте
  через `context.Background()`.
- **Совместимость со стандартной библиотекой** — `context.Context`
  везде: HTTP, SQL, gRPC, OpenTelemetry.
- **Безопасность** — невозможно подменить tenant_id через заголовок
  в production; обязательно через подписанный JWT.
- **Изоляция** — все ресурсы (rate limit, audit, circuit breaker)
  namespaced по tenant_id, cross-tenant access невозможен.

### Negative

- **Паника при отсутствии tenant_id** — `MustFromContext` паникует,
  что может уронить pod. Митигация: `recover()` в HTTP-handler'е,
  логирование и алерт. Это **лучше**, чем тихо обработать запрос
  без tenant_id.
- **Нельзя «случайно» использовать** — если модуль хочет tenant_id,
  он должен явно его извлечь. Это увеличивает boilerplate, но
  делает зависимости явными.
- **Проблемы с background-задачами** — фоновые процессы (cronjobs,
  reconciliation) не имеют request-scoped контекста. Нужно
  передавать tenant_id явно или обрабатывать все тенанты по очереди.
- **Тестирование** — нужно помнить о `tenant.WithID(ctx, ...)` в
  unit-тестах. Митигация: helper `tenant.TestContext(id)`.

### Neutral

- **Производительность** — `context.WithValue` и `ctx.Value` очень
  быстрые (наносекунды). При 10k RPS не влияет.
- **Размер context** — добавление одного key-value в context
  добавляет ~64 байта. При глубоком стеке (десятки вызовов) это
  может накапливаться, но не критично.
- **Совместимость с W3C traceparent** — tenant_id сосуществует с
  trace_id в context без конфликтов.

---

## Failure modes

### tenant_id отсутствует в контексте (программная ошибка)

```
    ┌──────────────────────────────────────────────────────────────┐
    │  Симптом: MustFromContext паникует                          │
    ├──────────────────────────────────────────────────────────────┤
    │                                                              │
    │  Возможные причины:                                          │
    │  • Middleware не применился (порядок handlers неверный)      │
    │  • Горутина создана без propagate context                    │
    │  • Тест забыл WithID                                         │
    │                                                              │
    │  Действия:                                                   │
    │  1. recover() в HTTP handler → 500                           │
    │  2. Логировать с trace_id и stack                            │
    │  3. Critical alert: programming error                        │
    │  4. Fix: проверить порядок middleware                        │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

**Это не runtime-ситуация, а programming error.** Должна быть
поймана в тестах, а не в production.

### JWT содержит tenant_id, отсутствующий в allowlist

```
    ┌──────────────────────────────────────────────────────────────┐
    │  Симптом: 403 Forbidden                                      │
    ├──────────────────────────────────────────────────────────────┤
    │                                                              │
    │  Возможные причины:                                          │
    │  • Тенант удалён, но JWT ещё валиден                         │
    │  • Атака: злоумышленник пытается выдать себя за другого      │
    │  • Ошибка в конфиге allowlist                                │
    │                                                              │
    │  Действия:                                                   │
    │  1. Логировать с tenant_id и SPIFFE ID                       │
    │  2. Warning alert при частых 403 для одного tenant_id        │
    │  3. Проверить allowlist (может, тенант просто не добавлен)   │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

### SPIFFE ID не авторизован для tenant_id

```
    ┌──────────────────────────────────────────────────────────────┐
    │  Симптом: 403 Forbidden                                      │
    ├──────────────────────────────────────────────────────────────┤
    │                                                              │
    │  Возможные причины:                                          │
    │  • Подмена: SPIFFE ID из одного namespace пытается          │
    │    обратиться к тенанту из другого                          │
    │  • Ошибка конфигурации authorized_spiffe_ids                 │
    │                                                              │
    │  Действия:                                                   │
    │  1. Security alert: возможная атака                          │
    │  2. Запись в immutable incident log (ADR-0002)               │
    │  3. Forensics: анализ SPIFFE ID, JWT claims                  │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

### Background-задача без tenant_id

```
    ┌──────────────────────────────────────────────────────────────┐
    │  Проблема: cronjob/reconciliation не имеет tenant_id         │
    ├──────────────────────────────────────────────────────────────┤
    │                                                              │
    │  Варианты:                                                   │
    │  • Обход всех тенантов в цикле:                              │
    │    for _, tid := range allTenants {                          │
    │        ctx := tenant.WithID(context.Background(), tid)       │
    │        process(ctx)                                          │
    │    }                                                         │
    │                                                              │
    │  • Использовать специальный «системный» tenant_id            │
    │    (например, "system") для internal операций                │
    │                                                              │
    │  Решение: обход тенантов с явным WithID. Не использовать     │
    │  «дефолтный» tenant — это anti-pattern.                      │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

### Расхождение tenant_id между слоями

```
    ┌──────────────────────────────────────────────────────────────┐
    │  Симптом: в audit log один tenant, в rate limit другой      │
    ├──────────────────────────────────────────────────────────────┤
    │                                                              │
    │  Возможные причины:                                          │
    │  • Модуль читает tenant_id не из context, а из заголовка     │
    │  • Кеширование контекста без учёта tenant_id                 │
    │  • Двойной вызов middleware (перезапись)                     │
    │                                                              │
    │  Митигация:                                                  │
    │  • Только `tenant.FromContext` — никаких других источников   │
    │  • Middleware вызывается ровно один раз                      │
    │  • Integration test: сравнение tenant_id из разных слоёв     │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

---

## Alternatives considered

### Alternative 1: tenant_id как параметр функции

```go
func (h *Handler) Handle(ctx context.Context, tenantID string, req *Request)
```

**Плюсы:**
- Явно видно в сигнатуре.
- Нет скрытых зависимостей.

**Минусы:**
- Плодит параметры при добавлении tenant-scoped фич.
- Легко забыть propagate через новый слой.
- Не работает с библиотеками, принимающими только context.

**Решение:** отклонено. context.Context идиоматичнее для Go.

### Alternative 2: глобальная переменная / singleton

```go
var CurrentTenant atomic.Value
```

**Плюсы:**
- Не нужно передавать через стек.

**Минусы:**
- **Катастрофа при concurrent запросах** — race condition.
- Не работает с goroutine'ами.
- Противоречит принципу «явное лучше неявного».

**Решение:** отклонено. Невозможно в concurrent-сервере.

### Alternative 3: goroutine-local storage

Библиотеки типа `github.com/jtolds/gls` или `github.com/timandy/routine`.

**Плюсы:**
- Не нужно передавать context.
- «Магически» работает везде.

**Минусы:**
- Не идиоматичен для Go.
- Ломается при `go func()`.
- Скрывает зависимости.
- Не совместим с context-aware библиотеками.

**Решение:** отклонено. Anti-pattern в Go.

### Alternative 4: HTTP header propagation (X-Tenant-ID везде)

Каждый сервис читает `X-Tenant-ID` из заголовка.

**Плюсы:**
- Работает между сервисами без JWT.
- Просто.
- Не требует context propagation.

**Минусы:**
- **Небезопасно** — заголовок легко подменить. Клиент может
  отправить `X-Tenant-ID: victim-corp` и получить доступ к чужим
  данным.
- **Потеря при proxy** — некоторые reverse proxy удаляют
  неизвестные заголовки.
- **Нет compile-time защиты** — легко забыть передать заголовок.
- **Не работает для internal gRPC** — заголовки не propagate
  автоматически между сервисами.

**Решение:** отклонено как основной механизм. `X-Tenant-ID`
разрешён **только для local development** (когда JWT не настроен).
В production заголовок игнорируется.

### Alternative 5: tenant_id как часть URL path

```
    POST /tenants/acme/mcp/tools/call
```

**Плюсы:**
- Видно в логах, метриках, trace'ах.
- RESTful — тенант как ресурс.
- Не требует context propagation.

**Минусы:**
- **Ломает MCP-протокол** — endpoint'ы фиксированы спецификацией
  (`/mcp`, `/sse`). Добавление tenant в path потребует кастомного
  клиента.
- **Утечка tenant_id** в URL — попадает в access logs, referer,
  browser history.
- **Дублирование** — tenant_id и в URL, и в JWT. Возможны
  расхождения.
- **Не работает для SSE** — long-lived connections в MCP не
  предполагают частую смену URL.

**Решение:** отклонено. Tenant_id должен быть **в контексте
аутентификации** (JWT), а не в URL.

---

## Action items

Задачи, вытекающие из этого ADR:

- [ ] **Пакет `internal/tenant`** — реализовать:
  - тип `TenantID`
  - `WithID`, `FromContext`, `MustFromContext`
  - helper `TestContext(id)` для unit-тестов
  - unit-тесты с race detector
- [ ] **Middleware** — реализовать `tenant.Middleware` с:
  - извлечением из JWT (приоритет)
  - fallback на `X-Tenant-ID` (только dev)
  - валидацией против allowlist
  - проверкой авторизации SPIFFE ID → tenant_id
- [ ] **Конфиг** — расширить `configs/tenants.yaml`:
  - секция `authorized_spiffe_ids` per tenant
  - флаг `allow_x_tenant_id_header` для dev
- [ ] **Тесты** — обязательно:
  - unit-тест `FromContext` (есть/нет/пустой)
  - unit-тест `MustFromContext` паникует при отсутствии
  - integration-тест middleware: JWT → context → handler
  - integration-тест cross-tenant: SVID тенанта A → tenant_id B → 403
  - race test: 100 goroutine'ов с разными tenant_id
- [ ] **Метрики** — добавить Prometheus:
  - `mcp_gateway_tenant_requests_total{tenant,method}`
  - `mcp_gateway_tenant_auth_failures_total{reason}`
  - `mcp_gateway_tenant_context_missing_total` (programming error)
- [ ] **Алерты** — добавить в runbook:
  - `tenant_context_missing_total` rate >0 → critical (bug)
  - `tenant_auth_failures_total` rate >1/min для одного tenant_id
    → warning (возможная атака или ошибка конфига)
- [ ] **Документация** — обновить:
  - `docs/architecture/trust-boundaries.md` — указать tenant_id
    как L7-атрибут после mTLS (L4) и JWT (L6)
  - `docs/security/threat-model.md` — добавить threat «cross-tenant
    access via tenant_id spoofing»
- [ ] **OpenTelemetry** — добавить `tenant.id` как span attribute:
  - фильтрация трейсов per tenant
  - анализ latency per tenant
  - алерты на anomaly per tenant

---

## References

- [Go blog: Contexts and structs](https://go.dev/blog/context-and-structs)
- [Go wiki: Context](https://github.com/golang/go/wiki/CodeReviewComments#contexts)
- [Dave Cheney: Context is for cancellation](https://dave.cheney.net/2017/01/26/context-is-for-cancellation)
- [JWT RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519)
- [OWASP: Multi-Tenancy Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Multitenant_Security_Cheat_Sheet.html)

---

## Related ADRs

- [ADR-0001: SPIFFE/SPIRE для mTLS](0001-use-spiffe-for-mtls.md) — SPIFFE ID — независимый от tenant_id уровень identity
- [ADR-0002: HMAC hash-chain для audit log](0002-hmac-hash-chain-for-audit.md) — tenant_id обязателен в каждой audit-записи
- [ADR-0003: Redis для rate limiting](0003-redis-for-rate-limiting.md) — tenant_id — ключ для rate limit
- [ADR-0005: gobreaker для circuit breaker](0005-circuit-breaker-library-choice.md) — изоляция circuit breaker per tenant_id