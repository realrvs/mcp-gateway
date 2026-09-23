# ADR-0003: Redis для per-tenant rate limiting

- **Status:** Accepted
- **Date:** 2026-09-23
- **Deciders:** Roman Sokolov (Architect)
- **Tags:** `reliability`, `rate-limiting`, `multi-tenancy`, `redis`, `finops`

---

## Context

MCP Gateway обслуживает **несколько тенантов одновременно** (см. ADR-0004).
Каждый вызов `tools/call` может приводить к дорогостоящему вызову
upstream LLM (единицы центов за 1k токенов). Без ограничений:

1. **Один тенант может исчерпать общую пропускную способность** —
   «noisy neighbor» проблема. Тестовый клиент с runaway-loop может
   уронить gateway для всех остальных.
2. **Затраты на LLM выходят из-под контроля** — FinOps-риск. Один
   сбойный агент может за час сгенерировать счёт на тысячи долларов.
3. **Upstream LLM API имеет свои лимиты** (rate limit, quota, TPM/RPM).
   Их превышение → `429`, degraded experience для всех тенантов.
4. **Нет защиты от abuse** — compromised клиент может устроить DoS
   или использовать gateway как бесплатный прокси.
5. **Compliance-требования** — некоторые регуляторы требуют fair-use
   policy и защиту от чрезмерного потребления ресурсов.

**Требуется per-tenant rate limiting** с поддержкой:
- Разных лимитов для разных методов (`tools/call` — дорого,
  `tools/list` — дёшево).
- Разных лимитов для разных tier'ов тенантов (enterprise, standard, free).
- Burst-ов (клиент может на короткое время превысить средний rate).
- Распределённого состояния (несколько pod'ов gateway делят лимит).

---

## Decision

**Используем Redis** как распределённое хранилище состояния rate
limiter'а с **sliding window** алгоритмом, реализованным через **Lua-скрипт**
для атомарности.

### Выбор алгоритма: sliding window

Рассмотренные алгоритмы:

```
    ┌────────────────────────────────────────────────────────────┐
    │  Token Bucket                                              │
    ├────────────────────────────────────────────────────────────┤
    │                                                            │
    │  • Bucket ёмкостью N, пополняется со скоростью R/сек       │
    │  • Каждый запрос забирает 1 токен                          │
    │  • Если токенов нет — отказ                                │
    │                                                            │
    │  Плюсы:                                                    │
    │  • Smooth rate, позволяет bursts до ёмкости bucket         │
    │  • Хорошо для API, где нужен средний rate                  │
    │                                                            │
    │  Минусы:                                                   │
    │  • Сложнее реализовать атомарно в Redis                    │
    │  • Не отражает «N запросов за окно», только «средний rate» │
    │                                                            │
    └────────────────────────────────────────────────────────────┘

    ┌────────────────────────────────────────────────────────────┐
    │  Fixed Window                                              │
    ├────────────────────────────────────────────────────────────┤
    │                                                            │
    │  • Окно 60 секунд, счётчик в Redis                         │
    │  • INCR на каждый запрос, EXPIRE на окно                   │
    │  • Если счётчик > N — отказ                                │
    │                                                            │
    │  Плюсы:                                                    │
    │  • Тривиально реализуется в Redis (INCR + EXPIRE)          │
    │  • O(1) память на tenant × method                          │
    │                                                            │
    │  Минусы:                                                   │
    │  • «Burst на границе окна» — 2N запросов в 2×окно          │
    │    (100 в конце окна + 100 в начале следующего)            │
    │  • Неточен для compliance (нельзя сказать «не более N в    │
    │    любой момент времени»)                                  │
    │                                                            │
    └────────────────────────────────────────────────────────────┘

    ┌────────────────────────────────────────────────────────────┐
    │  Sliding Window Log (наш выбор)                            │
    ├────────────────────────────────────────────────────────────┤
    │                                                            │
    │  • Храним timestamp каждого запроса в sorted set           │
    │  • ZREMRANGEBYSCORE — удаляем старые (за пределами окна)   │
    │  • ZCARD — считаем оставшиеся                              │
    │  • Если count >= N — отказ, иначе ZADD                     │
    │                                                            │
    │  Плюсы:                                                    │
    │  • Точный: «не более N запросов в любом окне размером W»   │
    │  • Burst-safe — нет проблемы на границе окна               │
    │  • Соответствует compliance (аудитор принимает)            │
    │                                                            │
    │  Минусы:                                                   │
    │  • O(N) память на tenant (N = размер лимита)               │
    │  • Чуть медленнее fixed window (но всё ещё O(log N))       │
    │                                                            │
    └────────────────────────────────────────────────────────────┘
```

**Решение: sliding window log.** При наших лимитах (десятки-тысячи
запросов в минуту на тенант) O(N) памяти — приемлемо. Точность важнее
экономии памяти.

### Ключи в Redis

```
    ┌────────────────────────────────────────────────────────────┐
    │  Формат ключа:                                             │
    │                                                            │
    │      rl:{tenant}:{method}:{window}                         │
    │       ▲                                                    │
    │       └── hash tag {tenant} — для Redis Cluster            │
    │           (все ключи одного тенанта на одном шарде)        │
    │                                                            │
    │  Примеры:                                                  │
    │                                                            │
    │      rl:{acme}:tools_call:60s                              │
    │      rl:{acme}:tools_list:60s                              │
    │      rl:{globex}:tools_call:60s                            │
    │                                                            │
    │  ВАЖНО: hash tag {tenant} обязателен для Cluster.          │
    │  Без него ключи одного тенанта могут попасть на разные     │
    │  шарды, и Lua-скрипт упадёт с CROSSSLOT ошибкой.           │
    │                                                            │
    │  Значение: Redis Sorted Set (ZSET)                         │
    │                                                            │
    │      member = now .. ":" .. seq                            │
    │               (компактнее UUID в ~2-3x по памяти)          │
    │      score  = timestamp в миллисекундах (Unix ms)          │
    │                                                            │
    │  TTL на весь ZSET: window_size + safety_margin (напр. 90s) │
    │                                                            │
    └────────────────────────────────────────────────────────────┘
```

**Почему `now:seq` вместо UUID:**

- UUID = 36 байт в ASCII, `now:seq` ~ 18-20 байт. Экономия памяти ~50%
  на ZSET при 100 тенантах × 10 методах.
- `seq` — монотонный счётчик в рамках миллисекунды, обеспечивает
  уникальность member'а без внешней генерации ID.
- Можно генерировать прямо в Lua: `now .. ":" .. redis.call('INCR', key .. ':seq')`.

### Lua-скрипт (атомарная операция)

Ключевой момент: **check-and-increment должны быть атомарными**.
Иначе при конкурентных запросах лимит будет превышаться.

```
    ┌────────────────────────────────────────────────────────────┐
    │  Наивная реализация (сломана):                             │
    ├────────────────────────────────────────────────────────────┤
    │                                                            │
    │  1. ZCARD rl:acme:tools_call:60s      → 99                 │
    │  2. Проверить 99 < 100                → OK                 │
    │  3. (между шагами 2 и 4 другой клиент тоже прочитал 99)    │
    │  4. ZADD rl:acme:tools_call:60s ...   → 101                │
    │                                                            │
    │  Лимит 100 превышен. Race condition.                       │
    │                                                            │
    └────────────────────────────────────────────────────────────┘

    ┌────────────────────────────────────────────────────────────┐
    │  Lua-скрипт (атомарно в Redis):                            │
    ├────────────────────────────────────────────────────────────┤
    │                                                            │
    │  local key = KEYS[1]                                       │
    │  local window = tonumber(ARGV[1])     -- 60000 ms          │
    │  local limit = tonumber(ARGV[2])      -- 100               │
    │  local req_id_suffix = ARGV[3]        -- seq из Gateway    │
    │                                                            │
    │  -- 1. Получить server-side время (защита от clock skew)   │
    │  local t = redis.call('TIME')                              │
    │  local now = (t[1] * 1000) + math.floor(t[2] / 1000)       │
    │                                                            │
    │  -- 2. Удалить записи за пределами окна                    │
    │  redis.call('ZREMRANGEBYSCORE', key,                       │
    │             0, now - window)                               │
    │                                                            │
    │  -- 3. Продлить TTL СРАЗУ                                   │
    │  --    (иначе под runaway-loop ключ протухнет, а ZCARD     │
    │  --     вернёт «протухшие» записи)                         │
    │  redis.call('PEXPIRE', key, window + 30000)                │
    │                                                            │
    │  -- 4. Посчитать актуальные записи                         │
    │  local count = redis.call('ZCARD', key)                    │
    │                                                            │
    │  -- 5. Проверить лимит                                     │
    │  if count >= limit then                                    │
    │      -- вернуть oldest_score для расчёта Retry-After       │
    │      local oldest = redis.call('ZRANGE', key, 0, 0,        │
    │                                'WITHSCORES')               │
    │      local oldest_score = tonumber(oldest[2]) or now       │
    │      return {0, count, oldest_score}                       │
    │  end                                                       │
    │                                                            │
    │  -- 6. Добавить запрос                                     │
    │  --    member = now:seq (компактнее UUID, дешевле память)  │
    │  local member = tostring(now) .. ':' .. req_id_suffix      │
    │  redis.call('ZADD', key, now, member)                      │
    │                                                            │
    │  -- 7. Вернуть результат + oldest для расчёта заголовков   │
    │  local oldest = redis.call('ZRANGE', key, 0, 0,            │
    │                            'WITHSCORES')                   │
    │  local oldest_score = tonumber(oldest[2]) or now           │
    │  return {1, count + 1, oldest_score}                       │
    │                                                            │
    └────────────────────────────────────────────────────────────┘
```

**Ключевые моменты реализации:**

1. **`TIME` внутри Lua** — server-side время Redis. Все pod'ы видят
   одно и то же время → нет clock-skew проблем.
2. **`PEXPIRE` до проверки лимита** — критично: под runaway-loop
   ключ продлевается на каждой итерации, не протухает, и `ZCARD`
   возвращает **актуальное** количество записей в окне.
3. **`ZREMRANGEBYSCORE` до `ZCARD`** — гарантия, что считаем только
   записи в пределах окна.
4. **Возврат `oldest_score`** — нужен для расчёта `Retry-After` и
   `X-RateLimit-Reset` без дополнительного round-trip к Redis.

**Почему Lua:** Redis выполняет Lua-скрипты **атомарно** —
никакие другие команды не выполняются между строками скрипта. Это
даёт атомарность check-and-increment без распределённых блокировок.

### Возвращаемые значения

Скрипт возвращает `{allowed, count, oldest_score}`:

| Поле | Тип | Описание |
|------|-----|----------|
| `allowed` | 0 \| 1 | 1 — запрос разрешён, 0 — отклонён |
| `count` | число | Количество запросов в окне (после добавления для allowed=1) |
| `oldest_score` | число | Unix ms самого старого запроса в окне |

На основе этого gateway формирует HTTP-ответ:

```
    ┌────────────────────────────────────────────────────────────┐
    │  Случай allowed = 1 (запрос разрешён):                     │
    ├────────────────────────────────────────────────────────────┤
    │                                                            │
    │  HTTP/1.1 200 OK                                           │
    │  X-RateLimit-Limit: 100                                    │
    │  X-RateLimit-Remaining: 42                                 │
    │  X-RateLimit-Reset: 1758624120                             │
    │                                                            │
    └────────────────────────────────────────────────────────────┘

    ┌────────────────────────────────────────────────────────────┐
    │  Случай allowed = 0 (запрос отклонён):                     │
    ├────────────────────────────────────────────────────────────┤
    │                                                            │
    │  HTTP/1.1 429 Too Many Requests                            │
    │  Retry-After: 17                                           │
    │  X-RateLimit-Limit: 100                                    │
    │  X-RateLimit-Remaining: 0                                  │
    │  X-RateLimit-Reset: 1758624120                             │
    │                                                            │
    │  Body: { "error": "rate_limit_exceeded",                   │
    │          "retry_after_seconds": 17 }                       │
    │                                                            │
    └────────────────────────────────────────────────────────────┘
```

**Формулы:**

```
    X-RateLimit-Remaining = max(0, limit - count)
    X-RateLimit-Reset     = (oldest_score + window) / 1000   (Unix sec)
    Retry-After           = ceil((oldest_score + window - now) / 1000)
```

`oldest_score` возвращается Lua-скриптом — не нужно делать
дополнительный `ZRANGE` запрос из gateway'я.

### Конфигурация лимитов

Лимиты задаются **per-tenant × per-method** в конфиге:

```yaml
tenants:
  - id: "acme"
    tier: "enterprise"
    rate_limit:
      tools_call:
        limit: 1000
        window: "60s"
      tools_list:
        limit: 5000
        window: "60s"
      resources_read:
        limit: 2000
        window: "60s"

  - id: "globex"
    tier: "standard"
    rate_limit:
      tools_call:
        limit: 100
        window: "60s"
      tools_list:
        limit: 500
        window: "60s"

  - id: "free-tier-demo"
    tier: "free"
    rate_limit:
      tools_call:
        limit: 10
        window: "60s"
      tools_list:
        limit: 50
        window: "60s"
```

**Дефолты** (если метод не указан явно):
- `tools/call` — 100/мин
- `tools/list` — 1000/мин
- `resources/read` — 500/мин
- Всё остальное — 1000/мин

### Per-tenant vs per-user

**Решение:** rate limiting **per tenant**, а не per user. Причины:

- Tenant — это **биллинговая единица** (FinOps). Мы хотим ограничить
  расходы на LLM для конкретного клиента, а не отдельного пользователя.
- Внутри тенанта может быть много пользователей (агентов, приложений).
  Ограничивать каждого отдельно — задача тенанта, не gateway.
- Простота: один ZSET на (tenant, method) vs комбинаторный взрыв
  на (tenant, user, method).

**Что делать, если тенант хочет per-user лимиты:**
Тенант может добавить `X-User-ID` заголовок, и gateway будет использовать
`rl:{tenant}:{user}:{method}:{window}` как ключ. Это **опциональная
фича** (TODO: реализовать при необходимости).

---

## Rationale

### Почему Redis, а не in-memory rate limiter

**In-memory** (например, `golang.org/x/time/rate`) имеет серьёзные
ограничения для нашего сценария:

```
    ┌────────────────────────────────────────────────────────────┐
    │  Проблема с in-memory при горизонтальном масштабировании:  │
    ├────────────────────────────────────────────────────────────┤
    │                                                            │
    │   Pod 1              Pod 2              Pod 3              │
    │   ┌─────┐            ┌─────┐            ┌─────┐            │
    │   │ 100 │            │ 100 │            │ 100 │            │
    │   │ req │            │ req │            │ req │            │
    │   └─────┘            └─────┘            └─────┘            │
    │                                                            │
    │   Tenant "acme" шлёт 300 запросов/мин.                     │
    │   Каждый pod видит 100 → все пропускают.                   │
    │   Реальный лимит 100 НЕ соблюдается.                       │
    │                                                            │
    │   Для соблюдения лимита 100 нужен общий state.             │
    │                                                            │
    └────────────────────────────────────────────────────────────┘
```

**Redis даёт общий state** для всех pod'ов. Альтернативы:

- **Sticky sessions** — привязка тенанта к одному pod'у. Плохо:
  теряется балансировка, при падении pod'а state теряется.
- **Gossip-протокол** (например, HashiCorp memberlist) — сложно,
  eventual consistency, не подходит для точных лимитов.
- **Postgres** — работает, но на порядок медленнее для high-frequency
  операций. Redis sub-millisecond, Postgres единицы ms.

**Выбор: Redis.** Это стандарт индустрии для rate limiting
(Cloudflare, GitHub, Stripe используют Redis или аналоги).

### Почему Lua-скрипт, а не WATCH/MULTI/EXEC (транзакции Redis)

**Redis транзакции** (`MULTI/EXEC`) и **optimistic locking** (`WATCH`):

- `WATCH key` → `MULTI` → команды → `EXEC` — если ключ изменился
  между `WATCH` и `EXEC`, транзакция откатывается.
- В нашем случае это приведёт к **retry-loop** под нагрузкой: 100
  concurrent запросов → 99 из них упадут с `EXECABORT` → retry.

**Lua-скрипт:**

- Выполняется **атомарно сервером Redis** без возможности
  вмешательства других команд.
- **Не требует retry.**
- **Один round-trip** к Redis вместо нескольких.

**Выбор: Lua.** Это рекомендуемый способ атомарных составных
операций в Redis.

### Почему sliding window, а не token bucket

**Token bucket** элегантен для API, где важен **средний rate**
(например, 100 req/сек с возможностью burst до 200). Но:

1. **Compliance:** аудитор спрашивает «какой максимальный rate?».
   Ответ token bucket — «не более N в секунду в среднем, но до 2N
   в burst» — вызывает вопросы.
2. **Sliding window** даёт чёткий ответ: «не более N в любом окне
   размером W». Это принимается аудиторами.
3. **Реализация:** sliding window log через ZSET — прямолинейна.
   Token bucket атомарно в Redis — сложнее (нужны Lua + accurate
   time source).

**Компромисс:** sliding window log хранит **каждый** запрос (O(N)
память). Для нашего профиля (десятки-тысячи запросов в минуту на
тенант) это приемлемо. Если лимит >10k/мин на тенант — пересмотрим
на sliding window counter (приближённый, O(1) память).

### Почему не API Gateway (Kong, Envoy, Traefik)

Эти решения имеют rate limiting из коробки, но:

- **Привязка к конкретному gateway** — мы строим свой, не хотим
  добавлять ещё один слой.
- **Multi-tenancy сложна** — per-tenant лимиты требуют кастомной
  конфигурации в каждом API Gateway.
- **Динамические лимиты** — нам нужно менять лимиты без рестарта
  (например, при повышении tier'а тенанта). В API Gateway это
  часто требует перезагрузки конфига.
- **Интеграция с FinOps** — мы хотим эмитить метрики per tenant ×
  method в нашем формате. API Gateway не даёт такой гибкости.

**Где API Gateway оправдан:** если у вас уже есть Kong/Envoy для
маршрутизации и вы хотите добавить rate limiting как часть общей
политики. У нас — свой gateway, и rate limiting — часть его логики.

### Почему не квота в Postgres

**Postgres-таблица** `rate_limits(tenant, method, window_start, count)`
с `UPDATE ... WHERE count < limit RETURNING count`:

- **Работает**, атомарность обеспечена на уровне строк.
- **Но:** в 10-100 раз медленнее Redis. При 10k RPS это создаёт
  bottleneck на Postgres.
- **Row-level locks** под нагрузкой → contention.
- **Не подходит** для high-frequency операций.

**Когда оправдано:** если RPS низкий (<100/сек), Postgres может
быть достаточен. У нас — целевые 10k RPS, нужен Redis.

---

## Consequences

### Positive

- **Точные per-tenant лимиты** — no noisy neighbor problem.
- **Распределённое состояние** — работает при горизонтальном
  масштабировании gateway.
- **Sub-millisecond latency** — Redis быстрее любой альтернативы
  с персистентностью.
- **Burst-safe** — sliding window корректно обрабатывает bursts.
- **FinOps-ready** — метрики per tenant × method для контроля
  расходов.
- **Стандартный подход** — индустрия использует Redis + Lua для
  rate limiting (Cloudflare, Stripe, GitHub).
- **Compliance-friendly** — sliding window принимается аудиторами.

### Negative

- **Redis как dependency** — если Redis недоступен, нужна политика
  (fail-open или fail-closed). См. Failure modes ниже.
- **O(N) память на tenant** — при лимите 10k/мин на 100 тенантов
  это ~1M членов в ZSET. Redis справляется, но требует мониторинга.
  Митигация: compact member (`now:seq` вместо UUID), что экономит
  ~50% памяти ZSET.
- **Операционная сложность** — Redis нужен в HA-конфигурации
  (Sentinel или Cluster) для production.
- **Network round-trip** — +0.5-2ms к каждому запросу. Для нашего
  профиля (LLM-вызовы по секундам) пренебрежимо.

### Neutral

- **TTL на ZSET** — `window + 30s` safety margin. Redis сам чистит
  неактивные ключи, не нужен отдельный cleanup job.
- **Мониторинг** — обязательные метрики: `redis_latency_p99`,
  `redis_memory_used`, `rate_limit_denied_total{tenant,method}`.
- **Per-user лимиты** — опциональная фича, не реализуем сейчас,
  но архитектура готова (см. выше).

---

## Failure modes

### Redis недоступен

**Ключевой вопрос:** fail-open или fail-closed?

```
    ┌────────────────────────────────────────────────────────────┐
    │  Fail-OPEN (пропускаем запросы без лимита):                │
    ├────────────────────────────────────────────────────────────┤
    │                                                            │
    │  Плюсы:                                                    │
    │  • Gateway продолжает обслуживать клиентов                 │
    │  • Нет downtime из-за Redis                                │
    │                                                            │
    │  Минусы:                                                   │
    │  • Noisy neighbor вернулся                                 │
    │  • FinOps-риск (uncontrolled LLM costs)                    │
    │  • Compliance-риск                                         │
    │                                                            │
    └────────────────────────────────────────────────────────────┘

    ┌────────────────────────────────────────────────────────────┐
    │  Fail-CLOSED (все запросы отклоняем):                      │
    ├────────────────────────────────────────────────────────────┤
    │                                                            │
    │  Плюсы:                                                    │
    │  • Лимиты соблюдаются всегда                               │
    │  • FinOps защищён                                          │
    │                                                            │
    │  Минусы:                                                   │
    │  • Redis down = gateway down                               │
    │  • Повышенные требования к HA Redis                        │
    │                                                            │
    └────────────────────────────────────────────────────────────┘
```

**Решение: fail-open с алертом** для standard/free tier,
**fail-closed** для enterprise tier с SLA.

```
    ┌────────────────────────────────────────────────────────────┐
    │  Политика per tier:                                        │
    ├────────────────────────────────────────────────────────────┤
    │                                                            │
    │  Tier       Redis down → поведение      SLA                │
    │  ─────────  ──────────────────────────  ─────────────────  │
    │                                                            │
    │  enterprise fail-CLOSED (503)           99.95%             │
    │  standard   fail-OPEN с алертом         99.9%              │
    │  free       fail-OPEN с логированием    best-effort        │
    │                                                            │
    └────────────────────────────────────────────────────────────┘
```

**Обоснование:**
- Enterprise-тенанты платят за SLA, для них лучше явный отказ
  (`503 Service Unavailable` с `Retry-After`), чем неограниченное
  потребление (которое в итоге приведёт к отказу upstream LLM).
- Standard/free — приемлемо кратковременное нарушение лимитов ради
  доступности.

**Настройка в конфиге:**

```yaml
tenants:
  - id: "acme"
    tier: "enterprise"
    rate_limit:
      redis_failure_mode: "fail-closed"
  - id: "globex"
    tier: "standard"
    rate_limit:
      redis_failure_mode: "fail-open"
```

**Алерт:** `mcp_gateway_rate_limit_redis_errors_total > 0` rate >0
>1m → critical.

### Redis latency spike

```
    ┌────────────────────────────────────────────────────────────┐
    │  Симптом: p99 latency на Lua-скрипт >10ms                  │
    ├────────────────────────────────────────────────────────────┤
    │                                                            │
    │  Возможные причины:                                        │
    │  • ZSET стал слишком большим (>10k членов)                 │
    │  • Redis под нагрузкой (много тенантов, много методов)     │
    │  • Network issues                                          │
    │  • Redis persistence (RDB fork) блокирует                  │
    │                                                            │
    │  Действия:                                                 │
    │  1. Проверить redis_slowlog                                │
    │  2. Проверить количество ключей и их размер                │
    │  3. Проверить memory pressure                              │
    │  4. Рассмотреть переход на sliding window counter          │
    │                                                            │
    └────────────────────────────────────────────────────────────┘
```

**Митигация:** `context.WithTimeout(50ms)` на Redis-операции.
Если превышено — применить per-tier политику (fail-open/fail-closed).

### Clock skew между pod'ами

**Решение:** используем `TIME` внутри Lua-скрипта — Redis даёт
единое server-side время для всех клиентов. Это устраняет
clock-skew проблему **by design**.

```
    local t = redis.call('TIME')
    local now = (t[1] * 1000) + math.floor(t[2] / 1000)  -- Unix ms
```

**Компромисс:** `TIME` возвращает время Redis-сервера, что может
отличаться от времени gateway'я. Но **все** pod'ы видят **одно и то
же** время → консистентность важнее абсолютной точности.

### Потеря данных Redis (не персистентно)

Если Redis перезапустится без persistence (или с потерей AOF),
состояние rate limiter'а сбросится.

**Последствия:** кратковременное «окно без лимитов» — все тенанты
снова получают полный лимит.

**Митигация:**

- **Redis в HA** (Sentinel или Cluster) с AOF persistence
- **RDB snapshots** каждые N минут
- **Приемлемо** кратковременное нарушение — это не критично для
  бизнеса (FinOps-риск мал за несколько секунд)

**Решение:** AOF + Sentinel. Не критично для SLA, но полезно.

---

## Alternatives considered

### Alternative 1: In-memory rate limiter (golang.org/x/time/rate)

**Плюсы:**
- Просто.
- Не требует Redis.
- Микросекундная latency.

**Минусы:**
- Не работает при горизонтальном масштабировании (см. выше).
- Sticky sessions как workaround — плохо для балансировки.

**Решение:** отклонено. Не масштабируется.

### Alternative 2: Postgres-based rate limiting

**Плюсы:**
- Единая инфраструктура с audit log.
- ACID-транзакции.

**Минусы:**
- В 10-100 раз медленнее Redis.
- Row-level locks → contention под нагрузкой.
- Не подходит для 10k RPS.

**Решение:** отклонено. Postgres не тот инструмент для
high-frequency state.

### Alternative 3: API Gateway (Kong, Envoy)

**Плюсы:**
- Готовое решение.
- Много plugins.
- Интеграция с observability.

**Минусы:**
- Ещё один слой инфраструктуры.
- Multi-tenancy сложна.
- Динамические лимиты часто требуют reload.

**Решение:** отклонено. Строим свой gateway.

### Alternative 4: Token bucket (вместо sliding window)

**Плюсы:**
- Smooth rate.
- O(1) память.
- Естественно обрабатывает bursts.

**Минусы:**
- Compliance-вопросы.
- Сложнее атомарно в Redis.

**Решение:** отклонено в пользу sliding window log. Пересмотрим,
если лимиты станут >10k/мин на тенант.

### Alternative 5: Sliding window counter (approximation)

**Плюсы:**
- O(1) память.
- Достаточно точен (погрешность <1%).
- Используется Cloudflare, Stripe.

**Минусы:**
- Не точный, а приближённый.
- Может пропустить или отклонить запрос на границе окна.

**Решение:** отклонено для PoC. Может быть использовано в будущем
при росте нагрузки.

---

## Action items

Задачи, вытекающие из этого ADR:

- [ ] **Lua-скрипт** — реализовать и протестировать
  `rate_limit.lua` с test vectors:
  - ровно `limit` запросов → все разрешены
  - `limit + 1` запросов → последний отклонён
  - разные окна (`60s`, `1s`)
  - параллельные вызовы (100 concurrent → ровно limit allowed)
  - Продление TTL под runaway-loop (denied, но ключ жив)
  - Возврат `oldest_score` при denied
  - Cluster mode (hash tag `{tenant}` — все ключи на одном шарде)
- [ ] **Конфиг лимитов** — расширить `configs/tenants.yaml` секцией
  `rate_limit` per method + `redis_failure_mode`.
- [ ] **HTTP middleware** — реализовать middleware, который:
  - Определяет (tenant, method) из контекста (см. ADR-0004)
  - Вызывает Lua-скрипт через `EVALSHA` (кеширование скрипта)
  - Формирует заголовки `X-RateLimit-*`
  - Возвращает `429` при отказе с корректным `Retry-After`
- [ ] **Метрики** — добавить Prometheus метрики:
  - `mcp_gateway_rate_limit_allowed_total{tenant,method}`
  - `mcp_gateway_rate_limit_denied_total{tenant,method}`
  - `mcp_gateway_rate_limit_redis_errors_total{tenant}`
  - `mcp_gateway_rate_limit_redis_latency_seconds` (histogram)
- [ ] **Алерты** — добавить в `docs/reliability/runbook.md`:
  - Redis unavailable
  - p99 latency >10ms
  - Denied rate >10% для тенанта (возможно, лимит слишком строгий)
- [ ] **Load test** — проверить производительность при 10k RPS:
  - Latency Lua-скрипта
  - Память Redis при 100 тенантах × 10 методах
  - Поведение под clock skew (TIME vs ARGV)
  - Cluster mode (sharding по hash tag)
- [ ] **Redis HA** — развернуть Sentinel (или Cluster) в production,
  настроить AOF persistence.
- [ ] **Dashboard** — Grafana dashboard с:
  - Rate limit hits/denials per tenant
  - Redis latency/memory
  - Top-N тенантов по denied rate

---

## References

- [Redis: Rate limiting pattern](https://redis.io/docs/manual/patterns/distributed-locks/)
- [Redis: Lua scripting](https://redis.io/docs/manual/programmability/eval-intro/)
- [Redis Cluster: Hash tags](https://redis.io/docs/reference/cluster-spec/#hash-tags)
- [Cloudflare: How we built rate limiting](https://blog.cloudflare.com/counting-things-a-lot-of-different-things/)
- [Stripe: Scaling your API with rate limiters](https://stripe.com/blog/rate-limiters)
- [IETF draft: RateLimit header fields for HTTP](https://datatracker.ietf.org/doc/draft-ietf-httpapi-ratelimit-headers/)
- [RFC 6585: Additional HTTP Status Codes (429)](https://datatracker.ietf.org/doc/html/rfc6585)
- [Google SRE Book: Handling Overload](https://sre.google/sre-book/handling-overload/)

---

## Related ADRs

- [ADR-0001: SPIFFE/SPIRE для mTLS](0001-use-spiffe-for-mtls.md) — определяет workload identity, не влияет на rate limit
- [ADR-0002: HMAC hash-chain для audit log](0002-hmac-hash-chain-for-audit.md) — rate limit denials также логируются в audit
- [ADR-0004: tenant_id в context](0004-tenant-id-in-context.md) — tenant_id — ключ для rate limit
- [ADR-0005: gobreaker для circuit breaker](0005-circuit-breaker-library-choice.md) — дополняет rate limiting при отказе upstream