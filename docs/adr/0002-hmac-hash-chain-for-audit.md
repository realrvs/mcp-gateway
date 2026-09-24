# ADR-0002: HMAC hash-chain для tamper-evident audit log

- **Status:** Accepted
- **Date:** 2026-09-23
- **Deciders:** Roman Sokolov (Architect)
- **Tags:** `security`, `audit`, `compliance`, `cryptography`, `observability`

---

## Context

Каждое действие через MCP Gateway (вызов инструмента, чтение ресурса, изменение
конфигурации тенанта) должно быть зафиксировано в **audit log**. Это требование
исходит из:

1. **Регуляторных требований:**
   - **152-ФЗ** (РФ) — фиксация операций с персональными данными
   - **GDPR** (EU) — Art. 30: Records of Processing Activities
   - **PCI DSS** (Req. 10) — logging всех доступов к системам с cardholder data
   - **HIPAA** (§164.312(b)) — audit controls для ePHI

2. **Внутренних требований InfoSec:**
   - Возможность расследования инцидентов («кто, когда, что сделал»)
   - Non-repudiation: автор действия не может отрицать факт его совершения
   - Обнаружение компрометации (аномальные вызовы, изменения в конфигурации)

3. **Защиты от внутреннего нарушителя:**
   - Администратор БД **не должен иметь возможности** незаметно изменить
     или удалить записи audit log
   - DBA, имеющий root-доступ к Postgres, **не должен** мочь «подчистить»
     свои следы
   - Даже при полной компрометации backend-инфраструктуры **должно быть
     возможно доказать факт модификации** audit-записей

**Обычные логи (plain text, structured JSON) не удовлетворяют этим требованиям:**
DBA может незаметно изменить записи, удалить инцидент, или backdate события.
Требуется **криптографический механизм**, который делает модификацию
**обнаруживаемой**.

---

## Decision

**Используем HMAC-protected hash-chain** для всех записей audit log.

### Структура записи

```go
type AuditEntry struct {
    Seq        uint64    // монотонно возрастающий порядковый номер
    Timestamp  time.Time // UTC
    TenantID   string    // из JWT/headers (см. ADR-0004)
    Actor      string    // SPIFFE ID (см. ADR-0001)
    Action     string    // "tools/call", "resources/read", "tenant.update"
    Resource   string    // идентификатор ресурса
    Outcome    string    // "allow" | "deny" | "error"
    Metadata   []byte    // canonical JSON (RFC 8785)
    KeyVersion uint32    // версия HMAC-ключа (для ротации)
    PrevHash   []byte    // SHA-256 hash предыдущей записи
    Hash       []byte    // SHA-256(canonical serialization)
    HMAC       []byte    // HMAC-SHA256(Key, Hash)
}
```

### Canonical serialization (детерминированное представление)

Критически важный аспект: **два вычисления хеша одной и той же логической
записи должны давать одинаковый результат байт-в-байт**. Иначе верификатор
не сможет воспроизвести хеш, и валидная запись будет помечена как
повреждённая.

#### Проблема

Простейший подход «сериализуем структуру в JSON и берём SHA-256» **ломается**
на нескольких уровнях:

| Источник недетерминизма | Пример | Последствие |
|-------------------------|--------|-------------|
| **Порядок ключей в JSON** | Go `encoding/json` сортирует ключи по алфавиту; другие языки — по вставке | Разный байтовый поток → разный хеш |
| **Whitespace и форматирование** | `{"a":1}` vs `{ "a": 1 }` | Разный хеш |
| **Unicode normalization** | `"café"` в NFC vs NFD | Разный хеш |
| **Timestamp precision** | `time.Time` содержит монотонные часы и timezone | Разный хеш при одинаковой логической дате |
| **Числовая точность** | Float `1.0` vs `1` vs `1.00` | Разный хеш |
| **Endianness** | `uint64(42)` → 8 байт в BE или LE | Разный хеш |
| **Pointer addresses** | Случайные адреса в памяти | Non-deterministic hash |

#### Решение: строгая бинарная сериализация

Для вычисления `Hash` используем **фиксированный бинарный формат**,
описанный явно:

```
    ┌──────────────────────────────────────────────────────────┐
    │  Hash-input buffer (byte layout, big-endian):            │
    ├──────────────────────────────────────────────────────────┤
    │                                                          │
    │   Offset  Size  Field                                    │
    │   ─────── ───── ─────────────────────────────────────    │
    │   0       8     Seq (uint64, BE)                         │
    │   8       8     Timestamp (UnixNano UTC, int64, BE)      │
    │   16      2     TenantID length (uint16, BE)             │
    │   18      N     TenantID (UTF-8 NFC, no BOM)             │
    │   ...     2     Actor length (uint16, BE)                │
    │   ...     M     Actor (UTF-8 NFC)                        │
    │   ...     2     Action length (uint16, BE)               │
    │   ...     K     Action (UTF-8 NFC)                       │
    │   ...     2     Resource length (uint16, BE)             │
    │   ...     L     Resource (UTF-8 NFC)                     │
    │   ...     2     Outcome length (uint16, BE)              │
    │   ...     P     Outcome (UTF-8 NFC)                      │
    │   ...     4     Metadata length (uint32, BE)             │
    │   ...     Q     Metadata (canonical JSON, UTF-8)         │
    │   ...     4     KeyVersion (uint32, BE)                  │
    │   ...     32    PrevHash (raw bytes)                     │
    │                                                          │
    │  Hash = SHA-256(buffer)                                  │
    │                                                          │
    └──────────────────────────────────────────────────────────┘
```

**Правила:**

- **Все length-prefix** — фиксированного размера (uint16 для строк
  до 64 KB, uint32 для Metadata до 4 GB).
- **Все integer** — big-endian (network byte order). Явно, не
  полагаемся на платформу.
- **Timestamp** — `UnixNano` в UTC. Монотонные часы **исключены**.
  Nanoseconds — максимальная разрешающая способность.
- **Строки** — UTF-8, **без BOM**, **в NFC-нормализации**.
- **Metadata** — Canonical JSON (RFC 8785):
  - Ключи отсортированы лексикографически (по codepoint UTF-16,
    как требует RFC 8785)
  - Без пробелов между токенами
  - Числа: без экспоненты для целых, минимальная точность для float
  - Строки: экранируются только обязательные символы
  - UTF-8 без escape для не-ASCII (кроме control characters)

#### Пример на Go

```go
func canonicalHash(e *AuditEntry) []byte {
    buf := new(bytes.Buffer)

    // Numbers — big-endian
    binary.Write(buf, binary.BigEndian, e.Seq)
    binary.Write(buf, binary.BigEndian, e.Timestamp.UTC().UnixNano())

    // Strings — length-prefixed UTF-8 NFC
    writeString16(buf, normalizeNFC(e.TenantID))
    writeString16(buf, normalizeNFC(e.Actor))
    writeString16(buf, normalizeNFC(e.Action))
    writeString16(buf, normalizeNFC(e.Resource))
    writeString16(buf, normalizeNFC(e.Outcome))

    // Metadata — canonical JSON (RFC 8785)
    canonicalMeta, _ := jsoncanonical.Marshal(e.Metadata)
    binary.Write(buf, binary.BigEndian, uint32(len(canonicalMeta)))
    buf.Write(canonicalMeta)

    // KeyVersion
    binary.Write(buf, binary.BigEndian, e.KeyVersion)

    // PrevHash
    buf.Write(e.PrevHash)

    // SHA-256
    h := sha256.Sum256(buf.Bytes())
    return h[:]
}
```

#### Cross-language verification

Спецификация сериализации **должна быть частью публичного API** — в
`docs/architecture/audit-format-v1.md` (TODO: создать). Это позволяет:

- Реализовать верификатор на **любом языке** (Python, Rust, Java)
  независимо от Go-реализации gateway.
- Провести **третьей стороной** (внешний аудит) без доступа к нашему
  коду — достаточно спецификации.
- Гарантировать, что **изменение формата** — это **новая версия**
  (`HashVersion` в записи), а не тихое breaking change.

#### Тестовые векторы

Обязательно включить в спецификацию **test vectors**:

```
    Test Vector 1: минимальная запись
    ─────────────────────────────────
    Input:
      Seq         = 1
      Timestamp   = 2026-09-23T12:00:00.000000000Z
      TenantID    = "dev"
      Actor       = "spiffe://mcp-gateway.local/ns/dev/sa/client"
      Action      = "tools/call"
      Resource    = "mcp.tool.echo"
      Outcome     = "allow"
      Metadata    = {"tool":"echo","args":{"msg":"hi"}}
      KeyVersion  = 1
      PrevHash    = 00...00 (32 bytes)

    Expected Hash  = <hex>
    Expected HMAC  = <hex>

    Test Vector 2: с unicode в Metadata
    ───────────────────────────────────
    ...

    Test Vector 3: с вложенным JSON в Metadata
    ──────────────────────────────────────────
    ...
```

Верификатор на любом языке, прошедший все test vectors — считается
совместимым.

### Схема hash-chain

Каждая запись **зависит от всех предыдущих**. Изменение любой записи
ломает хеш-цепочку, что обнаруживается верификатором.

```
    ┌──────────────┐
    │   GENESIS    │  Hash = SHA256("mcp-gateway-genesis")
    │              │  PrevHash = 0x00...00 (32 байта нулей)
    └───────┬──────┘
            │
            ▼
    ┌──────────────┐
    │   Entry 1    │  PrevHash = Hash(Genesis)
    │              │  Hash     = SHA256(canonical || PrevHash)
    │              │  HMAC     = HMAC-SHA256(Key, Hash)
    └───────┬──────┘
            │
            ▼
    ┌──────────────┐
    │   Entry 2    │  PrevHash = Hash(Entry 1)
    │              │  Hash     = SHA256(canonical || PrevHash)
    │              │  HMAC     = HMAC-SHA256(Key, Hash)
    └───────┬──────┘
            │
            ▼
    ┌──────────────┐
    │   Entry 3    │  PrevHash = Hash(Entry 2)
    │              │  Hash     = SHA256(canonical || PrevHash)
    │              │  HMAC     = HMAC-SHA256(Key, Hash)
    └───────┬──────┘
            │
            ▼
          ...
```

### HMAC поверх хеша

**Hash сам по себе недостаточен.** Атакующий с доступом на запись
может:

1. Изменить Entry N
2. Пересчитать Hash(Entry N)
3. Пересчитать Hash(Entry N+1) с новым PrevHash
4. ... и так далее до конца цепочки

**HMAC закрывает эту атаку.** Ключ HMAC хранится **вне** БД
(в Vault / K8s Secret), и атакующий с доступом к БД **не имеет**
ключа для пересчёта HMAC.

```
    ┌─────────────────────────────────────────────────────┐
    │  Что может сделать атакующий с доступом к БД:       │
    ├─────────────────────────────────────────────────────┤
    │                                                     │
    │  ✓ Изменить Entry N                                 │
    │  ✓ Пересчитать Hash(Entry N)                        │
    │  ✓ Пересчитать Hash(Entry N+1) с новым PrevHash     │
    │  ✓ ... до конца цепочки                             │
    │                                                     │
    │  ✗ Пересчитать HMAC — нужен секретный ключ          │
    │    (хранится в Vault, вне БД)                       │
    │                                                     │
    └─────────────────────────────────────────────────────┘

    HMAC = HMAC-SHA256(secret_key, Hash)

    Верификация:
    ┌──────────────────────────────────────────────────────┐
    │  for each entry:                                     │
    │    1. Проверить PrevHash == Hash(предыдущей)         │
    │    2. Проверить Hash    == SHA256(canonical || Prev) │
    │    3. Проверить HMAC    == HMAC-SHA256(Key, Hash)    │
    │  Если все 3 условия выполнены → запись валидна       │
    └──────────────────────────────────────────────────────┘
```

### Append-only storage

```
    ┌──────────────────────────────────────────────────────┐
    │              PostgreSQL — append-only                │
    ├──────────────────────────────────────────────────────┤
    │                                                      │
    │   Роли и права:                                      │
    │   ┌─────────────────────────┬──────────────────────┐ │
    │   │ mcp_gateway_app         │ INSERT only          │ │
    │   │                         │ NO UPDATE, NO DELETE │ │
    │   ├─────────────────────────┼──────────────────────┤ │
    │   │ audit_verifier          │ SELECT only          │ │
    │   ├─────────────────────────┼──────────────────────┤ │
    │   │ dba_admin               │ NO access to table   │ │
    │   │                         │ (RLS enforced)       │ │
    │   └─────────────────────────┴──────────────────────┘ │
    │                                                      │
    │   Партиционирование по месяцам:                      │
    │   ┌──────────────────┐                               │
    │   │ audit_log_2026_09│  ← активная партиция          │
    │   ├──────────────────┤                               │
    │   │ audit_log_2026_08│  ← архивирована в S3 (WORM)   │
    │   ├──────────────────┤                               │
    │   │ audit_log_2026_07│  ← архивирована в S3 (WORM)   │
    │   └──────────────────┘                               │
    │                                                      │
    └──────────────────────────────────────────────────────┘
```

- **Ежемесячные партиции** — `audit_log_YYYY_MM`.
- Старые партиции после retention period архивируются в **S3 object-lock**
  (WORM) или в отдельное append-only хранилище.
- **Корневой хеш** (Hash последней записи в партиции) периодически
  публикуется в **отдельное хранилище** (S3 object-lock, transparency log)
  — это защищает от пересчёта **всей** цепочки.

### Схема публикации корневого хеша

```
    ┌─────────────────────┐
    │   PostgreSQL        │
    │   audit_log         │
    └──────────┬──────────┘
               │  каждые 5 минут
               │  (last Hash в партиции)
               ▼
    ┌─────────────────────┐
    │   Off-site storage  │
    │   S3 object-lock    │  ← WORM, immutable
    │   (или transparency │
    │    log)             │
    └─────────────────────┘

    Зачем:
    • Если атакующий удалит ВСЮ таблицу — hash-chain не поможет.
    • Off-site публикация корневого хеша = доказательство того,
      что записи существовали в определённый момент времени.
    • Сверка: verifier периодически сравнивает текущий last Hash
      с последней публикацией. Расхождение = инцидент.
```

### Concurrency model

**Проблема:** при 10k RPS несколько goroutine'ов gateway одновременно
обрабатывают запросы. Каждая запись должна иметь:

- **Монотонный `Seq`** — без пропусков, без дублей.
- **Правильный `PrevHash`** — указывающий на **предыдущую** запись,
  а не на какую-то из параллельных.

**Наивный подход (сломан):**

```
    Goroutine A: read last_hash = H(N-1)
    Goroutine B: read last_hash = H(N-1)   ← прочитали одно и то же
    Goroutine A: compute Hash(A) with PrevHash = H(N-1)
    Goroutine B: compute Hash(B) with PrevHash = H(N-1)
    Goroutine A: insert Seq=N
    Goroutine B: insert Seq=N              ← ДУБЛЬ или RACE
```

**Результат:** либо коллизия Seq (нарушение unique constraint), либо
два разных Hash с одним PrevHash (нарушение цепочки), либо потерянные
записи.

#### Решение: single-writer batching worker

Архитектура audit writer — **один goroutine-владелец цепочки**,
который:

1. Принимает записи от множества handler-goroutine'ов через
   **buffered channel**.
2. **Единолично** определяет `Seq` и `PrevHash`.
3. **Батчит** записи (например, по 100 штук или по 100ms таймауту).
4. **Транзакционно** пишет батч в Postgres.
5. **Возвращает** ack через отдельный channel (или callback).

```
    ┌──────────────────────────────────────────────────────────────┐
    │                                                              │
    │   Handler goroutines (10k RPS)                               │
    │   ┌───────┐  ┌───────┐  ┌───────┐         ┌───────┐          │
    │   │  H1   │  │  H2   │  │  H3   │   ...   │  Hn   │          │
    │   └───┬───┘  └───┬───┘  └───┬───┘         └───┬───┘          │
    │       │          │          │                 │              │
    │       └──────────┴──────────┴─────────────────┘              │
    │                            │                                 │
    │                            ▼                                 │
    │              ┌──────────────────────────┐                    │
    │              │   auditEvents chan        │                    │
    │              │   (buffered, cap=10000)   │                    │
    │              └──────────┬───────────────┘                    │
    │                         │                                    │
    │                         ▼                                    │
    │         ┌─────────────────────────────────┐                  │
    │         │   Single Writer Goroutine       │                  │
    │         │                                 │                  │
    │         │   • batch: up to 100 events     │                  │
    │         │   • timeout: 100ms              │                  │
    │         │   • compute Seq, PrevHash       │                  │
    │         │   • compute Hash, HMAC          │                  │
    │         │   • INSERT in transaction       │                  │
    │         │   • ack via result channel      │                  │
    │         └──────────┬──────────────────────┘                  │
    │                    │                                          │
    │                    ▼                                          │
    │         ┌─────────────────────────────────┐                  │
    │         │   PostgreSQL                    │                  │
    │         │   INSERT ... (batch)            │                  │
    │         │   ← UNIQUE(seq) защищает от race│                  │
    │         └─────────────────────────────────┘                  │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

#### Гарантии

- **Монотонный Seq** — единственный writer выдаёт seq из атомарного
  счётчика в памяти (инициализируется из `MAX(seq)` при старте).
- **Консистентная цепочка** — каждый батч стартует с `PrevHash`
  последней успешно записанной записи.
- **Атомарность** — батч пишется одной транзакцией. При откате —
  откатываются **все** записи батча, счётчик в памяти **не**
  продвигается.
- **Backpressure** — если `auditEvents` переполнен (writer не
  успевает), handler'ы **блокируются** или получают
  `ErrAuditQueueFull`. Это осознанный fail-closed: лучше отклонить
  запрос, чем обработать без audit-записи.

#### Persistence of Seq

Важно: `Seq` **не** генерируется через Postgres sequence. Причины:

- Postgres sequence не атомарна с транзакцией (rollback не откатывает
  sequence → дырки в Seq).
- Мы хотим **непрерывную** цепочку без пропусков.

Вместо этого:

- Writer **инициализируется** при старте: `SELECT MAX(seq) FROM audit_log`
  → счётчик в памяти.
- **Единственный writer** инкрементирует счётчик.
- **При рестарте** счётчик восстанавливается из `MAX(seq)`.

**Угроза:** при одновременном запуске двух pod'ов с одним Postgres
оба могут инициализироваться из одного `MAX(seq)` и попытаться писать
с одинаковыми Seq. Митигация:

- **UNIQUE constraint** на `seq` — защита от дублей.
- **Advisory lock** в Postgres при инициализации writer'а — только
  один pod захватывает writer-роль за раз. Остальные переходят в
  standby и принимают `PrevHash` от лидера через отдельный механизм
  (или не пишут в audit вообще, а проксируют запись лидеру).

Это ограничивает **горизонтальное масштабирование audit writer'а**.
Для наших целей (10k RPS) один writer справляется: batched INSERT
100 записей за транзакцию → ~100 транзакций/сек → 10k записей/сек.

**Когда пересмотреть:** если RPS > 50k, добавим шардирование
audit log по тенантам (per-tenant writer'ы с отдельными цепочками).
Это меняет модель `PrevHash` — каждая цепочка независима.

#### Метрики

Обязательные Prometheus-метрики для concurrency:

```
    mcp_gateway_audit_queue_size              # текущий размер chan
    mcp_gateway_audit_queue_capacity          # capacity
    mcp_gateway_audit_batch_size              # histogram размера батча
    mcp_gateway_audit_write_duration_seconds  # histogram длительности INSERT
    mcp_gateway_audit_seq_current             # текущий Seq (gauge)
    mcp_gateway_audit_write_errors_total      # ошибки записи
    mcp_gateway_audit_queue_full_total        # backpressure events
```

Алерты:

- `audit_queue_size / audit_queue_capacity > 0.8` >1m → warning
- `audit_write_errors_total` rate >0 → critical
- `audit_seq_current` stagnated >30s → critical

### Ключ HMAC

- Хранится в **Vault** (или K8s Secret с RBAC «только gateway SA»).
- **Ротация каждые 90 дней** с сохранением старых ключей (для верификации
  исторических записей).
- Версия ключа включается в запись: `KeyVersion` (поле в структуре).
- Верификатор имеет доступ ко всем версиям ключей.

```
    ┌──────────────────────────────────────────────────────┐
    │                    Vault                             │
    ├──────────────────────────────────────────────────────┤
    │                                                      │
    │   mcp-gateway/audit-hmac-key                         │
    │   ├── v1   ← выпущен 2026-07-01, ротирован 2026-10-01│
    │   ├── v2   ← выпущен 2026-10-01, ротирован 2027-01-01│
    │   ├── v3   ← выпущен 2027-01-01, активный            │
    │   └── ...                                            │
    │                                                      │
    │   RBAC:                                              │
    │   • mcp-gateway SA  → read (текущий ключ + verify)   │
    │   • audit-verifier  → read (все версии)              │
    │   • остальные       → deny                           │
    │                                                      │
    └──────────────────────────────────────────────────────┘
```

### Верификация

```
    ┌──────────────────────────────────────────────────────┐
    │              Verification pipeline                   │
    ├──────────────────────────────────────────────────────┤
    │                                                      │
    │   1. Continuous verification (каждые 5 минут)        │
    │      └── проверка последних N записей                │
    │                                                      │
    │   2. Scheduled full verification (раз в сутки)       │
    │      └── проверка всей цепочки (с партициями)        │
    │                                                      │
    │   3. On-demand CLI (для расследований)               │
    │      └── gateway audit verify --from 1000 --to 2000  │
    │                                                      │
    │   4. Off-site root hash comparison (каждый час)      │
    │      └── сверка с публикациями в S3 object-lock      │
    │                                                      │
    └──────────────────────────────────────────────────────┘

    При обнаружении нарушения целостности:
    ┌──────────────────────────────────────────────────────┐
    │  1. Немедленный critical alert (page on-call)        │
    │  2. Автоматический freeze всех операций gateway      │
    │     (fail-closed)                                    │
    │  3. Запись инцидента в immutable incident log        │
    │     (отдельное хранилище, вне Postgres)              │
    │  4. Ручное расследование                             │
    │  5. Уведомление регулятора (если требуется)          │
    └──────────────────────────────────────────────────────┘
```

---

## Rationale

### Почему HMAC, а не цифровая подпись (GPG, RSA, Ed25519)

**Цифровая подпись** (public-key crypto) имеет свои плюсы:
- Non-repudiation — автор не может отрицать факт подписи
- Публичный ключ можно распространять для верификации
- Не требует защиты секрета на стороне верификатора

**Но** для нашего сценария HMAC предпочтительнее:

1. **Производительность:** HMAC-SHA256 в **10-100 раз быстрее**,
   чем ECDSA/RSA подписи. При 10k RPS это критично.
2. **Простота:** один секретный ключ vs управление ключевыми парами
   (private key, public key, rotation, revocation).
3. **Один trust domain:** все записи создаются **нами** (gateway).
   Нет внешних сторон, которым нужно верифицировать подпись без
   доступа к нашему секрету. Non-repudiation не требуется — мы не
   собираемся оспаривать свои же записи.
4. **Размер:** HMAC = 32 байта, ECDSA = 64-72 байта, RSA-2048 = 256 байт.
   При миллиардах записей это существенная экономия.

```
    ┌──────────────────┬──────────┬──────────┬─────────────┐
    │ Алгоритм         │ Размер   │ Скорость │ Non-repud.  │
    ├──────────────────┼──────────┼──────────┼─────────────┤
    │ HMAC-SHA256      │ 32 B     │ ~1 μs    │ Нет         │
    │ Ed25519          │ 64 B     │ ~50 μs   │ Да          │
    │ ECDSA P-256      │ 72 B     │ ~100 μs  │ Да          │
    │ RSA-2048         │ 256 B    │ ~1 ms    │ Да          │
    └──────────────────┴──────────┴──────────┴─────────────┘
```

**Гибридный подход (для будущего):** если потребуется non-repudiation
для внешних аудиторов, добавим **периодическую цифровую подпись**
корневого хеша (например, раз в час root hash подписывается Ed25519
и публикуется). Это дорого только для 24 подписей в сутки, а не для
каждой записи.

### Почему SHA-256, а не SHA-1, MD5 или BLAKE3

- **SHA-1 и MD5** — криптографически сломаны (collision attacks
  практически реализованы). Неприемлемы для security-critical систем.
- **SHA-256** — стандарт NIST, широко проверен, поддерживается
  аппаратно на современных CPU (SHA-NI), не имеет известных
  практических атак.
- **BLAKE3** — быстрее и криптографически сильнее, но менее
  стандартизирован для compliance-сценариев. Аудиторы (и регуляторы)
  предпочитают NIST-стандарты.
- **SHA-3** — тоже NIST, но менее распространён в production,
  и SHA-256 достаточно для наших требований.

**Выбор:** SHA-256 как компромисс между производительностью,
безопасностью и соответствием стандартам.

### Почему Postgres, а не immutable ledger (Hyperledger, QLDB)

**Blockchain-подобные решения** (Hyperledger Fabric, Amazon QLDB) дают
**immutable ledger** из коробки:

- Технически невозможно изменить запись
- Криптографически гарантирован порядок
- Готовые механизмы верификации

**Но:**

1. **Сложность развёртывания** — Hyperledger требует consensus-механизма,
   отдельные ноды, сертификаты. Для одного gateway это overkill.
2. **Операционная нагрузка** — нужно управлять нодами, обновлениями,
   мониторингом. QLDB — managed, но привязывает к AWS.
3. **Производительность** — distributed ledger медленнее для
   single-writer сценария (у нас именно single-writer: audit log
   пишет только gateway).
4. **Гибкость** — Postgres с RLS + наш hash-chain даёт все нужные
   свойства при меньшей сложности.

**Когда blockchain оправдан:** если audit log пишется несколькими
независимыми сторонами (например, несколько gateway в разных
организациях). У нас — не тот случай.

**Когда пересмотреть:** если появится требование «immutable by
infrastructure», а не «immutable by cryptography» (например,
регулятор требует физически неизменяемое хранилище) — мигрируем
на S3 object-lock или AWS QLDB.

### Почему не «просто append-only таблица»

Postgres-таблица с `REVOKE UPDATE, DELETE` **выглядит** append-only,
но:

- **Superuser может обойти** REVOKE. DBA с root-доступом может
  сделать `ALTER TABLE ... DISABLE TRIGGER` и удалить записи.
- **Нет криптографической гарантии** — нельзя доказать, что записи
  не были изменены. Только «мы обещаем, что не меняли».
- **Backup и restore** могут откатить таблицу до состояния, в котором
  не было инцидента.

**Hash-chain + HMAC** даёт **криптографическое доказательство**:
если цепочка сходится и HMAC валидны, записи **действительно** не
менялись с момента создания. Это соответствует стандарту **non-repudiation**
и принимается аудиторами.

### Почему не «structured logging с подписью»

Стандартные logging-системы (ELK, Loki, Splunk) поддерживают
immutable storage (WORM), но:

- **Дорого** — Splunk с WORM-storage стоит на порядок дороже
  Postgres + S3 object-lock.
- **Не даёт hash-chain** — записи изолированы, нельзя доказать
  порядок и целостность всей последовательности.
- **Вендор-лок** — миграция между системами теряет гарантии.

---

## Consequences

### Positive

- **Криптографическая гарантия** целостности — tampering обнаруживается.
- **Non-repudiation** действий — автор не может отрицать факт вызова.
- **Соответствие требованиям** 152-ФЗ, GDPR Art. 30, PCI DSS Req. 10,
  HIPAA §164.312(b).
- **Обнаружение инцидентов** — anomalous calls, несанкционированные
  изменения конфигурации.
- **Простота реализации** — Postgres + Go, без distributed ledger.
- **Низкая стоимость** — на порядок дешевле Splunk WORM.

### Negative

- **Оверхед на запись** — ~50μs на HMAC-SHA256 + запись в БД.
  При 10k RPS = 500ms CPU в секунду. Решается батчингом и async write.
- **Риск потери ключа HMAC** — если ключ утерян, верификация
  исторических записей **невозможна**. Требуется backup ключа в
  отдельное хранилище (Vault HA, sealed backup).
- **Риск компрометации ключа HMAC** — если ключ скомпрометирован,
  атакующий может пересчитать HMAC для всей цепочки. Митигация:
  ключ хранится в Vault, ротация каждые 90 дней, доступ только
  у gateway SA (RBAC).
- **Сложность операций** — отдельный verification job, алерты,
  процедура ротации ключей. Требует runbook.
- **Не защищает от полного удаления** — если атакующий удалит **всю**
  таблицу, hash-chain не поможет. Митигация: **off-site публикация
  корневого хеша** (S3 object-lock) даёт доказательство того, что
  записи существовали.

### Neutral

- **Размер хранилища** — добавление PrevHash (32) + Hash (32) +
  HMAC (32) + KeyVersion (4) = ~100 байт overhead на запись.
  Для 1M записей = ~100 MB. Приемлемо.
- **Postgres-партиции** — требуют управления (создание партиций,
  архивация старых). Автоматизируется через pg_partman или собственный
  cronjob.
- **Ключ HMAC — не «один на всех»** — см. раздел «Per-tenant HMAC keys».

---

## Per-tenant HMAC keys

**Решение:** используем **один общий ключ** для всех тенантов, но
**архитектурно готовы** к per-tenant ключам.

### Почему один общий ключ

- **Простота ротации** — один ключ, одна процедура.
- **Единая верификация** — один verifier проверяет все записи.
- **Compliance-сценарий** — аудитор проверяет целостность **всего**
  журнала, а не отдельных тенантов.

### Когда пересмотреть

Если появится требование «изоляция audit log тенантов» (например,
регулятор требует, чтобы тенант A не мог верифицировать записи
тенанта B), переходим на:

```
    ┌──────────────────────────────────────────────────────┐
    │   Per-tenant HMAC keys                               │
    ├──────────────────────────────────────────────────────┤
    │                                                      │
    │   mcp-gateway/audit-hmac-key/acme/v1                 │
    │   mcp-gateway/audit-hmac-key/acme/v2                 │
    │   mcp-gateway/audit-hmac-key/globex/v1               │
    │   mcp-gateway/audit-hmac-key/globex/v2               │
    │                                                      │
    │   Каждый тенант имеет свой KeyVersion space.         │
    │   Отдельные verifiers per tenant.                    │
    │   Разные S3 object-lock бакеты per tenant.           │
    │                                                      │
    └──────────────────────────────────────────────────────┘
```

Это **не текущий сценарий**, но архитектура позволяет мигрировать
без переработки hash-chain.

---

## Failure modes

### Ключ HMAC недоступен при старте gateway

```
    ┌──────────────────────────────────────────────────────┐
    │  Startup sequence:                                   │
    ├──────────────────────────────────────────────────────┤
    │                                                      │
    │  1. Получить SVID от SPIRE Agent     ─────► OK       │
    │  2. Подключиться к Vault             ─────► OK       │
    │  3. Прочитать HMAC-ключ              ─────► FAIL ✗   │
    │                                                      │
    │  Результат:                                          │
    │  • readinessProbe = 503                              │
    │  • K8s не направляет трафик на под                   │
    │  • Startup считается незавершённым                   │
    │                                                      │
    │  Это осознанное fail-closed решение:                 │
    │  лучше не обслужить запрос, чем обслужить без        │
    │  записи в audit.                                     │
    │                                                      │
    └──────────────────────────────────────────────────────┘
```

- **Alert:** `mcp_gateway_audit_ready == 0` >2m → critical.

### Ключ HMAC утерян

- **Что делать:** восстановить из backup (Vault sealed backup).
  Если backup недоступен — верификация исторических записей
  **невозможна** навсегда.
- **Митигация:** backup ключа в **отдельное** хранилище (не то же
  Vault, где production-ключ). Например: Vault + sealed backup в
  S3 с отдельным encryption key.
- **Процедура:** документируется в `docs/security/key-management.md`
  (TODO: создать).

### Ключ HMAC скомпрометирован

```
    ┌──────────────────────────────────────────────────────┐
    │  Incident response:                                  │
    ├──────────────────────────────────────────────────────┤
    │                                                      │
    │  1. Немедленная ротация                              │
    │     └── новый ключ с новой KeyVersion                │
    │                                                      │
    │  2. НЕ удалять старый ключ                           │
    │     └── он нужен для верификации исторических        │
    │         записей                                      │
    │                                                      │
    │  3. Сверить цепочку с off-site публикациями          │
    │     └── обнаружение подделанных записей              │
    │                                                      │
    │  4. Инцидент → в immutable incident log              │
    │                                                      │
    └──────────────────────────────────────────────────────┘
```

- **Обнаружение:** невозможно обнаружить скомпрометированный ключ
  только через верификацию (атакующий пересчитает HMAC корректно).
  Обнаружение — через **внешние индикаторы** (аномальные записи,
  жалобы клиентов, forensic analysis).

### Обнаружено нарушение целостности

```
    ┌──────────────────────────────────────────────────────┐
    │  Response pipeline:                                  │
    ├──────────────────────────────────────────────────────┤
    │                                                      │
    │  [Verifier detects break]                            │
    │           │                                          │
    │           ▼                                          │
    │  [Critical alert: page on-call + security team]      │
    │           │                                          │
    │           ▼                                          │
    │  [Auto-freeze: gateway переходит в fail-closed]      │
    │           │   все новые запросы → 503                │
    │           ▼                                          │
    │  [Immutable incident log]                            │
    │           │   запись ВНЕ Postgres                    │
    │           ▼                                          │
    │  [Ручное расследование]                              │
    │           │   определить: какие записи, когда, кем   │
    │           ▼                                          │
    │  [Уведомление регулятора]                            │
    │           │   если требуется по 152-ФЗ/GDPR          │
    │           ▼                                          │
    │  [Post-mortem + обновление процедур]                 │
    │                                                      │
    └──────────────────────────────────────────────────────┘
```

- **Процедура:** `docs/security/incident-response.md` (TODO: заполнить).

---

## Alternatives considered

### Alternative 1: Plain structured logging (JSON в файл)

**Плюсы:**
- Просто.
- Работает из коробки.
- Стандартный подход.

**Минусы:**
- Нет гарантии целостности.
- DBA/sysadmin может незаметно изменить.
- Не соответствует compliance-требованиям.

**Решение:** отклонено. Не даёт tamper-evidence.

### Alternative 2: Append-only Postgres без hash-chain

**Плюсы:**
- Проще, чем hash-chain.
- RLS + REVOKE UPDATE/DELETE.

**Минусы:**
- Superuser может обойти REVOKE.
- Нет криптографического доказательства.
- Backup/restore может откатить.

**Решение:** отклонено. Не защищает от внутреннего нарушителя.

### Alternative 3: Blockchain (Hyperledger, QLDB)

**Плюсы:**
- Immutable by infrastructure.
- Distributed.
- Non-repudiation.

**Минусы:**
- Overkill для single-writer.
- Операционная сложность.
- Дорого.
- Vendor lock (QLDB — AWS only).

**Решение:** отклонено. Postgres + HMAC даёт нужные свойства
при меньшей сложности.

### Alternative 4: Цифровая подпись Ed25519 каждой записи

**Плюсы:**
- Non-repudiation.
- Публичная верификация.

**Минусы:**
- Медленнее (10-100x).
- Управление ключевыми парами.
- Больше размер записи.

**Решение:** отклонено как основной механизм. Возможно **гибридное**
использование для подписи корневого хеша (раз в час), если появится
требование non-repudiation.

### Alternative 5: Splunk с WORM storage

**Плюсы:**
- Готовое решение.
- Immutable storage.
- Мощный поиск и dashboards.

**Минусы:**
- **Очень дорого** — Splunk Enterprise стоит $150+/GB/месяц.
- Вендор-лок.
- Нет hash-chain (только immutable storage).

**Решение:** отклонено как основное. Можно использовать **дополнительно**
для SIEM-интеграции, но не как источник истины.

---

## Action items

Задачи, вытекающие из этого ADR:

- [ ] **Спецификация сериализации** — создать
  `docs/architecture/audit-format-v1.md` с точным byte layout,
  правилами canonical JSON, NFC-нормализации, и **test vectors**.
- [ ] **Key management** — создать `docs/security/key-management.md`:
  процедура ротации HMAC-ключей (90 дней), backup/sealed restore,
  RBAC в Vault, процедура компрометации.
- [ ] **Root hash publication** — реализовать cron-job (или sidecar)
  для публикации `last_hash` активной партиции в S3 object-lock
  каждые 5 минут. Режим Object Lock: **COMPLIANCE** (не GOVERNANCE).
- [ ] **CLI `audit-verifier`** — разработать утилиту для:
  - локальной верификации (`audit-verifier verify --range A:B`)
  - CI/CD интеграции (проверка целостности после деплоя)
  - forensic analysis (экспорт подозрительных записей в JSONL)
- [ ] **Benchmark** — замерить реальную пропускную способность
  single-writer batched подхода на целевом железе (цель: 10k RPS
  с p99 <10ms).
- [ ] **Integration test** — тест с симуляцией:
  - DBA изменяет запись напрямую в Postgres → verifier обнаруживает
  - Восстановление из backup → verifier обнаруживает
  - Параллельный запуск двух pod'ов → advisory lock работает

---

## References

- [RFC 2104: HMAC: Keyed-Hashing for Message Authentication](https://datatracker.ietf.org/doc/html/rfc2104)
- [RFC 8785: JSON Canonicalization Scheme (JCS)](https://datatracker.ietf.org/doc/html/rfc8785)
- [FIPS 180-4: Secure Hash Standard (SHA-256)](https://csrc.nist.gov/publications/detail/fips/180/4/final)
- [NIST SP 800-92: Guide to Computer Security Log Management](https://csrc.nist.gov/publications/detail/sp/800-92/final)
- [Unicode Normalization Forms (UAX #15)](https://unicode.org/reports/tr15/)
- [152-ФЗ: О персональных данных](https://www.consultant.ru/document/cons_doc_LAW_61801/)
- [GDPR Art. 30: Records of Processing Activities](https://gdpr-info.eu/art-30-gdpr/)
- [PCI DSS v4.0 Req. 10: Log and Monitor All Access](https://www.pcisecuritystandards.org/)
- [AWS S3 Object Lock](https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html)
- [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)

---

## Related ADRs

- [ADR-0001: SPIFFE/SPIRE для mTLS](0001-use-spiffe-for-mtls.md) — SVID идентифицирует actor в audit-записях.
- [ADR-0004: tenant_id в context](0004-tenant-id-in-context.md) — tenant_id обязателен в каждой audit-записи.
- ADR-0010 (TBD): Key management для HMAC-ключей и SVID — управление секретами через Vault.