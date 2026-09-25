# ADR-0009: PII redaction pipeline

- **Status:** Planned
- **Date:** 2026-09-25
- **Deciders:** Roman Sokolov (Architect)
- **Tags:** `security`, `compliance`, `pii`, `privacy`, `gdpr`, `152-фз`

---

## Context

MCP Gateway проксирует запросы AI-агентов к LLM. В этих запросах
**могут содержаться персональные данные (PII)**:

- **Structured PII** — email, телефон, SSN, IBAN, credit card, passport.
- **Unstructured PII** — ФИО, адреса, даты рождения, медицинские данные.
- **Sensitive business data** — внутренние ID, номера договоров, суммы.

**Проблема:** PII уходят в LLM-провайдеров (GigaChat, YandexGPT, OpenAI,
Anthropic), которые:

- Могут сохранять данные (retention).
- Могут использовать для training (если не zero-retention).
- Могут быть в другой юрисдикции (GDPR, 152-ФЗ).

```
    ┌──────────────────────────────────────────────────────────────┐
    │                                                              │
    │  Без PII redaction:                                          │
    │                                                              │
    │  1. Пользователь: "Напиши письмо Иванову И.И. на             │
    │     ivanov@company.ru про договор №12345"                    │
    │                                                              │
    │  2. Gateway → GigaChat API                                   │
    │     ├── PII: Иванов И.И., ivanov@company.ru                  │
    │     └── Sensitive: договор №12345                            │
    │                                                              │
    │  3. GigaChat сохраняет в логах (30 дней retention)           │
    │                                                              │
    │  4. Утечка при компрометации провайдера                      │
    │                                                              │
    │  Compliance violations:                                      │
    │  • 152-ФЗ ст. 19 — нарушение защиты ПДн                      │
    │  • GDPR Art. 5 — нарушение принципов обработки               │
    │  • GDPR Art. 32 — нарушение security of processing           │
    │  • PCI DSS Req. 3 — cardholder data leak                     │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

**Требуется:**

- **Многоуровневая детекция PII** — regex + NER + per-tenant rules.
- **Обратимое маскирование** — плейсхолдеры `<EMAIL_1>`, восстановление после LLM.
- **Streaming-safe** — работает для SSE (chunked responses).
- **Per-tenant политики** — разные правила для GDPR, HIPAA, PCI DSS.
- **Fail-closed опция** — блокировка запроса, если detector не уверен.
- **Аудит redaction** — audit log записывает, что было отредактировано.
- **Compliance-ready** — 152-ФЗ, GDPR, PCI DSS, HIPAA.

---

## Decision

**Используем многоуровневый PII redaction pipeline** с reversible placeholders,
streaming-safe буфером и per-tenant политиками.

### Архитектура

```
    ┌───────────────────────────────────────────────────────────────────┐
    │                                                                    │
    │   Request flow                                                     │
    │                                                                    │
    │   Client                                                           │
    │      │                                                             │
    │      │  1. Request: "Напиши Иванову И.И. ..."                      │
    │      ▼                                                             │
    │   ┌──────────────────────────────────────────────────────────┐    │
    │   │  MCP Gateway                                              │    │
    │   │                                                            │    │
    │   │  ┌──────────────────────────────────────────────────┐    │    │
    │   │  │  PII Pipeline                                     │    │    │
    │   │  │                                                    │    │    │
    │   │  │  ┌─────────────────────┐                          │    │    │
    │   │  │  │  Layer 1: Regex      │  structured PII          │    │    │
    │   │  │  │  - Email             │  (email, phone, SSN,     │    │    │
    │   │  │  │  - Phone             │   IBAN, credit card)     │    │    │
    │   │  │  │  - SSN               │                          │    │    │
    │   │  │  │  - IBAN              │                          │    │    │
    │   │  │  │  - Credit card (Luhn)│                          │    │    │
    │   │  │  └─────────┬───────────┘                          │    │    │
    │   │  │            │                                       │    │    │
    │   │  │            ▼                                       │    │    │
    │   │  │  ┌─────────────────────┐                          │    │    │
    │   │  │  │  Layer 2: NER        │  unstructured PII        │    │    │
    │   │  │  │  - PER (Person)      │  (names, addresses)      │    │    │
    │   │  │  │  - LOC (Location)    │                          │    │    │
    │   │  │  │  - ORG (Organization)│                          │    │    │
    │   │  │  │  - DATE              │                          │    │    │
    │   │  │  └─────────┬───────────┘                          │    │    │
    │   │  │            │                                       │    │    │
    │   │  │            ▼                                       │    │    │
    │   │  │  ┌─────────────────────┐                          │    │    │
    │   │  │  │  Layer 3: Custom     │  per-tenant rules        │    │    │
    │   │  │  │  - Internal IDs      │  (regex patterns из      │    │    │
    │   │  │  │  - Contract numbers  │   configs/tenants.yaml)  │    │    │
    │   │  │  │  - Account numbers   │                          │    │    │
    │   │  │  └─────────┬───────────┘                          │    │    │
    │   │  │            │                                       │    │    │
    │   │  │            ▼                                       │    │    │
    │   │  │  ┌─────────────────────┐                          │    │    │
    │   │  │  │  Masking             │  reversible placeholders │    │    │
    │   │  │  │  <EMAIL_1>           │  mapping в request-scope │    │    │
    │   │  │  │  <PHONE_2>           │                          │    │    │
    │   │  │  │  <PERSON_3>          │                          │    │    │
    │   │  │  └─────────┬───────────┘                          │    │    │
    │   │  │            │                                       │    │    │
    │   │  └────────────┼───────────────────────────────────────┘    │    │
    │   │               │                                             │    │
    │   │               ▼                                             │    │
    │   │      2. Masked request: "Напиши <PERSON_1> ..."             │    │
    │   │               │                                             │    │
    │   └───────────────┼─────────────────────────────────────────────┘    │
    │                   │                                                  │
    │                   ▼                                                  │
    │   ┌──────────────────────────────────────────────────────────┐     │
    │   │  LLM API (GigaChat, YandexGPT)                            │     │
    │   │  ← PII не уходят в провайдера                             │     │
    │   └──────────────────────────┬───────────────────────────────┘     │
    │                              │                                      │
    │                              │  3. Response: "Dear <PERSON_1>, ..."  │
    │                              ▼                                      │
    │   ┌──────────────────────────────────────────────────────────┐     │
    │   │  PII Unmask                                               │     │
    │   │  ├── Reverse mapping <PERSON_1> → Иванов И.И.             │     │
    │   │  ├── Streaming-safe buffer (overlap 256 bytes)            │     │
    │   │  └── 4. Response: "Dear Иванов И.И., ..."                 │     │
    │   └──────────────────────────┬───────────────────────────────┘     │
    │                              │                                      │
    │                              ▼                                      │
    │                          Client                                     │
    │                                                                    │
    └───────────────────────────────────────────────────────────────────┘
```

### Три уровня детекции

```
    ┌──────────────────────────────────────────────────────────────┐
    │                                                              │
    │  Layer 1: Regex (structured PII)                             │
    │  ─────────────────────────────                               │
    │                                                              │
    │  Паттерны:                                                   │
    │  • Email:      [a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}│
    │  • Phone (RU): +7[0-9]{10} | 8[0-9]{10}                      │
    │  • SSN:        [0-9]{3}-[0-9]{2}-[0-9]{4}                    │
    │  • IBAN:       [A-Z]{2}[0-9]{2}[A-Z0-9]{1,30}                │
    │  • Credit card: [0-9]{4}[\s-]?[0-9]{4}... + Luhn check       │
    │  • Passport RU: [0-9]{2}\s?[0-9]{2}\s?[0-9]{6}               │
    │  • SNILS:      [0-9]{3}-[0-9]{3}-[0-9]{3}\s?[0-9]{2}         │
    │  • INN:        [0-9]{10} | [0-9]{12}                         │
    │                                                              │
    │  Преимущества:                                               │
    │  • Быстро (микросекунды)                                     │
    │  • Точность высокая для structured                           │
    │  • Zero dependencies                                         │
    │                                                              │
    │  Недостатки:                                                 │
    │  • Не работает для имён, адресов                             │
    │  • Ложные срабатывания (12-значные ID ≠ INN)                 │
    │                                                              │
    │  Реализация: Google RE2 (safe regex, no ReDoS)               │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘

    ┌──────────────────────────────────────────────────────────────┐
    │                                                              │
    │  Layer 2: NER (unstructured PII)                             │
    │  ────────────────────────────────                            │
    │                                                              │
    │  Модели:                                                     │
    │  • Natasha (RU) — для русского языка                         │
    │  • spaCy (EN) — для английского                              │
    │  • DeepPavlov (RU) — альтернатива                            │
    │  • Fine-tuned model — если нужно (custom)                    │
    │                                                              │
    │  Entity types:                                               │
    │  • PER — Person (Иванов И.И.)                                │
    │  • LOC — Location (Москва, ул. Ленина)                       │
    │  • ORG — Organization (ООО "Ромашка")                        │
    │  • DATE — Date (12.03.1985)                                  │
    │                                                              │
    │  Deployment:                                                 │
    │  • Sidecar container с NER-сервисом (gRPC)                   │
    │  • Модель: ~100 MB                                           │
    │  • Latency: ~50-100 ms per request                           │
    │                                                              │
    │  Альтернатива: Presidio (Microsoft)                          │
    │  • Поддерживает и regex, и NER                               │
    │  • Python-based                                               │
    │  • Sidecar container                                          │
    │                                                              │
    │  Решение: Natasha sidecar (RU-first)                          │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘

    ┌──────────────────────────────────────────────────────────────┐
    │                                                              │
    │  Layer 3: Custom rules (per-tenant)                          │
    │  ────────────────────────────────                            │
    │                                                              │
    │  Пример configs/tenants.yaml:                                │
    │                                                              │
    │  tenants:                                                    │
    │    - id: "acme"                                              │
    │      pii_policy: "strict"                                    │
    │      custom_patterns:                                        │
    │        - name: "contract_number"                             │
    │          regex: "ДОГ-[0-9]{6}"                               │
    │          type: "SENSITIVE"                                   │
    │        - name: "internal_id"                                 │
    │          regex: "ACME-[A-Z0-9]{8}"                           │
    │          type: "INTERNAL"                                    │
    │                                                              │
    │  Использование:                                              │
    │  • Tenant-specific patterns                                  │
    │  • Внутренние ID, номера договоров                           │
    │  • Compliance-specific (152-ФЗ, GDPR)                        │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

### Обратимое маскирование

```
    ┌──────────────────────────────────────────────────────────────┐
    │                                                              │
    │  Формат плейсхолдеров:                                       │
    │  <{TYPE}_{N}>                                                │
    │                                                              │
    │  Примеры:                                                    │
    │  • <EMAIL_1>, <EMAIL_2> — emails                             │
    │  • <PHONE_1> — phones                                        │
    │  • <PERSON_1>, <PERSON_2> — имена                            │
    │  • <LOC_1> — locations                                       │
    │  • <ORG_1> — organizations                                   │
    │  • <SSN_1> — SSN                                             │
    │  • <CONTRACT_1> — custom pattern                             │
    │                                                              │
    │  Mapping в request-scoped memory:                            │
    │                                                              │
    │  {                                                           │
    │    "<EMAIL_1>": "ivanov@company.ru",                         │
    │    "<PERSON_1>": "Иванов И.И.",                              │
    │    "<CONTRACT_1>": "ДОГ-123456"                              │
    │  }                                                           │
    │                                                              │
    │  ⚠️ Mapping хранится ТОЛЬКО в памяти, НЕ логируется          │
    │  ⚠️ TTL = длительность запроса (max 30 секунд)               │
    │  ⚠️ Zeroing после использования (для compliance)             │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

### Streaming-safe unmask

```
    ┌──────────────────────────────────────────────────────────────┐
    │                                                              │
    │  Проблема: SSE chunks могут разрезать placeholder.           │
    │                                                              │
    │  Пример:                                                     │
    │  Chunk 1: "Dear <PER"                                        │
    │  Chunk 2: "SON_1>, ..."                                      │
    │                                                              │
    │  Решение: overlap buffer 256 bytes                           │
    │                                                              │
    │  1. Получить chunk от LLM                                     │
    │  2. Добавить в buffer                                         │
    │  3. Найти последний "<" в buffer                              │
    │  4. Отправить клиенту всё до последнего "<"                   │
    │  5. Оставить в buffer всё после "<" (до 256 байт)             │
    │  6. Если placeholder полностью собран — unmask                │
    │  7. Если "<" не найден — отправить всё                        │
    │                                                              │
    │  Пример flow:                                                │
    │                                                              │
    │  Chunk 1: "Dear <PER"                                        │
    │  → Buffer: "Dear <PER"                                       │
    │  → Last "<" at index 5                                       │
    │  → Send: "Dear "                                             │
    │  → Buffer: "<PER"                                            │
    │                                                              │
    │  Chunk 2: "SON_1>, hello"                                    │
    │  → Buffer: "<PERSON_1>, hello"                               │
    │  → Last "<" at index 0                                       │
    │  → Complete placeholder found: "<PERSON_1>"                  │
    │  → Unmask: "Иванов И.И."                                     │
    │  → Send: "Иванов И.И., hello"                                │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

### Per-tenant PII policies

```
    ┌──────────────────────────────────────────────────────────────┐
    │                                                              │
    │  configs/tenants.yaml:                                       │
    │                                                              │
    │  tenants:                                                    │
    │    - id: "acme"                                              │
    │      pii_policy: "strict"     # fail-closed                  │
    │      detectors:                                              │
    │        - regex: true                                         │
    │        - ner: true                                           │
    │        - custom: true                                        │
    │      on_detector_error: "block"    # fail-closed             │
    │                                                              │
    │    - id: "globex"                                            │
    │      pii_policy: "gdpr"       # GDPR-specific                │
    │      detectors:                                              │
    │        - regex: true                                         │
    │        - ner: true                                           │
    │        - custom: false                                       │
    │      on_detector_error: "log_and_continue"                   │
    │                                                              │
    │    - id: "hipaa-tenant"                                      │
    │      pii_policy: "hipaa"      # HIPAA-specific               │
    │      detectors:                                              │
    │        - regex: true                                         │
    │        - ner: true                                           │
    │        - custom: true                                        │
    │      on_detector_error: "block"                              │
    │      additional_patterns:                                    │
    │        - name: "medical_record"                              │
    │          regex: "MRN-[0-9]{8}"                               │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

---

## Implementation details

### Go structs

```go
// Detector — интерфейс для детектора PII
type Detector interface {
    Detect(ctx context.Context, text string) ([]Detection, error)
    Name() string
}

// Detection — результат детекции
type Detection struct {
    Start      int    // позиция начала в тексте
    End        int    // позиция конца
    Type       string // "EMAIL" | "PHONE" | "PERSON" | ...
    Original   string // оригинальный текст
    Confidence float64 // 0.0 - 1.0 (для NER)
}

// Redactor — pipeline для redaction
type Redactor struct {
    detectors []Detector
    policy    Policy
    cache     *PlaceholderCache
}

// Policy — per-tenant политика
type Policy struct {
    TenantID       string
    Strict         bool  // fail-closed
    OnDetectorError string // "block" | "log_and_continue"
}

// Placeholder — маппинг placeholder → original
type Placeholder struct {
    Placeholder string
    Original    string
    Type        string
}

// RedactedText — результат redaction
type RedactedText struct {
    Text         string
    Placeholders []Placeholder
}
```

### Detector implementations

```go
// RegexDetector — Layer 1
type RegexDetector struct {
    patterns map[string]*regexp.Regexp
}

func NewRegexDetector() *RegexDetector {
    return &RegexDetector{
        patterns: map[string]*regexp.Regexp{
            "EMAIL":       regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`),
            "PHONE_RU":    regexp.MustCompile(`(?:\+7|8)[\s-]?\(?[0-9]{3}\)?[\s-]?[0-9]{3}[\s-]?[0-9]{2}[\s-]?[0-9]{2}`),
            "SSN":         regexp.MustCompile(`\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b`),
            "IBAN":        regexp.MustCompile(`\b[A-Z]{2}[0-9]{2}[A-Z0-9]{1,30}\b`),
            "CREDIT_CARD": regexp.MustCompile(`\b[0-9]{4}[\s-]?[0-9]{4}[\s-]?[0-9]{4}[\s-]?[0-9]{4}\b`),
            "INN_RU":      regexp.MustCompile(`\b[0-9]{10}\b|\b[0-9]{12}\b`),
            "SNILS_RU":    regexp.MustCompile(`\b[0-9]{3}-[0-9]{3}-[0-9]{3}\s?[0-9]{2}\b`),
        },
    }
}

func (d *RegexDetector) Detect(ctx context.Context, text string) ([]Detection, error) {
    var detections []Detection
    for typeName, pattern := range d.patterns {
        matches := pattern.FindAllStringIndex(text, -1)
        for _, match := range matches {
            original := text[match[0]:match[1]]
            
            // Валидация для credit card (Luhn)
            if typeName == "CREDIT_CARD" && !luhnCheck(original) {
                continue
            }
            
            detections = append(detections, Detection{
                Start:      match[0],
                End:        match[1],
                Type:       typeName,
                Original:   original,
                Confidence: 1.0,
            })
        }
    }
    return detections, nil
}
```

### NER sidecar (gRPC)

```go
// NERDetector — Layer 2, вызывает sidecar
type NERDetector struct {
    client NERServiceClient
}

func (d *NERDetector) Detect(ctx context.Context, text string) ([]Detection, error) {
    // gRPC вызов к Natasha sidecar
    req := &NERRequest{Text: text}
    
    ctx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
    defer cancel()
    
    resp, err := d.client.Detect(ctx, req)
    if err != nil {
        return nil, fmt.Errorf("ner sidecar failed: %w", err)
    }
    
    var detections []Detection
    for _, entity := range resp.Entities {
        detections = append(detections, Detection{
            Start:      entity.Start,
            End:        entity.End,
            Type:       entity.Type,  // "PER", "LOC", "ORG", "DATE"
            Original:   entity.Text,
            Confidence: entity.Confidence,
        })
    }
    return detections, nil
}
```

### Masking

```go
// Mask применяет placeholders и сохраняет mapping
func (r *Redactor) Mask(text string, detections []Detection) RedactedText {
    // Сортировка по позиции (start по убыванию)
    sort.Slice(detections, func(i, j int) bool {
        return detections[i].Start > detections[j].Start
    })
    
    counters := map[string]int{}
    placeholders := []Placeholder{}
    result := text
    
    for _, d := range detections {
        counters[d.Type]++
        placeholder := fmt.Sprintf("<%s_%d>", d.Type, counters[d.Type])
        
        result = result[:d.Start] + placeholder + result[d.End:]
        
        placeholders = append(placeholders, Placeholder{
            Placeholder: placeholder,
            Original:    d.Original,
            Type:        d.Type,
        })
    }
    
    return RedactedText{
        Text:         result,
        Placeholders: placeholders,
    }
}

// Unmask восстанавливает оригинал
func (r *Redactor) Unmask(text string, placeholders []Placeholder) string {
    for _, p := range placeholders {
        text = strings.ReplaceAll(text, p.Placeholder, p.Original)
    }
    return text
}
```

### Streaming-safe unmask

```go
// StreamingUnmasker — безопасный unmask для SSE
type StreamingUnmasker struct {
    placeholders []Placeholder
    buffer       []byte
    maxBuffer    int  // 256 bytes
}

func (u *StreamingUnmasker) Process(chunk []byte) []byte {
    u.buffer = append(u.buffer, chunk...)
    
    // Найти последний "<" в buffer
    lastOpen := bytes.LastIndexByte(u.buffer, '<')
    
    var send, keep []byte
    if lastOpen == -1 {
        // Нет "<" — отправить всё
        send = u.buffer
        keep = nil
    } else {
        // Отправить всё до "<", keep после
        send = u.buffer[:lastOpen]
        keep = u.buffer[lastOpen:]
    }
    
    // Unmask отправляемую часть
    unmasked := u.unmask(send)
    
    u.buffer = keep
    
    // Safety: если buffer > maxBuffer, force flush
    if len(u.buffer) > u.maxBuffer {
        unmasked = append(unmasked, u.unmask(u.buffer)...)
        u.buffer = nil
    }
    
    return unmasked
}
```

### Метрики

```
    ┌──────────────────────────────────────────────────────────────┐
    │                                                              │
    │  mcp_pii_redacted_total{                                     │
    │    tenant,              # "acme"                             │
    │    type                 # "EMAIL" | "PERSON" | "PHONE" | ... │
    │  } → counter (сколько PII отредактировано)                   │
    │                                                              │
    │  mcp_pii_detection_duration_seconds{tenant, layer} → hist    │
    │    buckets: [0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0]        │
    │                                                              │
    │  mcp_pii_detector_errors_total{tenant, layer, error_type}    │
    │    → counter                                                 │
    │                                                              │
    │  mcp_pii_detector_timeout_total{tenant, layer} → counter     │
    │                                                              │
    │  mcp_pii_false_positive_total{tenant, type} → counter        │
    │    (manual feedback через admin API)                         │
    │                                                              │
    │  mcp_pii_unmask_errors_total{tenant} → counter               │
    │                                                              │
    │  mcp_pii_blocked_requests_total{tenant, reason} → counter    │
    │    (для fail-closed политик)                                 │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

### Audit log integration

```
    ┌──────────────────────────────────────────────────────────────┐
    │                                                              │
    │  Каждое событие redaction логируется в audit log (ADR-0002): │
    │                                                              │
    │  AuditEntry {                                                │
    │    TenantID: "acme",                                         │
    │    Action:   "pii.redacted",                                 │
    │    Actor:    "spiffe://...",                                 │
    │    Metadata: {                                               │
    │      "types": ["EMAIL", "PERSON", "PHONE"],                  │
    │      "counts": {"EMAIL": 2, "PERSON": 1, "PHONE": 1},        │
    │      // ⚠️ БЕЗ оригинальных значений PII                     │
    │    },                                                        │
    │    Outcome: "allow" | "block"                                │
    │  }                                                           │
    │                                                              │
    │  Что НЕ логируется:                                          │
    │  • Оригинальные значения PII                                 │
    │  • Placeholders (они уже redacted)                           │
    │  • Mapping (только в памяти)                                 │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

### Rollout plan

```
    ┌──────────────────────────────────────────────────────────────┐
    │                                                              │
    │  Phase 1: Regex-only (Layer 1) — 1 неделя                    │
    │  ──────────────────────────────                              │
    │  • Regex-детектор для structured PII                         │
    │  • Обратимое маскирование                                    │
    │  • Streaming-safe unmask                                     │
    │  • Unit tests на test vectors                                │
    │  • Rollout с 10% трафика                                     │
    │                                                              │
    │  Phase 2: NER sidecar (Layer 2) — 2 недели                   │
    │  ──────────────────────────────                              │
    │  • Развернуть Natasha sidecar                                │
    │  • gRPC интеграция                                           │
    │  • Latency budget: <100ms p99                                │
    │  • Memory budget: <500 MB per pod                            │
    │  • Rollout с 50% трафика                                     │
    │                                                              │
    │  Phase 3: Custom patterns (Layer 3) — 1 неделя               │
    │  ────────────────────────────────                            │
    │  • Config-driven per-tenant patterns                         │
    │  • Validation + testing                                      │
    │  • Enable для selected tenants                                │
    │                                                              │
    │  Phase 4: Per-tenant policies — 1 неделя                     │
    │  ───────────────────────────                                 │
    │  • Fail-closed для strict тенантов                           │
    │  • Fail-open для остальных                                   │
    │  • Audit log integration                                      │
    │                                                              │
    │  Phase 5: Compliance certification — ongoing                 │
    │  ─────────────────────────────────                           │
    │  • Тесты на 152-ФЗ compliance                                │
    │  • Тесты на GDPR compliance                                  │
    │  • Тесты на PCI DSS compliance                               │
    │  • Penetration testing                                        │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

### Known limitations

```
    ┌──────────────────────────────────────────────────────────────┐
    │                                                              │
    │  1. NER false positives                                       │
    │     ⚠️ "Москва" может быть LOC в контексте города,            │
    │        но ORG в контексте компании                            │
    │     💡 Митигация:                                              │
    │        • Confidence threshold (0.7+)                          │
    │        • Per-tenant overrides                                 │
    │        • Manual feedback через admin API                      │
    │                                                              │
    │  2. NER false negatives                                       │
    │     ⚠️ Имена в нестандартных форматах,                        │
    │        transliteration, ошибки                                │
    │     💡 Митигация:                                              │
    │        • Multiple NER models (ensemble)                       │
    │        • Regular retraining                                   │
    │        • Fail-closed для strict tenants                       │
    │                                                              │
    │  3. Latency overhead                                           │
    │     ⚠️ NER sidecar добавляет 50-100ms p99                     │
    │     💡 Митигация:                                              │
    │        • Parallel detection (Layer 1 + Layer 2)               │
    │        • Caching (identical requests)                          │
    │        • Timeout с fallback                                    │
    │                                                              │
    │  4. Streaming unmask complexity                                │
    │     ⚠️ Overlap buffer может задерживать первый chunk          │
    │     💡 Митигация:                                              │
    │        • Max buffer 256 bytes                                  │
    │        • Timeout flush (100ms)                                │
    │        • Fallback на полный unmask после stream end           │
    │                                                              │
    │  5. Placeholder collision                                      │
    │     ⚠️ Если пользователь сам пишет "<EMAIL_1>" —               │
    │        может быть заменено неверно                             │
    │     💡 Митигация:                                              │
    │        • Uncommon prefix (например, "<__EMAIL_1__>")          │
    │        • Escape существующих placeholders в input             │
    │                                                              │
    │  6. Multi-language support                                     │
    │     ⚠️ Natasha — RU-only, spaCy — EN-only                     │
    │     💡 Митигация:                                              │
    │        • Auto-detect language                                  │
    │        • Multiple NER models per language                     │
    │        • Fallback на regex-only                                │
    │                                                              │
    │  7. Cost of NER sidecar                                        │
    │     ⚠️ ~500 MB RAM per pod, ~10% CPU                          │
    │     💡 Митигация:                                              │
    │        • Shared sidecar (не per-gateway-pod)                  │
    │        • GPU acceleration (если нужен throughput)             │
    │        • Batch processing                                      │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

---

## Rationale

### Почему многоуровневая детекция, а не один detector

**Только regex:**

- Быстро, но пропускает имена, адреса.
- False positives для ID.

**Только NER:**

- Покрывает имена, но медленно.
- Не покрывает structured PII (email, phone).

**Layer 1 + Layer 2 + Layer 3:**

- Layer 1 (regex) — быстро, для structured.
- Layer 2 (NER) — точно, для unstructured.
- Layer 3 (custom) — гибко, для per-tenant.

**Решение:** многоуровневая детекция.

### Почему reversible placeholders, а не полное удаление

**Полное удаление:**

- `<EMAIL>` → удалено.
- LLM не знает контекста.
- Ответ теряет смысл.

**Reversible placeholders:**

- `<EMAIL_1>` → placeholder.
- LLM видит контекст (это email).
- Ответ восстанавливается.

**Решение:** reversible placeholders.

### Почему Natasha (RU), а не Presidio (Microsoft)

**Presidio:**

- Мощный, поддерживает regex + NER.
- Python-based, требует sidecar.
- NER — английский (spaCy).
- Для русского — слабее.

**Natasha:**

- Russian-first.
- Хорошо работает с ФИО, адресами, организациями.
- Python-based, sidecar.
- Lightweight (~100 MB model).

**Для MCP Gateway в российском контексте:** Natasha предпочтительнее.

**Гибридный подход:** Presidio + Natasha — если нужны оба языка.

### Почему streaming-safe unmask, а не post-processing

**Post-processing (buffer весь ответ):**

- Просто.
- Но: latency = весь ответ.
- Для long responses (10+ секунд) — неприемлемо.

**Streaming-safe (overlap buffer):**

- Latency = первый chunk.
- Overlap 256 байт — покрывает 99% placeholders.
- Complexity: 50 строк Go.

**Решение:** streaming-safe.

### Почему per-tenant policies, а не глобальная

**Глобальная политика:**

- Одна для всех.
- Не учитывает compliance-различия.

**Per-tenant:**

- GDPR vs 152-ФЗ vs HIPAA.
- Разные detectors.
- Разные fail-closed политики.

**Решение:** per-tenant policies.

---

## Consequences

### Positive

- **PII не уходят в LLM** — compliance-ready.
- **Compliance-ready** — 152-ФЗ, GDPR, PCI DSS, HIPAA.
- **Reversible** — ответы сохраняют смысл.
- **Streaming-safe** — работает с SSE.
- **Per-tenant** — гибкие политики.
- **Audit-ready** — все redaction логируются.
- **Multi-layer** — высокая точность.

### Negative

- **Latency overhead** — +50-100ms p99 для NER.
  Митигация: parallel detection + caching.
- **NER sidecar** — доп. инфраструктура (~500 MB RAM).
  Митигация: shared sidecar.
- **False positives** — некоторые имена/места.
  Митигация: confidence threshold + feedback.
- **False negatives** — нестандартные форматы.
  Митигация: fail-closed + retraining.
- **Complexity** — 3 слоя, streaming buffer.
  Митигация: unit tests + test vectors.
- **Cost** — больше CPU, чем без redaction.
  Митигация: parallel, caching.

### Neutral

- **Prompt для LLM** — placeholders вместо PII.
  Может повлиять на качество для некоторых задач.
- **Debugging** — сложнее (нужно видеть оригинал).
  Митигация: admin endpoint для просмотра (audit-logged).
- **Language support** — RU + EN. Другие — нужны доп. модели.

---

## Failure modes

### NER sidecar недоступен

```
    ┌──────────────────────────────────────────────────────────────┐
    │                                                              │
    │  Симптом: Layer 2 детекция не работает                       │
    │                                                              │
    │  Поведение (per policy):                                     │
    │  • strict tenants → fail-closed (503)                        │
    │  • normal tenants → fail-open (regex-only)                   │
    │                                                              │
    │  Detection:                                                  │
    │  • Алерт: mcp_pii_detector_errors_total{layer="ner"} > 0     │
    │  • Алерт: mcp_pii_detector_timeout_total{layer="ner"} > 0    │
    │                                                              │
    │  Mitigation:                                                 │
    │  • Fallback на regex-only                                    │
    │  • Auto-restart sidecar                                      │
    │  • Circuit breaker на NER client                             │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

### Regex catastrophic backtracking (ReDoS)

```
    ┌──────────────────────────────────────────────────────────────┐
    │                                                              │
    │  Симптом: regex detection блокирует CPU                      │
    │                                                              │
    │  Причины:                                                    │
    │  • Nested quantifiers ((a+)+)                                │
    │  • Catastrophic backtracking                                 │
    │                                                              │
    │  Mitigation:                                                 │
    │  • Google RE2 (no backtracking)                              │
    │  • Timeout на каждый regex match                             │
    │  • Input size limits                                          │
    │                                                              │
    │  Detection:                                                  │
    │  • Алерт: mcp_pii_detection_duration_seconds{layer="regex"}  │
    │           p99 > 10ms                                          │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

### Unmask failure (placeholder не восстановлен)

```
    ┌──────────────────────────────────────────────────────────────┐
    │                                                              │
    │  Симптом: клиент видит "<EMAIL_1>" вместо email              │
    │                                                              │
    │  Причины:                                                    │
    │  • LLM переформатировала placeholder                          │
    │  • Chunk разрезал placeholder                                 │
    │  • Placeholder collision                                      │
    │                                                              │
    │  Detection:                                                  │
    │  • Алерт: mcp_pii_unmask_errors_total > 0                    │
    │  • Periodic scan responses на unmatched placeholders         │
    │                                                              │
    │  Mitigation:                                                 │
    │  • Streaming buffer 256 байт                                 │
    │  • Uncommon prefix placeholders                              │
    │  • Fallback на post-processing при ошибке                    │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

### PII leak (false negative)

```
    ┌──────────────────────────────────────────────────────────────┐
    │                                                              │
    │  Симптом: PII обнаружены в outgoing LLM request              │
    │                                                              │
    │  ⚠️ CRITICAL — compliance violation                          │
    │                                                              │
    │  Причины:                                                    │
    │  • NER false negative                                         │
    │  • Нестандартный формат PII                                   │
    │  • Новый тип PII (не в правилах)                             │
    │                                                              │
    │  Detection:                                                  │
    │  • Post-check на egress (DLP inspection)                     │
    │  • Periodic scan logs на PII patterns                        │
    │  • User feedback                                             │
    │                                                              │
    │  Mitigation:                                                 │
    │  • Defense in depth (post-check)                             │
    │  • Fail-closed для strict tenants                            │
    │  • Regular rules update                                      │
    │  • Regression tests                                          │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

---

## Alternatives considered

### Alternative 1: Полное удаление PII (без restore)

**Плюсы:**
- Максимальная безопасность.
- Просто.

**Минусы:**
- LLM теряет контекст.
- Ответ теряет смысл.
- Невозможно восстановить.

**Решение:** отклонено. Reversible placeholders лучше.

### Alternative 2: Redaction только на client-side

**Плюсы:**
- Gateway не обрабатывает PII.
- Меньше нагрузка.

**Минусы:**
- Клиент может не сделать redaction.
- Нет гарантии compliance.
- Не работает для legacy clients.

**Решение:** отклонено. Gateway должен быть enforcement point.

### Alternative 3: Только regex (без NER)

**Плюсы:**
- Быстро.
- Zero sidecar.
- Просто.

**Минусы:**
- Не покрывает имена, адреса.
- 152-ФЗ требует защиты имён → non-compliant.

**Решение:** отклонено. NER обязателен для compliance.

### Alternative 4: Post-processing (buffer весь ответ)

**Плюсы:**
- Просто.
- Точнее (весь контекст).

**Минусы:**
- Latency = весь ответ.
- Не работает для long responses.
- SSE теряет смысл.

**Решение:** отклонено. Streaming-safe обязателен.

### Alternative 5: Presidio вместо Natasha

**Плюсы:**
- Microsoft support.
- Multi-language.
- Rich features.

**Минусы:**
- Heavy (~1 GB).
- NER — English-first.
- Русский — слабее.
- Медленнее.

**Решение:** отклонено. Natasha для RU-контекста предпочтительнее.

### Alternative 6: Cloud DLP (Google DLP, AWS Macie)

**Плюсы:**
- Managed.
- Accurate.
- Multi-language.

**Минусы:**
- PII уходят в cloud (contradiction).
- Vendor lock-in.
- Стоимость высокая.
- Latency (network round-trip).

**Решение:** отклонено. PII не должны покидать периметр.

---

## Action items

Задачи, вытекающие из этого ADR:

- [ ] **Regex детектор (Layer 1)**:
  - Паттерны: email, phone RU, SSN, IBAN, credit card (Luhn), INN, SNILS
  - Google RE2 (no backtracking)
  - Unit tests на test vectors
  - Benchmark: p99 <1ms на 1 KB тексте

- [ ] **NER sidecar (Layer 2)**:
  - Natasha container (Python + gRPC)
  - Model: ~100 MB
  - Latency budget: p99 <100ms
  - Memory: <500 MB per pod
  - Health checks + auto-restart
  - Circuit breaker на client

- [ ] **Custom patterns (Layer 3)**:
  - `configs/tenants.yaml` формат
  - Loading + validation
  - Per-tenant patterns
  - Unit tests

- [ ] **Masking + Unmask**:
  - Обратимые placeholders
  - Request-scoped mapping (memory only)
  - Zeroing после использования
  - Unit tests

- [ ] **Streaming-safe unmask**:
  - Overlap buffer 256 байт
  - Timeout flush (100ms)
  - Integration test с SSE

- [ ] **Метрики**:
  - `mcp_pii_redacted_total{tenant, type}`
  - `mcp_pii_detection_duration_seconds{tenant, layer}`
  - `mcp_pii_detector_errors_total{tenant, layer, error_type}`
  - `mcp_pii_unmask_errors_total{tenant}`
  - `mcp_pii_blocked_requests_total{tenant, reason}`

- [ ] **Audit log integration**:
  - Log redaction events (без original values)
  - Integration с ADR-0002 (HMAC hash-chain)

- [ ] **Per-tenant policies**:
  - `configs/tenants.yaml` — pii_policy
  - strict / gdpr / hipaa
  - fail-closed / fail-open

- [ ] **Testing**:
  - Unit tests на test vectors (valid + invalid)
  - Integration test: end-to-end redaction
  - Integration test: streaming unmask
  - Load test: 10k RPS с redaction
  - Compliance tests: 152-ФЗ, GDPR, PCI DSS

- [ ] **Documentation**:
  - Обновить `docs/blueprint.md` — PII pipeline в capabilities
  - Обновить `docs/security/threat-model.md` — I-01 (PII leak)
  - Обновить `docs/reliability/runbook.md` — PII incident procedure

- [ ] **Compliance certification**:
  - Тесты на 152-ФЗ
  - Тесты на GDPR
  - External pentest
  - DPIA (Data Protection Impact Assessment)

---

## References

- [152-ФЗ: О персональных данных](https://www.consultant.ru/document/cons_doc_LAW_61801/)
- [GDPR Art. 5: Principles](https://gdpr-info.eu/art-5-gdpr/)
- [GDPR Art. 32: Security of Processing](https://gdpr-info.eu/art-32-gdpr/)
- [PCI DSS v4.0 Req. 3: Protect Stored Account Data](https://www.pcisecuritystandards.org/)
- [HIPAA §164.312: Technical Safeguards](https://www.hhs.gov/hipaa/for-professionals/security/)
- [Microsoft Presidio](https://microsoft.github.io/presidio/)
- [Natasha: Russian NLP](https://natasha.github.io/)
- [Google RE2](https://github.com/google/re2)
- [OWASP: PII Detection](https://owasp.org/www-community/vulnerabilities/Privacy_Violation)

---

## Related ADRs

- [ADR-0002: HMAC hash-chain для audit log](0002-hmac-hash-chain-for-audit.md) — redaction events логируются в audit
- [ADR-0006: Observability stack](0006-observability-stack.md) — метрики redaction
- [ADR-0007: Prompt A/B testing via Langfuse](0007-prompt-ab-testing.md) — prompts хранятся в redacted виде
- [ADR-0008: Cost attribution per agent](0008-cost-attribution-per-agent.md) — не влияет на cost tracking
- [ADR-0010: Key management (HMAC + SVID)](0010-key-management.md) (TBD) — Vault для ключей