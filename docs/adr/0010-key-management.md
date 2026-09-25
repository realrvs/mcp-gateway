# ADR-0010: Key management для HMAC и SVID

- **Status:** Planned
- **Date:** 2026-09-25
- **Deciders:** Roman Sokolov (Architect)
- **Tags:** `security`, `secrets`, `openbao`, `spiffe`, `hmac`, `cryptography`

---

## Context

MCP Gateway использует **два типа криптографических ключей**:

1. **HMAC keys** — для подписи audit log (см. ADR-0002).
2. **SPIFFE SVID** — X.509 сертификаты для mTLS (см. ADR-0001).

Каждый тип имеет **свой жизненный цикл**, **требования к хранению** и
**процедуры ротации**. Без чёткого управления ключами:

```
    ┌──────────────────────────────────────────────────────────────┐
    │                                                              │
    │  Проблема 1: Компрометация ключа = катастрофа                │
    │  ─────────────────────────────────────────                   │
    │                                                              │
    │  • HMAC key compromised → вся hash-chain можно пересчитать   │
    │  • SVID compromised → impersonation любого workload          │
    │                                                              │
    │  Проблема 2: Потеря ключа = невозможность восстановления     │
    │  ────────────────────────────────────────────────────────    │
    │                                                              │
    │  • HMAC key lost → невозможно верифицировать исторические    │
    │    audit-записи (compliance violation)                       │
    │  • SVID lost → gateway не может работать (fail-closed)       │
    │                                                              │
    │  Проблема 3: Ротация без плана = downtime                    │
    │  ────────────────────────────────────────                    │
    │                                                              │
    │  • Смена HMAC key без KeyVersion → ломает hash-chain        │
    │  • Смена SVID без graceful rotation → обрывает соединения   │
    │                                                              │
    │  Проблема 4: Отсутствие audit = невозможно доказать          │
    │  ────────────────────────────────────────                    │
    │                                                              │
    │  • Кто имел доступ к ключу?                                  │
    │  • Когда ключ был использован?                               │
    │  • Была ли несанкционированная попытка?                      │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

**Требуется:**

- **Централизованное хранение** — OpenBao для всех секретов.
- **Разделение ролей** — gateway SA, verifier SA, admin — разные права.
- **Автоматическая ротация** — HMAC 90 дней, SVID 1 час (SPIRE).
- **Graceful rotation** — без downtime и без потери данных.
- **Backup и recovery** — sealed backup для критичных ключей.
- **Audit всех доступов** — OpenBao audit log.
- **Incident response** — процедура при компрометации.

---

## Decision

**Используем OpenBao** как единый источник HMAC-ключей, **SPIRE**
как источник SVID, с разделением ролей, автоматической ротацией и
incident response playbook.

### Почему OpenBao, а не HashiCorp Vault

```
    ┌──────────────────────────────────────────────────────────────┐
    │                                                              │
    │  HashiCorp Vault:                                            │
    │                                                              │
    │  ✅ Industry standard                                        │
    │  ✅ Зрелый продукт                                           │
    │                                                              │
    │  ❌ BSL 1.1 license (не OSI-approved)                        │
    │  ❌ Платная лицензия для коммерческого использования          │
    │  ❌ Вендор-контроль (HashiCorp/IBM)                          │
    │  ❌ Enterprise features за отдельную плату                    │
    │                                                              │
    │  OpenBao (fork от Vault 1.14.x):                             │
    │                                                              │
    │  ✅ MPL 2.0 license (OSI-approved, free)                     │
    │  ✅ Linux Foundation governance                              │
    │  ✅ API-compatible с Vault                                   │
    │  ✅ Community-driven                                         │
    │  ✅ Namespaces доступны бесплатно                            │
    │                                                              │
    │  Различия:                                                   │
    │  • Token format: sbr.xxx (OpenBao) vs hvs.xxx (Vault)       │
    │  • Storage: только Raft + PostgreSQL (не Consul, etc.)       │
    │  • CLI: bao (вместо vault)                                   │
    │  • Go SDK: openbao/openbao/api/v2 (вместо hashicorp/vault)  │
    │  • Performance: ~21% медленнее с Raft storage                │
    │                                                              │
    │  ⚠️ Performance: 21% разница не критична для secrets reads,  │
    │     которые происходят 1-2 раза в час (cache TTL 5 минут)    │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

### Архитектура

```
    ┌───────────────────────────────────────────────────────────────────┐
    │                                                                    │
    │   ┌──────────────────────────────────────────────────────────┐    │
    │   │                                                            │    │
    │   │   OpenBao (HA, 3 nodes, Raft storage)                     │    │
    │   │                                                            │    │
    │   │   ┌────────────────────────────────────────────────┐      │    │
    │   │   │  Path: mcp-gateway/audit-hmac-key              │      │    │
    │   │   │  ├── v1 (2026-06-01, retired)                  │      │    │
    │   │   │  ├── v2 (2026-09-01, retired)                  │      │    │
    │   │   │  └── v3 (2026-12-01, active)                   │      │    │
    │   │   └────────────────────────────────────────────────┘      │    │
    │   │                                                            │    │
    │   │   ┌────────────────────────────────────────────────┐      │    │
    │   │   │  Path: mcp-gateway/llm-provider-keys           │      │    │
    │   │   │  ├── gigachat-api-key                          │      │    │
    │   │   │  ├── yandexgpt-api-key                         │      │    │
    │   │   │  └── ollama-bearer-token                       │      │    │
    │   │   └────────────────────────────────────────────────┘      │    │
    │   │                                                            │    │
    │   │   ┌────────────────────────────────────────────────┐      │    │
    │   │   │  Path: mcp-gateway/postgres                    │      │    │
    │   │   │  ├── gateway-user-password                     │      │    │
    │   │   │  └── verifier-user-password                    │      │    │
    │   │   └────────────────────────────────────────────────┘      │    │
    │   │                                                            │    │
    │   │   RBAC Policies:                                           │    │
    │   │   ├── mcp-gateway-app   → read active keys only            │    │
    │   │   ├── mcp-verifier-app  → read all historical HMAC keys    │    │
    │   │   └── mcp-admin         → write, rotate, manage             │    │
    │   │                                                            │    │
    │   └────────────────────────┬───────────────────────────────────┘    │
    │                            │                                        │
    │                            │ AppRole auth                           │
    │                            │ (role_id + secret_id)                  │
    │                            │                                        │
    │   ┌────────────────────────┼───────────────────────────────────┐    │
    │   │                        │                                   │    │
    │   │   ┌────────────────────▼──────────────┐                    │    │
    │   │   │  MCP Gateway (Go)                  │                    │    │
    │   │   │  ├── OpenBao client (AppRole)      │                    │    │
    │   │   │  ├── HMAC keys (active)             │                    │    │
    │   │   │  └── SVID (via SPIRE Agent)         │                    │    │
    │   │   └────────────────────┬───────────────┘                    │    │
    │   │                        │                                    │    │
    │   │   ┌────────────────────▼──────────────┐                    │    │
    │   │   │  Audit Verifier (CronJob)          │                    │    │
    │   │   │  ├── OpenBao client (AppRole)      │                    │    │
    │   │   │  └── HMAC keys (all versions)       │                    │    │
    │   │   └────────────────────────────────────┘                    │    │
    │   │                                                            │    │
    │   │   ┌────────────────────────────────────┐                    │    │
    │   │   │  SPIRE Server (HA, 3 nodes)        │                    │    │
    │   │   │  ├── SVID issuance                  │                    │    │
    │   │   │  ├── Attestation (K8s SA + image)   │                    │    │
    │   │   │  └── Trust bundle distribution      │                    │    │
    │   │   └────────────────────┬───────────────┘                    │    │
    │   │                        │                                    │    │
    │   │   ┌────────────────────▼───────────────┐                    │    │
    │   │   │  SPIRE Agent (DaemonSet)           │                    │    │
    │   │   │  └── Workload API (Unix socket)     │                    │    │
    │   │   └────────────────────────────────────┘                    │    │
    │   │                                                            │    │
    │   └────────────────────────────────────────────────────────────┘    │
    │                                                                    │
    └───────────────────────────────────────────────────────────────────┘
```

### Жизненный цикл HMAC key

```
    ┌──────────────────────────────────────────────────────────────┐
    │                                                              │
    │  Day 0:                                                      │
    │  ┌──────────────────────────────────────────────────────┐   │
    │  │  • OpenBao admin создаёт новый HMAC key (v3)          │   │
    │  │  • Key помечен как "active"                           │   │
    │  │  • Предыдущий key (v2) остаётся "verify-only"         │   │
    │  │  • Запись в OpenBao audit log                         │   │
    │  └──────────────────────────────────────────────────────┘   │
    │                                                              │
    │  Day 0 → Day 90:                                            │
    │  ┌──────────────────────────────────────────────────────┐   │
    │  │  • Gateway использует v3 для новых записей            │   │
    │  │  • Verifier использует v3 для новых + v2, v1          │   │
    │  │    для исторических                                    │   │
    │  │  • Каждая audit-запись содержит KeyVersion=3          │   │
    │  └──────────────────────────────────────────────────────┘   │
    │                                                              │
    │  Day 90:                                                    │
    │  ┌──────────────────────────────────────────────────────┐   │
    │  │  • Создаётся новый key (v4)                           │   │
    │  │  • v3 переходит в "verify-only"                       │   │
    │  │  • v1 можно архивировать (если >1 год)                │   │
    │  │  • Автоматически через OpenBao cronjob                │   │
    │  └──────────────────────────────────────────────────────┘   │
    │                                                              │
    │  Retention:                                                  │
    │  • Active keys: OpenBao (permanent)                          │
    │  • Verify-only keys: OpenBao (permanent)                     │
    │  • Archived keys: OpenBao (permanent) + sealed backup в S3   │
    │                                                              │
    │  ⚠️ НИКОГДА не удалять старые keys — они нужны для           │
    │     верификации исторических audit-записей                   │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

### Жизненный цикл SVID

```
    ┌──────────────────────────────────────────────────────────────┐
    │                                                              │
    │  Жизненный цикл SVID (управляется SPIRE, не нами):           │
    │                                                              │
    │  TTL: 1 час                                                  │
    │                                                              │
    │  0:00 ───────────────────────────────────────────────────    │
    │  │                                                            │
    │  │  SPIRE Agent выдаёт SVID                                   │
    │  │  ├── X.509 certificate                                    │
    │  │  ├── Private key                                          │
    │  │  └── Trust bundle                                         │
    │  │                                                            │
    │  0:30 ────────────────────────────────────────────────       │
    │  │                                                            │
    │  │  SPIRE Agent автоматически ротирует (за 30 минут           │
    │  │  до истечения)                                            │
    │  │  ├── Новый SVID                                            │
    │  │  ├── Graceful switch в go-spiffe                           │
    │  │  └── Старый SVID остаётся валидным до TTL                 │
    │  │                                                            │
    │  1:00 ────────────────────────────────────────────────       │
    │  │                                                            │
    │  │  Старый SVID истекает                                      │
    │  │  ├── Все соединения используют новый                       │
    │  │  └── Memory старого zeroed                                 │
    │                                                              │
    │  Failure modes:                                              │
    │  • SPIRE Agent down → SVID остаётся валидным до TTL          │
    │  • SPIRE Server down → Agent работает на кэше                │
    │  • Attestation failed → no new SVID → fail-closed            │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

### RBAC Policies в OpenBao

```
    ┌──────────────────────────────────────────────────────────────┐
    │                                                              │
    │  Policy: mcp-gateway-app                                     │
    │  ─────────────────────                                       │
    │                                                              │
    │  # Читать только активный HMAC key                           │
    │  path "mcp-gateway/audit-hmac-key/active" {                  │
    │    capabilities = ["read"]                                   │
    │  }                                                           │
    │                                                              │
    │  # Читать API keys для upstream                              │
    │  path "mcp-gateway/llm-provider-keys/*" {                    │
    │    capabilities = ["read"]                                   │
    │  }                                                           │
    │                                                              │
    │  # Читать DB credentials                                     │
    │  path "mcp-gateway/postgres/gateway-user-password" {         │
    │    capabilities = ["read"]                                   │
    │  }                                                           │
    │                                                              │
    │  # НЕТ доступа к historical HMAC keys                        │
    │  # НЕТ доступа к admin operations                            │
    │                                                              │
    ├──────────────────────────────────────────────────────────────┤
    │                                                              │
    │  Policy: mcp-verifier-app                                    │
    │  ───────────────────────                                     │
    │                                                              │
    │  # Читать ВСЕ версии HMAC keys (для верификации)             │
    │  path "mcp-gateway/audit-hmac-key/*" {                       │
    │    capabilities = ["read"]                                   │
    │  }                                                           │
    │                                                              │
    │  # Читать DB credentials для verifier                        │
    │  path "mcp-gateway/postgres/verifier-user-password" {        │
    │    capabilities = ["read"]                                   │
    │  }                                                           │
    │                                                              │
    │  # НЕТ доступа к API keys                                    │
    │  # НЕТ доступа к admin operations                            │
    │                                                              │
    ├──────────────────────────────────────────────────────────────┤
    │                                                              │
    │  Policy: mcp-admin                                          │
    │  ────────────────                                            │
    │                                                              │
    │  # Full access ко всем mcp-gateway/* paths                   │
    │  path "mcp-gateway/*" {                                      │
    │    capabilities = ["create", "read", "update", "delete",     │
    │                     "list"]                                  │
    │  }                                                           │
    │                                                              │
    │  ⚠️ Только для SRE Lead + Security Team                      │
    │  ⚠️ Audit log всех операций                                  │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

### Auto-rotation

```
    ┌──────────────────────────────────────────────────────────────┐
    │                                                              │
    │  HMAC key rotation (90 дней):                                │
    │                                                              │
    │  OpenBao cronjob (или внешний scheduler):                    │
    │                                                              │
    │  1. Проверить age активного ключа                            │
    │     if age > 90 days:                                        │
    │                                                              │
    │  2. Создать новый ключ (vN+1)                                │
    │     • Сгенерировать 32 random bytes                          │
    │     • Записать в OpenBao: mcp-gateway/audit-hmac-key/vN+1    │
    │     • Пометить как "active"                                  │
    │                                                              │
    │  3. Перевести старый ключ в "verify-only"                    │
    │     • Оставить доступ для verifier                           │
    │     • Убрать доступ для gateway app                          │
    │                                                              │
    │  4. Notify gateway (webhook / OpenBao event)                 │
    │     • Gateway перечитывает активный ключ                     │
    │     • Cache invalidation                                     │
    │     • Graceful switch (без downtime)                         │
    │                                                              │
    │  5. Audit log:                                               │
    │     "hmac_key_rotated: vN → vN+1"                            │
    │                                                              │
    │  SVID rotation (управляется SPIRE, не нами):                 │
    │  • Автоматически каждые 30 минут (TTL 1 час)                 │
    │  • Graceful switch в go-spiffe                                │
    │  • Не требует вмешательства                                   │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

### Backup strategy

```
    ┌──────────────────────────────────────────────────────────────┐
    │                                                              │
    │  Что бэкапить:                                               │
    │                                                              │
    │  • HMAC keys (active + verify-only + archived)               │
    │  • DB credentials                                            │
    │  • API keys для upstream                                     │
    │                                                              │
    │  Что НЕ бэкапить:                                            │
    │  • SVID (кратковременный, генерируется заново)               │
    │  • JWT secrets (управляется IdP)                             │
    │                                                              │
    │  Backup strategy:                                            │
    │                                                              │
    │  1. OpenBao snapshot (Raft)                                  │
    │     • Каждый час                                             │
    │     • Retention: 30 дней                                     │
    │     • Encrypted at rest                                      │
    │                                                              │
    │  2. Sealed backup в S3 (offline)                             │
    │     • Каждый день                                            │
    │     • Retention: 1 год                                       │
    │     • Отдельный encryption key (не в OpenBao)                │
    │     • Разные AWS account / регион                            │
    │                                                              │
    │  3. Test restore (ежемесячно)                                │
    │     • Restore из snapshot в staging                          │
    │     • Verify все keys доступны                               │
    │     • Verify audit verification работает                     │
    │                                                              │
    │  ⚠️ Sealed backup — критично:                                │
    │     Если OpenBao полностью потерян, backup = единственный    │
    │     способ восстановить HMAC keys для верификации            │
    │     audit-записей.                                            │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

### Incident response: компрометация ключа

```
    ┌──────────────────────────────────────────────────────────────┐
    │                                                              │
    │  Если HMAC key скомпрометирован:                             │
    │                                                              │
    │  1. НЕМЕДЛЕННО (0-5 минут):                                  │
    │     • Security Team + CISO: notify                           │
    │     • Freeze gateway (replicas=0)                            │
    │     • Freeze verifier                                        │
    │     • Preserve forensic state (не трогать OpenBao)           │
    │                                                              │
    │  2. ОЦЕНКА (5-30 минут):                                     │
    │     • Определить, какой ключ (vN)                            │
    │     • Найти, когда последний раз использовался                │
    │     • Проверить OpenBao audit log на подозрительные доступы  │
    │     • Оценить, могли ли быть подделаны audit-записи           │
    │                                                              │
    │  3. РОТАЦИЯ (30-60 минут):                                   │
    │     • Создать новый ключ (vN+1)                              │
    │     • Пометить скомпрометированный как "compromised"          │
    │     • НЕ удалять — нужен для forensics                       │
    │     • Gateway → использовать vN+1                            │
    │                                                              │
    │  4. ВЕРИФИКАЦИЯ (часы):                                      │
    │     • Проверить целостность audit log                        │
    │     • Сверить с off-site root hashes (S3 WORM)               │
    │     • Если найдены подделки → incident escalation            │
    │                                                              │
    │  5. УВЕДОМЛЕНИЕ (24-72 часа):                                │
    │     • Затронутые клиенты                                     │
    │     • Регулятор (если требуется по 152-ФЗ / GDPR)            │
    │     • Public disclosure (если нужно)                         │
    │                                                              │
    │  6. POST-MORTEM (1-2 недели):                                │
    │     • Root cause                                              │
    │     • Preventive measures                                     │
    │     • Update threat model + runbook                          │
    │                                                              │
    ├──────────────────────────────────────────────────────────────┤
    │                                                              │
    │  Если SVID скомпрометирован:                                 │
    │                                                              │
    │  1. НЕМЕДЛЕННО:                                              │
    │     • Revoke SVID в SPIRE Server                             │
    │     • Force re-attestation                                    │
    │     • Investigate pod compromise                              │
    │                                                              │
    │  2. Verify:                                                   │
    │     • Что делал скомпрометированный workload                  │
    │     • К каким ресурсам обращался                              │
    │     • Audit log за период компрометации                       │
    │                                                              │
    │  3. Rotate:                                                   │
    │     • Сменить ServiceAccount (если нужно)                    │
    │     • Сменить image SHA в attestation policy                 │
    │     • Restart pods                                            │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

---

## Implementation details

### Go structs

```go
package keymanager

import (
    "context"
    "fmt"
    "sync"
    "time"

    openbao "github.com/openbao/openbao/api/v2"
)

// KeyManager — управление ключами через OpenBao
type KeyManager struct {
    client *openbao.Client
    cache  *KeyCache
}

// HMACKey — HMAC ключ с версией
type HMACKey struct {
    Version   int
    Key       []byte
    CreatedAt time.Time
    Status    string  // "active" | "verify-only" | "compromised" | "archived"
}

// KeyCache — кеш ключей (TTL 5 минут)
type KeyCache struct {
    mu      sync.RWMutex
    keys    map[int]*HMACKey
    active  *HMACKey
    expires time.Time
}

// GetActiveKey возвращает активный HMAC key
func (km *KeyManager) GetActiveKey(ctx context.Context) (*HMACKey, error) {
    // 1. Проверить кеш
    if key, ok := km.cache.GetActive(); ok {
        return key, nil
    }

    // 2. Fetch из OpenBao
    secret, err := km.client.KVv2("mcp-gateway").Get(ctx, "audit-hmac-key/active")
    if err != nil {
        return nil, fmt.Errorf("openbao read failed: %w", err)
    }

    key := &HMACKey{
        Version:   secret.Data["version"].(int),
        Key:       []byte(secret.Data["key"].(string)),
        CreatedAt: secret.Data["created_at"].(time.Time),
        Status:    "active",
    }

    km.cache.SetActive(key)
    return key, nil
}

// GetKeyByVersion возвращает ключ по версии (для verifier)
func (km *KeyManager) GetKeyByVersion(ctx context.Context, version int) (*HMACKey, error) {
    path := fmt.Sprintf("audit-hmac-key/v%d", version)
    secret, err := km.client.KVv2("mcp-gateway").Get(ctx, path)
    if err != nil {
        return nil, err
    }

    return &HMACKey{
        Version:   version,
        Key:       []byte(secret.Data["key"].(string)),
        CreatedAt: secret.Data["created_at"].(time.Time),
        Status:    secret.Data["status"].(string),
    }, nil
}
```

### OpenBao client setup

```go
// NewOpenBaoClient создаёт клиент с AppRole auth
func NewOpenBaoClient(cfg OpenBaoConfig) (*openbao.Client, error) {
    // 1. TLS config (verify OpenBao cert)
    tlsConfig := &tls.Config{
        MinVersion: tls.VersionTLS13,
    }

    // 2. OpenBao client
    config := openbao.DefaultConfig()
    config.Address = cfg.Address
    config.HttpClient.Transport = &http.Transport{
        TLSClientConfig: tlsConfig,
    }

    client, err := openbao.NewClient(config)
    if err != nil {
        return nil, err
    }

    // 3. AppRole auth
    data := map[string]interface{}{
        "role_id":   cfg.RoleID,
        "secret_id": cfg.SecretID,
    }
    resp, err := client.Logical().Write("auth/approle/login", data)
    if err != nil {
        return nil, fmt.Errorf("approle login failed: %w", err)
    }

    client.SetToken(resp.Auth.ClientToken)

    // 4. Auto-renew token
    go renewToken(client, resp.Auth)

    return client, nil
}

// renewToken автоматически продлевает OpenBao token
func renewToken(client *openbao.Client, auth *openbao.SecretAuth) {
    ticker := time.NewTicker(time.Duration(auth.LeaseDuration/2) * time.Second)
    defer ticker.Stop()

    for range ticker.C {
        _, err := client.Auth().Token().RenewSelf(0)
        if err != nil {
            log.Error("openbao token renew failed", "error", err)
            // Retry with backoff или restart pod
        }
    }
}
```

### Key rotation (OpenBao cronjob)

```go
// RotateHMACKey — плановая ротация
func RotateHMACKey(ctx context.Context, client *openbao.Client) error {
    kv := client.KVv2("mcp-gateway")

    // 1. Получить активный ключ
    secret, err := kv.Get(ctx, "audit-hmac-key/active")
    if err != nil {
        return err
    }

    version := secret.Data["version"].(int)
    createdAt := secret.Data["created_at"].(time.Time)

    // 2. Проверить age
    age := time.Since(createdAt)
    if age < 90*24*time.Hour {
        return nil  // Ещё рано
    }

    // 3. Создать новый ключ
    newVersion := version + 1
    newKey := make([]byte, 32)
    if _, err := rand.Read(newKey); err != nil {
        return err
    }

    newPath := fmt.Sprintf("audit-hmac-key/v%d", newVersion)
    _, err = kv.Put(ctx, newPath, map[string]interface{}{
        "key":        base64.StdEncoding.EncodeToString(newKey),
        "created_at": time.Now(),
        "status":     "active",
    })
    if err != nil {
        return err
    }

    // 4. Обновить active pointer
    _, err = kv.Put(ctx, "audit-hmac-key/active", map[string]interface{}{
        "version":    newVersion,
        "created_at": time.Now(),
    })
    if err != nil {
        return err
    }

    // 5. Перевести старый ключ в verify-only
    oldPath := fmt.Sprintf("audit-hmac-key/v%d", version)
    oldSecret, _ := kv.Get(ctx, oldPath)
    oldData := oldSecret.Data
    oldData["status"] = "verify-only"
    kv.Put(ctx, oldPath, oldData)

    // 6. Audit log
    log.Info("hmac_key_rotated",
        "old_version", version,
        "new_version", newVersion)

    return nil
}
```

### Метрики

```
    ┌──────────────────────────────────────────────────────────────┐
    │                                                              │
    │  mcp_gateway_openbao_requests_total{                         │
    │    path,                 # "audit-hmac-key/active"           │
    │    result                # "success" | "error" | "denied"    │
    │  } → counter                                                 │
    │                                                              │
    │  mcp_gateway_openbao_request_duration_seconds{path} → hist   │
    │    buckets: [0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0]        │
    │                                                              │
    │  mcp_gateway_hmac_key_age_seconds{version} → gauge           │
    │    (возраст активного ключа)                                 │
    │                                                              │
    │  mcp_gateway_hmac_key_rotations_total{result} → counter      │
    │    (успешные/неуспешные ротации)                             │
    │                                                              │
    │  mcp_gateway_hmac_key_verify_errors_total{version} → counter │
    │    (ошибки верификации для конкретной версии)                │
    │                                                              │
    │  mcp_gateway_spiffe_svid_ttl_seconds → gauge                 │
    │    (сколько осталось до истечения SVID)                      │
    │                                                              │
    │  mcp_gateway_spiffe_attestation_errors_total{reason} → counter│
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

### Alerting

```
    ┌──────────────────────────────────────────────────────────────┐
    │                                                              │
    │  Critical (page on-call):                                    │
    │                                                              │
    │  • OpenBao недоступен >2m                                    │
    │  • HMAC key rotation failed                                  │
    │  • SVID TTL <5m                                              │
    │  • OpenBao token renewal failed                              │
    │  • HMAC key verify errors >0                                 │
    │                                                              │
    │  Warning (notify team):                                      │
    │                                                              │
    │  • HMAC key age >80 дней (приближается ротация)              │
    │  • SVID TTL <15m                                             │
    │  • OpenBao latency p99 >100ms                                │
    │  • OpenBao audit log storage >80% capacity                   │
    │  • SPIRE agent errors >0                                     │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

### Rollout plan

```
    ┌──────────────────────────────────────────────────────────────┐
    │                                                              │
    │  Phase 1: OpenBao setup — 1 неделя                           │
    │  ─────────────────────                                       │
    │  • Развернуть OpenBao HA (3 nodes, Raft storage)             │
    │  • Настроить AppRole auth                                    │
    │  • Создать policies (mcp-gateway-app, verifier, admin)       │
    │  • Настроить audit log (file + syslog)                       │
    │  • Настроить backup (snapshot + sealed S3)                   │
    │                                                              │
    │  Phase 2: HMAC keys migration — 1 неделя                     │
    │  ─────────────────────────────                               │
    │  • Создать initial HMAC key (v1)                             │
    │  • Обновить gateway: читать key из OpenBao                   │
    │  • Обновить verifier: читать все версии                      │
    │  • Integration test: rotation flow                           │
    │                                                              │
    │  Phase 3: SPIRE integration — 1 неделя                       │
    │  ────────────────────────────                                │
    │  • Развернуть SPIRE Server (HA)                              │
    │  • Развернуть SPIRE Agent (DaemonSet)                        │
    │  • Настроить WorkloadAttestor (K8s SA + image SHA)           │
    │  • Интегрировать go-spiffe в gateway                         │
    │  • Integration test: SVID rotation                           │
    │                                                              │
    │  Phase 4: Auto-rotation — 1 неделя                           │
    │  ────────────────────────                                    │
    │  • Cronjob для HMAC rotation (OpenBao)                       │
    │  • Webhook для gateway (cache invalidation)                  │
    │  • Test: rotation без downtime                               │
    │                                                              │
    │  Phase 5: Incident response — ongoing                        │
    │  ───────────────────────────                                 │
    │  • Playbook для key compromise                               │
    │  • Test quarterly (tabletop exercise)                        │
    │  • Update threat model                                        │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

### Known limitations

```
    ┌──────────────────────────────────────────────────────────────┐
    │                                                              │
    │  1. OpenBao как single point of failure                      │
    │     ⚠️ Если OpenBao down → gateway не может читать keys      │
    │     💡 Митигация:                                             │
    │        • OpenBao HA (3 nodes)                                │
    │        • Auto-unseal                                         │
    │        • Cache keys в gateway (TTL 5 мин)                    │
    │        • Fail-open для active keys (уже в кэше)              │
    │                                                              │
    │  2. OpenBao token renewal                                    │
    │     ⚠️ Token может истечь → потеря доступа                    │
    │     💡 Митигация:                                             │
    │        • Auto-renew в фоне                                   │
    │        • Alert при renew failure                             │
    │        • Restart pod при повторных failure                   │
    │                                                              │
    │  3. Storage backend                                          │
    │     ⚠️ OpenBao поддерживает только Raft + PostgreSQL         │
    │        (в отличие от Vault с Consul, DynamoDB и т.д.)        │
    │     💡 Для нашего use case Raft достаточно                    │
    │                                                              │
    │  4. Token format migration                                    │
    │     ⚠️ OpenBao использует sbr.xxx вместо hvs.xxx             │
    │     ⚠️ Старые Vault tokens остаются валидными до TTL         │
    │     💡 При миграции — перевыпустить все tokens               │
    │                                                              │
    │  5. Performance overhead                                      │
    │     ⚠️ ~21% медленнее Vault с Raft storage                   │
    │     💡 Не критично для secrets reads (1-2 раза в час)        │
    │                                                              │
    │  6. Plugin ecosystem                                          │
    │     ⚠️ Некоторые Vault-плагины не портированы в OpenBao      │
    │        (AWS auth, GCP auth — нужно проверять)                │
    │     💡 Для нашего use case AppRole достаточно                │
    │                                                              │
    │  7. Backup encryption key                                     │
    │     ⚠️ Sealed backup в S3 требует отдельный encryption key    │
    │        НЕ в OpenBao                                          │
    │     💡 Хранить в AWS KMS / Yandex KMS / физический HSM       │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

---

## Rationale

### Почему OpenBao, а не HashiCorp Vault

**Vault:**

- Industry standard.
- Зрелый.
- Но: BSL 1.1 license → платно для коммерческого использования.
- Vendor lock (HashiCorp → IBM).

**OpenBao:**

- MPL 2.0 license → бесплатно.
- Linux Foundation governance.
- API-compatible с Vault.
- Community-driven.

**Для российского enterprise-контекста:** OpenBao критичен, потому что:
- Нет юридических рисков (BSL → оплата).
- Нет vendor lock в недружественной юрисдикции.
- Полный контроль над кодом.

**Решение:** OpenBao.

### Почему OpenBao, а не Infisical

**Infisical:**

- Современный UI.
- Лёгкий.
- Но: менее зрелый.
- Меньше feature parity с Vault.
- Некоторые функции — только в платных тарифах.

**OpenBao:**

- Полная совместимость с Vault API.
- Готовые плагины для SPIFFE/SPIRE.
- Enterprise features бесплатно.

**Решение:** OpenBao.

### Почему AppRole, а не Kubernetes auth

**Kubernetes auth:**

- Работает из коробки в K8s.
- Автоматическая аттестация через SA token.
- Но: привязка к K8s.

**AppRole:**

- Работает везде (K8s, bare-metal, on-prem).
- role_id + secret_id как credentials.
- Более гибкий.

**Для heterogenous-среды:** AppRole предпочтительнее.

**Решение:** AppRole.

### Почему 90 дней для HMAC rotation

**Меньше 30 дней:**

- Слишком часто.
- Много operational overhead.
- Риск пропустить rotation.

**Больше 180 дней:**

- Слишком редко.
- Compliance риски.
- Больший impact при компрометации.

**90 дней:**

- Industry standard (NIST, PCI DSS).
- Достаточно часто для security.
- Не слишком обременительно.

**Решение:** 90 дней.

### Почему cache TTL 5 минут

**Меньше 1 минуты:**

- Много запросов в OpenBao.
- OpenBao под нагрузкой.

**Больше 30 минут:**

- Долго до применения rotation.
- Risk при компрометации.

**5 минут:**

- Баланс между нагрузкой и свежестью.
- При rotation — 5 минут до применения.
- OpenBao нагрузка минимальная (1-2 запроса в час).

**Решение:** 5 минут.

---

## Consequences

### Positive

- **Open source (MPL 2.0)** — нет юридических рисков.
- **Linux Foundation** — community-driven, не vendor lock.
- **API-compatible с Vault** — миграция простая.
- **SPIFFE/SPIRE интеграция** — из коробки.
- **RBAC policies** — разделение ролей.
- **Auto-rotation** — HMAC 90 дней.
- **Backup strategy** — sealed backup в S3.
- **Incident response** — playbook для компрометации.
- **Compliance-ready** — 152-ФЗ, GDPR, PCI DSS, HIPAA.

### Negative

- **OpenBao dependency** — если OpenBao down, gateway не может читать keys.
  Митигация: HA + cache.
- **Storage ограничения** — только Raft + PostgreSQL.
  Митигация: Raft достаточно.
- **Token format migration** — sbr.xxx вместо hvs.xxx.
  Митигация: перевыпуск токенов.
- **Performance ~21% медленнее** — не критично для reads.
- **Plugin ecosystem** — не все Vault-плагины портированы.
  Митигация: AppRole достаточно.

### Neutral

- **OpenBao CLI (bao)** — новая команда (вместо vault).
- **Go SDK** — `github.com/openbao/openbao/api/v2`.
- **Environment variables** — `BAO_ADDR` вместо `VAULT_ADDR`.

---

## Failure modes

### OpenBao недоступен

```
    ┌──────────────────────────────────────────────────────────────┐
    │                                                              │
    │  Симптом: gateway не может читать HMAC key                   │
    │                                                              │
    │  Поведение:                                                  │
    │  1. Cache hit (TTL 5 мин) → использовать закешированный key  │
    │  2. Cache miss → fail-closed (503)                           │
    │                                                              │
    │  ⚠️ Для gateway — fail-closed (без audit key нельзя работать)│
    │  ⚠️ Для verifier — fail-closed (без верификации нельзя)      │
    │                                                              │
    │  Detection:                                                  │
    │  • Алерт: mcp_gateway_openbao_requests_total{result="error"} │
    │  • Алерт: openbao_up == 0 > 2m                               │
    │                                                              │
    │  Mitigation:                                                 │
    │  • OpenBao HA (3 nodes)                                      │
    │  • Auto-restart pod                                          │
    │  • Network diagnostics                                        │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

### HMAC key rotation failed

```
    ┌──────────────────────────────────────────────────────────────┐
    │                                                              │
    │  Симптом: cronjob не смог создать новый key                  │
    │                                                              │
    │  Причины:                                                    │
    │  • OpenBao недоступен                                        │
    │  • RBAC policy не позволяет write                            │
    │  • Bug в cronjob                                             │
    │                                                              │
    │  ⚠️ Не критично для работы (старый key работает)             │
    │  ⚠️ Но: приближается срок ротации                            │
    │                                                              │
    │  Detection:                                                  │
    │  • Алерт: mcp_gateway_hmac_key_rotations_total{result=fail}  │
    │  • Алерт: mcp_gateway_hmac_key_age_seconds > 100 days        │
    │                                                              │
    │  Mitigation:                                                 │
    │  • Manual rotation через admin API                           │
    │  • Verify RBAC policies                                       │
    │  • Debug cronjob logs                                         │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

### SVID attestation failed

```
    ┌──────────────────────────────────────────────────────────────┐
    │                                                              │
    │  Симптом: SPIRE Agent не может аттестовать pod               │
    │                                                              │
    │  Причины:                                                    │
    │  • Image SHA изменился (deploy новой версии)                 │
    │  • ServiceAccount переименован                                │
    │  • SPIRE Server недоступен                                    │
    │                                                              │
    │  Поведение:                                                  │
    │  • SVID остаётся валидным до истечения TTL                   │
    │  • После истечения → fail-closed (503)                       │
    │                                                              │
    │  Detection:                                                  │
    │  • Алерт: mcp_gateway_spiffe_attestation_errors_total > 0    │
    │  • Алерт: mcp_gateway_spiffe_svid_ttl_seconds < 15m          │
    │                                                              │
    │  Mitigation:                                                 │
    │  • Verify ServiceAccount name                                │
    │  • Update image SHA в SPIRE registration                     │
    │  • Restart SPIRE Agent                                        │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

### Компрометация HMAC key

```
    ┌──────────────────────────────────────────────────────────────┐
    │                                                              │
    │  Симптом: обнаружена компрометация ключа                      │
    │                                                              │
    │  Причины:                                                    │
    │  • Утечка secret_id AppRole                                  │
    │  • Компрометация пода gateway                                │
    │  • Insider threat                                             │
    │                                                              │
    │  ⚠️ CRITICAL — потенциальная подделка audit log              │
    │                                                              │
    │  Действия (см. Incident response в разделе выше):            │
    │  1. Freeze gateway + verifier                                │
    │  2. Security Team + CISO notify                              │
    │  3. Оценка масштаба                                          │
    │  4. Ротация ключа                                             │
    │  5. Верификация с off-site root hashes                       │
    │  6. Уведомление регулятора (если нужно)                      │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

### OpenBao token renewal failed

```
    ┌──────────────────────────────────────────────────────────────┐
    │                                                              │
    │  Симптом: token истёк, gateway не может читать keys          │
    │                                                              │
    │  Причины:                                                    │
    │  • Network glitch                                             │
    │  • OpenBao overloaded                                        │
    │  • Bug в renewal logic                                        │
    │                                                              │
    │  Поведение:                                                  │
    │  • Cache продолжает работать (TTL 5 мин)                     │
    │  • После TTL → fail-closed                                    │
    │                                                              │
    │  Detection:                                                  │
    │  • Алерт: mcp_gateway_openbao_token_renew_errors_total > 0   │
    │                                                              │
    │  Mitigation:                                                 │
    │  • Retry с exponential backoff                               │
    │  • Restart pod при повторных failure                         │
    │  • Verify AppRole secret_id valid                            │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

---

## Alternatives considered

### Alternative 1: HashiCorp Vault (BSL 1.1)

**Плюсы:**
- Industry standard.
- Зрелый.
- Много features.

**Минусы:**
- BSL 1.1 license → платно для commercial use.
- Vendor lock (HashiCorp → IBM).
- Enterprise features за отдельную плату.

**Решение:** отклонено. OpenBao — fork с MPL 2.0.

### Alternative 2: Infisical (open-source)

**Плюсы:**
- Современный UI.
- Лёгкий.
- MIT license (core).

**Минусы:**
- Менее зрелый.
- Меньше feature parity с Vault.
- Некоторые функции — только платно.
- Нет встроенной SPIFFE интеграции.

**Решение:** отклонено. OpenBao предпочтительнее для enterprise.

### Alternative 3: AWS Secrets Manager / Yandex Lockbox

**Плюсы:**
- Managed.
- HA из коробки.
- Интеграция с cloud.

**Минусы:**
- Vendor lock.
- Дорого на объёме.
- Не работает вне cloud.
- Нет AppRole.

**Решение:** отклонено. OpenBao работает везде.

### Alternative 4: SOPS + git

**Плюсы:**
- Просто.
- GitOps-friendly.
- Бесплатно.

**Минусы:**
- Нет server.
- Нет dynamic secrets.
- Нет rotation.
- Нет RBAC.

**Решение:** отклонено. Не подходит для enterprise.

### Alternative 5: Kubernetes Secrets (native)

**Плюсы:**
- Встроено в K8s.
- Просто.

**Минусы:**
- Не encrypted at rest (по умолчанию).
- Нет rotation.
- Нет audit log.
- Нет RBAC (только K8s RBAC).

**Решение:** отклонено. Недостаточно для enterprise.

### Alternative 6: Своё решение

**Плюсы:**
- Полный контроль.

**Минусы:**
- 6+ месяцев разработки.
- Криптография — сложно.
- Нет community.

**Решение:** отклонено. OpenBao покрывает все нужды.

---

## Action items

Задачи, вытекающие из этого ADR:

- [ ] **OpenBao deployment**:
  - Helm chart (HA, 3 nodes, Raft)
  - TLS сертификаты
  - Auto-unseal (AWS KMS / Yandex KMS)
  - Backup strategy (snapshot + sealed S3)

- [ ] **RBAC policies**:
  - `mcp-gateway-app` — read active keys
  - `mcp-verifier-app` — read all HMAC versions
  - `mcp-admin` — full access
  - Unit tests для policies

- [ ] **AppRole setup**:
  - Создать role для gateway
  - Создать role для verifier
  - SecretID rotation (90 дней)
  - Integration test

- [ ] **Gateway integration**:
  - OpenBao Go client (`github.com/openbao/openbao/api/v2`)
  - KeyManager с cache (TTL 5 мин)
  - Auto-renew token
  - Fallback на cached keys при недоступности

- [ ] **HMAC key rotation**:
  - CronJob (OpenBao side) или external scheduler
  - Webhook → gateway cache invalidation
  - Integration test: rotation без downtime
  - Rollback plan при failed rotation

- [ ] **SPIRE integration**:
  - SPIRE Server (HA)
  - SPIRE Agent (DaemonSet)
  - WorkloadAttestor (K8s SA + image SHA)
  - go-spiffe integration в gateway

- [ ] **Метрики**:
  - `mcp_gateway_openbao_requests_total{path, result}`
  - `mcp_gateway_openbao_request_duration_seconds{path}`
  - `mcp_gateway_hmac_key_age_seconds{version}`
  - `mcp_gateway_hmac_key_rotations_total{result}`
  - `mcp_gateway_spiffe_svid_ttl_seconds`

- [ ] **Alerting**:
  - OpenBao down
  - HMAC key rotation failed
  - SVID TTL <15m
  - Token renewal failed
  - HMAC verify errors

- [ ] **Backup**:
  - Hourly Raft snapshot
  - Daily sealed backup в S3
  - Monthly restore test
  - Separate encryption key для backup

- [ ] **Incident response**:
  - Playbook для key compromise
  - Playbook для SVID compromise
  - Tabletop exercise (quarterly)
  - Update threat model

- [ ] **Documentation**:
  - Обновить `docs/blueprint.md` — OpenBao в capabilities
  - Обновить `docs/security/threat-model.md` — Key compromise threats
  - Обновить `docs/reliability/runbook.md` — incident procedures

---

## References

- [OpenBao: официальная документация](https://openbao.org/)
- [OpenBao: миграция с Vault](https://openbao.org/docs/installation/migrating-from-vault/)
- [OpenBao: Go SDK](https://github.com/openbao/openbao/tree/main/api)
- [Linux Foundation: OpenBao announcement](https://www.linuxfoundation.org/press/announcing-openbao)
- [HashiCorp: BSL 1.1 license change](https://www.hashicorp.com/blog/hashicorp-adopts-business-source-license)
- [SPIFFE: Upstream Authority plugins](https://spiffe.io/docs/latest/deploying/spire_server/)
- [NIST SP 800-57: Key Management](https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final)
- [NIST SP 800-92: Log Management](https://csrc.nist.gov/publications/detail/sp/800-92/final)
- [PCI DSS v4.0: Key Management Req. 3.5-3.7](https://www.pcisecuritystandards.org/)

---

## Related ADRs

- [ADR-0001: SPIFFE/SPIRE для mTLS](0001-use-spiffe-for-mtls.md) — SVID управляется SPIRE, ключи в OpenBao
- [ADR-0002: HMAC hash-chain для audit log](0002-hmac-hash-chain-for-audit.md) — HMAC keys в OpenBao
- [ADR-0006: Observability stack](0006-observability-stack.md) — метрики OpenBao
- [ADR-0009: PII redaction](0009-pii-redaction.md) — redaction events логируются в audit