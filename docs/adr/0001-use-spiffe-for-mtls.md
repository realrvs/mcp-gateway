# ADR-0001: Использование SPIFFE/SPIRE для mTLS между компонентами

- **Status:** Accepted
- **Date:** 2026-09-23
- **Deciders:** Roman Sokolov (Architect)
- **Tags:** `security`, `identity`, `mtls`, `zero-trust`

---

## Context

MCP Gateway — точка входа для трафика между AI-агентами (клиенты) и
upstream-сервисами (LLM API, MCP-серверы с инструментами, legacy-системы вроде 1С/SAP/EIS).
В production-среде требуется:

1. **Взаимная аутентификация** (mTLS) между всеми участниками — клиентом,
   gateway, upstream-сервисами. Односторонний TLS (только клиент проверяет сервер)
   недостаточен: нужно, чтобы gateway тоже знал, **кто именно** к нему пришёл.
2. **Проверяемая identity** — не просто «валидный сертификат», а конкретный
   workload: под `mcp-gateway` в namespace `mcp`, а не любой под с тем же сертификатом.
3. **Автоматическая ротация** сертификатов без перезапуска сервисов.
4. **Работа в heterogenous-среде:** Kubernetes в production, docker-compose
   локально, потенциально bare-metal в изолированных контурах заказчиков.
5. **Zero Trust**-модель: не доверять сети, проверять каждый запрос.

Существующие альтернативы (self-signed, Istio mTLS, cloud IAM) имеют ограничения,
описанные ниже в разделе «Alternatives considered».

---

## Decision

**Используем SPIFFE/SPIRE** как источник identity для всех внутренних
mTLS-соединений:

- **SPIFFE ID** — стандартизированный URI-идентификатор workload:
  `spiffe://<trust-domain>/ns/<namespace>/sa/<service-account>`
- **SVID** (SPIFFE Verifiable Identity Document) — X.509-сертификат с SPIFFE ID
  в Subject Alternative Name (SAN), выдаваемый SPIRE Agent через Workload API
- **SPIRE Server** — выдает SVID после аттестации workload
- **WorkloadAttestor `k8s`** — в production аттестация по namespace + service account +
  selector на образ (SHA256 образа)
- **WorkloadAttestor `unix`** — для локальной разработки в docker-compose
- **`github.com/spiffe/go-spiffe/v2`** — клиентская библиотека для Go
- **Ротация SVID** — автоматическая, через Workload API stream; TTL 1 час

**Авторизация:** SPIFFE ID allowlist для входящих вызовов. Не всякий SVID
имеет право дергать `tools/call` — только те, чьи SPIFFE ID внесены
в конфигурацию разрешённых клиентов для данного тенанта.

### SPIFFE ID vs tenant_id: разделение ответственности

Важно чётко разграничить два уровня identity:

| Уровень | Что идентифицирует | Где извлекается | Формат |
|---------|-------------------|-----------------|--------|
| **Transport (L4/L5)** | Workload (сервис, под, процесс) | mTLS handshake, SPIFFE SVID | `spiffe://<trust-domain>/ns/<ns>/sa/<sa>` |
| **Application (L7)** | Tenant (клиент gateway) | JWT claim `tenant_id` или HTTP-заголовок внутри TLS-туннеля | Строка-идентификатор тенанта |

**Ключевое правило:** SPIFFE отвечает **только за workload identity** —
кто именно (какой под/сервис) к нам пришёл. `tenant_id` — это **application-level**
атрибут, который передаётся **внутри** зашифрованного TLS-туннеля в JWT или заголовке.

**Следствия:**

- Один workload (например, `mcp-gateway` в namespace `mcp`) имеет **один SPIFFE ID**,
  независимо от того, сколько тенантов он обслуживает.
- Разграничение тенантов происходит **на уровне приложения** через tenant resolver
  middleware (см. ADR-0004).
- Мы **не создаём отдельные Workload Entry** для каждого тенанта — это привело бы
  к комбинаторному взрыву (N тенантов × M сред × K версий).
- Но: SPIFFE ID **может** использоваться в policy-решениях совместно с `tenant_id`
  (например, «тенант X принимает запросы только от SPIFFE ID агента Y»).

---

## Rationale

### Почему SPIFFE, а не «просто mTLS с самоподписанными сертификатами»

Самоподписанные сертификаты требуют ручного управления: создание, распространение,
ротация, отзыв. Это операционный ад, который в enterprise-среде превращается
в отдельный full-time проект. SPIFFE решает это через:

- **Автоматическую аттестацию** — workload доказывает свою идентичность
  через k8s API, а не через владение файлом с сертификатом
- **Автоматическую ротацию** — SVID имеет TTL, обновляется библиотекой
  прозрачно для приложения
- **Единый формат identity** — работает и в K8s, и вне его, не привязывает
  к конкретному cloud provider

### Почему не Istio mTLS

Istio предоставляет mTLS «из коробки», но:

- Требует установки всего service mesh — это **существенный overhead** для
  одного gateway, если у заказчика его ещё нет
- **Привязан к Kubernetes** — не работает в docker-compose (локальная разработка)
  и на bare-metal (изолированные контуры заказчиков)
- SPIFFE-идентичность в Istio есть, но она «внутри mesh», а нам нужна
  сквозная identity, включая входящие вызовы **снаружи** mesh
- Отладка проблем с Istio mTLS существенно сложнее, чем со SPIFFE

При этом важно: **SPIFFE-идентификаторы используются в Istio** — если
у заказчика уже есть Istio, наш gateway с SPIFFE SVID интегрируется с ним
напрямую (Istio поддерживает SPIFFE federation).

### Почему не cloud IAM (AWS IRSA, GCP Workload Identity, Azure Managed Identity)

- **Привязка к cloud provider** — мы не можем предположить, что заказчик
  использует AWS/GCP/Azure. Enterprise-контуры часто on-prem или в
  изолированных облаках (Yandex Cloud, VK Cloud)
- **Не работает за пределами облака** — при миграции или в гибридной среде
  identity ломается
- **Формат identity нестандартный** — нельзя использовать единый
  механизм авторизации в разных средах

### Почему WIMSE-совместимость важна

WIMSE (Workload Identity in Multi-System Environments) — развивающийся
стандарт IETF, расширяющий SPIFFE на multi-system сценарии (в том числе
AI-агенты). Наш проект **совместим с WIMSE** по identity-модели, что
соответствует стратегическому направлению развития агентных платформ.

---

## Consequences

### Positive

- **Переносимая identity** — работает в K8s, docker-compose, bare-metal
- **Zero Trust** — соответствует NIST SP 800-207
- **Автоматическая ротация** — операционная нагрузка минимальна
- **Совместимость с Istio** — интеграция, если у заказчика уже есть mesh
- **WIMSE-ready** — соответствует стратегическому направлению
- **Общий стандарт** — SPIFFE принят в CNCF, поддерживается крупными
  вендорами (HashiCorp, Google, Uber, Bloomberg)

### Negative

- **Операционная сложность** — добавляются 2 компонента: SPIRE Server
  и SPIRE Agent. В production это требует отдельного контроля, бэкапов
  и мониторинга
- **Обучение команды** — концепции SPIFFE (attestation, trust domain,
  SVID, workload entry) требуют времени на освоение
- **Локальная разработка сложнее** — нужен SPIRE в docker-compose,
  что добавляет ~500 MB к dev-окружению
- **Зависимость от SPIRE Agent** — если агент недоступен, новые SVID
  не выдаются (существующие продолжают работать до истечения TTL).
  См. раздел **Failure modes** ниже

### Neutral

- **Небольшой overhead на handshake** — SPIFFE SVID верифицируется
  за счёт коротких цепочек сертификатов, задержка <1ms. Для нашего
  профиля трафика (единицы секунд на вызов LLM) это пренебрежимо
- **Trust domain** — выбирается один раз при развёртывании, потом
  менять его больно. В нашем случае: `spiffe://mcp-gateway.local`
  для dev, `spiffe://<org>.internal` для production
- **SPIFFE Federation** — для внешних AI-агентов (из других кластеров
  или trust domain заказчика) потребуется настроить federation.
  См. раздел **Trust Domain Federation** ниже

---

## Failure modes

Поведение gateway при отказах SPIRE-компонентов:

### SPIRE Server недоступен

- **Что происходит:** SPIRE Agent продолжает работать на кэше выданных
  SVID и ключей. Существующие SVID продлеваются агентом до истечения
  их TTL (максимум 1 час после последнего успешного контакта с сервером).
- **Что делает gateway:** ничего не замечает — SVID продолжают работать.
- **Что делать:** алерт на `spire_server_up == 0` в течение >5 минут.
  Восстановление сервера в течение часа возвращает систему в норму без
  перезапуска gateway.
- **Долгосрочный сбой:** если сервер недоступен >1 часа, SVID истекают,
  новые выдать нельзя → gateway не может установить новые соединения
  с upstream. Это состояние деградации, требует эскалации.

### SPIRE Agent недоступен на ноде

- **Что происходит:** workload не может получить **новый** SVID, но
  текущий продолжает работать до истечения TTL.
- **Что делает gateway:** периодически пытается переподключиться
  к Workload API сокету с **exponential backoff** (100ms → 30s).
  Существующие соединения не разрываются.
- **Алерт:** `mcp_gateway_spiffe_svid_ttl_seconds < 900` (TTL <15 минут) →
  предупреждение. Это даёт окно на реакцию.
- **Критический сценарий:** если агент не восстановился до истечения TTL,
  gateway переходит в **fail-closed** режим: отклоняет новые запросы
  с `503 Service Unavailable` и метрикой `mcp_gateway_spiffe_unavailable_total`.
  Существующие **долгоживущие соединения** продолжают обрабатывать
  запросы — это частичная деградация, а не полный отказ.

### SVID не выдан при старте gateway

- **Что происходит:** под стартует, но SPIRE Agent недоступен или
  аттестация не проходит (например, образ не совпадает с selector).
- **Что делает gateway:** не переходит в `ready` state. `readinessProbe`
  возвращает `503`. Kubernetes **не отправляет трафик** на этот под
  (rolling update останавливается, если новый под не готов).
- **Правильная реакция:** не убивать под бесконечно (это убьёт диагностику),
  а оставить в `CrashLoopBackOff` после N попыток и разбираться вручную.
  В K8s это настраивается через `startupProbe` с `failureThreshold: 30`.

### Мониторинг SPIRE

Обязательные метрики (Prometheus):
- `spire_server_up`, `spire_agent_up` — доступность компонентов
- `mcp_gateway_spiffe_svid_ttl_seconds` — сколько осталось до истечения SVID
- `mcp_gateway_spiffe_errors_total{reason}` — ошибки аттестации, выдачи, подписи
- `mcp_gateway_spiffe_reconnect_attempts_total` — количество попыток
  переподключения к Workload API

Алерты (см. `docs/reliability/runbook.md`):
- `SVID TTL <15m` → warning
- `SVID TTL <5m` → critical, page on-call
- `spire_server_up == 0` >5m → warning
- `spire_agent_up == 0` >2m → critical

---

## Trust Domain Federation

Если в системе появляются **внешние AI-агенты** из других trust domain
(например, другой K8s-кластер, другой SPIRE Server, или партнёрская
система заказчика), применяется **SPIFFE Federation**:

### Что это даёт

- Внешний агент имеет SVID из **своего** trust domain (например,
  `spiffe://partner.example.com/...`)
- Наш gateway **доверяет** этому trust domain на основе федерации
  (обмен trust bundles между SPIFFE-совместимыми серверами)
- Авторизация по SPIFFE ID **партнёра** возможна через allowlist в конфиге
  (например, «тенант X принимает запросы от SPIFFE ID
  `spiffe://partner.example.com/ns/agents/sa/agent-y`»)

### Что нужно настроить

1. **SPIFFE Federation** через `federation relationships` между двумя
   SPIFFE-совместимыми серверами (нашим SPIRE Server и партнёрским)
2. **Bundle endpoint** — HTTPS-эндпоинт для обмена trust bundles
   (должен быть доступен из внешней сети)
3. **Авторизация по партнёрскому SPIFFE ID** — добавляется в конфиг
   gateway per-tenant allowlist
4. **Мониторинг federation** — алерты на устаревание bundle (`bundle_age_seconds`)

### Что НЕ делаем

- **Не выдаём SVID внешним агентам** из нашего trust domain — это
  нарушает Zero Trust (внешний агент не проходит нашу аттестацию)
- **Не используем `spiffe://` как application-level identity** — для
  разграничения тенантов по-прежнему используется `tenant_id` (см.
  раздел «SPIFFE ID vs tenant_id»)

### Что это даёт в долгосрочной перспективе

SPIFFE Federation — **это то, что делает identity переносимой между
организациями**. Если заказчик уже использует SPIFFE в своей
инфраструктуре, наш gateway встраивается в его trust fabric без
дополнительных механизмов (VPN, shared secrets, IP allowlist).
Это отличает SPIFFE от Istio mTLS (внутри одного mesh) и cloud IAM
(внутри одного cloud provider).

---

## Alternatives considered

### Alternative 1: Самоподписанные сертификаты

**Плюсы:**
- Минимальная сложность
- Работает везде, где есть TLS
- Не требует дополнительных компонентов

**Минусы:**
- Ручное управление ротацией — либо короткий TTL и боль, либо длинный TTL
  и компромисс безопасности
- Нет аттестации workload — владение файлом сертификата = identity
- Отзыв сертификата = отдельная проблема (CRL/OCSP), которую нужно
  самостоятельно реализовать

**Решение:** отклонено. Операционная нагрузка неприемлема для enterprise.

### Alternative 2: Istio mTLS

**Плюсы:**
- Готовое решение, много документации
- Интеграция с observability

**Минусы:**
- Привязка к K8s + Istio — не работает локально и на bare-metal
- Overhead на весь mesh
- Не покрывает входящие вызовы снаружи

**Решение:** отклонено как основное. Если у заказчика уже есть Istio,
наши SPIFFE SVID интегрируются с ним — но мы не полагаемся на Istio.

### Alternative 3: Cloud IAM (AWS IRSA / GCP Workload Identity)

**Плюсы:**
- Простота в облаке
- Интеграция с облачными сервисами

**Минусы:**
- Привязка к cloud provider
- Не работает вне облака
- Нестандартный формат identity

**Решение:** отклонено. Проект должен работать в любом окружении.

### Alternative 4: HashiCorp Vault для PKI

**Плюсы:**
- Мощная PKI, много возможностей
- Уже используется в enterprise-среде

**Минусы:**
- Vault — тяжёлая зависимость, отдельный компонент
- Аттестация workload в Vault реализуется сложнее, чем в SPIRE
- Не является стандартом для workload identity

**Решение:** отклонено. Vault может использоваться **дополнительно**
для хранения HMAC-ключей (см. ADR-0002), но не как источник identity.

---

## References

- [SPIFFE Standard](https://spiffe.io/docs/latest/spiffe-about/overview/)
- [SPIRE Documentation](https://spiffe.io/docs/latest/spire-about/)
- [SPIFFE Federation](https://spiffe.io/docs/latest/architecture/federation/README/)
- [NIST SP 800-207: Zero Trust Architecture](https://csrc.nist.gov/publications/detail/sp/800-207/final)
- [WIMSE IETF Working Group](https://datatracker.ietf.org/group/wimse/about/)
- [go-spiffe/v2 library](https://github.com/spiffe/go-spiffe)
- [Istio + SPIFFE integration](https://istio.io/latest/docs/ops/integrations/spire/)

---

## Related ADRs

- [ADR-0002: HMAC hash-chain для audit log](0002-hmac-hash-chain-for-audit.md) — использует SVID для подписи записей
- [ADR-0004: tenant_id в context](0004-tenant-id-in-context.md) — tenant_id извлекается после SPIFFE-аутентификации