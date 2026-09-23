# MCP Gateway: Production Blueprint

## 1. Проблема и контекст
TODO

## 2. Целевая архитектура
TODO (C4 Container diagram)

## 3. Ключевые архитектурные решения
- [ADR-0001: SPIFFE для mTLS](adr/0001-use-spiffe-for-mtls.md)
- [ADR-0002: HMAC hash-chain для audit](adr/0002-hmac-hash-chain-for-audit.md)
- [ADR-0003: Redis для rate limiting](adr/0003-redis-for-rate-limiting.md)
- [ADR-0004: tenant_id в context](adr/0004-tenant-id-in-context.md)
- [ADR-0005: gobreaker для circuit breaker](adr/0005-circuit-breaker-library-choice.md)

## 4. Безопасность и compliance
См. [Threat Model](security/threat-model.md)

## 5. Надёжность и SLO
См. [SLO](reliability/slo.md)

## 6. Multi-tenancy
TODO

## 7. Deployment
TODO

## 8. Observability
TODO

## 9. Roadmap / ограничения
TODO

## 10. Ссылки
TODO