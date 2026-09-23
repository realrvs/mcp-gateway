# Threat Model: MCP Gateway

## Scope
TODO

## Assets
- PII в промптах
- API-ключи upstream
- HMAC-ключи audit log
- SVID сертификаты
- Tenant config

## Trust Boundaries
См. [trust-boundaries.md](../architecture/trust-boundaries.md)

## Threats (STRIDE)

### Spoofing
**T-01: Подмена SPIFFE ID**
- Vector: TODO
- Mitigation: TODO
- Residual risk: TODO

### Tampering
**T-03: Модификация audit log**
- Vector: TODO
- Mitigation: HMAC + hash-chain
- Detection: periodic verify job

### Repudiation
TODO

### Information Disclosure
**T-05: Утечка PII в upstream LLM**
- Vector: detector miss
- Mitigation: multi-layer detection
- Residual risk: MEDIUM

### Denial of Service
TODO

### Elevation of Privilege
**T-07: Cross-tenant access**
- Mitigation: tenant_id в контексте + namespacing
- Verification: integration test