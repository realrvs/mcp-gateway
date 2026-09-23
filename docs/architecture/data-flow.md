# Data Flow

## Поток tools/call
1. Client → mTLS handshake
2. TenantResolver → tenant_id
3. Auth → SPIFFE ID
4. RateLimit → check per tenant
5. PII detect + mask
6. Audit → log (hash-chain)
7. CircuitBreaker → check upstream
8. Upstream LLM call
9. PII unmask
10. Audit → log response
11. Client ← response