# Trust Boundaries

1. Client → Gateway (mTLS, SPIFFE)
2. Gateway → SPIRE Agent (Unix socket)
3. Gateway → Redis (mTLS)
4. Gateway → Postgres (mTLS)
5. Gateway → Upstream LLM (HTTPS)