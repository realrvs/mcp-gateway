# SLO: MCP Gateway

## Service Level Indicators (SLI)

### Availability
- SLI: доля успешных запросов (2xx/3xx) / все
- Измерение: ate(mcp_requests_total{status!~"5.."}[5m])
- Окно: 30 дней

### Latency
- SLI: p99 для tools/call
- Измерение: histogram mcp_request_duration_seconds
- Порог: < 2s (без upstream), < 30s (с upstream)

## SLO
- 99.9% availability (43.2 мин/месяц)
- p99 < 2s для 95% 5-минутных окон

## SLO по тенантам
- Enterprise: 99.95%
- Standard: 99.9%
- Free: best-effort

## Что НЕ входит в SLO
- Отказы upstream LLM providers
- Отказы Redis/Postgres (degraded mode)

## Alerting
- Burn rate 2x за 1h → warning
- Burn rate 14.4x за 5m → critical

## Error Budget Policy
- Budget исчерпан → freeze feature-релизов