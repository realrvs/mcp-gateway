# ADR-0002: HMAC hash-chain для audit log

## Status
Accepted

## Context
TODO: почему обычный hash-chain недостаточен

## Decision
HMAC-SHA256(prev_hash || payload), ключ в Vault.

## Rationale
TODO

## Consequences
TODO