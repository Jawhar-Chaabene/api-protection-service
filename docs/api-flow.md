# API Flow

## ALLOW Flow

1. Client sends request to Gateway.
2. Gateway extracts:
   - `Authorization` token
   - `x-api-key`
   - headers/path/method/body/request-id/client-ip
3. Gateway sends gRPC `VerifyRequest` to Security Service.
4. Pipeline checks pass (`ALLOW`).
5. Gateway proxies request to Express backend.
6. Response from backend is returned to client.
7. Security Service stores log in MongoDB.

## DENY Flow

1. Client sends request to Gateway.
2. Security Service pipeline fails one stage.
3. `VerifyResponse` returns `DENY` + HTTP status + reason.
4. Gateway returns error immediately (request is never forwarded).
5. Security Service stores deny log in MongoDB.
6. Security Service publishes Kafka event to `security-alerts`.

## Example Denials

- Rate limit exceeded -> `429`
- Invalid/missing JWT -> `401`
- Invalid API key -> `403`
- RBAC or object-level mismatch (BOLA/BFLA) -> `403`
- Invalid request payload or duplicate params -> `400`

## Mapping to Attack Scenarios

- BOLA/ID enumeration: owner check on `/api/v1/accounts/{id}/transactions`
- JWT algorithm confusion: `alg=none` explicitly rejected
- NoSQL injection payloads: blocked by request validation patterns
- Parameter pollution: duplicate query params denied
- Hidden endpoint discovery: non-admin blocked on `/admin`, `/internal`, `/debug`, `/v2/api-docs`
