# CyberShield MVP - API Gateway + Security Module

This project delivers a production-style MVP for CyberShield with:
- `API Gateway` in Go (`cmd/gateway`)
- `Internal Security Module` in Go gRPC (`cmd/security-service`)
- Integration with an existing Express.js backend as upstream (`BACKEND_URL`)
- Shared MongoDB persistence for security logs and API keys
- Kafka publishing for deny/suspicious alerts (`security-alerts`)

The gateway always calls `SecurityService.Verify()` before forwarding to the backend.

## Project Structure

```text
.
├── cmd/
│   ├── gateway/
│   └── security-service/
├── internal/
│   ├── gateway/
│   ├── middleware/
│   ├── pipeline/
│   ├── service/
│   └── store/
├── proto/
├── infra/
│   ├── docker-compose.yml
│   └── mongo-init/
├── docs/
├── backend/
├── tests/
├── .env.example
└── Makefile
```

## Security Pipeline (Exact Order)

`Rate Limiter -> Metadata Extractor -> JWT Validator -> API Key Validator -> Request Validator -> RBAC/Object-Level -> Decision Engine`

## Quick Start (Local)

1. Copy env file:

```powershell
copy .env.example .env
```

2. Start infra/services:

```powershell
docker compose -f infra/docker-compose.yml up --build -d
```

3. Run tests:

```powershell
go test ./...
```

## Configuration

All runtime values are environment variables. Main ones:
- `GATEWAY_PORT`
- `SECURITY_SERVICE_ADDR`
- `BACKEND_URL` (Express upstream, not rebuilt here)
- `MONGODB_URI`, `MONGODB_DB`
- `KAFKA_BROKERS`
- `JWT_SECRET`, `JWT_ALGORITHMS`
- `RATE_LIMIT_RPS`, `RATE_LIMIT_BURST`
- `REQUIRE_API_KEY`

## Sample Requests

Use seeded API key from `infra/mongo-init/init.js`:
- plaintext key: `test-api-key`

### ALLOW example

```bash
curl -i http://localhost:8080/api/v1/accounts/1001/transactions \
  -H "Authorization: Bearer <valid_hs256_token_sub_1001>" \
  -H "x-api-key: test-api-key"
```

Expected: request proxied to backend.

### DENY examples

Invalid API key:

```bash
curl -i http://localhost:8080/api/v1/orders \
  -H "Authorization: Bearer <valid_token>" \
  -H "x-api-key: invalid"
```

Expected: `403`.

BOLA attempt:

```bash
curl -i http://localhost:8080/api/v1/accounts/9999/transactions \
  -H "Authorization: Bearer <valid_hs256_token_sub_1001>" \
  -H "x-api-key: test-api-key"
```

Expected: `403`.

Rate limit burst:

```bash
for i in {1..50}; do curl -s -o /dev/null -w "%{http_code}\n" http://localhost:8080/api/v1/login -X POST; done
```

Expected: some requests `429`.

## How Verify Works

1. Gateway extracts token, api key, headers, body metadata
2. Gateway sends `VerifyRequest` over gRPC
3. Security service decides:
   - `ALLOW`: gateway proxies to Express backend
   - `DENY`: gateway returns policy status code and does not forward
4. Security logs are saved in MongoDB (`security_logs`)
5. Deny events are published to Kafka topic `security-alerts`

## Integration With Existing Express Backend

The backend is treated as an external upstream service. This repo does not rebuild business logic.

Set:
- `BACKEND_URL=http://<express-host>:<port>`

Gateway will proxy all allowed routes to that upstream.

## Make Targets

```powershell
make proto
make build
make run-security
make run-gateway
make test
make docker-up
make docker-down
```
