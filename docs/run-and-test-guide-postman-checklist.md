# Run And Test Guide + Postman Collection Test Checklist

This guide covers:
- Running CyberShield locally
- Verifying health and core flows
- Testing all requested attack scenarios
- A Postman checklist you can execute in Runner

## 1) Prerequisites

- Docker Desktop installed and running
- Go 1.26+ installed
- PowerShell terminal
- Existing Express backend available (already implemented outside this repo)

Project root:

```powershell
cd D:\yessine\Projects\go\api-protection-service
```

## 2) Environment Setup

Create `.env` from example:

```powershell
Copy-Item .env.example .env
```

Edit `.env` values:

- `BACKEND_URL=http://host.docker.internal:3000` (or your backend URL)
- `JWT_SECRET=change-me` (replace for local testing if needed)
- `REQUIRE_API_KEY=true`
- keep defaults for Mongo/Kafka unless customized

## 3) Start All Services

```powershell
docker compose -f infra/docker-compose.yml up --build -d
```

Check status:

```powershell
docker compose -f infra/docker-compose.yml ps
```

Expected running services:
- `cybershield-gateway`
- `cybershield-security-service`
- `cybershield-mongodb`
- `cybershield-zookeeper`
- `cybershield-kafka`

## 4) Health and Readiness Checks

```powershell
curl http://localhost:8080/healthz
curl http://localhost:8080/readyz
```

Expected:
- `/healthz` -> `{"status":"ok"}`
- `/readyz` -> `{"status":"ready"}`

## 5) Run Automated Tests

All tests:

```powershell
go test ./...
```

Integration only:

```powershell
go test ./tests -v
```

## 6) Seeded Credentials Used by This MVP

- Seeded plaintext API key: `test-api-key`
- Mongo stores hash only (`infra/mongo-init/init.js`)

JWT should be HS256 signed with `.env` `JWT_SECRET`.

Recommended test JWT payload for normal user:

```json
{
  "sub": "1001",
  "roles": ["user"],
  "exp": 1893456000
}
```

Admin test payload:

```json
{
  "sub": "1",
  "roles": ["admin"],
  "exp": 1893456000
}
```

## 7) Quick curl Smoke Tests

Set token variable in PowerShell:

```powershell
$TOKEN = "<valid_user_jwt>"
$ADMIN_TOKEN = "<valid_admin_jwt>"
```

ALLOW flow (proxied):

```powershell
curl -i "http://localhost:8080/api/v1/accounts/1001/transactions" `
  -H "Authorization: Bearer $TOKEN" `
  -H "x-api-key: test-api-key"
```

BOLA DENY:

```powershell
curl -i "http://localhost:8080/api/v1/accounts/9999/transactions" `
  -H "Authorization: Bearer $TOKEN" `
  -H "x-api-key: test-api-key"
```

Invalid token:

```powershell
curl -i "http://localhost:8080/api/v1/orders" `
  -H "Authorization: Bearer invalid.token.here" `
  -H "x-api-key: test-api-key"
```

Invalid API key:

```powershell
curl -i "http://localhost:8080/api/v1/orders" `
  -H "Authorization: Bearer $TOKEN" `
  -H "x-api-key: wrong-key"
```

Rate limit burst:

```powershell
1..50 | ForEach-Object {
  curl -s -o $null -w "%{http_code}`n" -X POST "http://localhost:8080/api/v1/login"
}
```

## 8) Validate Mongo Logs and Kafka Alerts

Recent security logs:

```powershell
docker exec -it cybershield-mongodb mongosh api_protection --eval "db.security_logs.find().sort({timestamp:-1}).limit(20).pretty()"
```

Consume security alerts:

```powershell
docker exec -it cybershield-kafka kafka-console-consumer --bootstrap-server kafka:9092 --topic security-alerts --from-beginning --max-messages 20
```

## 9) Postman Collection Setup

Create a Postman collection named `CyberShield Security Tests`.

Collection variables:
- `baseUrl` = `http://localhost:8080`
- `token` = valid user JWT
- `adminToken` = valid admin JWT
- `apiKey` = `test-api-key`

Optional pre-request script (collection-level):

```javascript
pm.request.headers.upsert({ key: "x-api-key", value: pm.collectionVariables.get("apiKey") || "test-api-key" });
```

## 10) Postman Collection Test Checklist (12 Scenarios)

Use this table as your execution checklist.

| # | Scenario | Request | Payload / Setup | Expected |
|---|---|---|---|---|
| 1 | BOLA + ID Enumeration | `GET {{baseUrl}}/api/v1/accounts/{{accountId}}/transactions` | Header `Authorization: Bearer {{token}}`; Runner iterate `accountId=1..10000` | Only owned account allowed, others `403` |
| 2 | Advanced Injection (NoSQL/JSON) | `POST {{baseUrl}}/api/v1/login` | `{"username":{"$ne":null},"password":{"$ne":null}}` and `{"username":"admin' || '1'=='1","password":"anything"}` | `400`/deny, never bypass auth |
| 3 | Mass Assignment | `POST {{baseUrl}}/api/v1/users` | `{"email":"a@test.com","password":"123456","role":"admin","isVerified":true,"balance":1000000}` | `400` deny (whitelist enforced) |
| 4 | Rate Limit Bypass | `POST {{baseUrl}}/api/v1/login` | High parallel Runner iterations; try spoof `X-Forwarded-For` | Burst gets `429`; spoofing should not bypass |
| 5 | JWT Algorithm Confusion | protected route e.g. `/api/v1/orders` | token with header `{"alg":"none"}` | `401` deny |
| 6 | GraphQL Deep Query DoS | `POST {{baseUrl}}/graphql` | Deep nested query body | Deny/limit behavior (expect non-2xx if rejected by policy) |
| 7 | BFLA | `DELETE {{baseUrl}}/api/v1/users/2` | `Authorization: Bearer {{token}}` (non-admin) | `403` |
| 8 | Parameter Pollution | `GET {{baseUrl}}/api/v1/products?id=1&id=2&id=3` | valid auth headers | `400` deny |
| 9 | File Upload Abuse | `POST {{baseUrl}}/api/v1/upload` | multipart with disallowed type or oversized file | `400` deny by validator/size limits |
| 10 | Business Logic Abuse | `POST {{baseUrl}}/api/v1/orders` | negative quantity or manipulated price | should be denied by backend business rules; ensure not bypassed |
| 11 | Race Condition | `POST {{baseUrl}}/api/v1/transfer` | send concurrent transfer requests | backend should enforce transaction safety |
| 12 | Hidden Endpoints Discovery | `GET {{baseUrl}}/admin`, `/internal`, `/debug`, `/v2/api-docs` | normal user token | `403` for non-admin |

## 11) Postman Tests Snippets

Attach per-request tests:

```javascript
pm.test("Status is 403", function () {
  pm.response.to.have.status(403);
});
```

```javascript
pm.test("Status is 429", function () {
  pm.response.to.have.status(429);
});
```

```javascript
pm.test("Denied response contains correlation_id", function () {
  const body = pm.response.json();
  pm.expect(body).to.have.property("correlation_id");
});
```

Example pre-request script for dynamic account enumeration:

```javascript
const current = Number(pm.collectionVariables.get("accountId") || 1);
pm.collectionVariables.set("accountId", current + 1);
```

## 12) Practical Notes on Scope

- CyberShield gateway/security module enforce access and request-level protections.
- Business logic validation for domain rules (price/quantity/stock/race conditions) remains the backend responsibility.
- This MVP intentionally integrates with existing Express service and does not rebuild business endpoints.

## 13) Stop Services

```powershell
docker compose -f infra/docker-compose.yml down -v
```
