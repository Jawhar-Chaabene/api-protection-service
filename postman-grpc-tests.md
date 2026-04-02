# Postman gRPC Tests for API Protection Service

## Overview

This file contains every test case (equivalent to existing `cmd/test-client/main.go`) as Postman gRPC requests.
Run the security service first:

```bash
go run ./cmd/security-service
```

Postman -> GRPC -> URL: `localhost:50051`

---

## 1. Set up Postman gRPC request (common for all tests)

- Request type: **gRPC**
- Address: `localhost:50051`
- Service: `security.SecurityService`
- Method: `Verify`
- Add headers (Metadata):
  - `x-client-ip`: `192.168.1.100` (optional, for trace)
  - `x-user-id`: `42` (optional for object-level)
  - `x-roles`: (varies per test)

Payload body (JSON):

```json
{
  "path": "/api/public/docs",
  "method": "GET",
  "client_ip": "192.168.1.100"
}
```

Response should be:

```json
{
  "verdict": "ALLOW",
  "reason": ""
}
```

---

## 2. Postman tests (one request per case)

### 2.1 Test 1 - Public endpoint (anonymous)

Headers:
- `x-roles`: (empty or `anonymous`)

Payload:
```json
{
  "path": "/api/public/docs",
  "method": "GET",
  "client_ip": "192.168.1.100"
}
```

Expected response:
- `verdict`: `ALLOW`
- `reason`: ``

---

### 2.2 Test 2 - Health check (anonymous)

Headers:
- `x-roles`: (empty)

Payload:
```json
{
  "path": "/health",
  "method": "GET",
  "client_ip": "192.168.1.100"
}
```

Expected response:
- `verdict`: `ALLOW`

---

### 2.3 Test 3 - Users endpoint without role

Headers:
- none

Payload:
```json
{
  "path": "/api/users",
  "method": "GET",
  "client_ip": "192.168.1.100"
}
```

Expected response:
- `verdict`: `DENY`
- `reason`: contains `rbac: no role grants access to this resource`

---

### 2.4 Test 4 - Users endpoint with user role

Headers:
- `x-roles`: `user`

Payload:
```json
{
  "path": "/api/users",
  "method": "GET",
  "client_ip": "192.168.1.100"
}
```

Expected response:
- `verdict`: `ALLOW`

---

### 2.5 Test 5 - Admin endpoint with admin role

Headers:
- `x-roles`: `admin`

Payload:
```json
{
  "path": "/admin/dashboard",
  "method": "GET",
  "client_ip": "192.168.1.100"
}
```

Expected response:
- `verdict`: `ALLOW`

---

### 2.6 Test 6 - Object-level access allowed (user owns resource)

Headers:
- `x-roles`: `user`
- `x-user-id`: `42`

Payload:
```json
{
  "path": "/users/42",
  "method": "GET",
  "client_ip": "192.168.1.100"
}
```

Expected response:
- `verdict`: `ALLOW`

---

### 2.7 Test 7 - Object-level access denied (user does not own resource)

Headers:
- `x-roles`: `user`
- `x-user-id`: `42`

Payload:
```json
{
  "path": "/users/99",
  "method": "GET",
  "client_ip": "192.168.1.100"
}
```

Expected response:
- `verdict`: `DENY`
- `reason`: contains `object-level: access denied to another user's resource`

---

## 3. Validation test cases

### 3.1 Invalid path format

Payload:
```json
{
  "path": "api/public",
  "method": "GET",
  "client_ip": "192.168.1.100"
}
```
Expected: `DENY` + validation error.

### 3.2 Invalid method

Payload:
```json
{
  "path": "/api/public",
  "method": "TRACE",
  "client_ip": "192.168.1.100"
}
```
Expected: `DENY` + validation error.

### 3.3 Invalid client IP

Payload:
```json
{
  "path": "/api/public",
  "method": "GET",
  "client_ip": "invalid-ip"
}
```
Expected: `DENY` + validation error.

---

## 4. Notes

- In Postman gRPC mode, use the JSON payload as defined, and set metadata headers using the gRPC Headers panel.
- If you get `ResourceExhausted`, reduce repeated calls or restart service (rate limit triggers via x-client-ip canceling per second). 
- The existing `cmd/test-client/main.go` executes the same behavior as these cases, so it can be used as a source of truth.
