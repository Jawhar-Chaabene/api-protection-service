# Existing Express Backend Integration

This folder is intentionally lightweight.

Business backend endpoints are assumed to already exist in a separate Express.js service.

## Integration Contract

- Gateway forwards only `ALLOW` requests to the backend.
- Denied requests never reach backend.
- Backend URL is configured via:

```env
BACKEND_URL=http://<express-host>:<port>
```

## Example

- Local backend running at `http://localhost:3000`
- Set in `.env`:

```env
BACKEND_URL=http://host.docker.internal:3000
```

No backend business logic is reimplemented in this repository.
