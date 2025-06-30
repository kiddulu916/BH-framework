# Stages README

## JWT Authentication & Secret Management

### JWT Secret Sync & Rotation
- The JWT secret (`JWT_SECRET`) must match the backend's secret.
- To rotate the secret, run on the backend:
  ```sh
  python backend/utils/rotate_jwt_secret.py
  ```
- Copy the new secret to each stage's `.env` file under `JWT_SECRET`.

### JWT Token Generation (Universal Script)
- Use the universal script to generate a JWT for any stage:
  ```sh
  python stages/utils/generate_jwt.py --sub <stage_name> --env-path <path-to-stage-env>
  # Example for passive_recon:
  python stages/utils/generate_jwt.py --sub passive_recon_stage --env-path stages/passive_recon/.env
  ```
- The script uses `JWT_SECRET` and `JWT_ALGORITHM` from the specified `.env`.
- Copy the output token to `BACKEND_JWT_TOKEN` in the same `.env`.

### .env Setup Example
```
BACKEND_API_URL=http://backend:8000/api/v1/results/passive-recon
BACKEND_JWT_TOKEN=  # Set by generate_jwt.py
JWT_SECRET=         # Set by backend/utils/rotate_jwt_secret.py
JWT_ALGORITHM=HS256
```

### Best Practices
- Never commit secrets or tokens to version control.
- Rotate secrets regularly and update all containers.
- Use short-lived tokens (e.g., 1 hour expiry).

---
For backend-side usage, see the `backend/README.md`. 