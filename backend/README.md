# Backend README

## JWT Authentication & Secret Management

### JWT Secret Rotation
- To rotate the backend JWT secret:
  ```sh
  python backend/utils/rotate_jwt_secret.py
  ```
- This updates `JWT_SECRET` in `backend/.env`.
- **IMPORTANT:** After rotation, update the same secret in all stage containers' `.env` files.

### JWT Token Generation
- To generate a JWT for backend or admin use:
  ```sh
  python backend/utils/generate_jwt.py --sub backend
  # or for admin
  python backend/utils/generate_jwt.py --sub admin
  ```
- Uses `JWT_SECRET` and `JWT_ALGORITHM` from `backend/.env`.
- Prints the token for use in API requests or testing.

### Syncing with Stage Containers
- After rotating the secret, use the universal script in `stages/utils/generate_jwt.py` to generate new tokens for each stage, using the updated secret.
- All tokens must be generated with the same `JWT_SECRET` as the backend.

---
For more details, see the `stages/README.md` for stage-side usage.
