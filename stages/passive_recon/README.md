# Passive Recon Stage Container

## Overview
This container orchestrates multiple passive reconnaissance tools to enumerate subdomains, IPs, protocols, and related data for a given target domain. It is designed for automated, robust, and API-integrated bug bounty and security workflows.

## Features
- Runs multiple passive recon tools in sequence:
  - Sublist3r
  - Amass
  - Subfinder
  - Assetfinder
  - Gau
  - Cero
- Aggregates and deduplicates subdomains and other findings
- Saves both raw and parsed outputs to standardized directories
- Submits results to the backend API using JWT authentication
- Robust error handling: failures are logged, but do not halt the process

## Tools Included
- [Sublist3r](https://github.com/aboul3la/Sublist3r)
- [Amass](https://github.com/owasp-amass/amass)
- [Subfinder](https://github.com/projectdiscovery/subfinder)
- [Assetfinder](https://github.com/tomnomnom/assetfinder)
- [Gau](https://github.com/lc/gau)
- [Cero](https://github.com/glebarez/cero)
- [SecLists](https://github.com/danielmiessler/SecLists) (wordlists)

## Installation & Build

1. **Build the Docker image:**
   ```sh
   docker build -t passive_recon_stage .
   ```

2. **Set up the `.env` file:**
   - Copy and edit `stages/passive_recon/.env` as needed.
   - Generate a JWT token for API submission:
     ```sh
     python stages/utils/generate_jwt.py --sub passive_recon_stage
     ```
   - Rotate JWT secret as needed:
     ```sh
     python stages/utils/rotate_jwt_secret.py --sub passive_recon_stage
     ```

## Environment Variables
See `.env` for all options. Key variables:
- `BACKEND_API_URL`: Backend endpoint for result submission
- `BACKEND_JWT_TOKEN`: JWT token for API authentication
- Tool paths: `AMASS_PATH`, `SUBFINDER_PATH`, `ASSETFINDER_PATH`, `GAU_PATH`, `SUBLIST3R_PATH`, `CERO_PATH`
- `SECLISTS_PATH`: Path to SecLists wordlists

## Usage

### Run in Docker
```sh
docker run --rm \
  --env-file ./stages/passive_recon/.env \
  -v $(pwd)/outputs:/outputs \
  passive_recon_stage \
  --target example.com
```

### Run Locally
```sh
python run_passive_recon.py --target example.com
```

## Output Conventions
- **Raw outputs:** `/outputs/passive_recon/<TARGET>/<TOOL>.*`
- **Parsed outputs:** `/outputs/passive_recon/<TARGET>/parsed/<TOOL>_subdomains.json` (or similar)
- **Aggregated subdomains:** `/outputs/passive_recon/<TARGET>/parsed/all_subdomains.json`

## API Submission
- Both raw and parsed outputs are submitted to the backend API using the JWT token from `.env`.
- See [architecture.mdc](../../.cursor/rules/architecture.mdc) for details on the API pattern.

## Error Handling
- Each tool and API submission is wrapped in try/except.
- Failures are logged and summarized at the end; the process continues for all tools.

## Troubleshooting
- Ensure all tool paths in `.env` are correct and tools are installed in the container.
- Make sure `BACKEND_JWT_TOKEN` is valid and matches the backend's JWT secret.
- Check Docker volume mounts for output persistence.
- Review logs for error messages and summary at the end of each run.

## References
- [Project Architecture](../../.cursor/rules/architecture.mdc)
- [Security & Auth Rules](../../.cursor/rules/security-auth.mdc) 