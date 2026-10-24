# Vibe Sec Deployment

## Runtime Shape

The default Compose stack contains two services:

- `web`: Nginx serves the built Vue application and proxies `/api/` to `api`.
- `api`: FastAPI, the CLI runtime, SQLite state, sessions, artifacts, and external VRTM snapshots.

The optional `audit` profile runs the installed CLI in the same image without
opening another network port. The default image has no Docker socket and no
active-target access. Container scanner images must run through an explicitly
authorized host runner because a Docker-in-Docker path would otherwise break
the source mount boundary.

## Start

For the shortest Agent-assisted deployment path, use the repository wrapper. It
builds the Compose stack, installs the `vibe-sec` Skill, waits for the API health
check, and prints the local Web UI URL:

```powershell
scripts/agent-one-click-deploy.ps1 -Agent codex
```

```bash
sh scripts/agent-one-click-deploy.sh --agent codex
```

1. Create a host project directory, for example `./projects`, and place only
   projects that the platform is authorized to inspect there.
2. Copy `.env.example` to `.env` and set `VIBE_SEC_PROJECTS_PATH` when the
   projects are outside the repository.
3. Start the stack:

   ```powershell
   scripts/deploy.ps1 -Build -Detach
   ```

   ```bash
   sh scripts/deploy.sh --build --detach
   ```

4. Open the URL printed by the deployment script. Register projects with the
   container-visible path `/workspace/<directory-name>`, not the host path.

## LLM Secret

Keep provider credentials in a file outside the repository. Select the LLM
Compose overlay so the file is exposed as a Docker secret and loaded only by
the process entrypoint:

```powershell
scripts/deploy.ps1 -Build -Detach -LlmSecretFile C:\secrets\deepseek.key
```

```bash
sh scripts/deploy.sh --build --detach --llm-secret /run/user/1000/secrets/deepseek.key
```

Do not put the credential in `.env`, `compose.yml`, Skill text, project data,
or audit output. The API's model settings UI remains available for local model
profiles; protect the state volume accordingly.

## Headless Agent Run

Install the Skill for the active coding agent:

```powershell
scripts/install-agent-skill.ps1 -Agent codex
scripts/install-agent-skill.ps1 -Agent claude-code
```

```bash
sh scripts/install-agent-skill.sh codex
```

Then run a source-only audit through the Compose profile:

```bash
docker compose --profile audit run --rm audit \
  skill-audit /workspace/example --format json
```

The returned Skill contract contains the durable `RunSession`, evidence-bound
findings, remediation packages, and retest requirements. A `needs_evidence`
finding is not a verified vulnerability.

## State And Boundaries

- `vibe-sec-state` stores API SQLite state, sessions, artifacts, and VRTM snapshots.
- `/workspace` is mounted read-only by default. The default Web/API audit path
  writes no source files and stores VRTM snapshots under the state volume using
  a stable project hash. The explicit `model-init` CLI command is the documented
  exception and creates a project-owned declaration file.
- The Web service is the only published port. The API is private to the Compose
  network and is health-checked before the Web service starts.
- The deployment does not start a target, perform dynamic exploitation, or
  authorize remediation writes. Those actions require the existing Harness and
  approval contracts.
