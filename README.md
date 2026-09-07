<p align="center">
  <img src="https://minio.ginkida.dev/minion/github/portainer-mcp.png" alt="Portainer MCP Server" width="600">
</p>

# Portainer MCP Server

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://python.org)
[![MCP](https://img.shields.io/badge/MCP-compatible-green.svg)](https://modelcontextprotocol.io)
[![PyPI](https://img.shields.io/pypi/v/portainer-mcp)](https://pypi.org/project/portainer-mcp/)

An MCP (Model Context Protocol) server that gives AI assistants — Claude, Copilot, Cursor, and others — **53 tools to manage Portainer container environments**: deploy and update stacks (Env preserved, re-pull on demand), inspect Swarm services/tasks/nodes, manage containers/images/volumes/networks, exec commands, analyze logs, and inspect endpoints — all through natural language. Two optional Laravel helpers bring the total to 55.

> **For LLM agents:** This server connects via stdio transport and ships server instructions (start with services on Swarm, inspect before update). Every tool returns JSON. All mutating operations are audit-logged. Credential-looking values are masked as `[REDACTED]` unless you ask for `reveal_env=true`. Credentials are passed via environment variables, never hardcoded.

---

## Why Use This

- **Natural language DevOps** — Ask your AI assistant to deploy a stack, check container logs, or pull an image.
- **Swarm-native** — Services, tasks and nodes as first-class tools (`docker service ls/ps/logs/update` equivalents plus a per-stack health summary); stack deploys auto-detect Swarm vs standalone.
- **Safe by default** — Input validation, path traversal protection, sensitive field filtering, credential masking in stack/service inspect, `[REDACTED]` values can never be written back, and force-remove disabled by default.
- **Token auth** — Use a Portainer access token (`PORTAINER_API_KEY`) instead of an admin password.
- **Works everywhere** — Claude Desktop, Claude Code, Cursor, Windsurf, VS Code, Continue.dev.

---

## Quick Start

### 1. Install

```bash
pip install portainer-mcp
```

Or from source:

```bash
git clone https://github.com/ginkida/portainer-mcp.git
cd portainer-mcp
pip install -e .
```

### 2. Configure your AI client

Pick your client below, paste the config, and replace the placeholder values with your Portainer credentials.

---

## Client Configuration

### Claude Desktop

**File:** `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows)

```json
{
  "mcpServers": {
    "portainer": {
      "command": "python3",
      "args": ["-m", "portainer_mcp.server"],
      "env": {
        "PORTAINER_URL": "https://your-portainer:9443",
        "PORTAINER_API_KEY": "ptr_your-access-token",
        "PORTAINER_VERIFY_SSL": "false"
      }
    }
  }
}
```

`PORTAINER_API_KEY` is a Portainer access token (**My account → Access tokens**). You can use `PORTAINER_USERNAME` + `PORTAINER_PASSWORD` instead, as in the examples below.

### Claude Code

**File:** `.mcp.json` in your project root (project-scope) or `~/.claude.json` (user-scope)

```json
{
  "mcpServers": {
    "portainer": {
      "type": "stdio",
      "command": "python3",
      "args": ["-m", "portainer_mcp.server"],
      "env": {
        "PORTAINER_URL": "https://your-portainer:9443",
        "PORTAINER_USERNAME": "admin",
        "PORTAINER_PASSWORD": "${PORTAINER_PASSWORD}",
        "PORTAINER_VERIFY_SSL": "false"
      }
    }
  }
}
```

Or via CLI:

```bash
claude mcp add portainer -- python3 -m portainer_mcp.server
```

### Cursor

**File:** `~/.cursor/mcp.json` (global) or `.cursor/mcp.json` (project)

```json
{
  "mcpServers": {
    "portainer": {
      "command": "python3",
      "args": ["-m", "portainer_mcp.server"],
      "env": {
        "PORTAINER_URL": "https://your-portainer:9443",
        "PORTAINER_USERNAME": "admin",
        "PORTAINER_PASSWORD": "your-password",
        "PORTAINER_VERIFY_SSL": "false"
      }
    }
  }
}
```

### Windsurf

**File:** `~/.codeium/windsurf/mcp_config.json`

```json
{
  "mcpServers": {
    "portainer": {
      "command": "python3",
      "args": ["-m", "portainer_mcp.server"],
      "env": {
        "PORTAINER_URL": "https://your-portainer:9443",
        "PORTAINER_USERNAME": "admin",
        "PORTAINER_PASSWORD": "your-password",
        "PORTAINER_VERIFY_SSL": "false"
      }
    }
  }
}
```

### VS Code (GitHub Copilot)

**File:** `.vscode/mcp.json` in your workspace

```json
{
  "servers": {
    "portainer": {
      "type": "stdio",
      "command": "python3",
      "args": ["-m", "portainer_mcp.server"],
      "env": {
        "PORTAINER_URL": "${input:portainer-url}",
        "PORTAINER_USERNAME": "${input:portainer-username}",
        "PORTAINER_PASSWORD": "${input:portainer-password}",
        "PORTAINER_VERIFY_SSL": "false"
      }
    }
  },
  "inputs": [
    { "type": "promptString", "id": "portainer-url", "description": "Portainer base URL" },
    { "type": "promptString", "id": "portainer-username", "description": "Portainer username" },
    { "type": "promptString", "id": "portainer-password", "description": "Portainer password", "password": true }
  ]
}
```

### Continue.dev

**File:** `~/.continue/config.yaml` or `.continue/config.yaml`

```yaml
mcpServers:
  - name: portainer
    type: stdio
    command: python3
    args:
      - -m
      - portainer_mcp.server
    env:
      PORTAINER_URL: "https://your-portainer:9443"
      PORTAINER_USERNAME: "admin"
      PORTAINER_PASSWORD: "your-password"
      PORTAINER_VERIFY_SSL: "false"
```

---

## Environment Variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `PORTAINER_URL` | **Yes** | — | Portainer base URL, e.g. `https://portainer.example.com:9443`. Must be a root URL (no path). Plain `http://` to a non-loopback host is allowed but logs a cleartext-credentials warning. |
| `PORTAINER_API_KEY` | One of | — | Portainer access token, sent as `X-API-Key`. Preferred: no admin password on disk, no JWT/CSRF handshake. Takes precedence over username/password. |
| `PORTAINER_USERNAME` | One of | — | Portainer username (with `PORTAINER_PASSWORD`; ignored when `PORTAINER_API_KEY` is set) |
| `PORTAINER_PASSWORD` | One of | — | Portainer password |
| `PORTAINER_DEFAULT_ENDPOINT` | No | `1` | Default endpoint ID for container/image/stack operations |
| `PORTAINER_VERIFY_SSL` | No | `true` | Set to `false` for self-signed certificates |
| `PORTAINER_TIMEOUT` | No | `30` | Timeout (seconds) for ordinary API calls |
| `PORTAINER_LONG_TIMEOUT` | No | `300` | Timeout (seconds) for long-running operations: image pull, container exec, large log scans |
| `PORTAINER_HTTP_MAX_CONNECTIONS` | No | `100` | Max concurrent HTTP connections to Portainer |
| `PORTAINER_HTTP_MAX_KEEPALIVE` | No | `20` | Max idle keep-alive connections |
| `PORTAINER_JWT_TTL` | No | `25200` (7h) | Proactive JWT refresh interval (seconds). Set below Portainer's session timeout (default 8h) to avoid per-call 401 re-auth round-trips. Unused with `PORTAINER_API_KEY`. |
| `PORTAINER_ENABLE_LARAVEL_TOOLS` | No | `false` | Register the opinionated Laravel helpers (`portainer_laravel_errors`, `portainer_laravel_tinker`). Off by default — they assume a `backend` service with the app at `/var/www/app`. |

All values are validated at startup — a malformed URL, a non-numeric timeout, or a non-positive limit fails fast with a clear error instead of breaking later.

---

## Tools

All 53 tools are listed below with their parameters and descriptions (55 with the Laravel helpers enabled). Every tool returns JSON.

### Authentication

| Tool | Description |
|---|---|
| `portainer_status()` | Check connection and authentication status. Returns version, instance ID, auth mode, the number of endpoints and, for the default endpoint, its name/status and `swarm` (true only on a Swarm **manager**, where the service tools work) with `swarm_role`. |

### Endpoints (Environments)

| Tool | Description |
|---|---|
| `portainer_endpoints_list()` | List all environments. Returns id, name, type, url, status. |
| `portainer_endpoint_inspect(endpoint_id)` | Get endpoint details (sensitive fields like TLS certs are filtered; the bulky raw `DockerSnapshotRaw` dump is dropped, the snapshot counters stay). |

### Stacks

| Tool | Description |
|---|---|
| `portainer_stacks_list()` | List all stacks with id, name, type (`swarm`/`compose`), status, endpoint_id. |
| `portainer_stack_inspect(stack_id, reveal_env?)` | Get stack details, its Env variables and the compose file. Credential-looking values (`*PASSWORD`, `*SECRET`, `*TOKEN`, `*KEY`, DSNs, …) are masked as `[REDACTED]` unless `reveal_env=true`. |
| `portainer_stack_deploy(name, compose_content, env?, endpoint_id?)` | Deploy a new stack with optional Env variables. Auto-detects Swarm vs standalone. |
| `portainer_stack_update(stack_id, compose_content?, env?, env_remove?, prune?, pull_image?, detach_from_git?, endpoint_id?)` | Redeploy a stack. **The stored Env variables are always preserved** (Portainer replaces the whole list on every update; the tool reads it first and merges `env` / `env_remove` into it). `prune` defaults to the stack's current setting; `pull_image=true` is Portainer's "Re-pull image and redeploy" — required to roll out a new build of a `:latest` tag. A compose file containing `[REDACTED]` is rejected. A git-backed stack is refused unless `detach_from_git=true` (Portainer would silently drop the git link). `endpoint_id` is derived from the stack itself. |
| `portainer_stack_status(stack_name, endpoint_id?)` | Health summary: every service with running/desired replicas, update state and the task failures newer than its last good task. Cron-driven services (swarm-cronjob labels) are judged on their last run, not on replicas. Falls back to container states on a standalone endpoint (or for a Compose project on a manager). |
| `portainer_stack_wait(stack_name, timeout_seconds?, endpoint_id?)` | Poll `stack_status` after an update until every service is healthy, a rollout pauses on failure, or the timeout (default 120 s) elapses. Returns the final status plus `converged` / `reason` / `timed_out`. |
| `portainer_stack_delete(stack_id, endpoint_id?)` | Delete a stack (endpoint derived from the stack; a different `endpoint_id` is accepted only for an orphaned stack whose endpoint no longer exists). |
| `portainer_stack_start(stack_id, endpoint_id?)` | Start a stopped stack (endpoint derived from the stack). |
| `portainer_stack_stop(stack_id, endpoint_id?)` | Stop a running stack (endpoint derived from the stack). |

### Swarm

| Tool | Description |
|---|---|
| `portainer_services_list(endpoint_id?, stack_filter?)` | `docker service ls`: every service with stack, image (tag and digest separated), mode, **running/desired** replicas, published ports and update status. |
| `portainer_service_inspect(service_id, reveal_env?, endpoint_id?)` | Full service definition (spec, previous spec, update status). Credential-looking `Env` values are masked unless `reveal_env=true`. |
| `portainer_service_tasks(service_id, limit?, endpoint_id?)` | `docker service ps`: tasks by slot with state, node hostname, container id and the scheduler / start **error** — the first place to look when replicas won't come up. |
| `portainer_service_logs(service_id, tail?, since?, timestamps?, endpoint_id?)` | Aggregated logs of all the service's tasks across nodes. |
| `portainer_service_update(service_id, image?, replicas?, force_restart?, registry_id?, endpoint_id?)` | `docker service update`: change the image, scale, or `--force` a restart (reads the current spec + version, submits it back). Pass `image` without a digest to make Swarm resolve the tag's current digest; `force_restart` alone re-creates tasks with the pinned digest. Portainer's stored registry credentials are used automatically when the image host matches a configured registry (or pass `registry_id`). |
| `portainer_service_rollback(service_id, endpoint_id?)` | `docker service rollback`: revert to the previous spec (requires a prior update). |
| `portainer_service_wait(service_id, timeout_seconds?, endpoint_id?)` | Poll until the service is healthy and its update finished, the update paused on failure, or the timeout elapses. Returns the service summary with `converged` / `reason` and recent task errors. |
| `portainer_secrets_list(endpoint_id?)` | Swarm secrets: names and metadata only, never values. |
| `portainer_configs_list(endpoint_id?)` | Swarm configs: names and metadata only, never content. |
| `portainer_nodes_list(endpoint_id?)` | Swarm nodes: hostname, role, availability, state, leader, engine version, CPUs/memory, labels. |

### Containers

| Tool | Description |
|---|---|
| `portainer_containers_list(endpoint_id?, show_all?, name_filter?, stack_filter?)` | List containers with their `stack` and `service` (from Swarm/Compose labels). Set `show_all=true` to include stopped; `name_filter` applies a server-side Docker name filter; `stack_filter` keeps only one stack's containers. |
| `portainer_container_inspect(container_id, endpoint_id?)` | Get detailed container info. |
| `portainer_container_start(container_id, endpoint_id?)` | Start a stopped container. |
| `portainer_container_stop(container_id, endpoint_id?)` | Stop a running container. |
| `portainer_container_restart(container_id, endpoint_id?)` | Restart a container. |
| `portainer_container_remove(container_id, force?, endpoint_id?)` | Remove a container. `force` defaults to false. |
| `portainer_container_logs(container_id, tail?, since?, timestamps?, endpoint_id?)` | Get container logs as a JSON envelope (`logs`, `truncated`, `total_chars`). `tail` defaults to 100 (max 1000). `since` accepts a duration (`10m`, `2h`, `1d`), a Unix timestamp or an ISO-8601 datetime; `timestamps=true` prefixes each line. |
| `portainer_container_logs_grep(container_id, pattern, tail?, context_lines?, since?, timestamps?, endpoint_id?)` | Server-side regex over logs. Returns only matching lines (with optional context) — saves bandwidth on noisy logs. |
| `portainer_container_stats(container_id, endpoint_id?)` | Point-in-time CPU%, memory, network and block I/O stats (not a stream). |
| `portainer_container_exec(container_id, command, workdir?, user?, endpoint_id?)` | Run a shell command inside a running container and return its stdout/stderr + exit code. Audit-logged. |
| `portainer_stack_logs_errors(stack_name, tail?, endpoint_id?)` | Concurrent scan of every running container in a stack for HTTP 4xx/5xx, exceptions, fatal/critical levels, panics, OOM, PHP errors, etc. |

### Laravel (opt-in: `PORTAINER_ENABLE_LARAVEL_TOOLS=true`)

| Tool | Description |
|---|---|
| `portainer_laravel_errors(stack_name, tail?, endpoint_id?)` | Read `/var/www/app/storage/logs/laravel.log` inside each container of a stack and return `production.ERROR/CRITICAL/EMERGENCY` entries — the actual exception behind a 500. |
| `portainer_laravel_tinker(stack_name, code, endpoint_id?)` | Execute PHP via `php artisan tinker --execute=...` in the first running `{stack}_backend` container (Swarm, plain-Compose and Compose-v1 naming all matched). Code capped at 4096 chars. Audit-logged. |

### Images

| Tool | Description |
|---|---|
| `portainer_images_list(endpoint_id?, reference_filter?)` | List images with tags and sizes. `reference_filter` applies a server-side filter (e.g. `nginx:1.25`). |
| `portainer_image_inspect(image_id, endpoint_id?)` | Get detailed image info. Accepts `name:tag` or `name@sha256:digest`. |
| `portainer_image_pull(image_name, tag?, registry_id?, registry_auth?, endpoint_id?)` | Pull an image. `tag` defaults to `"latest"`. For a registry configured in Portainer the stored credentials are supplied by Portainer itself — the registry is matched automatically by the image's host (`reg.example.com/app` → the Portainer registry with that URL; Docker Hub images match a DockerHub-type registry), or pass `registry_id` explicitly; `registry_id=0` forces an anonymous pull (an explicit empty auth, so a stale stored token is bypassed); with several registries on the same host the pull stays anonymous and `credentials` names the candidate ids. A failed pull reports which credentials were used. No password passes through the model. The result reports `registry_id` and how `credentials` were chosen. `registry_auth` (base64 JSON `{"username":..,"password":..,"serveraddress":..}`) is only for registries Portainer doesn't know. The pull-progress stream is parsed and any `errorDetail` is surfaced as a tool error. |
| `portainer_image_remove(image_id, endpoint_id?)` | Remove an image. |
| `portainer_registries_list()` | Registries configured in Portainer (id, name, URL, type, authentication flag) — the `registry_id` source for pulls and service updates. |

### Volumes

| Tool | Description |
|---|---|
| `portainer_volumes_list(endpoint_id?, name_filter?)` | List Docker volumes. `name_filter` applies a server-side name filter. |
| `portainer_volume_inspect(volume_name, endpoint_id?)` | Get detailed volume info. |
| `portainer_volume_create(name, driver?, labels?, endpoint_id?)` | Create a volume. `driver` defaults to `"local"`. |
| `portainer_volume_remove(volume_name, force?, endpoint_id?)` | Remove a volume. `force` defaults to false. |

### Networks

| Tool | Description |
|---|---|
| `portainer_networks_list(endpoint_id?, name_filter?)` | List Docker networks with driver, scope and attached container count. `name_filter` applies a server-side name filter. |
| `portainer_network_inspect(network_id, endpoint_id?)` | Get detailed network info. |
| `portainer_network_create(name, driver?, internal?, labels?, endpoint_id?)` | Create a network. `driver` defaults to `"bridge"` (use `"overlay"` for Swarm). |
| `portainer_network_remove(network_id, endpoint_id?)` | Remove a network. |
| `portainer_network_connect(network_id, container_id, endpoint_id?)` | Attach a container to a network. |
| `portainer_network_disconnect(network_id, container_id, force?, endpoint_id?)` | Detach a container from a network. |

### System

| Tool | Description |
|---|---|
| `portainer_docker_info(endpoint_id?)` | OS, CPU, memory, container/image counts, `swarm_active` (node joined a Swarm) and `swarm_manager`. |
| `portainer_docker_disk_usage(endpoint_id?)` | Per-category disk usage (containers, images, volumes, build cache) with reclaimable size. |
| `portainer_docker_prune(target, all_images?, endpoint_id?)` | Reclaim disk: `target` is `containers` (stopped), `images` (dangling only, or all unused with `all_images=true`) or `build_cache`. Volumes are never pruned. Audit-logged. |

### Users

| Tool | Description |
|---|---|
| `portainer_users_list()` | List all Portainer users with id, username, role. |
| `portainer_user_inspect(user_id)` | Get user details. Sensitive fields (password hash, TFA material, tokens) are filtered out. |

---

## Example Workflows

**Deploy a new service:**
> "Deploy a stack called 'redis' with Redis 7 on port 6379"

The agent will call `portainer_stack_deploy(name="redis", compose_content="...")` with the generated compose YAML.

**Debug a failing container:**
> "Why is the nginx container crashing?"

The agent will call `portainer_containers_list()` to find the container, then `portainer_container_logs(container_id)` to inspect the logs.

**Roll out a new build on Swarm:**
> "Deploy the latest arena-etl image"

The agent will call `portainer_stack_update(stack_id, pull_image=true)` — the stack's Env variables are preserved — or `portainer_service_update(service_id, image="registry/app:latest")` for a single service, then `portainer_stack_wait("arena-etl")` to confirm the rollout converged (and `portainer_service_rollback` if it did not).

**Update an existing stack:**
> "Update the arena-etl stack to use the new image tag v2.1"

The agent will call `portainer_stack_inspect(stack_id, reveal_env=true)` to get the current compose file, modify the image tag, then `portainer_stack_update(stack_id, compose_content)`.

**Why are replicas down?**
> "arena-etl_worker shows 0/2"

The agent will call `portainer_service_tasks("arena-etl_worker")` and read the task `error` (`no suitable node`, `task: non-zero exit (137)`, image pull failures), then `portainer_service_logs` for the application side.

---

## Security

- **Access-token auth** (`PORTAINER_API_KEY`, sent as `X-API-Key`) — no admin password on disk, no session to refresh; Portainer skips CSRF checks for token requests. Falls back to **JWT auth** with proactive refresh (7h TTL, Portainer default is 8h), `asyncio.Lock`-guarded re-authentication for safe concurrent use, and 401/403-CSRF retry fallback.
- **CSRF handling** for Portainer 2.39+ — Referer + `X-CSRF-Token` are sent only on mutating methods; CSRF token is harvested from `X-CSRF-Token` response headers and refreshed automatically.
- **SSL verification** enabled by default. Only disable for self-signed certificates.
- **Input validation** — container IDs, image references (incl. digests), stack names, volume/network names are regex-validated before any API call. Path traversal (`..`) is blocked.
- **Sensitive field filtering** — `endpoint_inspect` strips TLS certificates, Azure credentials and security settings; `user_inspect` whitelists safe fields and hides password/TFA material; `registries_list` never returns registry credentials.
- **Credential masking** — `stack_inspect` and `service_inspect` mask Env values whose *name* looks like a credential (and any `user:pass@` inside URLs) as `[REDACTED]`; `reveal_env=true` shows them. A compose file or Env value containing `[REDACTED]` is refused by `stack_update`, so a masked value can never overwrite a real one. `stack_update` preserves the stack's stored Env on every redeploy.
- **Audit logging** — every mutating operation (deploy, delete, remove, pull, start, stop, exec, tinker) is logged to stderr with parameters.
- **No hardcoded credentials** — all secrets come from environment variables. Optional `X-Registry-Auth` for private-registry image pulls is passed in via parameter, never persisted.
- **Container removal** — `force` defaults to `false` to prevent accidental deletion of running containers.
- **Log/exec size limits** — output is capped at 100K characters to prevent memory exhaustion.
- **Non-JSON responses are surfaced, not swallowed** — a reverse proxy's HTML login page in place of the API is reported as "Unexpected response from Portainer" with the content type and the first bytes of the body.

---

## Development

```bash
git clone https://github.com/ginkida/portainer-mcp.git
cd portainer-mcp
pip install -e ".[dev]"
```

Run locally:

```bash
export PORTAINER_URL=https://your-portainer:9443
export PORTAINER_USERNAME=admin
export PORTAINER_PASSWORD=your-password
python3 -m portainer_mcp.server
```

Lint, type-check and test (CI runs the same on Python 3.10–3.13 for every push and pull request):

```bash
ruff check src/ tests/
mypy src/ tests/
pytest
```

---

## Requirements

- Python 3.10+
- A running Portainer instance (CE or Business Edition)
- Portainer API access (default port 9443)

## License

[MIT](LICENSE)
