<p align="center">
  <img src="https://minio.ginkida.dev/minion/github/portainer-mcp.png" alt="Portainer MCP Server" width="600">
</p>

# Portainer MCP Server

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://python.org)
[![MCP](https://img.shields.io/badge/MCP-compatible-green.svg)](https://modelcontextprotocol.io)
[![PyPI](https://img.shields.io/pypi/v/portainer-mcp)](https://pypi.org/project/portainer-mcp/)

An MCP (Model Context Protocol) server that gives AI assistants — Claude, Copilot, Cursor, and others — **41 tools to manage Portainer container environments**: deploy and update stacks, manage containers/images/volumes/networks, exec commands, analyze logs, debug Laravel apps, and inspect endpoints — all through natural language.

> **For LLM agents:** This server connects via stdio transport. Every tool returns JSON. All mutating operations are audit-logged. Credentials are passed via environment variables, never hardcoded.

---

## Why Use This

- **Natural language DevOps** — Ask your AI assistant to deploy a stack, check container logs, or pull an image.
- **Swarm-aware** — Automatically detects Docker Swarm clusters and uses the correct API.
- **Safe by default** — Input validation, path traversal protection, sensitive field filtering, and force-remove disabled by default.
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
        "PORTAINER_USERNAME": "admin",
        "PORTAINER_PASSWORD": "your-password",
        "PORTAINER_VERIFY_SSL": "false"
      }
    }
  }
}
```

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
| `PORTAINER_USERNAME` | **Yes** | — | Portainer username |
| `PORTAINER_PASSWORD` | **Yes** | — | Portainer password |
| `PORTAINER_DEFAULT_ENDPOINT` | No | `1` | Default endpoint ID for container/image/stack operations |
| `PORTAINER_VERIFY_SSL` | No | `true` | Set to `false` for self-signed certificates |
| `PORTAINER_TIMEOUT` | No | `30` | Timeout (seconds) for ordinary API calls |
| `PORTAINER_LONG_TIMEOUT` | No | `300` | Timeout (seconds) for long-running operations: image pull, container exec, large log scans |
| `PORTAINER_HTTP_MAX_CONNECTIONS` | No | `100` | Max concurrent HTTP connections to Portainer |
| `PORTAINER_HTTP_MAX_KEEPALIVE` | No | `20` | Max idle keep-alive connections |
| `PORTAINER_JWT_TTL` | No | `25200` (7h) | Proactive JWT refresh interval (seconds). Set below Portainer's session timeout (default 8h) to avoid per-call 401 re-auth round-trips. |

All values are validated at startup — a malformed URL, a non-numeric timeout, or a non-positive limit fails fast with a clear error instead of breaking later.

---

## Tools

All 41 tools are listed below with their parameters and descriptions. Every tool returns JSON.

### Authentication

| Tool | Description |
|---|---|
| `portainer_status()` | Check connection and authentication status. Returns version and instance ID. |

### Endpoints (Environments)

| Tool | Description |
|---|---|
| `portainer_endpoints_list()` | List all environments. Returns id, name, type, url, status. |
| `portainer_endpoint_inspect(endpoint_id)` | Get endpoint details (sensitive fields like TLS certs are filtered). |

### Stacks

| Tool | Description |
|---|---|
| `portainer_stacks_list()` | List all stacks with id, name, type, status, endpoint_id. |
| `portainer_stack_inspect(stack_id)` | Get stack details including the docker-compose file content. |
| `portainer_stack_deploy(name, compose_content, endpoint_id?)` | Deploy a new stack. Auto-detects Swarm vs standalone. |
| `portainer_stack_update(stack_id, compose_content?, endpoint_id?)` | Update a stack. Omit compose_content to redeploy existing. If `endpoint_id` is omitted, it is derived from the stack itself. |
| `portainer_stack_delete(stack_id)` | Delete a stack. |
| `portainer_stack_start(stack_id)` | Start a stopped stack. |
| `portainer_stack_stop(stack_id)` | Stop a running stack. |

### Containers

| Tool | Description |
|---|---|
| `portainer_containers_list(endpoint_id?, show_all?, name_filter?)` | List containers. Set `show_all=true` to include stopped; `name_filter` applies a server-side Docker name filter. |
| `portainer_container_inspect(container_id, endpoint_id?)` | Get detailed container info. |
| `portainer_container_start(container_id, endpoint_id?)` | Start a stopped container. |
| `portainer_container_stop(container_id, endpoint_id?)` | Stop a running container. |
| `portainer_container_restart(container_id, endpoint_id?)` | Restart a container. |
| `portainer_container_remove(container_id, force?, endpoint_id?)` | Remove a container. `force` defaults to false. |
| `portainer_container_logs(container_id, tail?, endpoint_id?)` | Get container logs as a JSON envelope (`logs`, `truncated`, `total_chars`). `tail` defaults to 100 (max 1000). |
| `portainer_container_logs_grep(container_id, pattern, tail?, context_lines?, endpoint_id?)` | Server-side regex over logs. Returns only matching lines (with optional context) — saves bandwidth on noisy logs. |
| `portainer_container_stats(container_id, endpoint_id?)` | Point-in-time CPU%, memory, network and block I/O stats (not a stream). |
| `portainer_container_exec(container_id, command, workdir?, user?, endpoint_id?)` | Run a shell command inside a running container and return its stdout/stderr + exit code. Audit-logged. |
| `portainer_stack_logs_errors(stack_name, tail?, endpoint_id?)` | Concurrent scan of every running container in a stack for HTTP 4xx/5xx, exceptions, fatal/critical levels, panics, OOM, PHP errors, etc. |
| `portainer_laravel_errors(stack_name, tail?, endpoint_id?)` | Read `/var/www/app/storage/logs/laravel.log` inside each container of a stack and return `production.ERROR/CRITICAL/EMERGENCY` entries — the actual exception behind a 500. |
| `portainer_laravel_tinker(stack_name, code, endpoint_id?)` | Execute PHP via `php artisan tinker --execute=...` in the first running `{stack}_backend` container (Swarm, plain-Compose and Compose-v1 naming all matched). Code capped at 4096 chars. Audit-logged. |

### Images

| Tool | Description |
|---|---|
| `portainer_images_list(endpoint_id?, reference_filter?)` | List images with tags and sizes. `reference_filter` applies a server-side filter (e.g. `nginx:1.25`). |
| `portainer_image_inspect(image_id, endpoint_id?)` | Get detailed image info. Accepts `name:tag` or `name@sha256:digest`. |
| `portainer_image_pull(image_name, tag?, registry_auth?, endpoint_id?)` | Pull an image. `tag` defaults to `"latest"`. `registry_auth` is an optional base64-encoded JSON `{"username":..,"password":..,"serveraddress":..}` forwarded as `X-Registry-Auth` — required for private registries. The pull-progress stream is parsed and any `errorDetail` is surfaced as a tool error (the previous version returned success regardless). |
| `portainer_image_remove(image_id, endpoint_id?)` | Remove an image. |

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
| `portainer_docker_info(endpoint_id?)` | OS, CPU, memory, container/image counts, swarm state. |
| `portainer_docker_disk_usage(endpoint_id?)` | Per-category disk usage (containers, images, volumes, build cache) with reclaimable size. |

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

**Update an existing stack:**
> "Update the arena-etl stack to use the new image tag v2.1"

The agent will call `portainer_stack_inspect(stack_id)` to get the current compose file, modify the image tag, then `portainer_stack_update(stack_id, compose_content)`.

---

## Security

- **JWT auth** with proactive refresh (7h TTL, Portainer default is 8h), `asyncio.Lock`-guarded re-authentication for safe concurrent use, and 401/403-CSRF retry fallback.
- **CSRF handling** for Portainer 2.39+ — Referer + `X-CSRF-Token` are sent only on mutating methods; CSRF token is harvested from `X-CSRF-Token` response headers and refreshed automatically.
- **SSL verification** enabled by default. Only disable for self-signed certificates.
- **Input validation** — container IDs, image references (incl. digests), stack names, volume/network names are regex-validated before any API call. Path traversal (`..`) is blocked.
- **Sensitive field filtering** — `endpoint_inspect` strips TLS certificates, Azure credentials and security settings; `user_inspect` whitelists safe fields and hides password/TFA material.
- **Audit logging** — every mutating operation (deploy, delete, remove, pull, start, stop, exec, tinker) is logged to stderr with parameters.
- **No hardcoded credentials** — all secrets come from environment variables. Optional `X-Registry-Auth` for private-registry image pulls is passed in via parameter, never persisted.
- **Container removal** — `force` defaults to `false` to prevent accidental deletion of running containers.
- **Log/exec size limits** — output is capped at 100K characters to prevent memory exhaustion.

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

Lint and type-check:

```bash
ruff check src/
mypy src/
```

---

## Requirements

- Python 3.10+
- A running Portainer instance (CE or Business Edition)
- Portainer API access (default port 9443)

## License

[MIT](LICENSE)
