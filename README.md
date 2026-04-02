<p align="center">
  <img src="https://minio.ginkida.dev/minion/github/portainer-mcp.png" alt="Portainer MCP Server" width="600">
</p>

# Portainer MCP Server

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://python.org)
[![MCP](https://img.shields.io/badge/MCP-compatible-green.svg)](https://modelcontextprotocol.io)
[![PyPI](https://img.shields.io/pypi/v/portainer-mcp)](https://pypi.org/project/portainer-mcp/)

An MCP (Model Context Protocol) server that gives AI assistants — Claude, Copilot, Cursor, and others — **23 tools to manage Portainer container environments**: deploy and update stacks, start/stop/restart containers, pull/remove images, inspect endpoints, and manage users — all through natural language.

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
| `PORTAINER_URL` | **Yes** | — | Portainer base URL (e.g. `https://portainer.example.com:9443`) |
| `PORTAINER_USERNAME` | **Yes** | — | Portainer username |
| `PORTAINER_PASSWORD` | **Yes** | — | Portainer password |
| `PORTAINER_DEFAULT_ENDPOINT` | No | `1` | Default endpoint ID for container/image/stack operations |
| `PORTAINER_VERIFY_SSL` | No | `true` | Set to `false` for self-signed certificates |

---

## Tools

All 23 tools are listed below with their parameters and descriptions. Every tool returns JSON.

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
| `portainer_stack_update(stack_id, compose_content?, endpoint_id?)` | Update a stack. Omit compose_content to redeploy existing. |
| `portainer_stack_delete(stack_id)` | Delete a stack. |
| `portainer_stack_start(stack_id)` | Start a stopped stack. |
| `portainer_stack_stop(stack_id)` | Stop a running stack. |

### Containers

| Tool | Description |
|---|---|
| `portainer_containers_list(endpoint_id?, all?)` | List containers. Set `all=true` to include stopped. |
| `portainer_container_inspect(container_id, endpoint_id?)` | Get detailed container info. |
| `portainer_container_start(container_id, endpoint_id?)` | Start a stopped container. |
| `portainer_container_stop(container_id, endpoint_id?)` | Stop a running container. |
| `portainer_container_restart(container_id, endpoint_id?)` | Restart a container. |
| `portainer_container_remove(container_id, force?, endpoint_id?)` | Remove a container. `force` defaults to false. |
| `portainer_container_logs(container_id, tail?, endpoint_id?)` | Get container logs. `tail` defaults to 100 (max 1000). |

### Images

| Tool | Description |
|---|---|
| `portainer_images_list(endpoint_id?)` | List images with tags and sizes. |
| `portainer_image_inspect(image_id, endpoint_id?)` | Get detailed image info. |
| `portainer_image_pull(image_name, tag?, endpoint_id?)` | Pull an image. `tag` defaults to "latest". |
| `portainer_image_remove(image_id, endpoint_id?)` | Remove an image. |

### Users

| Tool | Description |
|---|---|
| `portainer_users_list()` | List all Portainer users with id, username, role. |
| `portainer_user_inspect(user_id)` | Get user details. |

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

- **JWT auth** with proactive refresh (7h TTL, Portainer default is 8h) plus 401-retry fallback.
- **SSL verification** enabled by default. Only disable for self-signed certificates.
- **Input validation** — container IDs, image references, and stack names are validated with regex before API calls. Path traversal (`..`) is blocked.
- **Sensitive field filtering** — `endpoint_inspect` strips TLS certificates, Azure credentials, and security settings from responses.
- **Audit logging** — all mutating operations (deploy, delete, remove, pull, start, stop) are logged to stderr with parameters.
- **No hardcoded credentials** — all secrets come from environment variables.
- **Container removal** — `force` defaults to `false` to prevent accidental deletion of running containers.
- **Log size limits** — container logs are capped at 100K characters to prevent memory exhaustion.

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
