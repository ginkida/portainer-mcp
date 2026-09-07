from __future__ import annotations

import base64
import json
import logging
import re
from urllib.parse import quote

from mcp.server.fastmcp import FastMCP

from ..client import get_client
from ..config import get_config
from ..errors import error_response, resolve_endpoint, tool_error_handler, validate_id

logger = logging.getLogger(__name__)

# Optional digest suffix (e.g. @sha256:...). Allows any algo:hex pair commonly
# used by OCI (sha256, sha512). The hash must be at least 32 hex chars.
_IMAGE_REF_RE = re.compile(
    r"^[a-zA-Z0-9]([a-zA-Z0-9_.\-/]*[a-zA-Z0-9])?"
    r"(:[a-zA-Z0-9_.\-]+)?"
    r"(@[a-z0-9]+:[a-fA-F0-9]{32,})?$"
)
# Base64 (standard or URL-safe), with or without padding.
_REGISTRY_AUTH_RE = re.compile(r"^[A-Za-z0-9+/_\-]+={0,2}$")
# Cap on the /images/create progress stream we buffer before scanning for
# errors — a runaway pull log shouldn't exhaust memory.
_MAX_PULL_RESPONSE_BYTES = 5_000_000


def _validate_image_ref(ref: str) -> None:
    if not _IMAGE_REF_RE.match(ref) or ".." in ref:
        raise ValueError(
            f"Invalid image reference: {ref!r}. "
            "Expected format: [registry/]name[:tag][@algo:digest], "
            "no path traversal (..)"
        )


def portainer_registry_auth_header(registry_id: int) -> str:
    """X-Registry-Auth value that makes Portainer inject a stored registry's
    credentials. Portainer's Docker proxy decodes the header, looks the
    registry up by ``registryId`` and replaces the header with the real
    username/password before forwarding the request to the Docker daemon."""
    return base64.b64encode(json.dumps({"registryId": registry_id}).encode()).decode("ascii")


def _validate_registry_auth(auth: str) -> None:
    if len(auth) > 8192 or not _REGISTRY_AUTH_RE.match(auth):
        raise ValueError(
            "Invalid registry_auth: expected base64-encoded JSON "
            "({\"username\":..,\"password\":..,\"serveraddress\":..})"
        )


def _scan_pull_stream(text: str) -> list[str]:
    """Return the list of error messages found in a Docker /images/create
    response body. Docker returns 200 OK with newline-delimited JSON events,
    so a successful HTTP status doesn't imply the pull succeeded."""
    errors: list[str] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(event, dict):
            continue
        err = event.get("error")
        if err:
            errors.append(str(err))
            continue
        detail = event.get("errorDetail")
        if isinstance(detail, dict) and detail.get("message"):
            errors.append(str(detail["message"]))
    return errors


def register(mcp: FastMCP) -> None:
    @mcp.tool()
    @tool_error_handler
    async def portainer_images_list(
        endpoint_id: int | None = None,
        reference_filter: str | None = None,
    ) -> str:
        """List Docker images on an endpoint.

        Args:
            endpoint_id: Target endpoint ID (uses default if omitted)
            reference_filter: Only return images matching this reference
                (e.g. 'nginx' or 'nginx:1.25'; server-side Docker filter)
        """
        client = get_client()
        config = get_config()
        eid = resolve_endpoint(endpoint_id, config.default_endpoint)
        params: dict[str, str] = {}
        if reference_filter is not None:
            _validate_image_ref(reference_filter)
            params["filters"] = json.dumps({"reference": [reference_filter]})
        images = await client.get(
            f"/api/endpoints/{eid}/docker/images/json", params=params
        )
        result = []
        for img in images or []:
            result.append({
                "id": img["Id"][:19],
                "tags": img.get("RepoTags", []),
                "size_mb": round(img.get("Size", 0) / 1_048_576, 1),
                "created": img.get("Created"),
            })
        return json.dumps(result, indent=2, ensure_ascii=False)

    @mcp.tool()
    @tool_error_handler
    async def portainer_image_inspect(
        image_id: str,
        endpoint_id: int | None = None,
    ) -> str:
        """Get detailed information about a Docker image.

        Args:
            image_id: Image ID or name:tag
            endpoint_id: Target endpoint ID (uses default if omitted)
        """
        _validate_image_ref(image_id)
        client = get_client()
        config = get_config()
        eid = resolve_endpoint(endpoint_id, config.default_endpoint)
        safe_id = quote(image_id, safe="")
        data = await client.get(
            f"/api/endpoints/{eid}/docker/images/{safe_id}/json",
        )
        return json.dumps(data, indent=2, ensure_ascii=False)

    @mcp.tool()
    @tool_error_handler
    async def portainer_image_pull(
        image_name: str,
        tag: str = "latest",
        registry_id: int | None = None,
        registry_auth: str | None = None,
        endpoint_id: int | None = None,
    ) -> str:
        """Pull a Docker image from a registry.

        For a private registry configured in Portainer, pass its registry_id
        (see portainer_registries_list): Portainer injects the stored
        credentials itself, so no password ever passes through the model.
        Explicit registry_auth is only needed for a registry Portainer does
        not know about.

        Args:
            image_name: Image name (e.g. 'nginx', 'ghcr.io/org/app')
            tag: Image tag (default 'latest')
            registry_id: ID of a registry configured in Portainer whose
                stored credentials should be used
            registry_auth: Base64-encoded JSON
                ({"username":..,"password":..,"serveraddress":..})
                forwarded as X-Registry-Auth for a registry not configured
                in Portainer. Mutually exclusive with registry_id.
            endpoint_id: Target endpoint ID (uses default if omitted)
        """
        _validate_image_ref(f"{image_name}:{tag}")
        if registry_id is not None and registry_auth is not None:
            raise ValueError("Pass either registry_id or registry_auth, not both")
        client = get_client()
        config = get_config()
        eid = resolve_endpoint(endpoint_id, config.default_endpoint)

        headers: dict[str, str] = {}
        if registry_id is not None:
            validate_id(registry_id, "registry_id")
            headers["X-Registry-Auth"] = portainer_registry_auth_header(registry_id)
        elif registry_auth is not None:
            _validate_registry_auth(registry_auth)
            headers["X-Registry-Auth"] = registry_auth

        logger.info(
            "AUDIT: Pulling image %s:%s on endpoint %d (registry_id=%s)",
            image_name, tag, eid, registry_id,
        )
        resp = await client.request(
            "POST",
            f"/api/endpoints/{eid}/docker/images/create",
            params={"fromImage": image_name, "tag": tag},
            headers=headers,
            # Pulls routinely run for minutes; the default timeout would abort them.
            timeout=config.long_timeout,
        )

        # Docker streams progress as line-delimited JSON. A successful HTTP
        # status does NOT mean the pull succeeded — errors are in the body.
        # Read bytes (not .text) and bound the buffer so a runaway progress
        # stream can't exhaust memory.
        body = resp.content
        if len(body) > _MAX_PULL_RESPONSE_BYTES:
            logger.warning(
                "Image pull response is %d bytes; scanning first %d",
                len(body), _MAX_PULL_RESPONSE_BYTES,
            )
            body = body[:_MAX_PULL_RESPONSE_BYTES]
        errors = _scan_pull_stream(body.decode("utf-8", errors="replace"))
        if errors:
            return error_response(
                "Image pull failed",
                "; ".join(errors[:3]),
            )
        return json.dumps({
            "status": "pulled",
            "image": f"{image_name}:{tag}",
        }, indent=2, ensure_ascii=False)

    @mcp.tool()
    @tool_error_handler
    async def portainer_image_remove(
        image_id: str,
        endpoint_id: int | None = None,
    ) -> str:
        """Remove a Docker image.

        Args:
            image_id: Image ID or name:tag
            endpoint_id: Target endpoint ID (uses default if omitted)
        """
        _validate_image_ref(image_id)
        client = get_client()
        config = get_config()
        eid = resolve_endpoint(endpoint_id, config.default_endpoint)
        logger.info("AUDIT: Removing image %s on endpoint %d", image_id, eid)
        safe_id = quote(image_id, safe="")
        await client.delete(
            f"/api/endpoints/{eid}/docker/images/{safe_id}",
        )
        return json.dumps(
            {"status": "removed", "image_id": image_id}, indent=2, ensure_ascii=False
        )

    @mcp.tool()
    @tool_error_handler
    async def portainer_registries_list() -> str:
        """List registries configured in Portainer (id, name, URL, type).

        Use the id as registry_id in portainer_image_pull /
        portainer_service_update so Portainer supplies the stored credentials.
        """
        client = get_client()
        registries = await client.get("/api/registries")
        result = []
        for r in registries or []:
            result.append({
                "id": r.get("Id"),
                "name": r.get("Name"),
                "url": r.get("URL"),
                "type": r.get("Type"),
                "type_name": _REGISTRY_TYPES.get(r.get("Type"), "unknown"),
                "authentication": bool(r.get("Authentication")),
            })
        return json.dumps(result, indent=2, ensure_ascii=False)


# portainer.RegistryType
_REGISTRY_TYPES = {
    1: "quay", 2: "azure", 3: "custom", 4: "gitlab", 5: "proget", 6: "dockerhub", 7: "ecr",
}


# Re-exported for callers that want to assemble the X-Registry-Auth header
# without importing base64/json themselves.
def encode_registry_auth(
    username: str,
    password: str,
    serveraddress: str,
) -> str:
    """Build the base64-encoded JSON value Docker expects in X-Registry-Auth."""
    payload = json.dumps({
        "username": username,
        "password": password,
        "serveraddress": serveraddress,
    }).encode()
    return base64.b64encode(payload).decode("ascii")
