from __future__ import annotations

import base64
import json
import logging
import re
from typing import Any
from urllib.parse import quote

from mcp.server.fastmcp import FastMCP

from ..client import PortainerClient, get_client
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


# Hosts that mean "Docker Hub" — never matched against Portainer registries
# (a Hub registry entry in Portainer would only add credentials for pulls
# that work anonymously anyway, and most Hub pulls are of public images).
_DOCKER_HUB_HOSTS = frozenset({"docker.io", "index.docker.io", "registry-1.docker.io"})


def image_registry_host(image: str) -> str | None:
    """Registry host of an image reference, or ``None`` for Docker Hub.

    Docker's rule: the first path component is a registry only if it
    contains a ``.`` or ``:`` or is ``localhost``; otherwise it is a Hub
    namespace (``library/nginx``, ``ginkida/app``).
    """
    first, sep, _ = image.partition("/")
    if not sep:
        return None
    if "." not in first and ":" not in first and first != "localhost":
        return None
    return None if first.lower() in _DOCKER_HUB_HOSTS else first.lower()


def _registry_host(url: Any) -> str:
    """Normalise Portainer's Registry.URL (may carry a scheme or a path)."""
    if not isinstance(url, str):
        return ""
    host = url.strip().lower()
    if "://" in host:
        host = host.split("://", 1)[1]
    return host.split("/", 1)[0]


async def match_registry_id(client: PortainerClient, image: str) -> int | None:
    """Portainer registry whose URL matches the image's host, if any.

    Lets pulls and service updates of private images use the credentials
    stored in Portainer without the caller having to know the registry id.
    Tolerant: a failed registry listing (non-admin user, proxy hiccup) just
    means "no match" — the Docker call then proceeds as an anonymous pull.
    """
    host = image_registry_host(image)
    if host is None:
        return None
    try:
        registries = await client.get("/api/registries")
    except Exception as exc:
        logger.debug("Registry listing failed while matching %s: %s", image, exc)
        return None
    for reg in registries or []:
        if isinstance(reg, dict) and _registry_host(reg.get("URL")) == host:
            rid = reg.get("Id")
            if isinstance(rid, int) and not isinstance(rid, bool) and rid > 0:
                return rid
    return None


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

        Credentials for a registry configured in Portainer are supplied by
        Portainer itself: the registry is picked automatically by matching
        the image's host against portainer_registries_list, or explicitly
        via registry_id. No password ever passes through the model. Explicit
        registry_auth is only needed for a registry Portainer does not know.

        Args:
            image_name: Image name (e.g. 'nginx', 'ghcr.io/org/app')
            tag: Image tag (default 'latest')
            registry_id: ID of a registry configured in Portainer whose
                stored credentials should be used (auto-detected from the
                image host when omitted)
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
        credentials = "none"
        if registry_id is not None:
            validate_id(registry_id, "registry_id")
            credentials = "portainer"
        elif registry_auth is not None:
            _validate_registry_auth(registry_auth)
            headers["X-Registry-Auth"] = registry_auth
            credentials = "explicit"
        else:
            registry_id = await match_registry_id(client, image_name)
            if registry_id is not None:
                credentials = "portainer (auto)"
        if registry_id is not None:
            headers["X-Registry-Auth"] = portainer_registry_auth_header(registry_id)

        logger.info(
            "AUDIT: Pulling image %s:%s on endpoint %d (registry_id=%s, credentials=%s)",
            image_name, tag, eid, registry_id, credentials,
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
            "registry_id": registry_id,
            "credentials": credentials,
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
