from __future__ import annotations

import base64
import json
import logging
import re
from typing import Any
from urllib.parse import quote, urlsplit

from mcp.server.fastmcp import FastMCP

from ..client import PortainerClient, get_client
from ..config import get_config
from ..errors import error_response, resolve_endpoint, tool_error_handler, validate_id

logger = logging.getLogger(__name__)

# Optional digest suffix (e.g. @sha256:...). Allows any algo:hex pair commonly
# used by OCI (sha256, sha512). The hash must be at least 32 hex chars.
_IMAGE_REF_RE = re.compile(
    # optional registry host with port (`reg.local:5000/`) …
    r"^(?:[a-zA-Z0-9][a-zA-Z0-9.\-]{0,253}(?::[0-9]{1,5})?/)?"
    # … repository path, optional tag, optional digest
    r"[a-zA-Z0-9]([a-zA-Z0-9_.\-/]*[a-zA-Z0-9])?"
    r"(:[a-zA-Z0-9_.\-]+)?"
    r"(@[a-z0-9]+:[a-fA-F0-9]{32,})?$"
)
# A tag on its own (no `/`, no `@`): what `image_pull(tag=)` must look like.
_IMAGE_TAG_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.\-]{0,127}$")
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


# portainer.RegistryType
_REGISTRY_TYPES = {
    1: "quay",
    2: "azure",
    3: "custom",
    4: "gitlab",
    5: "proget",
    6: "dockerhub",
    7: "ecr",
}
_DOCKERHUB_REGISTRY_TYPE = next(k for k, v in _REGISTRY_TYPES.items() if v == "dockerhub")
# Every spelling of Docker Hub collapses to the canonical host, so a private
# Hub repository can match a DockerHub registry configured in Portainer
# (Portainer stores those with URL "docker.io").
_DOCKER_HUB = "docker.io"
_DOCKER_HUB_HOSTS = frozenset({_DOCKER_HUB, "index.docker.io", "registry-1.docker.io"})
# registry_id=0 is the explicit "anonymous, ignore any stored credentials"
# switch — validate_id would otherwise reject 0 and there would be no way
# to opt out of auto-matching (a rotated stored token breaks public pulls).
ANONYMOUS_REGISTRY = 0


def image_registry_host(image: str) -> str:
    """Registry host of an image reference (``docker.io`` for Docker Hub).

    Docker's rule: the first path component is a registry only if it
    contains a ``.`` or ``:`` or is ``localhost``; otherwise it is a Hub
    namespace (``library/nginx``, ``ginkida/app``). Default ports are
    dropped so ``reg.local:443/app`` matches a registry stored as
    ``https://reg.local``.
    """
    first, sep, _ = image.partition("/")
    # reference.splitDockerDomain: a component with an uppercase letter is a
    # host too (repository paths must be lowercase), so `Registry/app`
    # addresses host "registry", not the Hub namespace "Registry".
    looks_like_host = (
        "." in first or ":" in first or first == "localhost" or first != first.lower()
    )
    if not sep or not looks_like_host:
        return _DOCKER_HUB
    host = _registry_host(first)
    return _DOCKER_HUB if host in _DOCKER_HUB_HOSTS else host


def _is_hub_official(image: str) -> bool:
    """``nginx`` / ``library/nginx`` / ``docker.io/nginx`` — an official
    image, always public: a stored Hub token adds nothing to the pull."""
    if image_registry_host(image) != _DOCKER_HUB:
        return False
    first, sep, rest = image.partition("/")
    path = rest if sep and first.lower() in _DOCKER_HUB_HOSTS else image
    repo = path.split("@", 1)[0].rsplit(":", 1)[0]
    return "/" not in repo or repo.startswith("library/")


def _registry_host(url: Any) -> str:
    """Normalise Portainer's Registry.URL to ``host[:port]``.

    Portainer's URL field is free text: it may carry a scheme, userinfo, a
    path (``/v2/``) or a default port — none of which appear in an image
    reference. ``urlsplit`` needs a scheme to parse the authority.
    """
    if not isinstance(url, str) or not url.strip():
        return ""
    raw = url.strip()
    parts = urlsplit(raw if "://" in raw else f"//{raw}")
    host = (parts.hostname or "").lower()
    try:
        port = parts.port
    except ValueError:
        port = None
    if not host:
        return ""
    if port is None or port in (80, 443):
        return host
    return f"{host}:{port}"


async def match_registry_id(
    client: PortainerClient, eid: int, image: str
) -> tuple[int | None, str]:
    """``(registry_id, credentials label)`` for an image, from Portainer's registries.

    Lets pulls and service updates of private images use the credentials
    stored in Portainer without the caller having to know the registry id.
    Uses the endpoint-scoped listing (``/api/endpoints/{id}/registries``):
    the global ``/api/registries`` is admin-only, and the scoped one returns
    exactly the registries this user may use on this endpoint. Tolerant: a
    failed listing just means "no match" — the Docker call then proceeds
    anonymously and the label says why. More than one registry on the same
    host (GitLab: one per project; two Hub accounts) also means anonymous —
    guessing would fail a private pull while looking authorised, while a
    public image must keep working; the label carries the candidate ids.
    """
    host = image_registry_host(image)
    if host == _DOCKER_HUB and _is_hub_official(image):
        # Official images are public; a stored Hub token adds nothing and a
        # stale one would break the pull.
        return None, "none (official Docker Hub image)"
    try:
        registries = await client.get(f"/api/endpoints/{eid}/registries")
    except Exception as exc:
        logger.warning("Registry listing failed while matching %s: %s", image, exc)
        return None, "none (registry listing failed)"
    if not isinstance(registries, list):
        logger.warning("Unexpected registry listing body while matching %s", image)
        return None, "none (unexpected registry listing)"
    matches: list[int] = []
    for reg in registries:
        if not isinstance(reg, dict) or not reg.get("Authentication"):
            continue  # an unauthenticated entry injects nothing
        rid = reg.get("Id")
        if not isinstance(rid, int) or isinstance(rid, bool) or rid <= 0:
            continue
        reg_host = _registry_host(reg.get("URL"))
        if host == _DOCKER_HUB:
            hub_type = reg.get("Type") == _DOCKERHUB_REGISTRY_TYPE
            if hub_type or reg_host in _DOCKER_HUB_HOSTS:
                matches.append(rid)
        elif reg_host == host:
            matches.append(rid)
    if not matches:
        return None, "none"
    if len(matches) > 1:
        return None, f"none (ambiguous: registries {matches} match {host!r}; pass registry_id)"
    return matches[0], "portainer (auto)"


async def registry_auth_headers(
    client: PortainerClient,
    eid: int,
    image: str,
    registry_id: int | None,
    registry_auth: str | None = None,
) -> tuple[dict[str, str], int | None, str]:
    """The one credential-selection path for pulls and service updates.

    Returns ``(headers, registry_id, credentials)`` where ``credentials``
    says how they were chosen: ``portainer`` (explicit id), ``portainer
    (auto)`` (matched by host), ``explicit`` (raw X-Registry-Auth),
    ``anonymous (forced)`` (``registry_id=0``) or ``none``.
    """
    if registry_id is not None and registry_auth is not None:
        raise ValueError("Pass either registry_id or registry_auth, not both")
    if registry_id == ANONYMOUS_REGISTRY:
        return {}, None, "anonymous (forced)"
    if registry_id is not None:
        validate_id(registry_id, "registry_id")
        headers = {"X-Registry-Auth": portainer_registry_auth_header(registry_id)}
        return headers, registry_id, "portainer"
    if registry_auth is not None:
        _validate_registry_auth(registry_auth)
        return {"X-Registry-Auth": registry_auth}, None, "explicit"
    matched, credentials = await match_registry_id(client, eid, image)
    if matched is None:
        return {}, None, credentials
    return {"X-Registry-Auth": portainer_registry_auth_header(matched)}, matched, credentials


def registry_hint(registry_id: int | None, credentials: str) -> str:
    """Suffix for pull/update error details: which credentials were used and
    how to change that — a stale stored token or a denied listing otherwise
    surfaces as a bare "unauthorized"."""
    return (
        f" [registry_id={registry_id}, credentials={credentials}; pass registry_id "
        f"explicitly or registry_id={ANONYMOUS_REGISTRY} to pull anonymously]"
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

        Credentials for a registry configured in Portainer are supplied by
        Portainer itself: the registry is picked automatically by matching
        the image's host against portainer_registries_list (Docker Hub
        images match a DockerHub-type registry), or explicitly via
        registry_id. registry_id=0 forces an anonymous pull. No password
        ever passes through the model. Explicit registry_auth is only
        needed for a registry Portainer does not know.

        Args:
            image_name: Image name (e.g. 'nginx', 'ghcr.io/org/app')
            tag: Image tag (default 'latest')
            registry_id: ID of a registry configured in Portainer whose
                stored credentials should be used (auto-detected from the
                image host when omitted; 0 = pull anonymously)
            registry_auth: Base64-encoded JSON
                ({"username":..,"password":..,"serveraddress":..})
                forwarded as X-Registry-Auth for a registry not configured
                in Portainer. Mutually exclusive with registry_id.
            endpoint_id: Target endpoint ID (uses default if omitted)
        """
        # Validate the two parts separately: concatenated, a tag containing
        # "/" re-parses as a registry host:port and slips through. And the
        # name must not carry its own tag/digest: Docker's `tag` query param
        # would silently replace it and a different image would be pulled.
        _validate_image_ref(image_name)
        last = image_name.rsplit("/", 1)[-1]
        if ":" in last or "@" in image_name:
            raise ValueError(
                f"image_name {image_name!r} already carries a tag or digest; "
                "pass the tag via the tag argument instead"
            )
        if not _IMAGE_TAG_RE.match(tag):
            raise ValueError(f"Invalid tag: {tag!r}. Must match {_IMAGE_TAG_RE.pattern}")
        client = get_client()
        config = get_config()
        eid = resolve_endpoint(endpoint_id, config.default_endpoint)
        headers, registry_id, credentials = await registry_auth_headers(
            client, eid, image_name, registry_id, registry_auth
        )

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
                "; ".join(errors[:3]) + registry_hint(registry_id, credentials),
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
