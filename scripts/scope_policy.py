"""Shared, dependency-free scope parsing for Mulderx network tooling."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener


class ScopeError(ValueError):
    """The requested host or URL is not valid under the supplied scope."""


def normalize_hostname(value: str) -> str:
    raw = value.strip().strip("[]").rstrip(".")
    if not raw or any(ch.isspace() for ch in raw) or any(ch in raw for ch in "/\\@?#"):
        raise ScopeError("Se esperaba un hostname o una dirección IP, sin ruta ni credenciales.")
    try:
        return ipaddress.ip_address(raw).compressed.lower()
    except ValueError:
        pass
    try:
        host = raw.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ScopeError("Hostname IDNA inválido.") from exc
    if len(host) > 253:
        raise ScopeError("Hostname demasiado largo.")
    labels = host.split(".")
    if any(
        not label
        or len(label) > 63
        or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label)
        for label in labels
    ):
        raise ScopeError("Hostname inválido.")
    return host


def normalize_domain_input(value: str) -> str:
    """Accept a bare host or a root HTTP(S) URL, and return its canonical host."""
    raw = value.strip()
    if not raw:
        raise ScopeError("El dominio no puede estar vacío.")
    try:
        if "://" in raw:
            parsed = urlsplit(raw)
            if parsed.scheme.lower() not in {"http", "https"}:
                raise ScopeError("Solo se admiten URLs HTTP(S).")
        else:
            parsed = urlsplit("//" + raw)
        if parsed.username is not None or parsed.password is not None:
            raise ScopeError("No se admiten credenciales en el target.")
        if parsed.port is not None:
            raise ScopeError("El target debe ser un hostname sin puerto.")
        if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
            raise ScopeError("El target debe ser un dominio raíz, sin ruta, query ni fragmento.")
        if not parsed.hostname:
            raise ScopeError("No se pudo extraer un hostname del target.")
        return normalize_hostname(parsed.hostname)
    except ValueError as exc:
        if isinstance(exc, ScopeError):
            raise
        raise ScopeError("Target HTTP(S) inválido.") from exc


@dataclass(frozen=True)
class HostScope:
    root: str
    include_apex: bool = True
    include_subdomains: bool = False

    @classmethod
    def parse(cls, value: str, *, include_subdomains_for_root: bool = False) -> "HostScope":
        raw = value.strip()
        if raw.startswith("*."):
            root = normalize_hostname(raw[2:])
            try:
                ipaddress.ip_address(root)
            except ValueError:
                pass
            else:
                raise ScopeError("El wildcard solo se admite para nombres DNS, no direcciones IP.")
            return cls(root, include_apex=False, include_subdomains=True)
        if "*" in raw:
            raise ScopeError("El wildcard solo puede aparecer como prefijo '*.'.")
        return cls(
            normalize_hostname(raw),
            include_apex=True,
            include_subdomains=include_subdomains_for_root,
        )

    def matches_host(self, hostname: str) -> bool:
        try:
            host = normalize_hostname(hostname)
        except ScopeError:
            return False
        if host == self.root:
            return self.include_apex
        return self.include_subdomains and host.endswith("." + self.root)

    def matches_url(self, url: str, *, base_url: str | None = None) -> bool:
        candidate = url
        parsed = urlsplit(candidate)
        if not parsed.scheme and not parsed.netloc:
            if not base_url:
                return False
            candidate = urljoin(base_url, candidate)
            parsed = urlsplit(candidate)
        elif not parsed.scheme and parsed.netloc and base_url:
            base_scheme = urlsplit(base_url).scheme
            candidate = f"{base_scheme}:{candidate}"
            parsed = urlsplit(candidate)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            return False
        if parsed.username is not None or parsed.password is not None:
            return False
        try:
            parsed.port  # Force validation of malformed ports.
        except ValueError:
            return False
        return self.matches_host(parsed.hostname)


def url_in_scope(
    url: str,
    scope: str,
    *,
    base_url: str | None = None,
    include_subdomains_for_root: bool = False,
) -> bool:
    try:
        policy = HostScope.parse(scope, include_subdomains_for_root=include_subdomains_for_root)
    except ScopeError:
        return False
    return policy.matches_url(url, base_url=base_url)


def parse_orchestrator_target(target: str, scope_type: str) -> tuple[str, bool]:
    """Validate the legacy orchestrator's explicit exact-domain/wildcard mode."""
    raw = target.strip()
    wildcard = raw.startswith("*.")
    if scope_type not in {"domain", "wildcard"}:
        raise ScopeError("Tipo de scope desconocido.")
    if wildcard != (scope_type == "wildcard"):
        expected = "*.example.com" if scope_type == "wildcard" else "example.com"
        raise ScopeError(f"El target no coincide con --scope {scope_type}; usa {expected}.")
    host = normalize_hostname(raw[2:] if wildcard else raw)
    if wildcard:
        try:
            ipaddress.ip_address(host)
        except ValueError:
            pass
        else:
            raise ScopeError("No se admite wildcard sobre una dirección IP.")
    return host, wildcard


def build_katana_regex(target: str, scope_type: str = "domain") -> str:
    host, wildcard = parse_orchestrator_target(target, scope_type)
    if ":" in host:
        escaped_host = r"\[" + re.escape(host) + r"\]"
    else:
        escaped_host = re.escape(host)
    subdomain = r"([^/:?#@]+\.)+" if wildcard else ""
    return rf"^https?://{subdomain}{escaped_host}(:[0-9]+)?([/?#]|$)"


def validate_program_name(value: str) -> str:
    name = value.strip()
    if (
        not name
        or len(name) > 64
        or name in {".", ".."}
        or name.startswith(".")
        or name.endswith((".", " "))
        or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9 ._-]*", name)
        or name.lower() in {".credentials", ".git", ".aws"}
    ):
        raise ScopeError("Nombre de programa inválido; usa letras, números, espacios, punto, guion o underscore.")
    reserved = {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)), *(f"LPT{i}" for i in range(1, 10))}
    if name.split(".", 1)[0].upper() in reserved:
        raise ScopeError("El nombre de programa está reservado por Windows.")
    return name


class _ScopeRedirectHandler(HTTPRedirectHandler):
    def __init__(self, scope: str, include_subdomains_for_root: bool):
        super().__init__()
        self.scope = scope
        self.include_subdomains_for_root = include_subdomains_for_root

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        resolved = urljoin(req.full_url, newurl)
        if not url_in_scope(
            resolved,
            self.scope,
            include_subdomains_for_root=self.include_subdomains_for_root,
        ):
            raise ScopeError("Redirección bloqueada: el destino sale del scope autorizado.")
        return super().redirect_request(req, fp, code, msg, headers, resolved)


def open_scoped_url(
    url: str,
    scope: str,
    *,
    timeout: float = 20,
    headers: dict[str, str] | None = None,
    method: str = "GET",
    include_subdomains_for_root: bool = False,
):
    if not url_in_scope(url, scope, include_subdomains_for_root=include_subdomains_for_root):
        raise ScopeError("Request bloqueado: el URL sale del scope autorizado.")
    request = Request(url, headers=headers or {}, method=method)
    opener = build_opener(_ScopeRedirectHandler(scope, include_subdomains_for_root))
    return opener.open(request, timeout=timeout)
