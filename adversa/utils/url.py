"""URL normalization utilities."""
from urllib.parse import urlparse


def canonical_url(url: str) -> str:
    """Return a canonical form of a URL: scheme://host[:port]/path (no query/fragment, trailing slash stripped)."""
    parsed = urlparse(url)
    scheme = parsed.scheme or "https"
    host = (parsed.hostname or "").lower()
    port = parsed.port
    path = parsed.path.rstrip("/") or "/"
    if port and not ((scheme == "https" and port == 443) or (scheme == "http" and port == 80)):
        return f"{scheme}://{host}:{port}{path}"
    return f"{scheme}://{host}{path}"
