"""VibeGuard Registry MCP Server.

FastMCP server exposing tools for package registry verification,
typosquat detection, and dependency age/popularity analysis.

Usage:
    Standalone:  python registry_server.py
    Import:      from mcp_server.registry_server import mcp
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

import requests
from Levenshtein import distance as levenshtein_distance
from fastmcp import FastMCP

# ---------------------------------------------------------------------------
# Popular packages list — used for typosquat comparison
# ---------------------------------------------------------------------------
POPULAR_PACKAGES: list[str] = [
    "requests",
    "flask",
    "django",
    "numpy",
    "pandas",
    "tensorflow",
    "torch",
    "transformers",
    "openai",
    "langchain",
    "fastapi",
    "sqlalchemy",
    "boto3",
    "pillow",
    "scikit-learn",
    "beautifulsoup4",
    "celery",
    "redis",
    "pytest",
    "httpx",
    "pydantic",
    "uvicorn",
    "gunicorn",
    "aiohttp",
    "cryptography",
]

# Default HTTP timeout (seconds)
_HTTP_TIMEOUT: int = 15

# ---------------------------------------------------------------------------
# FastMCP server instance
# ---------------------------------------------------------------------------
mcp = FastMCP("VibeGuard Registry")


# ===== Helpers =============================================================

def _safe_get(url: str, timeout: int = _HTTP_TIMEOUT) -> requests.Response:
    """Perform a GET request with timeout and unified error handling.

    Args:
        url: The URL to fetch.
        timeout: Request timeout in seconds.

    Returns:
        The HTTP response object.

    Raises:
        requests.RequestException: On network / HTTP errors (except 404,
            which callers handle explicitly).
    """
    response = requests.get(url, timeout=timeout)
    return response


def _parse_creation_date(releases: dict[str, list[dict]]) -> Optional[str]:
    """Extract the earliest upload date from a PyPI releases dict.

    Args:
        releases: Mapping of version string → list of file-info dicts,
            each containing an ``upload_time_iso_8601`` key.

    Returns:
        ISO-8601 date string of the earliest upload, or ``None``
        if no uploads are found.
    """
    earliest: Optional[datetime] = None
    for _version, files in releases.items():
        for file_info in files:
            upload_str = file_info.get("upload_time_iso_8601")
            if upload_str:
                try:
                    upload_dt = datetime.fromisoformat(
                        upload_str.replace("Z", "+00:00")
                    )
                    if earliest is None or upload_dt < earliest:
                        earliest = upload_dt
                except (ValueError, TypeError):
                    continue
    return earliest.isoformat() if earliest else None


# ===== MCP Tools ===========================================================


@mcp.tool()
def check_pypi(package_name: str) -> dict[str, Any]:
    """Check whether a Python package exists on PyPI and return its metadata.

    Args:
        package_name: The exact package name to look up (e.g. ``requests``).

    Returns:
        A dict with keys ``exists``, ``name``, ``version``, ``summary``,
        ``author``, ``home_page``, and ``license``.  If the package is not
        found, ``exists`` is ``False`` and an ``error`` key is included.
    """
    url = f"https://pypi.org/pypi/{package_name}/json"
    try:
        resp = _safe_get(url)
        if resp.status_code == 404:
            return {
                "exists": False,
                "name": package_name,
                "error": "Package not found on PyPI",
            }
        resp.raise_for_status()
        data = resp.json()
        info = data.get("info", {})
        return {
            "exists": True,
            "name": info.get("name", package_name),
            "version": info.get("version", "unknown"),
            "summary": info.get("summary", ""),
            "author": info.get("author", "unknown"),
            "home_page": info.get("home_page", ""),
            "license": info.get("license", "unknown"),
        }
    except requests.RequestException as exc:
        return {
            "exists": False,
            "name": package_name,
            "error": f"PyPI request failed: {exc}",
        }


@mcp.tool()
def check_npm(package_name: str) -> dict[str, Any]:
    """Check whether a JavaScript package exists on the npm registry.

    Args:
        package_name: The exact npm package name (e.g. ``express``).

    Returns:
        A dict with keys ``exists``, ``name``, ``version``, ``description``,
        ``author``, and ``license``.  If not found, ``exists`` is ``False``.
    """
    url = f"https://registry.npmjs.org/{package_name}"
    try:
        resp = _safe_get(url)
        if resp.status_code == 404:
            return {
                "exists": False,
                "name": package_name,
                "error": "Package not found on npm",
            }
        resp.raise_for_status()
        data = resp.json()

        # npm "dist-tags.latest" → latest version key
        latest_version = data.get("dist-tags", {}).get("latest", "unknown")
        version_info = data.get("versions", {}).get(latest_version, {})

        # Author may be a string or dict
        raw_author = version_info.get("author") or data.get("author", "unknown")
        if isinstance(raw_author, dict):
            author = raw_author.get("name", "unknown")
        else:
            author = str(raw_author)

        return {
            "exists": True,
            "name": data.get("name", package_name),
            "version": latest_version,
            "description": data.get("description", ""),
            "author": author,
            "license": version_info.get("license", data.get("license", "unknown")),
        }
    except requests.RequestException as exc:
        return {
            "exists": False,
            "name": package_name,
            "error": f"npm request failed: {exc}",
        }


@mcp.tool()
def package_age_downloads(
    package_name: str,
    registry: str = "pypi",
) -> dict[str, Any]:
    """Retrieve a package's age (creation date) and approximate download count.

    Args:
        package_name: The package to query.
        registry: ``"pypi"`` (default) or ``"npm"``.

    Returns:
        A dict containing ``name``, ``registry``, ``created_date``,
        ``latest_version``, ``age_days``, and ``downloads_estimate``.
    """
    if registry.lower() == "npm":
        return _npm_age_downloads(package_name)
    return _pypi_age_downloads(package_name)


def _pypi_age_downloads(package_name: str) -> dict[str, Any]:
    """Internal: fetch age & downloads from PyPI."""
    url = f"https://pypi.org/pypi/{package_name}/json"
    try:
        resp = _safe_get(url)
        if resp.status_code == 404:
            return {
                "name": package_name,
                "registry": "pypi",
                "error": "Package not found on PyPI",
            }
        resp.raise_for_status()
        data = resp.json()
        info = data.get("info", {})
        releases = data.get("releases", {})

        created_date = _parse_creation_date(releases)
        age_days: Optional[int] = None
        if created_date:
            try:
                created_dt = datetime.fromisoformat(created_date)
                age_days = (datetime.now(timezone.utc) - created_dt).days
            except (ValueError, TypeError):
                pass

        # PyPI JSON API doesn't expose download counts directly.
        # We provide a rough heuristic from the number of releases.
        release_count = len(releases)
        downloads_estimate = (
            "high"
            if release_count > 50
            else "medium"
            if release_count > 10
            else "low"
        )

        return {
            "name": info.get("name", package_name),
            "registry": "pypi",
            "created_date": created_date,
            "latest_version": info.get("version", "unknown"),
            "age_days": age_days,
            "downloads_estimate": downloads_estimate,
        }
    except requests.RequestException as exc:
        return {
            "name": package_name,
            "registry": "pypi",
            "error": f"PyPI request failed: {exc}",
        }


def _npm_age_downloads(package_name: str) -> dict[str, Any]:
    """Internal: fetch age & downloads from npm."""
    url = f"https://registry.npmjs.org/{package_name}"
    try:
        resp = _safe_get(url)
        if resp.status_code == 404:
            return {
                "name": package_name,
                "registry": "npm",
                "error": "Package not found on npm",
            }
        resp.raise_for_status()
        data = resp.json()

        time_info = data.get("time", {})
        created_date = time_info.get("created")
        latest_version = data.get("dist-tags", {}).get("latest", "unknown")

        age_days: Optional[int] = None
        if created_date:
            try:
                created_dt = datetime.fromisoformat(
                    created_date.replace("Z", "+00:00")
                )
                age_days = (datetime.now(timezone.utc) - created_dt).days
            except (ValueError, TypeError):
                pass

        version_count = len(data.get("versions", {}))
        downloads_estimate = (
            "high"
            if version_count > 50
            else "medium"
            if version_count > 10
            else "low"
        )

        return {
            "name": data.get("name", package_name),
            "registry": "npm",
            "created_date": created_date,
            "latest_version": latest_version,
            "age_days": age_days,
            "downloads_estimate": downloads_estimate,
        }
    except requests.RequestException as exc:
        return {
            "name": package_name,
            "registry": "npm",
            "error": f"npm request failed: {exc}",
        }


@mcp.tool()
def typosquat_candidates(
    package_name: str,
    known_packages: Optional[list[str]] = None,
) -> dict[str, Any]:
    """Detect potential typosquatting by comparing a name to popular packages.

    Uses Levenshtein distance to find popular packages whose names are
    within edit-distance 1–2 of the queried name.

    Args:
        package_name: The package name to evaluate.
        known_packages: Optional override list of known-good names.
            Defaults to the built-in ``POPULAR_PACKAGES`` list.

    Returns:
        A dict with ``package_name``, ``similar_to`` (list of
        ``{name, distance}``), ``is_potential_typosquat`` flag,
        and ``risk_level`` (``"high"`` / ``"medium"`` / ``"low"`` / ``"none"``).
    """
    targets = known_packages if known_packages else POPULAR_PACKAGES
    similar: list[dict[str, Any]] = []

    normalized_name = package_name.lower().strip()

    for known in targets:
        # Skip exact matches — the package *is* the popular one
        if normalized_name == known.lower():
            continue
        dist = levenshtein_distance(normalized_name, known.lower())
        if dist <= 2:
            similar.append({"name": known, "distance": dist})

    # Sort by distance so the closest matches come first
    similar.sort(key=lambda x: x["distance"])

    # Determine risk level
    if not similar:
        risk_level = "none"
    elif any(s["distance"] == 1 for s in similar):
        risk_level = "high"
    else:
        risk_level = "medium"

    return {
        "package_name": package_name,
        "similar_to": similar,
        "is_potential_typosquat": len(similar) > 0,
        "risk_level": risk_level,
    }


# ---------------------------------------------------------------------------
# Standalone entry-point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("Starting VibeGuard Registry MCP Server …")
    mcp.run()
