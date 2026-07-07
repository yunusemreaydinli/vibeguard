"""DependencyAuditor Sub-Agent.

Scans a project's dependency files (requirements.txt, setup.py,
pyproject.toml, package.json), verifies each package against PyPI / npm,
and flags hallucinated, typosquatted, or suspiciously new packages.

The agent exposes two ADK ``FunctionTool``-compatible functions that
call the registries directly (same logic as the MCP server, but usable
inside the ADK agent loop without an MCP round-trip).
"""

from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from typing import Any, Optional

import requests
from Levenshtein import distance as levenshtein_distance
from google.adk.agents import Agent

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

POPULAR_PACKAGES: list[str] = [
    "requests", "flask", "django", "numpy", "pandas", "tensorflow",
    "torch", "transformers", "openai", "langchain", "fastapi",
    "sqlalchemy", "boto3", "pillow", "scikit-learn", "beautifulsoup4",
    "celery", "redis", "pytest", "httpx", "pydantic", "uvicorn",
    "gunicorn", "aiohttp", "cryptography",
]

_HTTP_TIMEOUT: int = 15

# Regex patterns for extracting package names from various dependency files
_REQ_LINE_RE = re.compile(
    r"^([A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?)"
)
_PYPROJECT_DEP_RE = re.compile(
    r"^([A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?)"
)

# ---------------------------------------------------------------------------
# Agent instruction (system prompt)
# ---------------------------------------------------------------------------

_DEPENDENCY_INSTRUCTION = """\
You are the DependencyAuditor agent. Your job is to scan a project's \
dependency files and verify each package exists in the official registry. \
Flag any package that:
1. Does not exist on PyPI or npm
2. Has typosquatting similarity to a popular package (Levenshtein distance ≤ 2)
3. Is very new (< 30 days old) with few downloads
4. Has a suspiciously similar name to known packages

When you receive a user message containing a repository path, call the \
``scan_dependencies`` tool with that path. Review the results and store \
your findings in the session state under 'dependency_findings'.

After scanning, provide a brief summary of:
- Total packages scanned
- Packages NOT found in the registry (hallucinated)
- Packages flagged for typosquatting risk
- Packages that are suspiciously new
"""


# ===== Dependency-file parsers =============================================


def _parse_requirements_txt(path: str) -> list[str]:
    """Extract package names from a requirements.txt file.

    Args:
        path: Absolute path to the requirements file.

    Returns:
        List of normalised package names.
    """
    packages: list[str] = []
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            for raw_line in fh:
                line = raw_line.strip()
                # Skip blanks, comments, options, and URL lines
                if not line or line.startswith(("#", "-", "http")):
                    continue
                match = _REQ_LINE_RE.match(line)
                if match:
                    packages.append(match.group(1).lower())
    except OSError:
        pass
    return packages


def _parse_setup_py(path: str) -> list[str]:
    """Extract package names from a setup.py ``install_requires`` list.

    Uses a simple regex heuristic — does **not** execute the file.

    Args:
        path: Absolute path to setup.py.

    Returns:
        List of package names found in ``install_requires``.
    """
    packages: list[str] = []
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            content = fh.read()
        # Locate install_requires=[...] block
        block_match = re.search(
            r"install_requires\s*=\s*\[([^\]]*)\]", content, re.DOTALL
        )
        if block_match:
            block = block_match.group(1)
            for item in re.findall(r"['\"]([^'\"]+)['\"]", block):
                m = _REQ_LINE_RE.match(item)
                if m:
                    packages.append(m.group(1).lower())
    except OSError:
        pass
    return packages


def _parse_pyproject_toml(path: str) -> list[str]:
    """Extract dependency names from a pyproject.toml file.

    Uses a lightweight regex approach so we don't need a TOML parser
    as an extra dependency.

    Args:
        path: Absolute path to pyproject.toml.

    Returns:
        List of package names found in ``dependencies`` or
        ``install_requires``.
    """
    packages: list[str] = []
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            content = fh.read()
        # Find all quoted strings inside dependencies = [...] blocks
        for block_match in re.finditer(
            r"dependencies\s*=\s*\[([^\]]*)\]", content, re.DOTALL
        ):
            block = block_match.group(1)
            for item in re.findall(r"['\"]([^'\"]+)['\"]", block):
                m = _PYPROJECT_DEP_RE.match(item)
                if m:
                    packages.append(m.group(1).lower())
    except OSError:
        pass
    return packages


def _parse_package_json(path: str) -> list[str]:
    """Extract dependency names from a package.json file.

    Reads both ``dependencies`` and ``devDependencies``.

    Args:
        path: Absolute path to package.json.

    Returns:
        List of package names.
    """
    packages: list[str] = []
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            data = json.load(fh)
        for key in ("dependencies", "devDependencies"):
            deps = data.get(key, {})
            if isinstance(deps, dict):
                packages.extend(deps.keys())
    except (OSError, json.JSONDecodeError):
        pass
    return packages


# ===== Registry helpers (same logic as MCP server) =========================


def _check_pypi(package_name: str) -> dict[str, Any]:
    """Verify a package on PyPI and return basic metadata.

    Args:
        package_name: The package to look up.

    Returns:
        Dict with ``exists``, ``name``, ``version``, ``summary``,
        ``author``, ``home_page``, ``license`` (or ``error``).
    """
    url = f"https://pypi.org/pypi/{package_name}/json"
    try:
        resp = requests.get(url, timeout=_HTTP_TIMEOUT)
        if resp.status_code == 404:
            return {"exists": False, "name": package_name, "error": "Not found on PyPI"}
        resp.raise_for_status()
        info = resp.json().get("info", {})
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
        return {"exists": False, "name": package_name, "error": str(exc)}


def _check_npm(package_name: str) -> dict[str, Any]:
    """Verify a package on npm and return basic metadata.

    Args:
        package_name: The npm package to look up.

    Returns:
        Dict with ``exists``, ``name``, ``version``, ``description``,
        ``author``, ``license`` (or ``error``).
    """
    url = f"https://registry.npmjs.org/{package_name}"
    try:
        resp = requests.get(url, timeout=_HTTP_TIMEOUT)
        if resp.status_code == 404:
            return {"exists": False, "name": package_name, "error": "Not found on npm"}
        resp.raise_for_status()
        data = resp.json()
        latest = data.get("dist-tags", {}).get("latest", "unknown")
        ver_info = data.get("versions", {}).get(latest, {})
        raw_author = ver_info.get("author") or data.get("author", "unknown")
        author = raw_author.get("name", "unknown") if isinstance(raw_author, dict) else str(raw_author)
        return {
            "exists": True,
            "name": data.get("name", package_name),
            "version": latest,
            "description": data.get("description", ""),
            "author": author,
            "license": ver_info.get("license", data.get("license", "unknown")),
        }
    except requests.RequestException as exc:
        return {"exists": False, "name": package_name, "error": str(exc)}


def _get_package_age(package_name: str, registry: str = "pypi") -> Optional[int]:
    """Return the age of a package in days, or ``None`` on failure.

    Args:
        package_name: The package to query.
        registry: ``"pypi"`` or ``"npm"``.

    Returns:
        Number of days since the earliest release, or ``None``.
    """
    try:
        if registry == "npm":
            resp = requests.get(
                f"https://registry.npmjs.org/{package_name}",
                timeout=_HTTP_TIMEOUT,
            )
            if resp.status_code != 200:
                return None
            created = resp.json().get("time", {}).get("created")
            if not created:
                return None
            dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
        else:
            resp = requests.get(
                f"https://pypi.org/pypi/{package_name}/json",
                timeout=_HTTP_TIMEOUT,
            )
            if resp.status_code != 200:
                return None
            releases = resp.json().get("releases", {})
            earliest: Optional[datetime] = None
            for files in releases.values():
                for f in files:
                    ts = f.get("upload_time_iso_8601")
                    if ts:
                        try:
                            udt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                            if earliest is None or udt < earliest:
                                earliest = udt
                        except (ValueError, TypeError):
                            continue
            if earliest is None:
                return None
            dt = earliest
        return (datetime.now(timezone.utc) - dt).days
    except Exception:  # noqa: BLE001 — network errors, parse errors, etc.
        return None


def _typosquat_check(package_name: str) -> dict[str, Any]:
    """Check a package name for typosquatting similarity.

    Args:
        package_name: The name to evaluate.

    Returns:
        Dict with ``similar_to``, ``is_potential_typosquat``, and
        ``risk_level``.
    """
    normalized = package_name.lower().strip()
    similar: list[dict[str, Any]] = []
    for known in POPULAR_PACKAGES:
        if normalized == known.lower():
            continue
        dist = levenshtein_distance(normalized, known.lower())
        if dist <= 2:
            similar.append({"name": known, "distance": dist})
    similar.sort(key=lambda x: x["distance"])

    if not similar:
        risk = "none"
    elif any(s["distance"] == 1 for s in similar):
        risk = "high"
    else:
        risk = "medium"

    return {
        "similar_to": similar,
        "is_potential_typosquat": len(similar) > 0,
        "risk_level": risk,
    }


# ===== ADK Tool Functions ==================================================


def scan_dependencies(repo_path: str) -> dict[str, Any]:
    """Scan a repository for dependency files and verify every package.

    Searches for ``requirements.txt``, ``setup.py``, ``pyproject.toml``,
    and ``package.json`` in the given repository path.  For each package
    found, checks the appropriate registry (PyPI for Python, npm for JS)
    and evaluates typosquatting risk.

    Args:
        repo_path: Absolute or relative path to the project root.

    Returns:
        A dict summarising the scan::

            {
                "repo_path": "...",
                "dependency_files_found": [...],
                "total_packages": N,
                "findings": [
                    {
                        "package": "...",
                        "source_file": "...",
                        "registry": "pypi" | "npm",
                        "exists": True | False,
                        "version": "...",
                        "typosquat_risk": "high" | "medium" | "low" | "none",
                        "typosquat_similar_to": [...],
                        "age_days": N | None,
                    },
                    ...
                ],
                "hallucinated_packages": [...],
                "typosquat_warnings": [...],
                "new_package_warnings": [...],
            }
    """
    repo_path = os.path.abspath(repo_path)
    if not os.path.isdir(repo_path):
        return {"error": f"Repository path does not exist: {repo_path}"}

    # ---- Discover dependency files ----------------------------------------
    dep_files: dict[str, str] = {}  # display_name → abs path
    candidates = {
        "requirements.txt": "requirements.txt",
        "setup.py": "setup.py",
        "pyproject.toml": "pyproject.toml",
        "package.json": "package.json",
    }
    for fname, display in candidates.items():
        fpath = os.path.join(repo_path, fname)
        if os.path.isfile(fpath):
            dep_files[display] = fpath

    # Also look one level deep for requirements*.txt files
    for entry in os.listdir(repo_path):
        if entry.startswith("requirements") and entry.endswith(".txt"):
            fpath = os.path.join(repo_path, entry)
            if os.path.isfile(fpath) and entry not in dep_files:
                dep_files[entry] = fpath

    if not dep_files:
        return {
            "repo_path": repo_path,
            "dependency_files_found": [],
            "total_packages": 0,
            "findings": [],
            "hallucinated_packages": [],
            "typosquat_warnings": [],
            "new_package_warnings": [],
            "message": "No dependency files found in the repository.",
        }

    # ---- Parse packages ---------------------------------------------------
    packages: list[tuple[str, str, str]] = []  # (name, source_file, registry)

    for display, fpath in dep_files.items():
        if display.endswith(".json"):
            for pkg in _parse_package_json(fpath):
                packages.append((pkg, display, "npm"))
        elif display == "setup.py":
            for pkg in _parse_setup_py(fpath):
                packages.append((pkg, display, "pypi"))
        elif display == "pyproject.toml":
            for pkg in _parse_pyproject_toml(fpath):
                packages.append((pkg, display, "pypi"))
        else:
            for pkg in _parse_requirements_txt(fpath):
                packages.append((pkg, display, "pypi"))

    # Deduplicate while preserving order
    seen: set[str] = set()
    unique_packages: list[tuple[str, str, str]] = []
    for pkg_tuple in packages:
        key = f"{pkg_tuple[0]}:{pkg_tuple[2]}"
        if key not in seen:
            seen.add(key)
            unique_packages.append(pkg_tuple)

    # ---- Check each package -----------------------------------------------
    findings: list[dict[str, Any]] = []
    hallucinated: list[str] = []
    typosquat_warnings: list[str] = []
    new_warnings: list[str] = []

    for pkg_name, source_file, registry in unique_packages:
        # Registry check
        if registry == "npm":
            reg_result = _check_npm(pkg_name)
        else:
            reg_result = _check_pypi(pkg_name)

        # Typosquat check
        typo_result = _typosquat_check(pkg_name)

        # Age check (skip if package doesn't exist)
        age_days: Optional[int] = None
        if reg_result.get("exists"):
            age_days = _get_package_age(pkg_name, registry)

        finding: dict[str, Any] = {
            "package": pkg_name,
            "source_file": source_file,
            "registry": registry,
            "exists": reg_result.get("exists", False),
            "version": reg_result.get("version"),
            "typosquat_risk": typo_result["risk_level"],
            "typosquat_similar_to": typo_result["similar_to"],
            "age_days": age_days,
        }
        findings.append(finding)

        # Accumulate warnings
        if not finding["exists"]:
            hallucinated.append(pkg_name)
        if typo_result["is_potential_typosquat"]:
            typosquat_warnings.append(pkg_name)
        if age_days is not None and age_days < 30:
            new_warnings.append(pkg_name)

    return {
        "repo_path": repo_path,
        "dependency_files_found": list(dep_files.keys()),
        "total_packages": len(unique_packages),
        "findings": findings,
        "hallucinated_packages": hallucinated,
        "typosquat_warnings": typosquat_warnings,
        "new_package_warnings": new_warnings,
    }


# ===== Agent definition ====================================================

dependency_agent = Agent(
    name="dependency_auditor",
    model=os.getenv("VIBEGUARD_MODEL", "gemini-2.5-flash-lite"),
    description=(
        "Scans project dependency files and verifies each package "
        "against PyPI/npm registries. Detects hallucinated packages, "
        "typosquatting, and suspiciously new dependencies."
    ),
    instruction=_DEPENDENCY_INSTRUCTION,
    tools=[scan_dependencies],
)
