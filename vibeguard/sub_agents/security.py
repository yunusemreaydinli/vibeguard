"""SecurityAgent sub-agent for VibeGuard.

Scans code files for security vulnerabilities using regex pattern matching
and LLM-assisted analysis. Covers hardcoded secrets, SQL injection,
dangerous code execution, insecure deserialization, and more.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

from google.adk.agents import Agent

# ---------------------------------------------------------------------------
# Regex-based security patterns
# ---------------------------------------------------------------------------

SECURITY_PATTERNS: dict[str, dict[str, Any]] = {
    "hardcoded_api_key": {
        "patterns": [
            # OpenAI-style secret keys
            r"[\"'](?:sk-[a-zA-Z0-9]{20,})[\"']",
            # AWS access key IDs
            r"[\"'](?:AKIA[A-Z0-9]{16})[\"']",
            # GitHub personal access tokens
            r"[\"'](?:ghp_[a-zA-Z0-9]{36})[\"']",
            # Generic api_key / apikey / api_secret assignments
            r"(?:api_key|apikey|api_secret|API_KEY)\s*=\s*[\"'][^\"'{\$][^\"']+",
            # Bearer tokens
            r"(?:Bearer\s+)[a-zA-Z0-9\-_.]+",
            # Slack tokens
            r"[\"'](?:xox[bprs]-[a-zA-Z0-9\-]+)[\"']",
            # Stripe keys
            r"[\"'](?:sk_live_[a-zA-Z0-9]{24,})[\"']",
            r"[\"'](?:rk_live_[a-zA-Z0-9]{24,})[\"']",
            # Twilio keys
            r"[\"'](?:SK[a-f0-9]{32})[\"']",
            # Google API keys
            r"[\"'](?:AIza[0-9A-Za-z\-_]{35})[\"']",
            # Private keys embedded inline
            r"-----BEGIN\s(?:RSA\s)?PRIVATE\sKEY-----",
        ],
        "severity": "critical",
        "description": "Hardcoded API key or secret detected",
    },
    "hardcoded_password": {
        "patterns": [
            # password = "...", secret = "...", etc.  (min 3-char value)
            r"(?:password|passwd|pwd|secret|token)\s*=\s*[\"'][^\"'{\$][^\"']{3,}[\"']",
            # DB connection strings with embedded credentials
            r"(?:mysql|postgres|postgresql|mongodb)://[^:]+:[^@]+@",
        ],
        "severity": "critical",
        "description": "Hardcoded password or secret",
    },
    "sql_injection": {
        "patterns": [
            # f-string in execute()
            r"(?:execute|cursor\.execute)\s*\(\s*f[\"']",
            # %-formatting in SQL
            r"(?:SELECT|INSERT|UPDATE|DELETE).*%s.*%",
            # .format() with SQL keywords
            r"\.format\s*\(.*\).*(?:SELECT|INSERT|UPDATE|DELETE)",
            r"(?:SELECT|INSERT|UPDATE|DELETE).*\.format\s*\(",
            # String concatenation in SQL
            r'(?:execute|cursor\.execute)\s*\(\s*["\']?\s*(?:SELECT|INSERT|UPDATE|DELETE).*\+',
        ],
        "severity": "high",
        "description": "Potential SQL injection vulnerability",
    },
    "dangerous_exec": {
        "patterns": [
            r"\beval\s*\(",
            r"\bexec\s*\(",
            r"os\.system\s*\(",
            r"subprocess\.call\s*\([^)]*shell\s*=\s*True",
            r"subprocess\.Popen\s*\([^)]*shell\s*=\s*True",
            r"subprocess\.run\s*\([^)]*shell\s*=\s*True",
            r"os\.popen\s*\(",
            r"commands\.getoutput\s*\(",
        ],
        "severity": "high",
        "description": "Dangerous code execution",
    },
    "insecure_deserialization": {
        "patterns": [
            r"pickle\.loads?\s*\(",
            r"yaml\.load\s*\([^)]*(?!Loader)",
            r"marshal\.loads?\s*\(",
            r"shelve\.open\s*\(",
            r"jsonpickle\.decode\s*\(",
        ],
        "severity": "high",
        "description": "Insecure deserialization",
    },
    "missing_input_validation": {
        "patterns": [
            # Flask routes that grab raw request data without validation
            r"request\.args\.get\s*\(",
            r"request\.form\.get\s*\(",
            r"request\.json",
            r"request\.data",
        ],
        "severity": "medium",
        "description": "Potential missing input validation on web request data",
    },
    "insecure_http": {
        "patterns": [
            # HTTP (non-HTTPS) URLs in code
            r"http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0)",
            # Disabled TLS verification
            r"verify\s*=\s*False",
        ],
        "severity": "medium",
        "description": "Insecure HTTP usage or disabled TLS verification",
    },
    "debug_in_production": {
        "patterns": [
            r"app\.run\s*\([^)]*debug\s*=\s*True",
            r"DEBUG\s*=\s*True",
        ],
        "severity": "medium",
        "description": "Debug mode enabled — should not be used in production",
    },
    "weak_crypto": {
        "patterns": [
            r"hashlib\.md5\s*\(",
            r"hashlib\.sha1\s*\(",
            r"DES\b",
            r"RC4\b",
        ],
        "severity": "medium",
        "description": "Weak or deprecated cryptographic algorithm",
    },
    "path_traversal": {
        "patterns": [
            r"open\s*\(\s*(?:request|user_input|filename|path)",
            r"os\.path\.join\s*\(\s*[^,]+,\s*(?:request|user_input)",
        ],
        "severity": "high",
        "description": "Potential path traversal vulnerability",
    },
}

# File extensions to scan
SCANNABLE_EXTENSIONS: set[str] = {".py", ".js", ".ts", ".jsx", ".tsx"}


# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------


def _read_file_safe(filepath: str) -> str | None:
    """Read a file, returning ``None`` on any decode/IO error."""
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as fh:
            return fh.read()
    except (OSError, IOError):
        return None


def _build_severity_breakdown(
    findings: list[dict[str, Any]],
) -> dict[str, int]:
    """Aggregate finding counts by severity level."""
    breakdown: dict[str, int] = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
    }
    for f in findings:
        level = f.get("severity", "low")
        breakdown[level] = breakdown.get(level, 0) + 1
    return breakdown


# ---------------------------------------------------------------------------
# Tool function
# ---------------------------------------------------------------------------


def scan_security(repo_path: str) -> dict[str, Any]:
    """Scan all code files in *repo_path* for security vulnerabilities.

    Walks the directory tree, reads files with supported extensions, and
    applies regex-based pattern matching for common vulnerability classes.

    Args:
        repo_path: Absolute path to the repository root.

    Returns:
        A dict with ``findings`` (list of individual issues), ``total_issues``,
        and ``severity_breakdown``.
    """
    repo = Path(repo_path)
    if not repo.is_dir():
        return {
            "findings": [],
            "total_issues": 0,
            "severity_breakdown": _build_severity_breakdown([]),
            "error": f"Repository path does not exist or is not a directory: {repo_path}",
        }

    findings: list[dict[str, Any]] = []

    for dirpath, _dirnames, filenames in os.walk(repo):
        # Skip hidden dirs and common non-source dirs
        rel = os.path.relpath(dirpath, repo)
        skip_dirs = {
            "node_modules",
            ".git",
            "__pycache__",
            ".venv",
            "venv",
            "env",
            ".tox",
            ".mypy_cache",
            "dist",
            "build",
        }
        if any(part in skip_dirs for part in Path(rel).parts):
            continue

        for filename in filenames:
            ext = os.path.splitext(filename)[1]
            if ext not in SCANNABLE_EXTENSIONS:
                continue

            filepath = os.path.join(dirpath, filename)
            content = _read_file_safe(filepath)
            if content is None:
                continue

            lines = content.splitlines()
            rel_filepath = os.path.relpath(filepath, repo)

            for category, config in SECURITY_PATTERNS.items():
                for pattern in config["patterns"]:
                    try:
                        regex = re.compile(pattern, re.IGNORECASE)
                    except re.error:
                        continue

                    for line_idx, line in enumerate(lines, start=1):
                        if regex.search(line):
                            # Trim very long lines for readability
                            snippet = line.strip()
                            if len(snippet) > 200:
                                snippet = snippet[:200] + "…"

                            findings.append(
                                {
                                    "file": rel_filepath,
                                    "line_number": line_idx,
                                    "category": category,
                                    "severity": config["severity"],
                                    "code_snippet": snippet,
                                    "description": config["description"],
                                }
                            )

    # De-duplicate (same file + line + category)
    seen: set[tuple[str, int, str]] = set()
    unique_findings: list[dict[str, Any]] = []
    for f in findings:
        key = (f["file"], f["line_number"], f["category"])
        if key not in seen:
            seen.add(key)
            unique_findings.append(f)

    unique_findings.sort(
        key=lambda f: (
            {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(
                f["severity"], 4
            ),
            f["file"],
            f["line_number"],
        )
    )

    return {
        "findings": unique_findings,
        "total_issues": len(unique_findings),
        "severity_breakdown": _build_severity_breakdown(unique_findings),
    }


# ---------------------------------------------------------------------------
# Agent definition
# ---------------------------------------------------------------------------

security_agent = Agent(
    name="SecurityAgent",
    model=os.getenv("VIBEGUARD_MODEL", "gemini-2.0-flash"),
    description=(
        "Scans code repositories for security vulnerabilities including "
        "hardcoded secrets, SQL injection, dangerous eval/exec usage, "
        "insecure deserialization, and missing input validation."
    ),
    instruction=(
        "You are the SecurityAgent. Scan all code files in the provided "
        "repository for security vulnerabilities. Look for:\n"
        "1. Hardcoded API keys, passwords, and secrets\n"
        "2. SQL injection vulnerabilities\n"
        "3. Dangerous eval/exec/os.system usage\n"
        "4. Insecure deserialization (pickle, yaml without SafeLoader)\n"
        "5. Missing input validation in web endpoints\n"
        "6. Insecure HTTP and disabled TLS verification\n"
        "7. Debug mode left enabled\n"
        "8. Weak cryptographic algorithms\n"
        "9. Path traversal risks\n\n"
        "Use the scan_security tool on the repo path. Summarize the results "
        "clearly, grouping by severity. Store findings in session state "
        "under 'security_findings'."
    ),
    tools=[scan_security],
)
