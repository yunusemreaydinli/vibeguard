"""ReportAgent sub-agent for VibeGuard.

Collects findings from the DependencyAuditor, SecurityAgent, and APIChecker,
calculates a composite risk score, and produces both Markdown and JSON
formatted reports.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from google.adk.agents import Agent

# ---------------------------------------------------------------------------
# Scoring weights
# ---------------------------------------------------------------------------

SCORE_WEIGHTS: dict[str, int] = {
    "non_existent_package": 20,
    "typosquat_risk": 15,
    "critical_security": 15,
    "high_security": 10,
    "medium_security": 5,
    "low_security": 2,
    "hallucinated_api": 10,
}

MAX_RISK_SCORE = 100

# Risk-level badges
RISK_BADGES: list[tuple[int, str, str]] = [
    (80, "🔴", "Critical"),
    (50, "🟠", "High"),
    (20, "🟡", "Medium"),
    (0, "🟢", "Low"),
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _risk_badge(score: int) -> tuple[str, str]:
    """Return ``(emoji, label)`` for a given risk score."""
    for threshold, emoji, label in RISK_BADGES:
        if score >= threshold:
            return emoji, label
    return "🟢", "Low"


def _clamp(value: int, lo: int = 0, hi: int = MAX_RISK_SCORE) -> int:
    """Clamp *value* to ``[lo, hi]``."""
    return max(lo, min(hi, value))


def _compute_risk_score(
    dep_findings: dict[str, Any],
    sec_findings: dict[str, Any],
    api_findings: dict[str, Any],
) -> int:
    """Compute an aggregate risk score from all finding dicts."""
    score = 0

    # --- Dependency findings ---
    for dep in dep_findings.get("findings", []):
        status = dep.get("status", "").lower()
        if status == "not_found" or dep.get("exists") is False:
            score += SCORE_WEIGHTS["non_existent_package"]
        # typosquat_risk is a level string: "none" / "medium" / "high".
        # Only the real risk levels should score — "none" must not.
        if dep.get("typosquat_risk") not in (None, "none"):
            score += SCORE_WEIGHTS["typosquat_risk"]

    # --- Security findings ---
    severity_breakdown = sec_findings.get("severity_breakdown", {})
    score += severity_breakdown.get("critical", 0) * SCORE_WEIGHTS["critical_security"]
    score += severity_breakdown.get("high", 0) * SCORE_WEIGHTS["high_security"]
    score += severity_breakdown.get("medium", 0) * SCORE_WEIGHTS["medium_security"]
    score += severity_breakdown.get("low", 0) * SCORE_WEIGHTS["low_security"]

    # --- API hallucination findings ---
    hallucinated = api_findings.get("total_hallucinated_calls", 0)
    score += hallucinated * SCORE_WEIGHTS["hallucinated_api"]

    return _clamp(score)


# ---------------------------------------------------------------------------
# Markdown report builder
# ---------------------------------------------------------------------------


def _build_markdown_report(
    repo_path: str,
    risk_score: int,
    dep_findings: dict[str, Any],
    sec_findings: dict[str, Any],
    api_findings: dict[str, Any],
) -> str:
    """Build a comprehensive Markdown-formatted security report."""
    emoji, level = _risk_badge(risk_score)
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    repo_name = os.path.basename(os.path.normpath(repo_path)) or repo_path

    lines: list[str] = []

    # ── Header ──────────────────────────────────────────────────────────
    lines.append(f"# {emoji} VibeGuard Security Report")
    lines.append("")
    lines.append(f"**Repository:** `{repo_name}`  ")
    lines.append(f"**Scan Date:** {timestamp}  ")
    lines.append(f"**Risk Score:** **{risk_score}/100** — {emoji} {level}  ")
    lines.append("")

    # ── Executive Summary ───────────────────────────────────────────────
    lines.append("## Executive Summary")
    lines.append("")

    dep_issues = len(dep_findings.get("findings", []))
    sec_issues = sec_findings.get("total_issues", 0)
    api_issues = api_findings.get("total_hallucinated_calls", 0)
    total_issues = dep_issues + sec_issues + api_issues

    lines.append(
        f"VibeGuard scanned **`{repo_name}`** and identified "
        f"**{total_issues}** issue(s) across three audit dimensions:"
    )
    lines.append("")
    lines.append("| Category | Issues |")
    lines.append("|---|---|")
    lines.append(f"| 📦 Dependency Audit | {dep_issues} |")
    lines.append(f"| 🔒 Security Scan | {sec_issues} |")
    lines.append(f"| 🤖 API Hallucination Check | {api_issues} |")
    lines.append(f"| **Total** | **{total_issues}** |")
    lines.append("")

    # ── Dependency Audit ────────────────────────────────────────────────
    lines.append("## 📦 Dependency Audit Results")
    lines.append("")

    dep_list = dep_findings.get("findings", [])
    if dep_list:
        lines.append("| Package | Status | Risk | Details |")
        lines.append("|---|---|---|---|")
        for dep in dep_list:
            pkg = dep.get("package", "unknown")
            exists = dep.get("exists")
            status = "✅ Found" if exists else "❌ Not found"
            typo_risk = dep.get("typosquat_risk")
            typo = (
                f"⚠️ Typosquat ({typo_risk})"
                if typo_risk not in (None, "none")
                else "—"
            )
            if not exists:
                detail = "Package does not exist in the registry (hallucinated)"
            elif dep.get("age_days") is not None and dep["age_days"] < 30:
                detail = f"Suspiciously new ({dep['age_days']} days old)"
            else:
                similar = dep.get("typosquat_similar_to") or []
                detail = (
                    "Looks like: "
                    + ", ".join(s.get("name", "?") for s in similar)
                    if similar
                    else ""
                )
            lines.append(f"| `{pkg}` | {status} | {typo} | {detail} |")
        lines.append("")
    else:
        lines.append("*No dependency issues detected.*")
        lines.append("")

    # ── Security Scan ───────────────────────────────────────────────────
    lines.append("## 🔒 Security Scan Results")
    lines.append("")

    sec_list = sec_findings.get("findings", [])
    if sec_list:
        sb = sec_findings.get("severity_breakdown", {})
        lines.append(
            f"**Severity Breakdown:** "
            f"🔴 Critical: {sb.get('critical', 0)} · "
            f"🟠 High: {sb.get('high', 0)} · "
            f"🟡 Medium: {sb.get('medium', 0)} · "
            f"🟢 Low: {sb.get('low', 0)}"
        )
        lines.append("")
        lines.append("| # | File | Line | Severity | Category | Description |")
        lines.append("|---|---|---|---|---|---|")
        for idx, finding in enumerate(sec_list, 1):
            sev_emoji = {
                "critical": "🔴",
                "high": "🟠",
                "medium": "🟡",
                "low": "🟢",
            }.get(finding.get("severity", ""), "⚪")
            lines.append(
                f"| {idx} "
                f"| `{finding.get('file', '')}` "
                f"| {finding.get('line_number', '')} "
                f"| {sev_emoji} {finding.get('severity', '').title()} "
                f"| {finding.get('category', '')} "
                f"| {finding.get('description', '')} |"
            )
        lines.append("")

        # Code snippets for critical / high findings (max 10)
        severe = [
            f for f in sec_list if f.get("severity") in ("critical", "high")
        ][:10]
        if severe:
            lines.append("### Critical & High Severity Details")
            lines.append("")
            for finding in severe:
                lines.append(
                    f"**{finding.get('file', '')}:{finding.get('line_number', '')}** "
                    f"— {finding.get('description', '')}"
                )
                snippet = finding.get("code_snippet", "")
                if snippet:
                    lines.append("```")
                    lines.append(snippet)
                    lines.append("```")
                lines.append("")
    else:
        lines.append("*No security vulnerabilities detected.* ✅")
        lines.append("")

    # ── API Hallucination Check ─────────────────────────────────────────
    lines.append("## 🤖 API Hallucination Check")
    lines.append("")

    api_list = api_findings.get("findings", [])
    files_scanned = api_findings.get("total_files_scanned", 0)
    lines.append(f"Files scanned: **{files_scanned}**")
    lines.append("")

    if api_list:
        lines.append("| File | Line | Module | Called Function | Suggestion |")
        lines.append("|---|---|---|---|---|")
        for finding in api_list:
            lines.append(
                f"| `{finding.get('file', '')}` "
                f"| {finding.get('line_number', '')} "
                f"| `{finding.get('module', '')}` "
                f"| `{finding.get('called_function', '')}` "
                f"| {finding.get('suggestion', '')} |"
            )
        lines.append("")
    else:
        lines.append("*No hallucinated API calls detected.* ✅")
        lines.append("")

    # ── Recommendations ─────────────────────────────────────────────────
    lines.append("## 📋 Recommendations")
    lines.append("")
    recommendations = _build_recommendations(dep_findings, sec_findings, api_findings)
    for idx, rec in enumerate(recommendations, 1):
        lines.append(f"{idx}. {rec}")
    lines.append("")

    # ── Footer ──────────────────────────────────────────────────────────
    lines.append("---")
    lines.append(f"*Report generated by VibeGuard v0.1.0 at {timestamp}*")
    lines.append("")

    return "\n".join(lines)


def _build_recommendations(
    dep_findings: dict[str, Any],
    sec_findings: dict[str, Any],
    api_findings: dict[str, Any],
) -> list[str]:
    """Generate actionable recommendations based on the findings."""
    recs: list[str] = []

    # Dependency-related
    dep_list = dep_findings.get("findings", [])
    non_existent = [d for d in dep_list if d.get("status") == "not_found" or d.get("exists") is False]
    typosquats = [
        d for d in dep_list if d.get("typosquat_risk") not in (None, "none")
    ]

    if non_existent:
        pkgs = ", ".join(f"`{d.get('package', '?')}`" for d in non_existent)
        recs.append(
            f"**Remove non-existent packages** ({pkgs}). These were likely "
            f"hallucinated by an AI code generator and will cause "
            f"installation failures or, worse, install a malicious package."
        )

    if typosquats:
        pkgs = ", ".join(f"`{d.get('package', '?')}`" for d in typosquats)
        recs.append(
            f"**Verify potentially typosquatted packages** ({pkgs}). "
            f"Confirm these are the intended packages and not malicious "
            f"look-alikes."
        )

    # Security-related
    sb = sec_findings.get("severity_breakdown", {})
    if sb.get("critical", 0):
        recs.append(
            "**Immediately rotate any exposed secrets.** Hardcoded API keys "
            "and passwords must be moved to environment variables or a "
            "secrets manager (e.g., AWS Secrets Manager, HashiCorp Vault)."
        )
    if sb.get("high", 0):
        recs.append(
            "**Fix high-severity issues** including SQL injection risks, "
            "dangerous `eval`/`exec` usage, and insecure deserialization. "
            "Use parameterized queries, avoid `eval`, and use safe loaders."
        )
    if sb.get("medium", 0):
        recs.append(
            "**Address medium-severity issues** such as disabled TLS "
            "verification, debug mode in production, and weak crypto "
            "algorithms."
        )

    # API-related
    if api_findings.get("total_hallucinated_calls", 0):
        recs.append(
            "**Fix hallucinated API calls.** Replace non-existent function "
            "calls with the correct API. Consult official package "
            "documentation."
        )

    if not recs:
        recs.append(
            "No critical issues found — keep following security best practices! 🎉"
        )

    return recs


# ---------------------------------------------------------------------------
# JSON report builder
# ---------------------------------------------------------------------------


def _build_json_report(
    repo_path: str,
    risk_score: int,
    dep_findings: dict[str, Any],
    sec_findings: dict[str, Any],
    api_findings: dict[str, Any],
) -> dict[str, Any]:
    """Build a structured JSON report."""
    emoji, level = _risk_badge(risk_score)
    timestamp = datetime.now(timezone.utc).isoformat()

    return {
        "report_version": "1.0",
        "generator": "VibeGuard v0.1.0",
        "timestamp": timestamp,
        "repository": os.path.basename(os.path.normpath(repo_path)),
        "risk_score": risk_score,
        "risk_level": level,
        "summary": {
            "total_issues": (
                len(dep_findings.get("findings", []))
                + sec_findings.get("total_issues", 0)
                + api_findings.get("total_hallucinated_calls", 0)
            ),
            "dependency_issues": len(dep_findings.get("findings", [])),
            "security_issues": sec_findings.get("total_issues", 0),
            "api_hallucinations": api_findings.get("total_hallucinated_calls", 0),
        },
        "dependency_audit": dep_findings,
        "security_scan": sec_findings,
        "api_check": api_findings,
        "recommendations": _build_recommendations(
            dep_findings, sec_findings, api_findings
        ),
    }


# ---------------------------------------------------------------------------
# Tool function
# ---------------------------------------------------------------------------


def generate_report(
    repo_path: str,
    dependency_findings: Optional[dict[str, Any]] = None,
    security_findings: Optional[dict[str, Any]] = None,
    api_findings: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """Generate the final VibeGuard risk report.

    Accepts findings directly as arguments. When invoked by the LLM tool
    layer, findings can also be passed from session state by the agent
    instruction.

    Args:
        repo_path: Absolute path to the scanned repository.
        dependency_findings: Output from the DependencyAuditor.
        security_findings: Output from the SecurityAgent.
        api_findings: Output from the APIChecker.

    Returns:
        A dict containing ``risk_score``, ``risk_level``, ``markdown_report``,
        ``json_report``, and a ``report_saved_to`` path (if written to disk).
    """
    dep = dependency_findings or {"findings": []}
    sec = security_findings or {"findings": [], "total_issues": 0, "severity_breakdown": {}}
    api = api_findings or {"findings": [], "total_hallucinated_calls": 0, "total_files_scanned": 0}

    risk_score = _compute_risk_score(dep, sec, api)
    _emoji, risk_level = _risk_badge(risk_score)

    md_report = _build_markdown_report(repo_path, risk_score, dep, sec, api)
    json_report = _build_json_report(repo_path, risk_score, dep, sec, api)

    # Attempt to save reports to disk alongside the repo
    report_dir = os.path.join(repo_path, ".vibeguard")
    saved_paths: dict[str, str] = {}
    try:
        os.makedirs(report_dir, exist_ok=True)

        md_path = os.path.join(report_dir, "report.md")
        with open(md_path, "w", encoding="utf-8") as fh:
            fh.write(md_report)
        saved_paths["markdown"] = md_path

        json_path = os.path.join(report_dir, "report.json")
        with open(json_path, "w", encoding="utf-8") as fh:
            json.dump(json_report, fh, indent=2, default=str)
        saved_paths["json"] = json_path

    except OSError:
        # Non-fatal — reports are still returned in the dict
        pass

    return {
        "risk_score": risk_score,
        "risk_level": risk_level,
        "markdown_report": md_report,
        "json_report": json_report,
        "report_saved_to": saved_paths,
    }


# ---------------------------------------------------------------------------
# Agent definition
# ---------------------------------------------------------------------------

report_agent = Agent(
    name="ReportAgent",
    model=os.getenv("VIBEGUARD_MODEL", "gemini-2.5-flash-lite"),
    description=(
        "Collects all findings from the DependencyAuditor, SecurityAgent, "
        "and APIChecker, then generates a comprehensive security report with "
        "risk scoring and actionable recommendations."
    ),
    instruction=(
        "You are the ReportAgent. Collect all findings from the "
        "DependencyAuditor, SecurityAgent, and APIChecker (stored in "
        "session state), then generate a comprehensive security report.\n\n"
        "Use the generate_report tool. Pass in the repo_path and any "
        "findings available in session state:\n"
        "  - 'dependency_findings' from the DependencyAuditor\n"
        "  - 'security_findings' from the SecurityAgent\n"
        "  - 'api_findings' from the APIChecker\n\n"
        "The report should include:\n"
        "- A risk score (0-100) with severity level\n"
        "- Executive summary with issue counts\n"
        "- Detailed findings organized by category\n"
        "- Actionable recommendations\n\n"
        "Store the final report in session state under 'final_report'."
    ),
    tools=[generate_report],
)
