"""VibeGuard Root Orchestrator Agent.

Coordinates four sub-agents in sequence:
    1. DependencyAuditor — checks packages against registries
    2. APIChecker       — validates API endpoint references
    3. SecurityAgent    — scans for common security issues
    4. ReportAgent      — compiles the final audit report

Uses Google ADK ``SequentialAgent`` so each sub-agent runs in order
and shares session state for accumulated findings.
"""

from __future__ import annotations

from google.adk.agents import SequentialAgent

from vibeguard.sub_agents.dependency import dependency_agent
from vibeguard.sub_agents.api_checker import api_checker_agent
from vibeguard.sub_agents.security import security_agent
from vibeguard.sub_agents.report import report_agent

# ---------------------------------------------------------------------------
# Root orchestrator — public symbol imported by the ADK runner
# ---------------------------------------------------------------------------

root_agent = SequentialAgent(
    name="vibeguard_orchestrator",
    description=(
        "VibeGuard: Multi-agent security auditor for vibe-coded projects. "
        "Scans repositories for hallucinated packages, fake API calls, "
        "and security vulnerabilities."
    ),
    sub_agents=[
        dependency_agent,
        api_checker_agent,
        security_agent,
        report_agent,
    ],
)
