"""Data loading for the FORGE dashboard.

All filesystem access is centralised here. Path constants resolve relative
to the project root so the dashboard works regardless of CWD.
"""

import contextlib
import json
import logging
from pathlib import Path
from typing import Any

import pandas as pd

logger = logging.getLogger("forge.dashboard")


PROJECT_ROOT = Path(__file__).resolve().parent.parent
RESULTS_DIR = PROJECT_ROOT / "data" / "results"
KNOWLEDGE_DIR = PROJECT_ROOT / "data" / "knowledge"
LOGS_DIR = PROJECT_ROOT / "logs"
BATCH_DIR = PROJECT_ROOT / "data" / "config" / "batches"
CACHE_DIR = PROJECT_ROOT / "data" / "cache"
ANALYSIS_DIR = PROJECT_ROOT / "data" / "analysis"
BATCH_TRACKING_FILE = ANALYSIS_DIR / "batch_tracking.json"


def load_results() -> pd.DataFrame:
    """Load all ``result.json`` files into a DataFrame."""
    rows: list[dict[str, Any]] = []
    skipped = 0
    if not RESULTS_DIR.exists():
        logger.warning("Results directory %s does not exist", RESULTS_DIR)
        return pd.DataFrame()

    for result_file in sorted(RESULTS_DIR.glob("CVE-*/result.json")):
        try:
            data: dict[str, Any] = json.loads(result_file.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("Skipping malformed %s: %s", result_file, exc)
            skipped += 1
            continue

        rows.append(_build_row(data, result_file))

    if skipped:
        logger.warning("Skipped %d malformed result files", skipped)
    logger.info("Loaded %d results (%d skipped)", len(rows), skipped)
    return pd.DataFrame(rows)


def _build_row(data: dict[str, Any], result_file: Path) -> dict[str, Any]:
    """Convert a single result.json dict into a flat row dict."""
    tokens: dict[str, Any] = data.get("tokens", {})
    intel: dict[str, Any] = data.get("intel_report", {})
    manifest: dict[str, Any] = data.get("manifest", {})
    resolved_pkg: dict[str, Any] = data.get("resolved_package", {})

    row: dict[str, Any] = {
        "cve_id": data.get("cve_id", result_file.parent.name),
        "status": data.get("status", "unknown"),
        "level": data.get("exploitation_level", 0),
        "cost": tokens.get("estimated_cost_usd", 0.0),
        "prompt_tokens": tokens.get("prompt_tokens", 0),
        "completion_tokens": tokens.get("completion_tokens", 0),
        "total_tokens": tokens.get("total_tokens", 0),
        "llm_calls": tokens.get("llm_calls", 0),
        "wall_clock_s": data.get("wall_clock_seconds", 0.0),
        "tool_calls": data.get("tool_calls_total", 0),
        "techniques": ", ".join(data.get("techniques_used", [])),
        "detection_rules_count": len(data.get("detection_rules", [])),
        "generation_attempts": data.get("generation_attempts", 0),
        "oracle_confidence": data.get("oracle_confidence", 0.0),
        "app_healthy": data.get("app_healthy", False),
        "error_message": data.get("error_message", ""),
        "error_category": data.get("error_category", ""),
        "cwe": _extract_cwe(intel, data),
        "language": (
            manifest.get("language")
            or intel.get("language")
            or intel.get("tech_stack", {}).get("language", "")
            or resolved_pkg.get("language", "")
        ),
        "package": intel.get("vulnerable_package", ""),
        "version": intel.get("vulnerable_version", ""),
    }

    # Per-agent costs
    agent_results: dict[str, Any] = data.get("agent_results", {})
    for agent_name in ("intel", "generator", "planner", "exploit", "detector"):
        ar: dict[str, Any] = agent_results.get(agent_name, {})
        ar_tokens: dict[str, Any] = ar.get("tokens", {})
        row[f"{agent_name}_cost"] = ar_tokens.get("estimated_cost_usd", 0.0)

    return row


def _extract_cwe(intel: dict[str, Any], data: dict[str, Any]) -> str:
    """Best-effort CWE extraction from intel report or top-level fields."""
    cwe = str(intel.get("primary_cwe", ""))
    if not cwe:
        cwe_ids = intel.get("cwe_ids", [])
        if isinstance(cwe_ids, list) and cwe_ids:
            cwe = str(cwe_ids[0])
    if not cwe:
        cwe = str(data.get("cwe_id", ""))
    return cwe


def load_batch_files() -> dict[str, list[str]]:
    """Load batch ``.txt`` files from the config directory."""
    batches: dict[str, list[str]] = {}
    if not BATCH_DIR.exists():
        return batches
    for bf in sorted(BATCH_DIR.glob("*.txt")):
        cves = [
            line.strip()
            for line in bf.read_text().splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]
        if cves:
            batches[bf.stem] = cves
    return batches


def count_knowledge_entries() -> dict[str, int]:
    """Count entries in each knowledge store."""
    counts: dict[str, int] = {"graph": 0, "learnings": 0, "cookbook": 0, "detection_kb": 0}
    if not KNOWLEDGE_DIR.exists():
        return counts

    _count_jsonl_dir(KNOWLEDGE_DIR / "graph", counts, "graph")

    learnings_file = KNOWLEDGE_DIR / "learnings" / "learnings.jsonl"
    if learnings_file.exists():
        with contextlib.suppress(OSError):
            counts["learnings"] = sum(1 for _ in learnings_file.open())

    cookbook_dir = KNOWLEDGE_DIR / "cookbook" / "languages"
    if cookbook_dir.exists():
        for f in cookbook_dir.glob("*.yaml"):
            with contextlib.suppress(OSError):
                counts["cookbook"] += f.read_text().count("- id:")

    detection_dir = KNOWLEDGE_DIR / "detection"
    if detection_dir.exists():
        counts["detection_kb"] += sum(1 for _ in detection_dir.rglob("*.yaml"))
        for f in detection_dir.rglob("*.jsonl"):
            with contextlib.suppress(OSError):
                counts["detection_kb"] += sum(1 for _ in f.open())

    return counts


def _count_jsonl_dir(directory: Path, counts: dict[str, int], key: str) -> None:
    """Sum line counts across all JSONL files in *directory*."""
    if not directory.exists():
        return
    for f in directory.glob("*.jsonl"):
        with contextlib.suppress(OSError):
            counts[key] += sum(1 for _ in f.open())


def read_log_tail(path: Path, lines: int = 50) -> str:
    """Read the last *lines* lines of a log file."""
    try:
        all_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        return "\n".join(all_lines[-lines:])
    except OSError:
        return "(unable to read log)"


def load_detection_rules(cve_id: str) -> list[dict[str, str]]:
    """Load detection rules for a specific CVE from its result.json."""
    result_file = RESULTS_DIR / cve_id / "result.json"
    if not result_file.exists():
        return []

    try:
        data: dict[str, Any] = json.loads(result_file.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return []

    rules: list[dict[str, str]] = []
    for i, rule in enumerate(data.get("detection_rules", [])):
        rules.append(_normalise_rule(rule, i))
    return rules


def _normalise_rule(rule: object, index: int) -> dict[str, str]:
    """Normalise a detection rule entry (dict or str) into a display dict."""
    if isinstance(rule, dict):
        content = str(rule.get("content", rule.get("rule", "")))
        if not content:
            content = json.dumps(rule, indent=2)
            rule_type = "json"
        else:
            rule_type = str(rule.get("rule_type", rule.get("type", "")))
            if not rule_type:
                rule_type = _infer_rule_type(content)
        return {
            "title": str(rule.get("title", rule.get("name", f"Rule {index + 1}"))),
            "type": rule_type,
            "content": content,
            "description": str(rule.get("description", "")),
        }
    text = str(rule)
    rule_type = _infer_rule_type(text)
    # Extract title from Sigma YAML if possible
    title = f"Rule {index + 1}"
    if rule_type == "sigma":
        for line in text.splitlines():
            if line.startswith("title:"):
                title = line[len("title:") :].strip()
                break
    return {
        "title": title,
        "type": rule_type,
        "content": text,
        "description": "",
    }


def _infer_rule_type(content: str) -> str:
    """Heuristically detect rule type from raw content."""
    stripped = content.lstrip()
    if stripped.startswith("title:") or stripped.startswith("logsource:"):
        return "sigma"
    if stripped.startswith("alert ") or stripped.startswith("drop "):
        return "snort"
    if stripped.startswith("rule ") and "{" in stripped:
        return "yara"
    return "unknown"


def load_batch_tracking() -> list[dict[str, Any]]:
    """Load the batch tracking JSON written by ``batch_health_check.py``."""
    if not BATCH_TRACKING_FILE.exists():
        return []
    try:
        data = json.loads(BATCH_TRACKING_FILE.read_text(encoding="utf-8"))
        if isinstance(data, list):
            return data
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("Could not load batch tracking: %s", exc)
    return []
