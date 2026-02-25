"""Dynatrace design tokens, CSS injection, and Plotly theme helpers.

Supports dark (default) and light themes via ``st.session_state["theme"]``.
All color access goes through ``get_palette()`` which returns the active palette.

Reference: https://developer.dynatrace.com/design/design-tokens/Colors/
"""

from __future__ import annotations

from typing import Any

import plotly.graph_objects as go
import streamlit as st

# ── Semantic Colors (theme-independent) ────────────────────────────────────────

PRIMARY = "#474fcf"
PRIMARY_LIGHT = "#999bed"
SUCCESS = "#5eb1a9"
SUCCESS_DARK = "#2f6862"
WARNING = "#eea746"
CRITICAL = "#c82d40"
BLUE = "#1284ea"

LEVEL_COLORS: dict[int, str] = {
    0: CRITICAL,   # L0: failed
    1: WARNING,    # L1: info disclosure
    2: PRIMARY_LIGHT,  # L2: partial exploit
    3: SUCCESS,    # L3: full exploit
}
LEVEL_LABELS: dict[int, str] = {0: "L0", 1: "L1", 2: "L2", 3: "L3"}

LEVEL_COLOR_MAP: dict[str, str] = {v: LEVEL_COLORS[k] for k, v in LEVEL_LABELS.items()}
"""Mapping from label string ('L0'…'L3') to hex color — for px color_discrete_map."""

CHART_SEQUENCE = [
    PRIMARY_LIGHT, SUCCESS, WARNING, CRITICAL, BLUE,
    "#b8bbff", "#7ed1c9", "#ffc974",
]

AGENT_LABELS = ["Intel", "Generator", "Planner", "Exploit", "Detector"]
AGENT_COST_COLS = [
    "intel_cost", "generator_cost", "planner_cost",
    "exploit_cost", "detector_cost",
]
AGENT_COLORS = [BLUE, PRIMARY_LIGHT, WARNING, CRITICAL, SUCCESS]

# ── Palettes ───────────────────────────────────────────────────────────────────

_DARK_PALETTE: dict[str, str] = {
    "bg_base": "#19192c",
    "bg_surface": "#111122",
    "bg_container": "#212135",
    "bg_elevated": "#292a3e",
    "border": "#3b3b52",
    "text": "#f0f0f5",
    "text_muted": "#a0a1c0",
    "template": "plotly_dark",
}

_LIGHT_PALETTE: dict[str, str] = {
    "bg_base": "#f5f5fa",
    "bg_surface": "#ffffff",
    "bg_container": "#e8e8f0",
    "bg_elevated": "#dcdce8",
    "border": "#c0c0d0",
    "text": "#1a1a2e",
    "text_muted": "#5a5a7a",
    "template": "plotly_white",
}


def is_light_theme() -> bool:
    """Return True if the user has selected light theme.

    Currently always False — Streamlit bakes ``config.toml`` colors into
    native widgets (dataframes, inputs, selects) at startup, so CSS-only
    overrides cannot fully switch to a light palette.
    """
    return False


def get_palette() -> dict[str, str]:
    """Return the active color palette based on session state."""
    return _LIGHT_PALETTE if is_light_theme() else _DARK_PALETTE


# ── Legacy module-level aliases (for imports that don't go through palette) ────
# These are DARK-only; prefer get_palette() for theme-aware code.
BG_BASE = _DARK_PALETTE["bg_base"]
BG_SURFACE = _DARK_PALETTE["bg_surface"]
BG_CONTAINER = _DARK_PALETTE["bg_container"]
BG_ELEVATED = _DARK_PALETTE["bg_elevated"]
BORDER = _DARK_PALETTE["border"]
TEXT = _DARK_PALETTE["text"]
TEXT_MUTED = _DARK_PALETTE["text_muted"]

# ── Plotly Layout ──────────────────────────────────────────────────────────────

# Static layout kept for backward compat; prefer build_plotly_layout()
PLOTLY_LAYOUT: dict[str, object] = {
    "template": "plotly_dark",
    "paper_bgcolor": BG_CONTAINER,
    "plot_bgcolor": BG_BASE,
    "font": {"color": TEXT, "size": 12},
    "xaxis": {"gridcolor": BORDER, "zerolinecolor": BORDER},
    "yaxis": {"gridcolor": BORDER, "zerolinecolor": BORDER},
    "colorway": CHART_SEQUENCE,
    "margin": {"l": 40, "r": 20, "t": 40, "b": 40},
}


def build_plotly_layout() -> dict[str, Any]:
    """Build a Plotly layout dict for the active theme."""
    p = get_palette()
    return {
        "template": p["template"],
        "paper_bgcolor": p["bg_container"],
        "plot_bgcolor": p["bg_base"],
        "font": {"color": p["text"], "size": 12},
        "xaxis": {"gridcolor": p["border"], "zerolinecolor": p["border"]},
        "yaxis": {"gridcolor": p["border"], "zerolinecolor": p["border"]},
        "colorway": CHART_SEQUENCE,
        "margin": {"l": 40, "r": 20, "t": 40, "b": 40},
    }


BAR_LINE = {"color": BORDER, "width": 1}
"""Default outline for bar chart traces — subtle border on dark background."""


def apply_dt_layout(fig: go.Figure) -> go.Figure:
    """Apply Dynatrace layout (theme-aware) to a Plotly figure.

    Automatically adds a thin border to every ``Bar`` trace for visual
    definition, and positions bar text outside with 15% y-axis headroom.
    """
    layout = build_plotly_layout()
    fig.update_layout(**layout)

    p = get_palette()
    bar_line = {"color": p["border"], "width": 1}

    has_bar = False
    max_y: float = 0.0
    for trace in fig.data:
        if isinstance(trace, go.Bar):
            trace.update(marker_line=bar_line, textposition="outside")
            has_bar = True
            if trace.y is not None:
                try:
                    trace_max = max(float(v) for v in trace.y if v is not None)
                    max_y = max(max_y, trace_max)
                except (ValueError, TypeError):
                    pass

    # Add 15% headroom for bar text labels (only for single-axis bar charts)
    if has_bar and max_y > 0:
        current_layout = fig.layout
        # Don't override if there's a secondary y-axis or explicit range
        if not getattr(current_layout, "yaxis2", None):
            y_range = getattr(current_layout.yaxis, "range", None)
            if y_range is None:
                fig.update_layout(yaxis_range=[0, max_y * 1.15])

    return fig


def level_badge(level: int) -> str:
    """Return an HTML badge for an exploitation level."""
    label = LEVEL_LABELS.get(level, f"L{level}")
    css_class = f"badge-l{level}" if level in LEVEL_LABELS else "badge-run"
    return f'<span class="forge-badge {css_class}">{label}</span>'


def rule_syntax(rule_type: str) -> str:
    """Map detection rule type to Streamlit code-block language."""
    return {
        "sigma": "yaml",
        "snort": "text",
        "suricata": "text",
        "yara": "text",
        "json": "json",
        "yaml": "yaml",
    }.get(rule_type.lower(), "text")


# ── CSS Builder ────────────────────────────────────────────────────────────────


def build_css() -> str:
    """Build the full CSS string for the active theme."""
    p = get_palette()
    return f"""
<style>
    /* ── Reduce Streamlit top whitespace (keep enough for the toolbar) ── */
    .block-container {{
        padding-top: 2.5rem !important;
        padding-bottom: 0rem;
    }}

    /* ── Metric cards ── */
    [data-testid="stMetric"] {{
        background: {p['bg_container']};
        border: 1px solid {p['border']};
        border-radius: 8px;
        padding: 12px 16px;
    }}
    [data-testid="stMetricValue"] {{
        font-size: 1.6rem;
        font-weight: 600;
    }}
    [data-testid="stMetricLabel"] {{
        color: {p['text_muted']};
        font-size: 0.85rem;
        text-transform: uppercase;
        letter-spacing: 0.5px;
    }}

    /* ── Tab styling ── */
    [data-testid="stTabs"] button {{ font-weight: 500; }}
    [data-testid="stTabs"] button[aria-selected="true"] {{
        border-bottom-color: {PRIMARY} !important;
    }}

    /* ── Progress bar ── */
    [data-testid="stProgress"] > div > div {{
        background-color: {PRIMARY} !important;
    }}

    /* ── Table header ── */
    [data-testid="stDataFrame"] th {{
        background: {p['bg_elevated']} !important;
        color: {p['text_muted']} !important;
    }}

    /* ── Sidebar ── */
    section[data-testid="stSidebar"] {{
        border-right: 1px solid {p['border']};
    }}

    /* ── Status badges ── */
    .forge-badge {{
        display: inline-block; padding: 2px 10px; border-radius: 12px;
        font-size: 0.8rem; font-weight: 600; letter-spacing: 0.3px;
    }}
    .badge-l0 {{ background: {CRITICAL}22; color: {CRITICAL}; border: 1px solid {CRITICAL}44; }}
    .badge-l1 {{ background: {WARNING}22; color: {WARNING}; border: 1px solid {WARNING}44; }}
    .badge-l2 {{
        background: {PRIMARY_LIGHT}22; color: {PRIMARY_LIGHT};
        border: 1px solid {PRIMARY_LIGHT}44;
    }}
    .badge-l3 {{ background: {SUCCESS}22; color: {SUCCESS}; border: 1px solid {SUCCESS}44; }}
    .badge-ok {{ background: {SUCCESS}22; color: {SUCCESS}; border: 1px solid {SUCCESS}44; }}
    .badge-err {{ background: {CRITICAL}22; color: {CRITICAL}; border: 1px solid {CRITICAL}44; }}
    .badge-run {{ background: {BLUE}22; color: {BLUE}; border: 1px solid {BLUE}44; }}

    /* ── Batch card ── */
    .batch-card {{
        background: {p['bg_container']}; border: 1px solid {p['border']};
        border-radius: 8px; padding: 12px 16px; margin-bottom: 8px;
    }}
    .batch-card h4 {{ margin: 0 0 4px 0; color: {p['text']}; font-size: 0.95rem; }}
    .batch-progress {{ color: {p['text_muted']}; font-size: 0.85rem; }}

    /* ── Pulsing animation for active runs ── */
    @keyframes forge-pulse {{
        0%, 100% {{ opacity: 1; }}
        50% {{ opacity: 0.3; }}
    }}
    .forge-pulse-dot {{
        display: inline-block; width: 8px; height: 8px; border-radius: 50%;
        background: {BLUE}; animation: forge-pulse 1.5s ease-in-out infinite;
        margin-right: 6px; vertical-align: middle;
    }}
    .forge-status-running {{ color: {BLUE}; font-weight: 600; font-size: 0.9rem; }}
    .forge-status-done {{ color: {SUCCESS}; font-weight: 600; font-size: 0.9rem; }}

    /* ── Sidebar batch mini-card ── */
    .sidebar-batch {{
        background: {p['bg_container']}; border: 1px solid {p['border']};
        border-radius: 6px; padding: 6px 10px; margin-bottom: 4px; font-size: 0.8rem;
    }}
    .sidebar-batch-name {{ color: {p['text']}; font-weight: 500; }}
    .sidebar-batch-stat {{ color: {p['text_muted']}; }}

    /* ── Detection rule card ── */
    .rule-card {{
        background: {p['bg_container']}; border: 1px solid {p['border']};
        border-radius: 8px; padding: 12px 16px; margin-bottom: 8px;
    }}
    .rule-type-sigma {{ border-left: 3px solid {PRIMARY_LIGHT}; }}
    .rule-type-snort {{ border-left: 3px solid {WARNING}; }}
    .rule-type-other {{ border-left: 3px solid {p['text_muted']}; }}

    /* ── Pagination ── */
    .page-info {{ color: {p['text_muted']}; font-size: 0.85rem; padding-top: 8px; }}

    /* ── Level filter checkboxes ── */
    .level-filter-row {{
        display: flex; gap: 6px; margin-bottom: 8px;
    }}
    .level-filter-chip {{
        display: inline-flex; align-items: center; gap: 4px;
        padding: 4px 10px; border-radius: 14px; font-size: 0.8rem;
        font-weight: 600; cursor: pointer; letter-spacing: 0.3px;
    }}
    .level-chip-on {{
        opacity: 1.0;
    }}
    .level-chip-off {{
        opacity: 0.35;
    }}

    /* ── Header ── */
    h1 {{ margin-top: 0 !important; padding-top: 0 !important; }}
</style>
"""


# Keep CUSTOM_CSS as a backward-compat alias (dark theme only)
CUSTOM_CSS = build_css()
