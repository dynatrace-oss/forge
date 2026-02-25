#!/usr/bin/env python3
"""FORGE Dashboard — Streamlit entry point.

Thin orchestrator: loads data, renders sidebar/header/metrics, dispatches to
tab modules.  All heavy lifting lives in ``theme``, ``data``, ``overview``,
``detail``, ``rq_exploitation``, and ``rq_quality``.

Usage:
    .venv/bin/streamlit run dashboard/app.py --server.port 8501 --server.headless true
"""

from __future__ import annotations

import logging
import sys
import time
from pathlib import Path

# Streamlit runs this file as __main__ from inside dashboard/, so the parent
# (project root) must be on sys.path for ``from dashboard import …`` to work.
_PROJECT_ROOT = str(Path(__file__).resolve().parent.parent)
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

import pandas as pd  # noqa: E402
import streamlit as st  # noqa: E402

from dashboard import batch_tracking, detail, overview, rq_exploitation, rq_quality  # noqa: E402
from dashboard import data as loader  # noqa: E402
from dashboard.theme import (  # noqa: E402
    CRITICAL,
    LEVEL_COLORS,
    PRIMARY_LIGHT,
    SUCCESS,
    WARNING,
    build_css,
    get_palette,
)

logger = logging.getLogger("forge.dashboard")
logging.basicConfig(level=logging.INFO, format="%(name)s | %(levelname)s | %(message)s")


# ── Helper functions ───────────────────────────────────────────────────────────


def _render_run_status(
    raw: pd.DataFrame,
    batch_map: dict[str, list[str]],
    selected_batch: str,
) -> None:
    """Render the run-status section inside the sidebar."""
    p = get_palette()
    st.divider()
    st.markdown(
        f'<p style="color:{p["text_muted"]}; font-size:0.75rem; '
        f'text-transform:uppercase; letter-spacing:0.5px; margin-bottom:4px;">'
        f"Run Status</p>",
        unsafe_allow_html=True,
    )

    if raw.empty:
        st.markdown(
            '<span class="forge-status-running">'
            '<span class="forge-pulse-dot"></span>'
            "Waiting for results\u2026</span>",
            unsafe_allow_html=True,
        )
        return

    total_completed = len(raw)
    if selected_batch != "All" and selected_batch in batch_map:
        total_expected = len(batch_map[selected_batch])
    else:
        total_expected = (
            sum(len(v) for v in batch_map.values()) if batch_map else total_completed
        )

    progress = (total_completed / total_expected * 100) if total_expected > 0 else 100.0
    is_running = progress < 100.0

    if is_running:
        st.markdown(
            f'<span class="forge-status-running">'
            f'<span class="forge-pulse-dot"></span>'
            f"Running \u2014 {total_completed}/{total_expected} CVEs"
            f"</span>",
            unsafe_allow_html=True,
        )
    else:
        st.markdown(
            f'<span class="forge-status-done">'
            f"\u2714 Complete \u2014 {total_completed}/{total_expected} CVEs"
            f"</span>",
            unsafe_allow_html=True,
        )

    st.progress(min(progress / 100, 1.0))

    # Per-batch breakdown — collapsible to avoid sidebar scroll at 24 batches
    if batch_map and len(batch_map) > 1:
        with st.expander("Batch Breakdown", expanded=False):
            all_completed_cves = set(raw["cve_id"])
            for bname, bcves in batch_map.items():
                done = len(all_completed_cves & set(bcves))
                total = len(bcves)
                pct = (done / total * 100) if total > 0 else 0
                if done == total:
                    status_color = SUCCESS
                elif done > 0:
                    status_color = WARNING
                else:
                    status_color = p["text_muted"]
                st.markdown(
                    f'<div class="sidebar-batch">'
                    f'<span class="sidebar-batch-name">{bname}</span> '
                    f'<span class="sidebar-batch-stat" style="color:{status_color};">'
                    f"{done}/{total} ({pct:.0f}%)</span>"
                    f"</div>",
                    unsafe_allow_html=True,
                )


def _render_metrics(df: pd.DataFrame) -> None:
    """Render the six top-level metric cards."""
    total_completed = len(df)
    total_cost = float(df["cost"].sum())
    mean_cost = float(df["cost"].mean()) if total_completed else 0.0
    mean_wall_min = float(df["wall_clock_s"].mean() / 60) if total_completed else 0.0
    success_count = len(df[df["level"] >= 1])
    success_rate = (success_count / total_completed * 100) if total_completed else 0.0
    l3_count = len(df[df["level"] == 3])

    c1, c2, c3, c4, c5, c6 = st.columns(6)
    c1.metric("Completed", total_completed)
    c2.metric("Success (L1+)", f"{success_rate:.1f}%")
    c3.metric("L3 (Full)", l3_count)
    c4.metric("Total Cost", f"${total_cost:.2f}")
    c5.metric("Avg $/CVE", f"${mean_cost:.2f}")
    c6.metric("Avg Time", f"{mean_wall_min:.1f} min")


# ── Page config (must be first Streamlit call) ─────────────────────────────────

st.set_page_config(page_title="FORGE", page_icon="\u2692\ufe0f", layout="wide")


# ── Sidebar ────────────────────────────────────────────────────────────────────

with st.sidebar:
    # Branding + theme toggle
    p = get_palette()
    st.markdown(
        f'<p style="color:{p["text_muted"]}; font-size:0.7rem; '
        f'text-transform:uppercase; letter-spacing:1px; margin-bottom:2px;">'
        f"Dynatrace CNS</p>",
        unsafe_allow_html=True,
    )

    st.divider()

    st.markdown(
        f'<h3 style="color:{PRIMARY_LIGHT}; margin-bottom:4px;">Controls</h3>',
        unsafe_allow_html=True,
    )

    refresh_interval: str = st.selectbox(
        "Auto-refresh", ["Manual", "30s", "60s", "120s"], index=1, key="sb_refresh",
    )

    batch_filter: str = st.selectbox(
        "Filter by batch", ["All"] + list(loader.load_batch_files().keys()),
        index=0, key="sb_batch",
    )

    # Level filter — color-coded checkboxes in a row
    p = get_palette()
    st.markdown(
        f'<p style="color:{p["text_muted"]}; font-size:0.75rem; '
        f'text-transform:uppercase; letter-spacing:0.5px; margin-bottom:4px; '
        f'margin-top:8px;">Level Filter</p>',
        unsafe_allow_html=True,
    )
    lf_cols = st.columns(4)
    level_filter: list[int] = []
    for i, col in enumerate(lf_cols):
        color = LEVEL_COLORS[i]
        checked = col.checkbox(f"L{i}", value=True, key=f"lf_{i}")
        if checked:
            level_filter.append(i)
        # Colored bar indicator under each checkbox
        col.markdown(
            f'<div style="width:100%; height:3px; background:{color}; '
            f'border-radius:2px; margin-top:-8px; '
            f'opacity:{"1.0" if checked else "0.25"};"></div>',
            unsafe_allow_html=True,
        )


# ── Inject theme-aware CSS (after sidebar sets theme toggle) ───────────────────

st.markdown(build_css(), unsafe_allow_html=True)


# ── Data loading ───────────────────────────────────────────────────────────────

with st.spinner("Loading results..."):
    df_raw = loader.load_results()
    batches = loader.load_batch_files()


# ── Run status in sidebar ──────────────────────────────────────────────────────

with st.sidebar:
    _render_run_status(df_raw, batches, batch_filter)

    if refresh_interval != "Manual":
        interval_sec = int(refresh_interval.replace("s", ""))
        time.sleep(0.1)
        st.session_state.setdefault("_last_refresh", 0.0)
        if time.time() - st.session_state["_last_refresh"] > interval_sec:
            st.session_state["_last_refresh"] = time.time()
            st.rerun()


# ── Header ─────────────────────────────────────────────────────────────────────

p = get_palette()
st.markdown(
    f'<h1 style="margin-bottom:0; color:{p["text"]};">'
    f'<span style="color:{PRIMARY_LIGHT};">FORGE</span> Dashboard</h1>',
    unsafe_allow_html=True,
)


# ── Filter data ────────────────────────────────────────────────────────────────

df = df_raw.copy()

if df.empty:
    st.info("No results found yet. Waiting for first CVE to complete...")
    st.stop()

if batch_filter != "All" and batch_filter in batches:
    df = df[df["cve_id"].isin(batches[batch_filter])]

df = df[df["level"].isin(level_filter)]

if df.empty:
    st.warning("No results match the current filters.")
    st.stop()


# ── Metrics row ────────────────────────────────────────────────────────────────

_render_metrics(df)

st.divider()

# ── Tabs ───────────────────────────────────────────────────────────────────────

tab_ov, tab_tbl, tab_bt, tab_rul, tab_kg, tab_rq12, tab_rq34, tab_err = st.tabs(
    [
        "Overview",
        "Per-CVE Table",
        "Batch Tracking",
        "Detection Rules",
        "Knowledge Growth",
        "RQ1-RQ2: Exploitation",
        "RQ3-RQ4: Detection & Knowledge",
        "Errors & Logs",
    ]
)

with tab_ov:
    overview.render(df)
with tab_tbl:
    detail.render_table(df)
with tab_bt:
    batch_tracking.render(df)
with tab_rul:
    detail.render_rules(df)
with tab_kg:
    detail.render_knowledge(df)
with tab_rq12:
    rq_exploitation.render(df)
with tab_rq34:
    rq_quality.render(df)
with tab_err:
    detail.render_errors(df)
