"""Batch Tracking tab — per-batch health, stop conditions, cumulative progress."""

from __future__ import annotations

from typing import Any

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from dashboard.data import load_batch_tracking
from dashboard.theme import (
    CHART_SEQUENCE,
    CRITICAL,
    PRIMARY_LIGHT,
    SUCCESS,
    WARNING,
    apply_dt_layout,
    get_palette,
)


def render(df: pd.DataFrame) -> None:
    """Render the Batch Tracking tab."""
    tracking = load_batch_tracking()
    if not tracking:
        st.info(
            "No batch tracking data yet. "
            "The `scripts/ec2/run_evaluation.sh` orchestrator writes "
            "tracking data after each batch."
        )
        return

    _render_summary(tracking)
    st.divider()
    _render_tracking_table(tracking)
    st.divider()
    _render_stop_conditions(tracking)
    st.divider()
    _render_cumulative_charts(tracking)


def _render_summary(tracking: list[dict[str, Any]]) -> None:
    """Top-level summary metrics across all completed batches."""
    total_batches = len(tracking)
    total_completed = sum(t.get("cves_completed", 0) for t in tracking)
    total_gen_failures = sum(t.get("gen_failures", 0) for t in tracking)
    total_pipe_errors = sum(t.get("pipeline_errors", 0) for t in tracking)
    total_cost = sum(t.get("total_cost_usd", 0) for t in tracking)
    total_l1_plus = sum(t.get("l1_plus", 0) for t in tracking)
    total_assessable = sum(t.get("assessable", 0) for t in tracking)
    latest = tracking[-1]

    c1, c2, c3, c4, c5, c6, c7 = st.columns(7)
    c1.metric("Batches Done", f"{total_batches}/24")
    c2.metric("CVEs Processed", total_completed)
    c3.metric("Gen Fails", total_gen_failures)
    c4.metric("Pipe Errors", total_pipe_errors)
    c5.metric("Total Cost", f"${total_cost:.2f}")
    c6.metric(
        "L1+ Rate",
        f"{total_l1_plus / max(total_assessable, 1) * 100:.1f}%",
    )
    c7.metric("Disk Free", f"{latest.get('disk_free_gb', 0):.0f} GB")


def _render_tracking_table(tracking: list[dict[str, Any]]) -> None:
    """Per-batch tracking table with color-coded verdicts."""
    st.subheader("Per-Batch Results")

    rows = []
    for t in tracking:
        levels = t.get("levels", {})
        knowledge = t.get("knowledge", {})
        rows.append(
            {
                "Batch": t.get("batch", ""),
                "CVEs": t.get("cves_completed", 0),
                "Gen Fail": t.get("gen_failures", 0),
                "Pipe Err": t.get("pipeline_errors", 0),
                "L0": levels.get("L0", 0),
                "L1": levels.get("L1", 0),
                "L2": levels.get("L2", 0),
                "L3": levels.get("L3", 0),
                "Cost ($)": t.get("total_cost_usd", 0),
                "$/CVE": t.get("mean_cost_usd", 0),
                "Time (min)": t.get("total_time_min", 0),
                "Rules": t.get("detection_rules", 0),
                "KB Total": sum(knowledge.values()) if knowledge else 0,
                "Cookbook": knowledge.get("cookbook", 0),
                "Disk (GB)": t.get("disk_free_gb", 0),
                "Verdict": t.get("verdict", ""),
            }
        )

    table_df = pd.DataFrame(rows)

    # Color the verdict column
    def _color_verdict(val: object) -> str:
        v = str(val)
        if v == "PASS":
            return f"background-color: {SUCCESS}33; color: {SUCCESS}"
        if v == "FAIL":
            return f"background-color: {CRITICAL}33; color: {CRITICAL}"
        return f"background-color: {WARNING}33; color: {WARNING}"

    styled = table_df.style.map(_color_verdict, subset=["Verdict"])
    st.dataframe(styled, use_container_width=True, height=min(600, len(rows) * 38 + 40))


def _render_stop_conditions(tracking: list[dict[str, Any]]) -> None:
    """Show stop condition status for the latest batch."""
    p = get_palette()
    st.subheader("Stop Condition Status (Latest Batch)")
    latest = tracking[-1]
    checks = latest.get("checks", [])

    if not checks:
        st.info("No health check data available.")
        return

    cols = st.columns(len(checks))
    for col, check in zip(cols, checks, strict=True):
        passed = check.get("passed", False)
        icon = "PASS" if passed else "FAIL"
        color = SUCCESS if passed else CRITICAL
        name = str(check.get("name", "")).replace("_", " ").title()
        col.markdown(
            f'<div style="text-align:center; padding:8px; '
            f"border:1px solid {color}44; border-radius:8px; "
            f'background:{color}11;">'
            f'<div style="color:{color}; font-weight:600; font-size:1.1rem;">{icon}</div>'
            f'<div style="color:{p["text_muted"]}; font-size:0.75rem; '
            f'margin-top:4px;">{name}</div>'
            f'<div style="color:{color}; font-size:0.85rem;">'
            f'{check.get("value", "")}</div>'
            f"</div>",
            unsafe_allow_html=True,
        )

    if latest.get("verdict") == "FAIL":
        st.error(f"Evaluation stopped: {latest.get('reason', 'Unknown')}")


def _render_cumulative_charts(tracking: list[dict[str, Any]]) -> None:
    """Cumulative cost, L1+ rate, and knowledge growth across batches."""
    if len(tracking) < 2:
        return

    st.subheader("Trends Across Batches")

    # Prepare data
    batches = [t.get("batch", "") for t in tracking]
    cum_cost: list[float] = []
    cum_l1_plus: list[float] = []
    cum_assessable: list[int] = []
    kb_totals: list[int] = []
    cookbook_counts: list[int] = []
    running_cost = 0.0
    running_l1 = 0
    running_assess = 0

    for t in tracking:
        running_cost += t.get("total_cost_usd", 0)
        running_l1 += t.get("l1_plus", 0)
        running_assess += t.get("assessable", 0)
        cum_cost.append(running_cost)
        cum_l1_plus.append(running_l1 / max(running_assess, 1) * 100)
        cum_assessable.append(running_assess)
        knowledge = t.get("knowledge", {})
        kb_totals.append(sum(knowledge.values()))
        cookbook_counts.append(knowledge.get("cookbook", 0))

    col1, col2 = st.columns(2)

    # Cumulative cost + running mean $/CVE
    with col1:
        fig = go.Figure()
        fig.add_trace(
            go.Bar(
                x=batches,
                y=[t.get("total_cost_usd", 0) for t in tracking],
                name="Batch Cost",
                marker_color=CHART_SEQUENCE[0],
                opacity=0.7,
                text=[f"${c:.0f}" for c in [t.get("total_cost_usd", 0) for t in tracking]],
            )
        )
        fig.add_trace(
            go.Scatter(
                x=batches,
                y=[
                    c / max(a, 1)
                    for c, a in zip(cum_cost, cum_assessable, strict=True)
                ],
                name="Cumul. $/CVE",
                yaxis="y2",
                mode="lines+markers",
                line={"color": WARNING, "width": 2},
            )
        )
        fig.update_layout(
            title="Cost per Batch + Running Mean",
            yaxis_title="Batch Cost ($)",
            yaxis2={"title": "$/CVE", "overlaying": "y", "side": "right"},
            legend={"orientation": "h", "y": -0.2},
            height=380,
        )
        st.plotly_chart(apply_dt_layout(fig), use_container_width=True, key="bt_cost")

    # Knowledge growth
    with col2:
        fig = go.Figure()
        fig.add_trace(
            go.Scatter(
                x=batches,
                y=kb_totals,
                name="KB Total",
                mode="lines+markers",
                line={"color": PRIMARY_LIGHT, "width": 2},
            )
        )
        fig.add_trace(
            go.Scatter(
                x=batches,
                y=cookbook_counts,
                name="Cookbook Tips",
                mode="lines+markers",
                line={"color": SUCCESS, "width": 2},
            )
        )
        fig.update_layout(
            title="Knowledge Store Growth",
            yaxis_title="Entries",
            legend={"orientation": "h", "y": -0.2},
            height=380,
        )
        st.plotly_chart(apply_dt_layout(fig), use_container_width=True, key="bt_knowledge")

    st.divider()

    # L1+ rate trend
    fig = px.line(
        x=batches,
        y=cum_l1_plus,
        labels={"x": "Batch", "y": "Cumulative L1+ Rate (%)"},
        height=300,
        color_discrete_sequence=[SUCCESS],
    )
    fig.update_layout(title="Cumulative L1+ Rate")
    st.plotly_chart(apply_dt_layout(fig), use_container_width=True, key="bt_l1rate")
