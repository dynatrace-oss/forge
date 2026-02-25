"""RQ3 (Detection Quality) and RQ4 (Knowledge Amortization) tab."""

from __future__ import annotations

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from dashboard.data import count_knowledge_entries
from dashboard.theme import (
    AGENT_COLORS,
    AGENT_COST_COLS,
    AGENT_LABELS,
    LEVEL_COLOR_MAP,
    LEVEL_LABELS,
    PRIMARY_LIGHT,
    SUCCESS,
    WARNING,
    apply_dt_layout,
    get_palette,
)


def render(df: pd.DataFrame) -> None:
    """Render RQ3 and RQ4 sections."""
    if len(df) < 50:
        st.warning(
            f"N={len(df)} \u2014 metrics are preliminary. "
            f"Full analysis requires the 600-CVE run."
        )

    _render_rq3(df)
    st.divider()
    _render_rq4(df)


def _render_rq3(df: pd.DataFrame) -> None:
    p = get_palette()
    st.header("RQ3 \u2014 Detection Quality")

    c1, c2 = st.columns(2)
    with c1:
        st.subheader("Detection Rule Coverage")
        det_with = len(df[df["detection_rules_count"] > 0])
        st.metric("CVEs with Detection Rules", f"{det_with}/{len(df)}")
        fig = px.pie(
            names=["With Rules", "Without Rules"],
            values=[det_with, len(df) - det_with],
            color_discrete_sequence=[SUCCESS, p["border"]],
            height=350,
        )
        st.plotly_chart(apply_dt_layout(fig), use_container_width=True, key="rq3_coverage")

    with c2:
        st.subheader("Rules per CVE Distribution")
        rules_df = df[df["detection_rules_count"] > 0]
        if rules_df.empty:
            st.info("No detection rules generated yet.")
        else:
            fig = px.histogram(
                rules_df,
                x="detection_rules_count",
                nbins=10,
                height=350,
                labels={"detection_rules_count": "Rules per CVE"},
                color_discrete_sequence=[PRIMARY_LIGHT],
            )
            st.plotly_chart(
                apply_dt_layout(fig),
                use_container_width=True,
                key="rq3_rules_hist",
            )

    st.divider()

    st.subheader("Detection Rules by Exploitation Level")
    det_by_level = df.groupby("level")["detection_rules_count"].mean().reset_index()
    det_by_level["level_label"] = det_by_level["level"].map(LEVEL_LABELS)
    fig = px.bar(
        det_by_level,
        x="level_label",
        y="detection_rules_count",
        text=det_by_level["detection_rules_count"].round(1),
        height=380,
        labels={"level_label": "Level", "detection_rules_count": "Mean Rules"},
        color="level_label",
        color_discrete_map=LEVEL_COLOR_MAP,
    )
    fig.update_layout(showlegend=False)
    st.plotly_chart(apply_dt_layout(fig), use_container_width=True, key="rq3_det_level")

    _rq3_detection_cwe_radar(df)


def _rq3_detection_cwe_radar(df: pd.DataFrame) -> None:
    """Radar chart showing detection rule coverage % per CWE type."""
    p = get_palette()
    cwe_df = df[df["cwe"] != ""]
    if cwe_df.empty:
        return

    top_cwes = cwe_df["cwe"].value_counts().head(8)
    if len(top_cwes) < 3:
        return  # radar needs >= 3 vertices

    st.divider()
    st.subheader("Detection Coverage by CWE (Top 8)")
    radar_rows: list[dict[str, object]] = []
    for cwe_id in top_cwes.index:
        subset = cwe_df[cwe_df["cwe"] == cwe_id]
        has_rules = len(subset[subset["detection_rules_count"] > 0])
        coverage = has_rules / len(subset) * 100
        radar_rows.append(
            {"cwe": str(cwe_id), "coverage": round(coverage, 1), "count": len(subset)}
        )

    r_vals = [float(str(r["coverage"])) for r in radar_rows]
    r_vals.append(r_vals[0])
    theta = [str(r["cwe"]) for r in radar_rows]
    theta.append(theta[0])

    fig = go.Figure()
    fig.add_trace(
        go.Scatterpolar(
            r=r_vals,
            theta=theta,
            fill="toself",
            name="Detection Coverage (%)",
            line={"color": WARNING, "width": 2},
            fillcolor="rgba(238, 167, 70, 0.2)",
        )
    )
    fig.update_layout(
        polar={
            "bgcolor": p["bg_base"],
            "radialaxis": {
                "visible": True,
                "range": [0, 105],
                "gridcolor": p["border"],
                "ticksuffix": "%",
            },
            "angularaxis": {"gridcolor": p["border"]},
        },
        height=380,
        showlegend=False,
    )
    st.plotly_chart(apply_dt_layout(fig), use_container_width=True, key="rq3_cwe_det_radar")


def _render_rq4(df: pd.DataFrame) -> None:
    p = get_palette()
    st.header("RQ4 \u2014 Knowledge Amortization")
    if len(df) < 2:
        st.info("Need at least 2 CVEs for amortization analysis.")
        return

    df_seq = df.reset_index(drop=True)
    df_seq["seq"] = range(1, len(df_seq) + 1)
    df_seq["rolling_cost"] = df_seq["cost"].expanding().mean()

    _rq4_amortization(df_seq, p)
    st.divider()
    _rq4_gen_and_tools(df_seq)
    st.divider()
    _rq4_knowledge_summary()


def _rq4_amortization(df_seq: pd.DataFrame, p: dict[str, str]) -> None:
    c1, c2 = st.columns(2)

    with c1:
        st.subheader("Cost Amortization Curve")
        fig = go.Figure()
        fig.add_trace(
            go.Scatter(
                x=df_seq["seq"],
                y=df_seq["cost"],
                mode="markers",
                name="Per-CVE Cost",
                marker={"color": p["text_muted"], "size": 5, "opacity": 0.6},
            )
        )
        fig.add_trace(
            go.Scatter(
                x=df_seq["seq"],
                y=df_seq["rolling_cost"],
                mode="lines",
                name="Rolling Average",
                line={"color": PRIMARY_LIGHT, "width": 2},
            )
        )
        fig.update_layout(
            xaxis_title="CVE Sequence", yaxis_title="Cost (USD)", height=380,
        )
        st.plotly_chart(apply_dt_layout(fig), use_container_width=True, key="rq4_amort")

    with c2:
        st.subheader("Per-Agent Cost Decomposition")
        existing = [c for c in AGENT_COST_COLS if c in df_seq.columns]
        if not existing:
            return
        fig = go.Figure()
        for col, label, color in zip(
            AGENT_COST_COLS, AGENT_LABELS, AGENT_COLORS, strict=True,
        ):
            if col in df_seq.columns:
                fig.add_trace(
                    go.Scatter(
                        x=df_seq["seq"],
                        y=df_seq[col].expanding().mean(),
                        mode="lines",
                        name=label,
                        stackgroup="one",
                        line={"color": color},
                    )
                )
        fig.update_layout(
            xaxis_title="CVE Sequence",
            yaxis_title="Rolling Avg Cost (USD)",
            height=380,
        )
        st.plotly_chart(
            apply_dt_layout(fig), use_container_width=True, key="rq4_agent_cost",
        )


def _rq4_gen_and_tools(df_seq: pd.DataFrame) -> None:
    c1, c2 = st.columns(2)

    with c1:
        st.subheader("Generation Attempts (Rolling Avg)")
        df_seq = df_seq.copy()
        df_seq["rolling_gen"] = df_seq["generation_attempts"].expanding().mean()
        fig = px.line(
            df_seq,
            x="seq",
            y="rolling_gen",
            height=380,
            labels={"seq": "CVE Sequence", "rolling_gen": "Avg Gen Attempts"},
            color_discrete_sequence=[WARNING],
        )
        st.plotly_chart(apply_dt_layout(fig), use_container_width=True, key="rq4_gen_roll")

    with c2:
        st.subheader("Tool Calls (Rolling Avg)")
        df_seq["rolling_tools"] = df_seq["tool_calls"].expanding().mean()
        fig = px.line(
            df_seq,
            x="seq",
            y="rolling_tools",
            height=380,
            labels={"seq": "CVE Sequence", "rolling_tools": "Avg Tool Calls"},
            color_discrete_sequence=[SUCCESS],
        )
        st.plotly_chart(apply_dt_layout(fig), use_container_width=True, key="rq4_tools")


def _rq4_knowledge_summary() -> None:
    st.subheader("Knowledge Store Summary")
    knowledge = count_knowledge_entries()
    cols = st.columns(4)
    cols[0].metric("Graph Entries", knowledge["graph"])
    cols[1].metric("Learnings", knowledge["learnings"])
    cols[2].metric("Cookbook Tips", knowledge["cookbook"])
    cols[3].metric("Detection KB", knowledge["detection_kb"])
