"""Overview tab — level distribution, cost, time, efficiency, and agent charts."""

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from dashboard.theme import (
    AGENT_COLORS,
    AGENT_COST_COLS,
    AGENT_LABELS,
    LEVEL_COLOR_MAP,
    LEVEL_COLORS,
    LEVEL_LABELS,
    PRIMARY_LIGHT,
    apply_dt_layout,
    get_palette,
)


def render(df: pd.DataFrame) -> None:
    """Render the Overview tab."""
    _row_level_and_cost(df)
    st.divider()
    _row_time_and_cost_level(df)
    st.divider()
    _row_tokens_and_agent(df)


def _row_level_and_cost(df: pd.DataFrame) -> None:
    c1, c2 = st.columns(2)

    with c1:
        st.subheader("Level Distribution")
        level_counts = df["level"].value_counts().sort_index()
        level_df = pd.DataFrame(
            {
                "Level": [f"L{i}" for i in range(4)],
                "Count": [int(level_counts.get(i, 0)) for i in range(4)],
            }
        )
        level_df["Pct"] = (level_df["Count"] / level_df["Count"].sum() * 100).round(1)
        fig = px.bar(
            level_df,
            x="Level",
            y="Count",
            color="Level",
            color_discrete_map={f"L{k}": v for k, v in LEVEL_COLORS.items()},
            text=level_df.apply(lambda r: f"{r['Count']} ({r['Pct']}%)", axis=1),
            height=380,
        )
        fig.update_layout(showlegend=False)
        st.plotly_chart(apply_dt_layout(fig), use_container_width=True, key="ov_levels")

    with c2:
        st.subheader("Cost Distribution")
        fig = px.box(
            df,
            y="cost",
            points="all",
            height=380,
            labels={"cost": "Cost (USD)"},
            color_discrete_sequence=[PRIMARY_LIGHT],
        )
        st.plotly_chart(apply_dt_layout(fig), use_container_width=True, key="ov_cost")


def _row_time_and_cost_level(df: pd.DataFrame) -> None:
    c1, c2 = st.columns(2)

    with c1:
        st.subheader("Wall Clock Time (min)")
        df_time = df.assign(time_min=df["wall_clock_s"] / 60)
        fig = px.histogram(
            df_time,
            x="time_min",
            nbins=20,
            height=380,
            labels={"time_min": "Minutes"},
            color_discrete_sequence=[PRIMARY_LIGHT],
        )
        st.plotly_chart(apply_dt_layout(fig), use_container_width=True, key="ov_time")

    with c2:
        st.subheader("Cost vs Exploitation Level")
        df_cvl = df.assign(Level=df["level"].map(LEVEL_LABELS))
        fig = px.box(
            df_cvl,
            x="Level",
            y="cost",
            points="all",
            color="Level",
            color_discrete_map=LEVEL_COLOR_MAP,
            labels={"cost": "Cost (USD)"},
            height=380,
            category_orders={"Level": ["L0", "L1", "L2", "L3"]},
        )
        fig.update_layout(showlegend=False)
        st.plotly_chart(apply_dt_layout(fig), use_container_width=True, key="ov_cost_level")


def _row_tokens_and_agent(df: pd.DataFrame) -> None:
    c1, c2 = st.columns(2)

    with c1:
        st.subheader("Token Efficiency")
        df_tok = df.assign(Level=df["level"].map(LEVEL_LABELS))
        fig = px.scatter(
            df_tok,
            x="total_tokens",
            y="cost",
            color="Level",
            color_discrete_map=LEVEL_COLOR_MAP,
            size="wall_clock_s",
            hover_data=["cve_id"],
            labels={
                "total_tokens": "Total Tokens",
                "cost": "Cost (USD)",
                "wall_clock_s": "Time (s)",
            },
            height=380,
        )
        st.plotly_chart(apply_dt_layout(fig), use_container_width=True, key="ov_token_eff")

    with c2:
        st.subheader("Per-Agent Average Cost")
        existing = [c for c in AGENT_COST_COLS if c in df.columns]
        if not existing:
            return
        means = [
            float(df[c].mean()) if c in df.columns else 0.0
            for c in AGENT_COST_COLS
        ]
        fig = go.Figure(
            go.Bar(
                x=AGENT_LABELS,
                y=means,
                marker_color=AGENT_COLORS,
                text=[f"${v:.3f}" for v in means],
            )
        )
        fig.update_layout(
            yaxis_title="Avg Cost (USD)", height=380, showlegend=False,
        )
        st.plotly_chart(apply_dt_layout(fig), use_container_width=True, key="ov_agent_bar")
