"""Detail tabs — Per-CVE Table, Detection Rules, Knowledge Growth, Errors & Logs."""

from __future__ import annotations

import math

import pandas as pd
import plotly.express as px
import streamlit as st

from dashboard.data import (
    LOGS_DIR,
    count_knowledge_entries,
    load_detection_rules,
    read_log_tail,
)
from dashboard.theme import (
    CRITICAL,
    PRIMARY_LIGHT,
    SUCCESS,
    WARNING,
    apply_dt_layout,
    get_palette,
    rule_syntax,
)

_RULE_TYPE_LABEL: dict[str, str] = {
    "sigma": "SIGMA",
    "snort": "SNORT",
    "yara": "YARA",
}

_PAGE_SIZE = 30
"""Fixed number of rows per page in the Per-CVE table."""


def _rule_type_badge(rtype: str) -> str:
    """Return a display label for the rule type."""
    return _RULE_TYPE_LABEL.get(rtype, "RULE")


def render_table(df: pd.DataFrame) -> None:
    """Render the Per-CVE Table tab with search filters and bottom pagination."""
    st.subheader("Per-CVE Results")

    display_df = _prepare_table_df(df)

    # ── Search / filter row ────────────────────────────────────────────────
    fc1, fc2, fc3, fc4 = st.columns([3, 2, 2, 2])

    with fc1:
        cve_search = st.text_input(
            "Search CVE", placeholder="e.g. 2024-41", key="tbl_cve_search",
        )
    with fc2:
        lang_options = sorted(display_df["Lang"].dropna().unique().tolist())
        lang_filter = st.multiselect("Language", lang_options, key="tbl_lang_filter")
    with fc3:
        cwe_options = sorted(display_df["CWE"].dropna().unique().tolist())
        cwe_filter = st.multiselect("CWE", cwe_options, key="tbl_cwe_filter")
    with fc4:
        status_options = ["All"] + sorted(df["status"].dropna().unique().tolist())
        status_filter: str = st.selectbox(
            "Status", status_options, index=0, key="tbl_status_filter",
        )

    # Apply filters
    filtered = display_df.copy()
    if cve_search:
        filtered = filtered[
            filtered["CVE"].str.contains(cve_search, case=False, na=False)
        ]
    if lang_filter:
        filtered = filtered[filtered["Lang"].isin(lang_filter)]
    if cwe_filter:
        filtered = filtered[filtered["CWE"].isin(cwe_filter)]
    if status_filter != "All":
        filtered = filtered[filtered["Status"] == status_filter]

    total_rows = len(filtered)
    if total_rows == 0:
        st.info("No CVEs match the current filters.")
        return

    # ── Table display ──────────────────────────────────────────────────────
    total_pages = min(20, max(1, math.ceil(total_rows / _PAGE_SIZE)))

    # Initialize page state
    if "tbl_page" not in st.session_state:
        st.session_state["tbl_page"] = 1
    # Clamp to valid range
    page = max(1, min(st.session_state["tbl_page"], total_pages))

    start = (page - 1) * _PAGE_SIZE
    paged = filtered.iloc[start : start + _PAGE_SIZE]
    styled = paged.style.map(_color_level, subset=["Level"])
    st.dataframe(
        styled,
        use_container_width=True,
        height=min(900, len(paged) * 38 + 40),
    )

    # ── Bottom pagination ──────────────────────────────────────────────────
    p = get_palette()
    nav_l, nav_c, nav_r = st.columns([1, 2, 1])

    with nav_l:
        if page > 1:
            if st.button("\u2190 Previous", key="tbl_prev"):
                st.session_state["tbl_page"] = page - 1
                st.rerun()

    with nav_c:
        st.markdown(
            f'<p style="text-align:center; color:{p["text_muted"]}; '
            f'font-size:0.85rem; padding-top:8px;">'
            f"Page {page} of {total_pages} \u2014 {total_rows} CVEs</p>",
            unsafe_allow_html=True,
        )

    with nav_r:
        if page < total_pages:
            if st.button("Next \u2192", key="tbl_next"):
                st.session_state["tbl_page"] = page + 1
                st.rerun()


def _prepare_table_df(df: pd.DataFrame) -> pd.DataFrame:
    """Select, round, and rename columns for the table display."""
    cols = [
        "cve_id",
        "cwe",
        "language",
        "package",
        "version",
        "level",
        "cost",
        "wall_clock_s",
        "status",
        "detection_rules_count",
        "generation_attempts",
        "oracle_confidence",
        "tool_calls",
    ]
    # Only include columns that exist in the DataFrame (package/version may
    # be absent in older result sets).
    cols = [c for c in cols if c in df.columns]
    out = df[cols].copy()
    out["wall_clock_min"] = (out["wall_clock_s"] / 60).round(2)
    out = out.drop(columns=["wall_clock_s"])
    out["cost"] = out["cost"].round(3)
    out["oracle_confidence"] = out["oracle_confidence"].round(2)
    return out.rename(
        columns={
            "cve_id": "CVE",
            "cwe": "CWE",
            "language": "Lang",
            "package": "Package",
            "version": "Version",
            "level": "Level",
            "cost": "Cost ($)",
            "wall_clock_min": "Time (min)",
            "status": "Status",
            "detection_rules_count": "Rules",
            "generation_attempts": "Gen Attempts",
            "oracle_confidence": "Oracle Conf",
            "tool_calls": "Tool Calls",
        }
    )


def _color_level(val: object) -> str:
    """Dynatrace-themed background for level cells."""
    colors = {
        0: f"{CRITICAL}33",
        1: f"{WARNING}33",
        2: f"{PRIMARY_LIGHT}33",
        3: f"{SUCCESS}33",
    }
    try:
        level = int(str(val))
        return f"background-color: {colors.get(level, '')}"
    except (TypeError, ValueError):
        return ""


def render_rules(df: pd.DataFrame) -> None:
    """Render the Detection Rules viewer tab."""
    p = get_palette()
    st.subheader("Detection Rules Viewer")

    cves_with_rules = df[df["detection_rules_count"] > 0]
    total_rules = int(df["detection_rules_count"].sum())

    m1, m2, m3 = st.columns(3)
    m1.metric("CVEs with Rules", f"{len(cves_with_rules)}/{len(df)}")
    m2.metric("Total Rules", total_rules)
    m3.metric(
        "Avg Rules/CVE",
        f"{total_rules / len(cves_with_rules):.1f}" if len(cves_with_rules) > 0 else "0",
    )

    if cves_with_rules.empty:
        st.info("No detection rules generated yet. Rules appear as CVEs are processed.")
        return

    cve_options = sorted(cves_with_rules["cve_id"].tolist())
    selected: str = st.selectbox(
        "Select CVE to view rules",
        cve_options,
        index=0,
        key="rules_cve_select",
    )
    if not selected:
        return

    rules = load_detection_rules(selected)
    if not rules:
        st.warning(f"Could not load rules for {selected}.")
        return

    st.markdown(
        f'<p style="color:{p["text_muted"]}; font-size:0.85rem;">'
        f"{len(rules)} rule(s) for {selected}</p>",
        unsafe_allow_html=True,
    )
    for idx, rule in enumerate(rules):
        rtype = rule["type"].lower()
        badge = _rule_type_badge(rtype)
        with st.expander(f"{badge}  {rule['title']}", expanded=(idx == 0)):
            if rule["description"]:
                st.caption(rule["description"])
            st.code(rule["content"], language=rule_syntax(rtype))


def render_knowledge(df: pd.DataFrame) -> None:
    """Render the Knowledge Growth tab."""
    st.subheader("Knowledge Store Growth")
    knowledge = count_knowledge_entries()

    if all(v == 0 for v in knowledge.values()):
        st.info("No knowledge entries found. Stores populate as CVEs are processed.")
        return

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Graph Entries", knowledge["graph"])
    c2.metric("Learnings", knowledge["learnings"])
    c3.metric("Cookbook Tips", knowledge["cookbook"])
    c4.metric("Detection KB", knowledge["detection_kb"])

    if len(df) <= 1:
        return

    st.divider()

    st.subheader("Cumulative Knowledge vs CVE Sequence")
    df_sorted = df.sort_values("wall_clock_s").reset_index(drop=True)
    df_sorted["seq"] = range(1, len(df_sorted) + 1)
    df_sorted["rolling_avg_cost"] = df_sorted["cost"].expanding().mean()
    fig = px.line(
        df_sorted,
        x="seq",
        y="rolling_avg_cost",
        height=380,
        labels={"seq": "CVE Sequence", "rolling_avg_cost": "Rolling Avg Cost ($)"},
        color_discrete_sequence=[PRIMARY_LIGHT],
    )
    st.plotly_chart(apply_dt_layout(fig), use_container_width=True, key="kg_rolling")


def render_errors(df: pd.DataFrame) -> None:
    """Render the Errors & Logs tab."""
    st.subheader("Failed / Errored CVEs")
    _show_errors(df)
    _show_cost_caps(df)
    _show_log_tail()


def _show_errors(df: pd.DataFrame) -> None:
    error_df = df[df["status"].isin(["error", "generation_failed", "deploy_failed"])]
    if error_df.empty:
        st.markdown(
            '<span class="forge-badge badge-ok">No errors or failures detected</span>',
            unsafe_allow_html=True,
        )
        return
    display = error_df[["cve_id", "status", "error_category", "error_message"]].rename(
        columns={
            "cve_id": "CVE",
            "status": "Status",
            "error_category": "Category",
            "error_message": "Error Message",
        },
    )
    st.dataframe(display, use_container_width=True, height=300)


def _show_cost_caps(df: pd.DataFrame) -> None:
    caps = df[df["status"] == "cost_cap_reached"]
    if caps.empty:
        return
    st.subheader(f"Cost-Cap CVEs ({len(caps)})")
    display = caps[["cve_id", "level", "cost"]].rename(
        columns={"cve_id": "CVE", "level": "Level", "cost": "Cost ($)"},
    )
    st.dataframe(display, use_container_width=True)


def _show_log_tail() -> None:
    st.subheader("Recent Log Tail")
    if not LOGS_DIR.exists():
        st.info("Logs directory does not exist yet.")
        return

    log_files = sorted(
        LOGS_DIR.glob("CVE-*.log"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    if not log_files:
        st.info("No CVE log files found.")
        return

    selected: str = st.selectbox(
        "Log file",
        [f.name for f in log_files[:20]],
        index=0,
        key="err_logfile",
    )
    st.code(read_log_tail(LOGS_DIR / selected, lines=50), language="text")
