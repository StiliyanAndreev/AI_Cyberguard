import logging
import os
import sys

import pandas as pd
import plotly.express as px
import streamlit as st

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from engine.ai_engine import analyze_commit_batch
from engine.config import (
    MAX_BATCH_SIZE,
    MAX_DIFF_TOTAL_CHARS,
    RISK_CRITICAL_MIN,
    RISK_SAFE_MAX,
    RISK_SUSPICIOUS_MAX,
    TOP_RISKY_DEVS,
)
from engine.db_handler import delete_scan, get_all_scans, init_db, save_scan
from engine.git_handler import get_commit_diff, get_latest_commits, get_repo
from engine.eval_engine import compute_metrics, get_ground_truth
from engine.static_baseline import analyze_diff, score_diff
from engine.ueba_engine import build_developer_profiles

logging.basicConfig(level=logging.INFO)

# ---------------------------------------------------------------------------
# Login gate
# ---------------------------------------------------------------------------
st.set_page_config(page_title="CyberGuard AI Platform", page_icon="🛡️", layout="wide")

if "authenticated" not in st.session_state:
    st.session_state["authenticated"] = False

if not st.session_state["authenticated"]:
    st.title("🛡️ CyberGuard - Login")
    password = st.text_input("Password", type="password")
    if st.button("Login"):
        expected = os.getenv("APP_PASSWORD", "cyberguard")
        if password == expected:
            st.session_state["authenticated"] = True
            st.rerun()
        else:
            st.error("Incorrect password.")
    st.stop()

init_db()

# ---------------------------------------------------------------------------
# Translations
# ---------------------------------------------------------------------------
translations = {
    "BG": {
        "nav_title": "Навигация",
        "menu_dash": "📊 Глобално табло",
        "menu_scan": "➕ Сканиране на проект",
        "menu_people": "👥 Хора и UEBA",
        "menu_logs": "⚙️ Системни логове",
        "menu_eval": "📈 Оценка на системата",
        "dash_title": "Сигурен преглед на организацията",
        "kpi_projects": "Проекти",
        "kpi_critical": "Критични",
        "kpi_suspicious": "Подозрителни",
        "kpi_safe": "Безопасни",
        "btn_explore": "Разгледай",
        "filter_label": "Филтрирай по проект:",
        "all_projects": "Всички проекти",
        "chart_trend": "Тенденция на заплахите",
        "chart_devs": "🔥 Топ рискови програмисти (Среден Score)",
        "chart_dist": "Разпределение на риска",
        "scan_title": "Добавяне на нов проект",
        "scan_mode": "Тип източник",
        "repo_url": "URL на хранилището",
        "local_path": "Локална папка",
        "token_label": "Access Token (Опционално)",
        "btn_fetch": "🔎 Изтегли коммити",
        "btn_analyze": "🚀 Анализирай и запиши",
        "report_tab": "🧠 AI Доклад",
        "code_tab": "💻 Изходен код",
    },
    "EN": {
        "nav_title": "Navigation",
        "menu_dash": "📊 Global Dashboard",
        "menu_scan": "➕ Scan & Add Project",
        "menu_people": "👥 People & UEBA",
        "menu_logs": "⚙️ System Logs",
        "menu_eval": "📈 Evaluation Metrics",
        "dash_title": "Organizational Security Overview",
        "kpi_projects": "Projects",
        "kpi_critical": "Critical",
        "kpi_suspicious": "Suspicious",
        "kpi_safe": "Safe",
        "btn_explore": "Explore",
        "filter_label": "Filter by Project:",
        "all_projects": "All Projects",
        "chart_trend": "Threat Trend Over Time",
        "chart_devs": f"🔥 Top {TOP_RISKY_DEVS} Riskiest Developers (Avg Score)",
        "chart_dist": "Risk Distribution",
        "scan_title": "Ingest New Repository",
        "scan_mode": "Source Type",
        "repo_url": "Repository URL",
        "local_path": "Local Folder Path",
        "token_label": "Access Token (Optional)",
        "btn_fetch": "🔎 Fetch Commits",
        "btn_analyze": "🚀 Analyze Batch & Save",
        "report_tab": "🧠 AI Forensic Report",
        "code_tab": "💻 View Source Code",
    },
}

# ---------------------------------------------------------------------------
# Page config & sidebar
# ---------------------------------------------------------------------------
if "lang" not in st.session_state:
    st.session_state["lang"] = "EN"
st.sidebar.title("🛡️ CyberGuard")
lang_choice = st.sidebar.radio("🌐 Language / Език", ["EN", "BG"], horizontal=True)
st.session_state["lang"] = lang_choice
t = translations[st.session_state["lang"]]

st.markdown("""
    <style>
    .kpi-card { background-color: #161b22; padding: 20px; border-radius: 10px;
                border: 1px solid #30363d; text-align: center; }
    .kpi-title { font-size: 16px; color: #8b949e; }
    .kpi-value { font-size: 32px; font-weight: bold; }
    .color-red    { color: #ff4b4b; }
    .color-yellow { color: #faca2b; }
    .color-green  { color: #21c354; }
    .dev-card { background-color: #161b22; padding: 20px; border-radius: 12px;
                border-left: 6px solid #30363d; margin-bottom: 15px; }
    </style>
""", unsafe_allow_html=True)

if "dash_view" not in st.session_state:
    st.session_state["dash_view"] = "Main"
if "dash_filter" not in st.session_state:
    st.session_state["dash_filter"] = None


def go_to_view(view_name: str, filter_val=None) -> None:
    st.session_state["dash_view"] = view_name
    st.session_state["dash_filter"] = filter_val
    st.rerun()


st.sidebar.markdown("---")
menu = st.sidebar.radio(t["nav_title"], [t["menu_dash"], t["menu_scan"], t["menu_people"], t["menu_eval"], t["menu_logs"]])

# ---------------------------------------------------------------------------
# Load data
# ---------------------------------------------------------------------------
raw_data = get_all_scans()
df = (
    pd.DataFrame(raw_data, columns=["ID", "Repo", "Author", "Hash", "Score", "Report", "Diff", "Date"])
    if raw_data
    else pd.DataFrame()
)
if not df.empty:
    df["Date"] = pd.to_datetime(df["Date"])
    df["Status"] = pd.cut(
        df["Score"],
        bins=[-1, RISK_SAFE_MAX, RISK_SUSPICIOUS_MAX, 100],
        labels=["Green (Safe)", "Yellow (Suspicious)", "Red (Critical)"],
    )

# ---------------------------------------------------------------------------
# PAGE 1: Global Dashboard
# ---------------------------------------------------------------------------
if menu == t["menu_dash"]:
    if df.empty:
        st.title(t["dash_title"])
        st.info("No data yet. Go to Scan & Add Project to get started.")
    else:
        if st.session_state["dash_view"] == "Main":
            st.title(t["dash_title"])

            all_repos = [t["all_projects"]] + sorted(df["Repo"].unique().tolist())
            col_filter, _ = st.columns([1, 3])
            with col_filter:
                selected_repo = st.selectbox(t["filter_label"], all_repos)

            f_df = df if selected_repo == t["all_projects"] else df[df["Repo"] == selected_repo]

            c1, c2, c3, c4 = st.columns(4)
            with c1:
                st.markdown(f"<div class='kpi-card'><div class='kpi-title'>{t['kpi_projects']}</div>"
                            f"<div class='kpi-value'>{f_df['Repo'].nunique()}</div></div>",
                            unsafe_allow_html=True)
                if st.button(f"📂 {t['btn_explore']} Projects", use_container_width=True):
                    go_to_view("Projects")
            with c2:
                st.markdown(f"<div class='kpi-card'><div class='kpi-title'>{t['kpi_critical']}</div>"
                            f"<div class='kpi-value color-red'>{len(f_df[f_df['Score'] >= RISK_CRITICAL_MIN])}</div></div>",
                            unsafe_allow_html=True)
                if st.button(f"🚨 {t['btn_explore']} Critical", use_container_width=True):
                    go_to_view("Status", "Red (Critical)")
            with c3:
                st.markdown(f"<div class='kpi-card'><div class='kpi-title'>{t['kpi_suspicious']}</div>"
                            f"<div class='kpi-value color-yellow'>"
                            f"{len(f_df[(f_df['Score'] > RISK_SAFE_MAX) & (f_df['Score'] < RISK_CRITICAL_MIN)])}"
                            f"</div></div>", unsafe_allow_html=True)
                if st.button(f"⚠️ {t['btn_explore']} Suspicious", use_container_width=True):
                    go_to_view("Status", "Yellow (Suspicious)")
            with c4:
                st.markdown(f"<div class='kpi-card'><div class='kpi-title'>{t['kpi_safe']}</div>"
                            f"<div class='kpi-value color-green'>{len(f_df[f_df['Score'] <= RISK_SAFE_MAX])}</div></div>",
                            unsafe_allow_html=True)
                if st.button(f"✅ {t['btn_explore']} Safe", use_container_width=True):
                    go_to_view("Status", "Green (Safe)")

            st.write("---")
            if not f_df.empty:
                fig_trend = px.line(
                    f_df.sort_values("Date"), x="Date", y="Score", color="Repo",
                    title=t["chart_trend"], template="plotly_dark", markers=True,
                )
                fig_trend.add_hline(y=RISK_CRITICAL_MIN, line_dash="dash", line_color="red")
                st.plotly_chart(fig_trend, use_container_width=True)

                col_left, col_right = st.columns(2)
                with col_left:
                    risky_devs = (
                        f_df.groupby("Author")["Score"]
                        .mean()
                        .reset_index()
                        .sort_values("Score", ascending=False)
                        .head(TOP_RISKY_DEVS)
                    )
                    fig_devs = px.bar(
                        risky_devs, x="Score", y="Author", orientation="h",
                        title=t["chart_devs"], color="Score",
                        color_continuous_scale="Reds", template="plotly_dark",
                    )
                    fig_devs.update_layout(yaxis={"categoryorder": "total ascending"})
                    st.plotly_chart(fig_devs, use_container_width=True)
                with col_right:
                    fig_pie = px.pie(
                        f_df, names="Status", title=t["chart_dist"], hole=0.4,
                        color="Status",
                        color_discrete_map={
                            "Red (Critical)": "#ff4b4b",
                            "Yellow (Suspicious)": "#faca2b",
                            "Green (Safe)": "#21c354",
                        },
                        template="plotly_dark",
                    )
                    st.plotly_chart(fig_pie, use_container_width=True)
            else:
                st.info("No data to display for the selected filters.")

        elif st.session_state["dash_view"] == "Projects":
            if st.button("⬅️ Back"):
                go_to_view("Main")
            st.title("📂 Monitored Projects Details")
            proj_stats = df.groupby("Repo").agg(
                Total_Commits=("Hash", "count"),
                Avg_Risk=("Score", "mean"),
                Max_Risk=("Score", "max"),
                Latest_Scan=("Date", "max"),
            ).reset_index()
            st.dataframe(proj_stats, use_container_width=True, hide_index=True)

        elif st.session_state["dash_view"] == "Status":
            if st.button("⬅️ Back"):
                go_to_view("Main")
            current_status = st.session_state["dash_filter"]
            st.title(f"Investigation View: {current_status}")
            filtered_view_df = df[df["Status"] == current_status]
            if filtered_view_df.empty:
                st.info("No records found.")
            else:
                for _, row in filtered_view_df.iterrows():
                    with st.expander(f"{row['Date']} | {row['Repo']} | Risk: {row['Score']}/100"):
                        st.write(f"**Author:** `{row['Author']}`")
                        tab1, tab2 = st.tabs([t["report_tab"], t["code_tab"]])
                        with tab1:
                            st.info(row["Report"])
                        with tab2:
                            st.code(row["Diff"], language="diff")

# ---------------------------------------------------------------------------
# PAGE 2: Scan & Add Project
# ---------------------------------------------------------------------------
elif menu == t["menu_scan"]:
    st.title(t["scan_title"])
    mode = st.radio(t["scan_mode"], ["Git Remote URL", "Local Path"], horizontal=True)

    col_url, col_token = st.columns([3, 1])
    with col_url:
        if mode == "Git Remote URL":
            path_input = st.text_input(t["repo_url"], placeholder="https://github.com/user/repo.git")
        else:
            path_input = st.text_input(t["local_path"], placeholder="data/test_repo")
    with col_token:
        token = st.text_input(t["token_label"], type="password") if mode == "Git Remote URL" else ""

    if st.button(t["btn_fetch"], use_container_width=True):
        if not path_input.strip():
            st.warning("Please enter a repository URL or local path.")
        else:
            # Store ONLY the clean path — token is never saved to session state
            st.session_state["current_path"] = path_input.strip()
            st.session_state["current_token"] = token  # stored only in session, not in DB or logs
            st.session_state["current_mode"] = mode

    cp = st.session_state.get("current_path", "")
    if cp:
        try:
            is_remote = st.session_state.get("current_mode") == "Git Remote URL"
            stored_token = st.session_state.get("current_token", "")

            with st.spinner("Connecting to Git provider..."):
                # Token is passed to git_handler; URL embedding happens there, never in session state
                repo, subpath = get_repo(cp, is_cloud=is_remote, token=stored_token)
                commits = get_latest_commits(repo, path=subpath)

            clean_repo_name = cp.rstrip("/").split("/")[-1].replace(".git", "")
            st.success(f"Connected to: `{clean_repo_name}`")

            if len(commits) > MAX_BATCH_SIZE:
                st.info(f"Showing latest {MAX_BATCH_SIZE} commits (batch limit).")

            selected_ids = st.multiselect(
                "Select Commits",
                [f"{c.hexsha[:8]} - {c.author.name}: {c.message[:40]}" for c in commits],
            )

            if st.button(t["btn_analyze"], type="primary"):
                if not selected_ids:
                    st.warning("Please select at least one commit.")
                elif len(selected_ids) > MAX_BATCH_SIZE:
                    st.error(f"Maximum {MAX_BATCH_SIZE} commits per batch. Please deselect some.")
                else:
                    commits_to_analyze = []
                    for sel_id in selected_ids:
                        hash_only = sel_id.split(" - ")[0]
                        c_obj = next(c for c in commits if c.hexsha.startswith(hash_only))
                        diff_text = get_commit_diff(repo, c_obj)

                        if "\x00" in diff_text:
                            diff_text = "WARNING: Binary file changes detected. Code analysis skipped."
                        elif len(diff_text) > MAX_DIFF_TOTAL_CHARS:
                            diff_text = diff_text[:MAX_DIFF_TOTAL_CHARS] + "\n...[Truncated]"

                        commits_to_analyze.append({
                            "hash": hash_only,
                            "author": c_obj.author.name,
                            "msg": c_obj.message,
                            "diff": diff_text,
                        })

                    with st.spinner("🧠 AI Batch Auditing..."):
                        batch_results = analyze_commit_batch(commits_to_analyze)

                    if isinstance(batch_results, list) and batch_results and "error" in batch_results[0]:
                        st.error(batch_results[0]["error"])
                    else:
                        for idx, res in enumerate(batch_results):
                            save_scan(
                                clean_repo_name,
                                commits_to_analyze[idx]["author"],
                                res.get("hash", commits_to_analyze[idx]["hash"]),
                                res.get("risk_score"),
                                res.get("report", ""),
                                commits_to_analyze[idx]["diff"],
                            )
                        st.success(f"✅ Successfully analysed and saved {len(batch_results)} commits!")
                        st.rerun()

        except ValueError as exc:
            st.error(f"Input validation error: {exc}")
        except Exception as exc:
            st.error(f"Unexpected error: {exc}")
            logging.exception("Scan page error")

# ---------------------------------------------------------------------------
# PAGE 3: People / UEBA
# ---------------------------------------------------------------------------
elif menu == t["menu_people"]:
    st.title("Developer Threat Intelligence (UEBA)")

    if df.empty:
        st.info("No scan data available. Run some scans first.")
    else:
        profiles = build_developer_profiles(df)

        if profiles.empty:
            st.info("Could not build developer profiles.")
        else:
            # Detection method banner
            method = profiles["detection_method"].iloc[0]
            if "Isolation Forest" in method:
                st.success("🤖 ML anomaly detection active (Isolation Forest)")
            else:
                st.warning(f"⚠️ {method} — scan more developers to enable ML detection")

            # Summary metrics
            total = len(profiles)
            risky = profiles["is_risky"].sum()
            col1, col2, col3 = st.columns(3)
            col1.metric("Total Developers", total)
            col2.metric("Flagged as Risky", int(risky), delta=None)
            col3.metric("Trusted", int(total - risky))

            st.write("---")

            # Anomaly score bar chart (when ML is active)
            if "Isolation Forest" in method:
                fig_if = px.bar(
                    profiles.sort_values("if_score", ascending=False),
                    x="Author", y="if_score",
                    color="is_risky",
                    color_discrete_map={True: "#ff4b4b", False: "#21c354"},
                    title="Isolation Forest Anomaly Scores per Developer",
                    labels={"if_score": "Anomaly Score (higher = riskier)", "is_risky": "Flagged"},
                    template="plotly_dark",
                )
                st.plotly_chart(fig_if, use_container_width=True)

            # Developer cards
            for _, row in profiles.iterrows():
                border_color = "#ff4b4b" if row["is_risky"] else "#21c354"
                trust_label = "🔴 HIGH RISK INSIDER" if row["is_risky"] else "🟢 TRUSTED"
                trust_color = "#ff4b4b" if row["is_risky"] else "#21c354"

                rule_badge = "⚡ Rule" if row["rule_flag"] else ""
                ml_badge = "🤖 ML" if row["if_anomaly"] else ""
                badges = " ".join(filter(None, [rule_badge, ml_badge])) or "—"

                hour = row['avg_commit_hour']
                hour_label = f"{hour:.0f}:00"
                hour_flag = "⚠️" if hour < 6 or hour > 22 else ""
                weekend_pct = row['weekend_ratio'] * 100
                weekend_flag = "⚠️" if weekend_pct > 40 else ""

                st.markdown(f"""
                <div style="background-color:#161b22; padding:20px; border-radius:12px;
                            border-left:6px solid {border_color}; margin-bottom:15px;">
                    <h3 style="margin:0 0 8px 0;">👤 {row['Author']}</h3>
                    <p style="margin:4px 0;">Trust Level: <span style="color:{trust_color}; font-weight:bold;">{trust_label}</span>
                       &nbsp;|&nbsp; Detection triggers: <b>{badges}</b></p>
                    <p style="margin:4px 0;"><b>Projects:</b> {', '.join(row['projects'])}</p>
                    <p style="margin:4px 0;"><b>Commits analysed:</b> {row['total_scans']}
                       &nbsp;|&nbsp; <b>Avg risk:</b> {row['avg_risk']:.1f}%
                       &nbsp;|&nbsp; <b>Max risk:</b> {row['max_risk']}%
                       &nbsp;|&nbsp; <b>Std dev:</b> {row['std_risk']:.1f}
                       &nbsp;|&nbsp; <b>Anomaly score:</b> {row['if_score']:.3f}</p>
                    <p style="margin:4px 0;"><b>Avg commit hour:</b> {hour_label} {hour_flag}
                       &nbsp;|&nbsp; <b>Weekend commits:</b> {weekend_pct:.0f}% {weekend_flag}</p>
                </div>
                """, unsafe_allow_html=True)

# ---------------------------------------------------------------------------
# PAGE 4: Evaluation Metrics
# ---------------------------------------------------------------------------
elif menu == t["menu_eval"]:
    import plotly.graph_objects as go

    st.title("Detection Evaluation — Precision / Recall / F1")
    st.markdown(
        "Quantitative evaluation of the AI detection system against a labelled "
        "ground-truth dataset. Ground truth is derived automatically from the "
        "**test_attacks_repo** threat simulation repository."
    )

    if df.empty:
        st.info("No scan data available. Run some scans first.")
    else:
        repos = sorted(df["Repo"].unique().tolist())
        selected_eval_repo = st.selectbox("Select repository to evaluate:", repos)

        repo_df = df[df["Repo"] == selected_eval_repo].copy()

        with st.spinner("Loading ground truth from repository..."):
            ground_truth = get_ground_truth(selected_eval_repo)

        if ground_truth is None:
            st.warning(
                f"Ground truth could not be derived for **{selected_eval_repo}**. "
                "Only the built-in **test_attacks_repo** is supported automatically. "
                "Ensure the repository folder exists under `data/`."
            )
        else:
            from engine.config import RISK_CRITICAL_MIN

            threshold = st.slider(
                "Classification threshold (risk score ≥ threshold → predicted malicious)",
                min_value=0, max_value=100, value=RISK_CRITICAL_MIN, step=5,
            )

            metrics = compute_metrics(repo_df, ground_truth, threshold=threshold)

            if metrics is None:
                st.warning(
                    "None of the scanned commits matched the ground truth hashes. "
                    "Re-scan the repository after regenerating it with "
                    "`python scripts/generate_attacks_repo.py`."
                )
            else:
                tab_cg, tab_baseline = st.tabs([
                    "🤖 CyberGuard AI Metrics",
                    "🔍 Baseline Comparison (SAST-style)",
                ])

                # ════════════════════════════════════════════════════
                # TAB 1 — CyberGuard AI metrics
                # ════════════════════════════════════════════════════
                with tab_cg:
                    st.write("---")
                    k1, k2, k3, k4 = st.columns(4)
                    with k1:
                        st.markdown(
                            f"<div class='kpi-card'><div class='kpi-title'>Precision</div>"
                            f"<div class='kpi-value'>{metrics['precision']:.3f}</div></div>",
                            unsafe_allow_html=True,
                        )
                    with k2:
                        st.markdown(
                            f"<div class='kpi-card'><div class='kpi-title'>Recall</div>"
                            f"<div class='kpi-value'>{metrics['recall']:.3f}</div></div>",
                            unsafe_allow_html=True,
                        )
                    with k3:
                        st.markdown(
                            f"<div class='kpi-card'><div class='kpi-title'>F1-Score</div>"
                            f"<div class='kpi-value'>{metrics['f1']:.3f}</div></div>",
                            unsafe_allow_html=True,
                        )
                    with k4:
                        st.markdown(
                            f"<div class='kpi-card'><div class='kpi-title'>Accuracy</div>"
                            f"<div class='kpi-value'>{metrics['accuracy']:.3f}</div></div>",
                            unsafe_allow_html=True,
                        )

                    st.write("")
                    col_cm, col_counts = st.columns([1, 1])

                    with col_cm:
                        cm = metrics["confusion_matrix"]
                        z = [[cm[1][1], cm[1][0]],
                             [cm[0][1], cm[0][0]]]
                        text = [
                            [f"TP = {cm[1][1]}", f"FN = {cm[1][0]}"],
                            [f"FP = {cm[0][1]}", f"TN = {cm[0][0]}"],
                        ]
                        fig_cm = go.Figure(data=go.Heatmap(
                            z=z,
                            x=["Predicted Malicious", "Predicted Safe"],
                            y=["Actual Malicious", "Actual Safe"],
                            text=text,
                            texttemplate="%{text}",
                            textfont={"size": 16},
                            colorscale="RdYlGn_r",
                            showscale=False,
                        ))
                        fig_cm.update_layout(
                            title="Confusion Matrix — CyberGuard AI",
                            template="plotly_dark",
                            height=340,
                        )
                        st.plotly_chart(fig_cm, use_container_width=True)

                    with col_counts:
                        st.subheader("Classification Summary")
                        st.markdown(f"""
| Metric | Value |
|---|---|
| True Positives (TP) | **{metrics['tp']}** — malicious correctly flagged |
| False Positives (FP) | **{metrics['fp']}** — safe commits incorrectly flagged |
| True Negatives (TN) | **{metrics['tn']}** — safe commits correctly cleared |
| False Negatives (FN) | **{metrics['fn']}** — malicious commits missed |
| Total evaluated | **{metrics['total']}** ({metrics['malicious_total']} malicious, {metrics['safe_total']} safe) |
| Threshold used | **{metrics['threshold']}**/100 |
                        """)

                    st.write("---")
                    st.subheader("Per-Commit Classification Detail")
                    detail_df = metrics["matched_df"][
                        ["Hash", "Author", "Score", "true_label", "predicted"]
                    ].copy()
                    detail_df["Ground Truth"] = detail_df["true_label"].map(
                        {1: "🔴 Malicious", 0: "🟢 Safe"}
                    )
                    detail_df["Predicted"] = detail_df["predicted"].map(
                        {1: "🔴 Malicious", 0: "🟢 Safe"}
                    )
                    detail_df["Correct"] = (
                        detail_df["true_label"] == detail_df["predicted"]
                    ).map({True: "✅", False: "❌"})
                    detail_df = detail_df.drop(columns=["true_label", "predicted"])
                    detail_df = detail_df.rename(columns={"Score": "Risk Score"})
                    st.dataframe(
                        detail_df.sort_values("Risk Score", ascending=False),
                        use_container_width=True,
                        hide_index=True,
                    )
                    st.caption(
                        f"Evaluation performed within the scope of the prepared test scenarios. "
                        f"Classification threshold: risk score ≥ {threshold}."
                    )

                # ════════════════════════════════════════════════════
                # TAB 2 — Baseline SAST comparison
                # ════════════════════════════════════════════════════
                with tab_baseline:
                    st.markdown(
                        "Rule-based static analysis applied to the stored git diffs — "
                        "equivalent to running **Semgrep / Bandit** on the added lines of "
                        "each commit. Patterns cover hardcoded IPs, exec(base64.decode()), "
                        "subprocess execution, credential file reads, SUID bits, and more. "
                        "Results are compared with CyberGuard's LLM-based detection."
                    )
                    st.write("---")

                    # Build per-commit comparison rows
                    matched_df = metrics["matched_df"].copy()
                    rows = []
                    for _, row in matched_df.iterrows():
                        findings = analyze_diff(row.get("Diff", ""))
                        sast_flag = len(findings) > 0
                        sast_high = sum(1 for f in findings if f.severity == "HIGH")
                        cg_flag = bool(row["predicted"])
                        true_flag = bool(row["true_label"])

                        if true_flag and cg_flag and sast_flag:
                            detection = "Both"
                        elif true_flag and cg_flag and not sast_flag:
                            detection = "CyberGuard only"
                        elif true_flag and not cg_flag and sast_flag:
                            detection = "SAST only"
                        elif not true_flag and not cg_flag and not sast_flag:
                            detection = "Neither (safe)"
                        elif not true_flag and (cg_flag or sast_flag):
                            detection = "False positive"
                        else:
                            detection = "Missed (FN)"

                        rows.append({
                            "Hash":             row["Hash"],
                            "Author":           row["Author"],
                            "Risk Score":       row["Score"],
                            "SAST HIGH rules":  sast_high,
                            "Ground Truth":     "🔴 Malicious" if true_flag else "🟢 Safe",
                            "Detection":        detection,
                            "SAST Rules Hit":   ", ".join(f.rule_id for f in findings) or "—",
                        })

                    cmp_df = pd.DataFrame(rows)

                    # ── Summary KPIs ─────────────────────────────────
                    both        = (cmp_df["Detection"] == "Both").sum()
                    cg_only     = (cmp_df["Detection"] == "CyberGuard only").sum()
                    sast_only   = (cmp_df["Detection"] == "SAST only").sum()
                    missed      = (cmp_df["Detection"] == "Missed (FN)").sum()
                    false_pos   = (cmp_df["Detection"] == "False positive").sum()

                    b1, b2, b3, b4, b5 = st.columns(5)
                    for col, label, val, color in [
                        (b1, "Both detected",        both,      "#21c354"),
                        (b2, "CyberGuard only",       cg_only,   "#4b9fea"),
                        (b3, "SAST only",             sast_only, "#faca2b"),
                        (b4, "Missed by both",        missed,    "#ff4b4b"),
                        (b5, "False positives",       false_pos, "#a0a0a0"),
                    ]:
                        col.markdown(
                            f"<div class='kpi-card'>"
                            f"<div class='kpi-title'>{label}</div>"
                            f"<div class='kpi-value' style='color:{color}'>{val}</div>"
                            f"</div>",
                            unsafe_allow_html=True,
                        )

                    st.write("")

                    # ── Side-by-side confusion matrices ──────────────
                    col_l, col_r = st.columns(2)

                    # CyberGuard confusion matrix (already computed)
                    with col_l:
                        cm_cg = metrics["confusion_matrix"]
                        z_cg = [[cm_cg[1][1], cm_cg[1][0]],
                                [cm_cg[0][1], cm_cg[0][0]]]
                        text_cg = [
                            [f"TP={cm_cg[1][1]}", f"FN={cm_cg[1][0]}"],
                            [f"FP={cm_cg[0][1]}", f"TN={cm_cg[0][0]}"],
                        ]
                        fig_cg2 = go.Figure(data=go.Heatmap(
                            z=z_cg, x=["Pred Malicious", "Pred Safe"],
                            y=["Actual Malicious", "Actual Safe"],
                            text=text_cg, texttemplate="%{text}",
                            textfont={"size": 14}, colorscale="Blues",
                            showscale=False,
                        ))
                        fig_cg2.update_layout(
                            title="CyberGuard AI", template="plotly_dark", height=300,
                        )
                        st.plotly_chart(fig_cg2, use_container_width=True)

                    # SAST confusion matrix (build from cmp_df)
                    with col_r:
                        from engine.eval_engine import compute_metrics as _cm
                        sast_gt = {
                            row["Hash"]: (row["Ground Truth"] == "🔴 Malicious")
                            for _, row in cmp_df.iterrows()
                        }
                        sast_scores_df = matched_df.copy()
                        sast_scores_df["Score"] = [
                            score_diff(r.get("Diff", "")) * 20
                            for _, r in sast_scores_df.iterrows()
                        ]
                        sast_metrics = _cm(sast_scores_df, sast_gt, threshold=1)
                        if sast_metrics:
                            cm_s = sast_metrics["confusion_matrix"]
                            z_s = [[cm_s[1][1], cm_s[1][0]],
                                   [cm_s[0][1], cm_s[0][0]]]
                            text_s = [
                                [f"TP={cm_s[1][1]}", f"FN={cm_s[1][0]}"],
                                [f"FP={cm_s[0][1]}", f"TN={cm_s[0][0]}"],
                            ]
                            fig_sast = go.Figure(data=go.Heatmap(
                                z=z_s, x=["Pred Malicious", "Pred Safe"],
                                y=["Actual Malicious", "Actual Safe"],
                                text=text_s, texttemplate="%{text}",
                                textfont={"size": 14}, colorscale="Oranges",
                                showscale=False,
                            ))
                            fig_sast.update_layout(
                                title="SAST Baseline (rule-based)",
                                template="plotly_dark", height=300,
                            )
                            st.plotly_chart(fig_sast, use_container_width=True)

                            # Metric comparison table
                            st.subheader("Metric Comparison")
                            st.markdown(f"""
| Metric | CyberGuard AI (LLM) | SAST Baseline (rules) |
|---|---|---|
| Precision | **{metrics['precision']:.3f}** | {sast_metrics['precision']:.3f} |
| Recall | **{metrics['recall']:.3f}** | {sast_metrics['recall']:.3f} |
| F1-Score | **{metrics['f1']:.3f}** | {sast_metrics['f1']:.3f} |
| Accuracy | **{metrics['accuracy']:.3f}** | {sast_metrics['accuracy']:.3f} |
| False Positives | {metrics['fp']} | {sast_metrics['fp']} |
| False Negatives | {metrics['fn']} | {sast_metrics['fn']} |
                            """)

                    # ── Per-commit comparison table ───────────────────
                    st.write("---")
                    st.subheader("Per-Commit Detection Breakdown")

                    color_map = {
                        "Both":             "#21c354",
                        "CyberGuard only":  "#4b9fea",
                        "SAST only":        "#faca2b",
                        "Neither (safe)":   "#8b949e",
                        "False positive":   "#a0a0a0",
                        "Missed (FN)":      "#ff4b4b",
                    }
                    st.dataframe(
                        cmp_df.sort_values("Risk Score", ascending=False),
                        use_container_width=True,
                        hide_index=True,
                    )
                    st.caption(
                        "SAST rules are applied to the added lines (+) of each stored diff. "
                        "A commit is flagged by SAST when at least one HIGH-severity rule triggers. "
                        "'CyberGuard only' rows highlight cases where semantic LLM analysis "
                        "detects threats that pattern-matching alone cannot identify."
                    )

# ---------------------------------------------------------------------------
# PAGE 5: System Logs
# ---------------------------------------------------------------------------
elif menu == t["menu_logs"]:
    st.title("Raw Database Logs")
    if df.empty:
        st.info("Database is empty.")
    else:
        st.download_button(
            "📥 Export DB to CSV",
            df.to_csv(index=False),
            "cyberguard_db.csv",
            "text/csv",
        )
        st.dataframe(df.sort_values("Date", ascending=False), use_container_width=True, hide_index=True)

        st.write("---")
        st.subheader("🗑️ Delete Scan Record")
        del_id = st.number_input("Scan ID to delete", min_value=1, step=1)
        if st.button("Delete", type="primary"):
            if del_id in df["ID"].values:
                delete_scan(int(del_id))
                st.success(f"Scan #{del_id} deleted.")
                st.rerun()
            else:
                st.error(f"No scan found with ID {del_id}.")
