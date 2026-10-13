import hashlib
import sqlite3
from pathlib import Path
from datetime import datetime

import pandas as pd
import plotly.express as px
import streamlit as st
import streamlit_authenticator as stauth

from detector import analyze_events
from validator import validate_csv


# -------------------- PAGE CONFIG --------------------
st.set_page_config(
    page_title="Cyber Sentinels",
    page_icon="🛡️",
    layout="wide",
)

DB_PATH = Path(__file__).resolve().parent / "cyber_sentinels.db"


# -------------------- SQLITE HISTORY --------------------
def get_connection():
    conn = sqlite3.connect(DB_PATH, timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_database():
    with get_connection() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS analysis_runs (
                run_id INTEGER PRIMARY KEY AUTOINCREMENT,
                analyzed_at TEXT NOT NULL,
                file_hash TEXT NOT NULL UNIQUE,
                filename TEXT NOT NULL,
                event_count INTEGER NOT NULL,
                incident_count INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS analysis_accounts (
                run_id INTEGER NOT NULL,
                account TEXT NOT NULL,
                PRIMARY KEY (run_id, account),
                FOREIGN KEY (run_id) REFERENCES analysis_runs(run_id)
                    ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS incidents (
                incident_id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id INTEGER NOT NULL,
                account TEXT NOT NULL,
                computer TEXT NOT NULL,
                rule TEXT NOT NULL,
                severity TEXT NOT NULL,
                start_time TEXT,
                end_time TEXT,
                event_ids TEXT,
                evidence TEXT,
                recommendation TEXT,
                FOREIGN KEY (run_id) REFERENCES analysis_runs(run_id)
                    ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_incidents_account
                ON incidents(account);
            CREATE INDEX IF NOT EXISTS idx_accounts_account
                ON analysis_accounts(account);
            """
        )


def find_existing_run(file_hash):
    with get_connection() as conn:
        return conn.execute(
            "SELECT run_id FROM analysis_runs WHERE file_hash = ?",
            (file_hash,),
        ).fetchone()


def get_historical_warnings(current_accounts):
    """Find accounts in this upload that were flagged in earlier uploads."""
    if not current_accounts:
        return pd.DataFrame()

    unique_accounts = sorted({str(a).strip() for a in current_accounts if str(a).strip()})
    if not unique_accounts:
        return pd.DataFrame()

    placeholders = ",".join("?" for _ in unique_accounts)
    query = f"""
        SELECT
            i.account AS account,
            COUNT(DISTINCT i.run_id) AS previous_flagged_runs,
            COUNT(i.incident_id) AS previous_incidents,
            MAX(r.analyzed_at) AS last_flagged_at,
            GROUP_CONCAT(DISTINCT i.rule) AS previous_rules
        FROM incidents i
        JOIN analysis_runs r ON r.run_id = i.run_id
        WHERE i.account IN ({placeholders})
        GROUP BY i.account
        ORDER BY COUNT(DISTINCT i.run_id) DESC, COUNT(i.incident_id) DESC
    """
    with get_connection() as conn:
        rows = conn.execute(query, unique_accounts).fetchall()
    return pd.DataFrame([dict(row) for row in rows])


def save_analysis(file_hash, filename, event_count, incidents, accounts):
    """Persist only analysis metadata, account identifiers, and incidents—not raw CSVs."""
    analyzed_at = datetime.now().astimezone().isoformat(timespec="seconds")
    with get_connection() as conn:
        existing = conn.execute(
            "SELECT run_id FROM analysis_runs WHERE file_hash = ?",
            (file_hash,),
        ).fetchone()
        if existing:
            return int(existing["run_id"]), False

        cursor = conn.execute(
            """
            INSERT INTO analysis_runs
                (analyzed_at, file_hash, filename, event_count, incident_count)
            VALUES (?, ?, ?, ?, ?)
            """,
            (analyzed_at, file_hash, Path(filename).name, int(event_count), len(incidents)),
        )
        run_id = int(cursor.lastrowid)

        unique_accounts = sorted({
            str(account).strip()
            for account in accounts
            if pd.notna(account) and str(account).strip()
        })
        conn.executemany(
            "INSERT OR IGNORE INTO analysis_accounts (run_id, account) VALUES (?, ?)",
            [(run_id, account) for account in unique_accounts],
        )

        if not incidents.empty:
            records = []
            for _, row in incidents.iterrows():
                records.append((
                    run_id,
                    str(row.get("account", "")),
                    str(row.get("computer", "")),
                    str(row.get("rule", "")),
                    str(row.get("severity", "")),
                    str(row.get("start_time", "")),
                    str(row.get("end_time", "")),
                    str(row.get("event_ids", "")),
                    str(row.get("evidence", "")),
                    str(row.get("recommendation", "")),
                ))
            conn.executemany(
                """
                INSERT INTO incidents
                    (run_id, account, computer, rule, severity, start_time,
                     end_time, event_ids, evidence, recommendation)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                records,
            )
    return run_id, True


def get_recent_runs(limit=50):
    with get_connection() as conn:
        rows = conn.execute(
            """
            SELECT run_id, analyzed_at, filename, event_count, incident_count
            FROM analysis_runs
            ORDER BY run_id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    return pd.DataFrame([dict(row) for row in rows])


def get_repeat_accounts(min_runs=2):
    with get_connection() as conn:
        rows = conn.execute(
            """
            SELECT
                i.account AS account,
                COUNT(DISTINCT i.run_id) AS flagged_runs,
                COUNT(i.incident_id) AS total_incidents,
                MAX(r.analyzed_at) AS last_flagged_at,
                GROUP_CONCAT(DISTINCT i.rule) AS rules
            FROM incidents i
            JOIN analysis_runs r ON r.run_id = i.run_id
            GROUP BY i.account
            HAVING COUNT(DISTINCT i.run_id) >= ?
            ORDER BY COUNT(DISTINCT i.run_id) DESC, COUNT(i.incident_id) DESC
            """,
            (min_runs,),
        ).fetchall()
    return pd.DataFrame([dict(row) for row in rows])


def get_run_incidents(run_id):
    with get_connection() as conn:
        rows = conn.execute(
            """
            SELECT account, computer, rule, severity, start_time, end_time,
                   event_ids, evidence, recommendation
            FROM incidents
            WHERE run_id = ?
            ORDER BY
                CASE severity
                    WHEN 'Critical Review' THEN 1
                    WHEN 'High' THEN 2
                    WHEN 'Medium' THEN 3
                    ELSE 4
                END,
                account
            """,
            (int(run_id),),
        ).fetchall()
    return pd.DataFrame([dict(row) for row in rows])


def clear_database_history():
    with get_connection() as conn:
        conn.execute("DELETE FROM incidents")
        conn.execute("DELETE FROM analysis_accounts")
        conn.execute("DELETE FROM analysis_runs")


init_database()


# -------------------- ADMIN AUTHENTICATION --------------------
def show_login():
    try:
        username = st.secrets["auth"]["username"]
        password_hash = st.secrets["auth"]["password_hash"]
        cookie_key = st.secrets["auth"]["cookie_key"]
    except Exception:
        st.error(
            "Authentication secrets are missing. Configure "
            "`.streamlit/secrets.toml` with the [auth] username, "
            "password_hash, and cookie_key values."
        )
        st.stop()

    credentials = {
        "usernames": {
            username: {
                "name": "Administrator",
                "password": password_hash,
            }
        }
    }

    authenticator = stauth.Authenticate(
        credentials=credentials,
        cookie_name="cyber_sentinels_auth",
        cookie_key=cookie_key,
        cookie_expiry_days=7,
        auto_hash=False,
    )
    authenticator.login(
        location="main",
        max_login_attempts=5,
        fields={
            "Form name": "Cyber Sentinels Admin Login",
            "Username": "Username",
            "Password": "Password",
            "Login": "Log in",
        },
    )
    auth_status = st.session_state.get("authentication_status")
    if auth_status is not True:
        if auth_status is False:
            st.error("Invalid username or password.")
        st.stop()
    return authenticator


authenticator = show_login()


# -------------------- THEME --------------------
st.markdown(
    """
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700&family=Inter:wght@400;500;600&family=JetBrains+Mono:wght@400;500;600&display=swap');
    :root {
      --bg:#00161A; --sidebar:#001114; --card:#002429; --elevated:#062F35;
      --border:#3C494C; --cyan:#22D3EE; --cyan-soft:#8AEBFF;
      --mint:#5FF7AF; --pink:#FFB1C7; --text:#C4E9F0; --muted:#BBC9CD;
    }
    .stApp,[data-testid="stAppViewContainer"] {
      background:var(--bg); color:var(--text); font-family:'Inter',sans-serif;
    }
    [data-testid="stSidebar"] {background:var(--sidebar);border-right:1px solid var(--border);}
    h1,h2,h3 {font-family:'Plus Jakarta Sans',sans-serif!important;color:var(--cyan-soft)!important;}
    [data-testid="stMetric"] {background:var(--card);border:1px solid var(--border);border-radius:12px;padding:18px;}
    [data-testid="stMetricLabel"] {color:var(--muted);}
    [data-testid="stMetricValue"] {color:var(--cyan-soft);}
    .stButton>button,.stDownloadButton>button {background:var(--cyan);color:#00363E;border:0;border-radius:8px;font-weight:600;}
    .stButton>button:hover,.stDownloadButton>button:hover {background:var(--cyan-soft);color:var(--bg);}
    [data-testid="stFileUploader"] {background:var(--card);border:1px dashed var(--cyan);border-radius:12px;padding:12px;}
    div[data-testid="stVerticalBlockBorderWrapper"] {border-color:var(--border);}
    hr {border-color:var(--border);}
    code,.technical {font-family:'JetBrains Mono',monospace;}
    </style>
    """,
    unsafe_allow_html=True,
)


# -------------------- SETTINGS --------------------
defaults = {
    "failed_threshold": 3,
    "consecutive_threshold": 5,
    "window_minutes": 10,
    "opening_hour": 8,
    "closing_hour": 18,
}
for key, value in defaults.items():
    if key not in st.session_state:
        st.session_state[key] = value


# -------------------- UI HELPERS --------------------
def clear_current_analysis():
    for key in [
        "incidents", "event_count", "analysis_hash", "repeat_warnings",
        "current_run_id", "current_filename", "duplicate_upload",
    ]:
        st.session_state.pop(key, None)


def show_metrics(incidents, event_count):
    count = len(incidents)
    affected = incidents["account"].nunique() if count else 0
    high = int((incidents["severity"] == "High").sum()) if count else 0
    critical = int((incidents["severity"] == "Critical Review").sum()) if count else 0
    repeat_count = len(st.session_state.get("repeat_warnings", pd.DataFrame()))
    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Events Analyzed", event_count)
    c2.metric("Incidents Detected", count)
    c3.metric("Affected Accounts", affected)
    c4.metric("High-Severity Alerts", high)
    c5.metric("Historical Warnings", repeat_count)


def show_historical_warnings(warnings_df, heading="Historical Warnings"):
    st.markdown(f"### ⚠️ {heading}")
    if warnings_df is None or warnings_df.empty:
        st.success("No previously flagged accounts were found in this upload.")
        return

    st.caption(
        "These accounts appeared in the current upload and were flagged in "
        "earlier, distinct analyses. This is a review signal, not proof of misuse."
    )
    for _, row in warnings_df.iterrows():
        with st.container(border=True):
            st.markdown(f"**{row['account']}**")
            st.warning(
                f"Previously flagged in {int(row['previous_flagged_runs'])} "
                f"separate analysis run(s); "
                f"{int(row['previous_incidents'])} historical incident(s)."
            )
            st.caption(f"Previous rule(s): {row.get('previous_rules') or 'Not available'}")
            st.caption(f"Last flagged: {row.get('last_flagged_at') or 'Unknown'}")


def show_incidents(incidents):
    if incidents.empty:
        st.success("No incidents detected in this dataset.")
        return

    st.markdown("### Incident Details")
    display_df = incidents.copy()
    display_df["event_ids"] = display_df["event_ids"].astype(str)

    def severity_style(value):
        styles = {
            "Medium": "color:#FBBF24;background-color:#3B2F12;font-weight:bold",
            "High": "color:#FB923C;background-color:#3B2115;font-weight:bold",
            "Critical Review": "color:#F87171;background-color:#3B171D;font-weight:bold",
        }
        return styles.get(value, "")

    st.dataframe(
        display_df.style.applymap(severity_style, subset=["severity"]),
        use_container_width=True,
        hide_index=True,
        column_config={
            "severity": st.column_config.TextColumn("Severity"),
            "event_ids": st.column_config.TextColumn("Evidence Event IDs"),
            "evidence": st.column_config.TextColumn("Why it was flagged"),
            "recommendation": st.column_config.TextColumn("Recommended review"),
        },
    )

    st.markdown("### Incident Distribution")
    counts = (
        incidents["rule"].value_counts()
        .rename_axis("Detection Rule")
        .reset_index(name="Count")
    )
    fig = px.pie(
        counts,
        names="Detection Rule",
        values="Count",
        hole=0.65,
        color_discrete_sequence=["#22D3EE", "#5FF7AF", "#FFB1C7"],
    )
    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font_color="#C4E9F0",
        legend_title_text="",
        margin=dict(t=20, b=20, l=10, r=10),
    )
    fig.update_traces(
        textposition="inside",
        textinfo="percent",
        marker=dict(line=dict(color="#00161A", width=3)),
    )
    st.plotly_chart(fig, use_container_width=True)
    st.download_button(
        "Export Incidents as CSV",
        data=incidents.to_csv(index=False),
        file_name="cyber_sentinels_incidents.csv",
        mime="text/csv",
    )


# -------------------- SIDEBAR --------------------
with st.sidebar:
    st.markdown("## 🛡️ Cyber Sentinels")
    st.caption("AUTHENTICATION MONITORING")
    st.divider()
    page = st.radio(
        "NAVIGATION",
        ["Dashboard", "Analyze Logs", "History", "Settings"],
        label_visibility="visible",
    )
    st.divider()
    authenticator.logout(
        button_name="Log out",
        location="sidebar",
        key="admin_logout",
    )
    st.divider()
    st.caption("Explainable security analysis")
    st.caption("Alerts are leads for human review.")
    sidebar_warnings = st.session_state.get("repeat_warnings", pd.DataFrame())
    if not sidebar_warnings.empty:
        st.warning(f"{len(sidebar_warnings)} historical account warning(s)")
        with st.expander("View repeat accounts"):
            for account in sidebar_warnings["account"].tolist():
                st.write(f"• {account}")


st.title("Cyber Sentinels")
st.caption("Explainable authentication monitoring for shared labs")


# -------------------- DASHBOARD --------------------
if page == "Dashboard":
    st.markdown("## Security Overview")
    st.caption("Current analysis results and repeat-account warnings.")

    if "incidents" not in st.session_state:
        st.info("No current analysis results yet. Open Analyze Logs to upload a CSV.")
    else:
        show_metrics(st.session_state["incidents"], st.session_state["event_count"])
        st.divider()
        show_historical_warnings(
            st.session_state.get("repeat_warnings", pd.DataFrame())
        )
        st.divider()
        show_incidents(st.session_state["incidents"])
        if st.button("Clear current results"):
            clear_current_analysis()
            st.rerun()

    st.markdown("## Recurring Historical Accounts")
    repeat_accounts = get_repeat_accounts(min_runs=2)
    if repeat_accounts.empty:
        st.info("No account has been flagged across two or more distinct analysis runs yet.")
    else:
        st.caption("Accounts flagged in at least two distinct analysis runs.")
        st.dataframe(repeat_accounts, use_container_width=True, hide_index=True)


# -------------------- ANALYZE LOGS --------------------
elif page == "Analyze Logs":
    st.markdown("## Analyze Authentication Logs")
    st.write(
        "Upload a CSV to validate the records, detect suspicious patterns, "
        "and compare current accounts with historical findings."
    )
    uploaded_file = st.file_uploader(
        "Upload authentication logs",
        type=["csv"],
        help="Required columns: event_id, timestamp, account, computer, event",
    )

    if uploaded_file is not None:
        file_bytes = uploaded_file.getvalue()
        current_hash = hashlib.sha256(file_bytes).hexdigest()

        if st.session_state.get("analysis_hash") != current_hash:
            clear_current_analysis()

        try:
            df = pd.read_csv(uploaded_file)
            errors, warnings = validate_csv(df)
            for warning in warnings:
                st.warning(warning)

            if errors:
                for error in errors:
                    st.error(error)
            else:
                st.success(f"CSV validated: {len(df)} events found.")
                with st.expander("Preview uploaded events"):
                    st.dataframe(df.head(100), use_container_width=True, hide_index=True)

                with st.expander("Active detection settings"):
                    st.write(f"Failed-login threshold: **{st.session_state.failed_threshold}**")
                    st.write(f"Consecutive-failure threshold: **{st.session_state.consecutive_threshold}**")
                    st.write(f"Detection window: **{st.session_state.window_minutes} minutes**")
                    st.write(
                        f"Lab hours: **{st.session_state.opening_hour:02d}:00–"
                        f"{st.session_state.closing_hour:02d}:00**"
                    )

                if st.button("Run Security Analysis", type="primary"):
                    try:
                        incidents = analyze_events(
                            df,
                            failed_threshold=st.session_state.failed_threshold,
                            consecutive_threshold=st.session_state.consecutive_threshold,
                            window_minutes=st.session_state.window_minutes,
                            opening_hour=st.session_state.opening_hour,
                            closing_hour=st.session_state.closing_hour,
                        )

                        account_col = df["account"].dropna().astype(str).str.strip()
                        # Look up prior warnings BEFORE saving the current run.
                        repeat_warnings = get_historical_warnings(account_col.tolist())

                        existing = find_existing_run(current_hash)
                        if existing:
                            st.session_state["duplicate_upload"] = True
                            run_id = int(existing["run_id"])
                        else:
                            run_id, _ = save_analysis(
                                current_hash,
                                uploaded_file.name,
                                len(df),
                                incidents,
                                account_col.tolist(),
                            )
                            st.session_state["duplicate_upload"] = False

                        st.session_state["incidents"] = incidents
                        st.session_state["event_count"] = len(df)
                        st.session_state["analysis_hash"] = current_hash
                        st.session_state["repeat_warnings"] = repeat_warnings
                        st.session_state["current_run_id"] = run_id
                        st.session_state["current_filename"] = uploaded_file.name
                        st.rerun()
                    except Exception as exc:
                        st.error(f"Analysis failed: {exc}")

                if st.session_state.get("analysis_hash") == current_hash and "incidents" in st.session_state:
                    if st.session_state.get("duplicate_upload"):
                        st.info(
                            "This exact CSV was analyzed before. Its existing history "
                            "was reused, so uploading it again does not inflate repeat counts."
                        )
                    else:
                        st.success("Analysis completed and saved to SQLite history.")

                    show_metrics(st.session_state["incidents"], st.session_state["event_count"])
                    st.divider()
                    show_historical_warnings(
                        st.session_state.get("repeat_warnings", pd.DataFrame())
                    )
                    st.divider()
                    show_incidents(st.session_state["incidents"])
        except Exception as exc:
            st.error(f"Could not read the uploaded CSV: {exc}")


# -------------------- HISTORY --------------------
elif page == "History":
    st.markdown("## Analysis History")
    st.caption("SQLite stores analysis metadata, account identifiers, and detected incidents—not raw CSV files.")

    runs = get_recent_runs()
    if runs.empty:
        st.info("No analyses have been saved yet.")
    else:
        st.dataframe(runs, use_container_width=True, hide_index=True)
        run_options = {
            f"Run {int(row.run_id)} · {row.filename} · {row.analyzed_at}": int(row.run_id)
            for row in runs.itertuples(index=False)
        }
        selected_label = st.selectbox("Inspect a saved analysis", list(run_options.keys()))
        selected_run = run_options[selected_label]
        saved_incidents = get_run_incidents(selected_run)
        st.markdown("### Saved Incidents")
        if saved_incidents.empty:
            st.success("No incidents were recorded for this run.")
        else:
            st.dataframe(saved_incidents, use_container_width=True, hide_index=True)
            st.download_button(
                "Download saved incidents",
                data=saved_incidents.to_csv(index=False),
                file_name=f"cyber_sentinels_run_{selected_run}_incidents.csv",
                mime="text/csv",
            )

    st.markdown("### Repeat Accounts")
    repeat_accounts = get_repeat_accounts(min_runs=2)
    if repeat_accounts.empty:
        st.info("No account has been flagged in multiple distinct runs yet.")
    else:
        st.dataframe(repeat_accounts, use_container_width=True, hide_index=True)


# -------------------- SETTINGS --------------------
elif page == "Settings":
    st.markdown("## Detection Settings")
    st.write("Changes apply to the next analysis.")

    with st.form("detection_settings"):
        st.markdown("### Repeated Login Failures")
        threshold = st.number_input(
            "Minimum failed attempts before success",
            min_value=1,
            max_value=20,
            value=int(st.session_state.failed_threshold),
        )
        window = st.number_input(
            "Detection window (minutes)",
            min_value=1,
            max_value=120,
            value=int(st.session_state.window_minutes),
        )

        st.divider()
        st.markdown("### Lab Operating Hours")
        opening = st.number_input(
            "Opening hour (24-hour format)",
            min_value=0,
            max_value=23,
            value=int(st.session_state.opening_hour),
        )
        closing = st.number_input(
            "Closing hour (24-hour format)",
            min_value=1,
            max_value=24,
            value=int(st.session_state.closing_hour),
            help="24 means midnight at the end of the day.",
        )

        st.divider()
        st.markdown("### Consecutive Failures")
        consecutive_threshold = st.number_input(
            "Consecutive failures before alert",
            min_value=5,
            max_value=20,
            value=int(st.session_state.consecutive_threshold),
        )

        submitted = st.form_submit_button("Save Settings")
        if submitted:
            if opening >= closing:
                st.error("Opening hour must be earlier than closing hour.")
            else:
                st.session_state.failed_threshold = int(threshold)
                st.session_state.window_minutes = int(window)
                st.session_state.opening_hour = int(opening)
                st.session_state.closing_hour = int(closing)
                st.session_state.consecutive_threshold = int(consecutive_threshold)
                clear_current_analysis()
                st.success("Settings saved. Run your analysis again.")

    st.divider()
    st.markdown("### Local History Management")
    st.caption(
        "Clearing history permanently deletes saved analysis metadata and incident history "
        "from the local SQLite database. Export anything you need first."
    )
    confirm_clear = st.checkbox("I understand that clearing history cannot be undone.")
    if st.button("Clear SQLite History", disabled=not confirm_clear):
        clear_database_history()
        clear_current_analysis()
        st.success("SQLite history cleared.")
        st.rerun()

    st.divider()
    st.caption(
        "These rules flag events for review; they do not prove malicious activity "
        "or block accounts. Repeated usernames may not always represent the same person."
    )
