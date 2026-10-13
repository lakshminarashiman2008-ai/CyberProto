import hashlib
import html
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


# -------------------- THEME --------------------
st.markdown(
    """
    <style>
    @import url('https://fonts.googleapis.com/css2?family=DM+Mono:wght@400;500&family=DM+Sans:wght@400;500;600;700&family=Space+Grotesk:wght@400;500;600;700&display=swap');
    :root {--bg:#001316;--sidebar:#001013;--panel:#002328;--panel2:#002b30;--border:#12434a;--cyan:#21d5e8;--ice:#bcecf3;--mint:#59f0b0;--pink:#ff8fb8;--red:#ff6b79;--amber:#ffd166;--text:#c1dce0;--muted:#78969b;}
    html,body,[class*="css"] {font-family:'DM Sans',sans-serif;}
    .stApp,[data-testid="stAppViewContainer"] {background:radial-gradient(ellipse at 60% -20%,#06383e 0%,var(--bg) 48%);color:var(--text);}
    [data-testid="stHeader"]{background:rgba(0,19,22,.92);border-bottom:1px solid var(--border);}
    [data-testid="stSidebar"]{background:var(--sidebar);border-right:1px solid #12363b;}
    [data-testid="stSidebar"] > div:first-child{padding-top:1rem;}
    [data-testid="stRadio"] > div{gap:5px;}
    [data-testid="stRadio"] label{padding:9px 11px;border-radius:9px;border:1px solid transparent;transition:all .15s ease;}
    [data-testid="stRadio"] label:hover{background:#052b30;border-color:#12434a;}
    [data-testid="stRadio"] label:has(input:checked){background:#07363c;border-color:#17616a;}
    [data-testid="stTabs"] button{color:#9fc4c9;}
    [data-testid="stExpander"]{border:1px solid var(--border)!important;border-radius:11px!important;background:#002126!important;}
    [data-testid="stAlert"]{border-radius:10px;}
    [data-testid="stFileUploaderDropzone"]{background:#002126!important;border:1px dashed #21717a!important;border-radius:12px!important;}
    h1,h2,h3{font-family:'Space Grotesk',sans-serif!important;color:var(--ice)!important;letter-spacing:-.025em;}
    h1{font-size:2rem!important;} h2{font-size:1.35rem!important;} h3{font-size:1.05rem!important;}
    p, label, [data-testid="stMarkdownContainer"]{color:var(--text);}
    [data-testid="stCaptionContainer"]{color:var(--muted);}
    [data-testid="stMetric"]{background:linear-gradient(145deg,#052b30,#002126);border:1px solid var(--border);border-radius:15px;padding:18px 18px 15px;box-shadow:0 8px 24px #00000014;}
    [data-testid="stMetricLabel"]{color:#91b5bb;font-family:'DM Mono',monospace;font-size:.68rem;text-transform:uppercase;letter-spacing:.09em;}
    [data-testid="stMetricValue"]{color:var(--ice);font-family:'Space Grotesk',sans-serif;font-weight:600;}
    [data-testid="stMetricDelta"]{font-family:'DM Mono',monospace;}
    .stButton>button,.stDownloadButton>button,[data-testid="stFormSubmitButton"] button{background:var(--cyan);color:#00252a;border:0;border-radius:9px;font-weight:700;transition:all .15s ease;}
    .stButton>button:hover,.stDownloadButton>button:hover,[data-testid="stFormSubmitButton"] button:hover{background:#a2f5ff;color:#001316;box-shadow:0 0 0 3px #21d5e822;}
    [data-testid="stFileUploader"]{background:#002328;border:1px dashed #21717a;border-radius:14px;padding:14px;}
    [data-testid="stFileUploader"] section{background:transparent;}
    [data-testid="stVerticalBlockBorderWrapper"]{background:rgba(0,35,40,.55);border-color:var(--border)!important;border-radius:14px;}
    [data-testid="stDataFrame"]{border:1px solid var(--border);border-radius:12px;overflow:hidden;}
    [data-baseweb="input"] input,[data-baseweb="select"]>div,textarea{background:#002126!important;border-color:var(--border)!important;color:var(--ice)!important;border-radius:8px!important;}
    [role="radiogroup"] label{background:#05262a;border:1px solid transparent;border-radius:8px;padding:8px 10px;margin:3px 0;}
    [role="radiogroup"] label:has(input:checked){border-color:var(--cyan);background:#07363c;}
    hr{border-color:var(--border)!important;}
    code,.mono{font-family:'DM Mono',monospace;}
    .brand-lockup{padding:8px 4px 18px;border-bottom:1px solid #14363b;margin-bottom:18px;}
    .brand-name{font:600 20px 'Space Grotesk',sans-serif;color:#c7f1f5;letter-spacing:-.04em;}
    .brand-sub{font:10px 'DM Mono',monospace;letter-spacing:.14em;color:#7fa2a8;margin-top:3px;}
    .eyebrow{font:10px 'DM Mono',monospace;letter-spacing:.12em;text-transform:uppercase;color:var(--cyan);margin-bottom:8px;}
    .hero-panel{height:100%;min-height:220px;background:linear-gradient(140deg,#07353a 0%,#002328 70%);border:1px solid #12434a;border-radius:16px;padding:23px 24px;}
    .hero-title{font:600 25px 'Space Grotesk',sans-serif;color:#c5edf2;letter-spacing:-.04em;margin:0 0 8px;}
    .hero-copy{font-size:13px;line-height:1.65;color:#a7c6ca;max-width:690px;}
    .hero-pill{display:inline-block;border:1px solid #14515a;background:#07353a;color:#8feefa;border-radius:99px;padding:5px 9px;font:10px 'DM Mono',monospace;letter-spacing:.07em;margin-bottom:12px;}
    .mini-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:8px;margin-top:18px;}
    .mini-card{background:#002126;border:1px solid #0d3c42;border-radius:10px;padding:12px;min-height:72px;}
    .mini-label{font:10px 'DM Mono',monospace;color:#89aeb4;text-transform:uppercase;letter-spacing:.06em;}
    .mini-value{font:500 13px 'DM Mono',monospace;color:#c6eef3;margin-top:7px;}
    .status-dot{display:inline-block;width:7px;height:7px;background:var(--mint);border-radius:50%;margin-right:7px;box-shadow:0 0 10px #59f0b077;}
    .activity-card{background:#002126;border:1px solid #0c3b41;border-radius:11px;padding:13px 14px;margin:8px 0;}
    .activity-top{display:flex;justify-content:space-between;gap:10px;align-items:center;margin-bottom:6px;}
    .activity-name{font:500 12px 'DM Mono',monospace;color:#b9edf2;}
    .activity-time{font:10px 'DM Mono',monospace;color:#6d9399;}
    .severity{font:10px 'DM Mono',monospace;padding:3px 7px;border-radius:99px;letter-spacing:.04em;}
    .sev-high{background:#4a1530;color:#ff9dc4;}.sev-medium{background:#453615;color:#ffd77d;}.sev-critical{background:#501a24;color:#ff929a;}.sev-low{background:#064d3a;color:#6df4bd;}
    .activity-copy{font-size:12px;line-height:1.55;color:#a6c3c8;}
    .login-shell{max-width:620px;margin:3vh auto 12px;padding:28px 30px 22px;background:linear-gradient(145deg,rgba(5,43,48,.94),rgba(0,28,32,.96));border:1px solid #14515a;border-radius:20px;box-shadow:0 24px 80px #00000035;position:relative;overflow:hidden;}
    .login-shell:after{content:"";position:absolute;width:220px;height:220px;right:-90px;top:-120px;border-radius:50%;border:1px solid #1b677033;box-shadow:0 0 0 22px #1b677014,0 0 0 46px #1b67700c;pointer-events:none;}
    .login-mark{display:flex;align-items:center;justify-content:center;width:48px;height:48px;border:1px solid #1b6770;border-radius:14px;background:#07363c;color:var(--cyan);font-size:28px;margin-bottom:20px;box-shadow:0 0 28px #21d5e817;}
    .login-title{font:600 clamp(30px,4vw,42px) 'Space Grotesk',sans-serif;color:#e0fbff;letter-spacing:-.055em;line-height:1.1;margin:0 0 10px;}
    .login-title span{color:var(--cyan);}
    .login-copy{max-width:440px;color:#9bbfc4;font-size:14px;line-height:1.7;}
    .login-status{margin-top:22px;padding-top:15px;border-top:1px solid #12434a;font:10px 'DM Mono',monospace;letter-spacing:.08em;color:#9dc2c7;}
    .login-divider{color:#426d73;padding:0 8px;}
    [data-testid="stForm"]{max-width:620px;margin:0 auto 5vh;padding:22px 30px 26px;background:rgba(0,27,31,.85);border:1px solid #12434a;border-radius:0 0 18px 18px;}
    [data-testid="stForm"] label{font-size:12px;color:#a9cdd2;}
    [data-testid="stForm"] [data-baseweb="input"] input{padding:12px 13px;}
    [data-testid="stForm"] button{width:100%;min-height:44px;margin-top:8px;}
    [data-testid="stSidebar"] [data-testid="stButton"]>button{width:100%;text-align:left;justify-content:flex-start;background:transparent;color:#8eafb4;border:1px solid transparent;border-radius:10px;padding:11px 13px;font-size:13px;font-weight:600;box-shadow:none;}
    [data-testid="stSidebar"] [data-testid="stButton"]>button:hover{background:#052b30;color:#d7f7fb;border-color:#12434a;}
    [data-testid="stSidebar"] [data-testid="stButton"]>button[kind="primary"]{background:linear-gradient(100deg,#073b42,#062a30);color:#8ef2fb;border-color:#17616a;box-shadow:inset 3px 0 0 var(--cyan);}
    .nav-section{font:10px 'DM Mono',monospace;letter-spacing:.15em;color:#5f858b;margin:12px 0 8px 4px;}
    .page-header{display:flex;align-items:center;gap:10px;margin-bottom:5px;}
    .section-copy{color:#8fb2b8;font-size:13px;line-height:1.6;}
    @media(max-width:900px){.mini-grid{grid-template-columns:1fr}.hero-title{font-size:21px}.login-shell{margin-top:1vh;padding:23px 20px}.login-title{font-size:31px}[data-testid="stForm"]{padding:18px 20px}}
    </style>
    """,
    unsafe_allow_html=True,
)


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
    st.markdown(
        """<div class="login-shell"><div class="login-mark">◈</div><div class="eyebrow">SECURITY OPERATIONS · AUTHENTICATION</div><div class="login-title">Cyber <span>Sentinels</span></div><div class="login-copy">Evidence-led authentication monitoring for shared lab environments.</div><div class="login-status"><span class="status-dot"></span>SECURE ANALYST ACCESS <span class="login-divider">/</span> LOCAL SESSION</div></div>""",
        unsafe_allow_html=True,
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
        "current_run_id", "current_filename", "duplicate_upload", "analysis_complete",
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
def choose_page(destination):
    st.session_state["active_page"] = destination

if "active_page" not in st.session_state:
    st.session_state["active_page"] = "Dashboard"

with st.sidebar:
    st.markdown("""<div class="brand-lockup"><div class="brand-name">◈ Cyber Sentinels</div><div class="brand-sub">SHARED LAB AUTH GUARD</div></div><div class="eyebrow"><span class="status-dot"></span>MONITORING READY</div>""", unsafe_allow_html=True)
    st.caption("Explainable authentication monitoring")
    st.markdown('<div class="nav-section">WORKSPACE</div>', unsafe_allow_html=True)
    nav_items = [("Dashboard", "◫"), ("History", "◷"), ("Settings", "⚙")]
    for destination, glyph in nav_items:
        is_active = st.session_state["active_page"] == destination
        if st.button(f"{glyph}    {destination}", key=f"nav_{destination.lower()}", type="primary" if is_active else "secondary", use_container_width=True):
            choose_page(destination)
            st.rerun()
    st.divider()
    authenticator.logout(
        button_name="↪  Log out",
        location="sidebar",
        key="admin_logout",
    )
    st.divider()
    st.caption("Alerts are leads for human review.")

page = st.session_state["active_page"]

header_left, header_right = st.columns([3, 1])
with header_left:
    st.markdown("### ◉ Authentication Telemetry & Incident Overview")
with header_right:
    st.markdown("<div style='text-align:right;padding-top:12px;font:10px DM Mono,monospace;color:#59f0b0'>● ENGINE READY <span style='color:#78969b'> · LOCAL ANALYSIS</span></div>", unsafe_allow_html=True)


# -------------------- DASHBOARD --------------------
if page == "Dashboard":
    incidents = st.session_state.get("incidents", pd.DataFrame(columns=["account", "computer", "rule", "severity", "start_time", "end_time", "event_ids", "evidence", "recommendation"]))
    event_count = int(st.session_state.get("event_count", 0))
    affected = int(incidents["account"].nunique()) if not incidents.empty else 0
    high = int((incidents["severity"] == "High").sum()) if not incidents.empty else 0
    critical = int((incidents["severity"] == "Critical Review").sum()) if not incidents.empty else 0
    medium = int((incidents["severity"] == "Medium").sum()) if not incidents.empty else 0
    repeat_warnings = st.session_state.get("repeat_warnings", pd.DataFrame())
    repeat_count = len(repeat_warnings) if isinstance(repeat_warnings, pd.DataFrame) else 0

    top_a, top_b = st.columns([1.45, 1])
    with top_a:
        st.markdown(f"""<div class="hero-panel"><div class="hero-pill">SCOPE MONITOR · LOCAL ENVIRONMENT</div><div class="hero-title">Shared Lab Authentication</div><div class="hero-copy">A clear view of authentication events, suspicious login patterns and recurring accounts across your uploaded datasets. Every alert includes evidence to support analyst review.</div><div class="mini-grid"><div class="mini-card"><div class="mini-label">◷ Analysis Window</div><div class="mini-value">{st.session_state.opening_hour:02d}:00 – {st.session_state.closing_hour:02d}:00</div><div style="font-size:11px;color:#78969b;margin-top:4px">Configured lab hours</div></div><div class="mini-card"><div class="mini-label">⌘ Detection Rules</div><div class="mini-value">3 Active Rules</div><div style="font-size:11px;color:#59f0b0;margin-top:4px">Rule-based · Explainable</div></div><div class="mini-card"><div class="mini-label">⛨ Response Mode</div><div class="mini-value">Human-in-the-Loop</div><div style="font-size:11px;color:#78969b;margin-top:4px">No automatic lockouts</div></div></div></div>""", unsafe_allow_html=True)
    with top_b:
        with st.container(border=True):
            st.markdown("<div class='eyebrow'>● LOG INGESTION ENGINE</div>", unsafe_allow_html=True)
            st.markdown("### Analyze New Auth Logs")
            st.markdown("<div class='hero-copy'>Drop a CSV here to validate records, run detection rules and compare accounts against saved SQLite history.</div>", unsafe_allow_html=True)
            uploaded_file = st.file_uploader(
                "Choose authentication CSV", type=["csv"], key="dashboard_csv_upload",
                help="Required columns: event_id, timestamp, account, computer, event",
                label_visibility="collapsed",
            )
            st.caption("Required fields: event_id · timestamp · account · computer · event")
            if uploaded_file is not None:
                file_bytes = uploaded_file.getvalue()
                current_hash = hashlib.sha256(file_bytes).hexdigest()
                try:
                    uploaded_df = pd.read_csv(pd.io.common.BytesIO(file_bytes))
                    errors, warnings = validate_csv(uploaded_df)
                    for warning in warnings:
                        st.warning(warning)
                    if errors:
                        for error in errors:
                            st.error(error)
                    else:
                        st.success(f"CSV validated · {len(uploaded_df):,} events ready")
                        with st.expander("Preview uploaded events"):
                            st.dataframe(uploaded_df.head(50), use_container_width=True, hide_index=True)
                        if st.button("Run Security Analysis", type="primary", use_container_width=True, key="dashboard_run_analysis"):
                            try:
                                detected = analyze_events(
                                    uploaded_df,
                                    failed_threshold=st.session_state.failed_threshold,
                                    consecutive_threshold=st.session_state.consecutive_threshold,
                                    window_minutes=st.session_state.window_minutes,
                                    opening_hour=st.session_state.opening_hour,
                                    closing_hour=st.session_state.closing_hour,
                                )
                                accounts = uploaded_df["account"].dropna().astype(str).str.strip()
                                prior_warnings = get_historical_warnings(accounts.tolist())
                                existing = find_existing_run(current_hash)
                                if existing:
                                    run_id = int(existing["run_id"])
                                    duplicate = True
                                else:
                                    run_id, _ = save_analysis(current_hash, uploaded_file.name, len(uploaded_df), detected, accounts.tolist())
                                    duplicate = False
                                st.session_state["incidents"] = detected
                                st.session_state["event_count"] = len(uploaded_df)
                                st.session_state["analysis_hash"] = current_hash
                                st.session_state["repeat_warnings"] = prior_warnings
                                st.session_state["current_run_id"] = run_id
                                st.session_state["current_filename"] = uploaded_file.name
                                st.session_state["duplicate_upload"] = duplicate
                                st.session_state["analysis_complete"] = True
                                st.rerun()
                            except Exception as exc:
                                st.error(f"Analysis failed: {exc}")
                except Exception as exc:
                    st.error(f"Could not read the uploaded CSV: {exc}")
            st.caption("Alerts are indicators for human review, not proof of a breach.")

    st.markdown("<div style='height:12px'></div>", unsafe_allow_html=True)
    m1,m2,m3,m4 = st.columns(4)
    m1.metric("Events Analyzed", f"{event_count:,}")
    m2.metric("Incidents Detected", f"{len(incidents):,}")
    m3.metric("Affected Accounts", f"{affected:,}")
    m4.metric("Historical Warnings", f"{repeat_count:,}", delta="Repeat accounts" if repeat_count else None, delta_color="off")

    left, right = st.columns([1, 1.45])
    with left:
        with st.container(border=True):
            st.markdown("<div class='eyebrow'>CLASSIFICATION SPLIT</div>", unsafe_allow_html=True)
            st.markdown("### Incident Distribution")
            if incidents.empty:
                st.markdown("<div style='padding:36px 12px;text-align:center;color:#78969b'>Your incident distribution will appear here after the first analysis.</div>", unsafe_allow_html=True)
            else:
                counts = incidents["severity"].value_counts().rename_axis("Severity").reset_index(name="Count")
                fig = px.pie(counts, names="Severity", values="Count", hole=.68, color="Severity", color_discrete_map={"Medium":"#ffd166","High":"#ff8fb8","Critical Review":"#ff5964"})
                fig.update_layout(paper_bgcolor="rgba(0,0,0,0)",plot_bgcolor="rgba(0,0,0,0)",font_color="#c1dce0",showlegend=True,legend_title_text="",margin=dict(t=8,b=8,l=8,r=8),height=290)
                fig.update_traces(textposition="inside",textinfo="percent",marker=dict(line=dict(color="#002328",width=3)))
                st.plotly_chart(fig,use_container_width=True,config={"displayModeBar":False})
                st.caption(f"{len(incidents):,} flagged events · {high} high · {critical} critical review · {medium} medium")
    with right:
        with st.container(border=True):
            st.markdown("<div class='eyebrow'>◉ ANALYST WORKSPACE</div>", unsafe_allow_html=True)
            st.markdown("### Recent Security Activity")
            if incidents.empty:
                st.markdown("<div style='padding:24px 10px;text-align:center;color:#78969b'>No security activity to display yet.<br>Upload a CSV and run analysis to populate this stream.</div>", unsafe_allow_html=True)
            else:
                recent = incidents.tail(5).iloc[::-1]
                for _, row in recent.iterrows():
                    severity = str(row.get("severity", "Medium"))
                    css_sev = "sev-critical" if severity == "Critical Review" else ("sev-high" if severity == "High" else "sev-medium")
                    stamp = str(row.get("end_time", ""))
                    stamp = stamp[-8:] if len(stamp) >= 8 else "Review"
                    evidence = str(row.get("evidence", "Flagged by detection rule"))
                    st.markdown(f"""<div class="activity-card"><div class="activity-top"><span class="activity-name">{html.escape(str(row.get('computer','Unknown host')))} · {html.escape(str(row.get('account','Unknown account')))}</span><span><span class="severity {css_sev}">{severity.upper()}</span> <span class="activity-time">{stamp}</span></span></div><div class="activity-copy">{html.escape(evidence)}</div><div style="font:10px DM Mono,monospace;color:#78969b;margin-top:7px">{html.escape(str(row.get('rule','Detection rule')))}</div></div>""", unsafe_allow_html=True)
                st.caption("Most recent findings from the current analysis. Review evidence before taking action.")

    st.markdown("### Historical Warnings")
    current_warnings = st.session_state.get("repeat_warnings", pd.DataFrame())
    global_repeat_accounts = get_repeat_accounts(min_runs=2)
    with st.expander(f"View historical account warnings · {len(current_warnings)} current-upload match(es)", expanded=False):
        show_historical_warnings(current_warnings, heading="Accounts previously flagged in earlier uploads")
        st.divider()
        st.markdown("#### Repeatedly flagged accounts across all saved runs")
        if global_repeat_accounts.empty:
            st.caption("No account has been flagged across two or more distinct analysis runs yet.")
        else:
            st.caption("Repeated flags are a review signal, not proof of misuse.")
            st.dataframe(global_repeat_accounts, use_container_width=True, hide_index=True)

    with st.expander(f"Full incident register · {len(incidents)} incident(s)", expanded=not incidents.empty):
        show_incidents(incidents)

    if not incidents.empty and st.button("Clear Current Results"):
        clear_current_analysis()
        st.rerun()


# -------------------- HISTORY --------------------
elif page == "History":
    st.markdown("<div class='eyebrow'>◷ AUDIT TRAIL</div>", unsafe_allow_html=True)
    st.markdown("## Analysis History")
    st.markdown("<div class='section-copy'>A searchable audit trail of completed analyses and evidence-backed findings. Raw CSV uploads are not stored in SQLite.</div>", unsafe_allow_html=True)
    st.markdown("<div style='height:12px'></div>", unsafe_allow_html=True)
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


# -------------------- SETTINGS --------------------
elif page == "Settings":
    st.markdown("<div class='eyebrow'>⚙ CONTROL PLANE</div>", unsafe_allow_html=True)
    st.markdown("## Detection Settings")
    st.markdown("<div class='section-copy'>Tune the detection thresholds used for future uploads. Changes take effect the next time you run an analysis.</div>", unsafe_allow_html=True)
    st.markdown("<div style='height:12px'></div>", unsafe_allow_html=True)

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
