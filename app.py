
import hashlib
import bcrypt
import pandas as pd
import plotly.express as px
import streamlit as st
import streamlit_authenticator as stauth
from detector import analyze_events
from validator import validate_csv


st.set_page_config(
    page_title="Cyber Sentinels",
    page_icon="🛡️",
    layout="wide",
)
# -------------------- ADMIN AUTHENTICATION --------------------


def show_login():
    username = st.secrets["auth"]["username"]
    password_hash = st.secrets["auth"]["password_hash"]
    cookie_key = st.secrets["auth"]["cookie_key"]

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

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700&family=Inter:wght@400;500;600&family=JetBrains+Mono:wght@400;500;600&display=swap');

:root {
    --bg: #00161A;
    --sidebar: #001114;
    --card: #002429;
    --elevated: #062F35;
    --border: #3C494C;
    --cyan: #22D3EE;
    --cyan-soft: #8AEBFF;
    --mint: #5FF7AF;
    --pink: #FFB1C7;
    --text: #C4E9F0;
    --muted: #BBC9CD;
}

.stApp, [data-testid="stAppViewContainer"] {
    background: var(--bg);
    color: var(--text);
    font-family: 'Inter', sans-serif;
}

[data-testid="stSidebar"] {
    background: var(--sidebar);
    border-right: 1px solid var(--border);
}

h1, h2, h3 {
    font-family: 'Plus Jakarta Sans', sans-serif !important;
    color: var(--cyan-soft) !important;
}

[data-testid="stMetric"] {
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 18px;
}

[data-testid="stMetricLabel"] {
    color: var(--muted);
}

[data-testid="stMetricValue"] {
    color: var(--cyan-soft);
}

.stButton > button, .stDownloadButton > button {
    background: var(--cyan);
    color: #00363E;
    border: none;
    border-radius: 8px;
    font-weight: 600;
}

.stButton > button:hover, .stDownloadButton > button:hover {
    background: var(--cyan-soft);
    color: var(--bg);
}

[data-testid="stFileUploader"] {
    background: var(--card);
    border: 1px dashed var(--cyan);
    border-radius: 12px;
    padding: 12px;
}

div[data-testid="stVerticalBlockBorderWrapper"] {
    border-color: var(--border);
}

hr {
    border-color: var(--border);
}

code, .technical {
    font-family: 'JetBrains Mono', monospace;
}
</style>
""", unsafe_allow_html=True)


# -------------------- DEFAULT SETTINGS --------------------

defaults = {
    "failed_threshold": 3,
    "window_minutes": 10,
    "opening_hour": 8,
    "closing_hour": 18,
}

for key, value in defaults.items():
    if key not in st.session_state:
        st.session_state[key] = value


# -------------------- SIDEBAR --------------------

with st.sidebar:
    st.markdown("## 🛡️ Cyber Sentinels")
    st.caption("AUTHENTICATION MONITORING")
    st.divider()

    page = st.radio(
        "NAVIGATION",
        ["Dashboard", "Analyze Logs", "Settings"],
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


# -------------------- HELPERS --------------------

def clear_analysis():
    for key in ["incidents", "event_count", "analysis_hash"]:
        st.session_state.pop(key, None)


def show_metrics(incidents, event_count):
    incident_count = len(incidents)
    affected = (
        incidents["account"].nunique()
        if incident_count else 0
    )
    high_count = (
        int((incidents["severity"] == "High").sum())
        if incident_count else 0
    )

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Events Analyzed", event_count)
    c2.metric("Incidents Detected", incident_count)
    c3.metric("Affected Accounts", affected)
    c4.metric("High-Severity Alerts", high_count)


def show_incidents(incidents):
    if incidents.empty:
        st.success("No incidents detected in this dataset.")
        return

    st.markdown("### Incident Details")

    display_df = incidents.copy()
    display_df["event_ids"] = display_df["event_ids"].astype(str)

    st.dataframe(
        display_df,
        use_container_width=True,
        hide_index=True,
        column_config={
            "severity": st.column_config.TextColumn("Severity"),
            "event_ids": st.column_config.TextColumn("Evidence Event IDs"),
            "evidence": st.column_config.TextColumn("Why it was flagged"),
            "recommendation": st.column_config.TextColumn(
                "Recommended review"
            ),
        },
    )

    st.markdown("### Incident Distribution")

    counts = (
        incidents["rule"]
        .value_counts()
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


# -------------------- DASHBOARD --------------------

st.title("Cyber Sentinels")
st.caption("Explainable authentication monitoring for shared labs")

if page == "Dashboard":
    st.markdown("## Security Overview")
    st.caption("Summary of the most recent successful analysis.")

    if "incidents" not in st.session_state:
        st.info(
            "No analysis results yet. Open **Analyze Logs** to upload "
            "an authentication CSV and run the detector."
        )
    else:
        incidents = st.session_state["incidents"]
        event_count = st.session_state["event_count"]

        show_metrics(incidents, event_count)
        st.divider()
        show_incidents(incidents)

        if st.button("Clear current results"):
            clear_analysis()
            st.rerun()


# -------------------- ANALYZE LOGS --------------------

elif page == "Analyze Logs":
    st.markdown("## Analyze Authentication Logs")
    st.write(
        "Upload a CSV to validate the records and identify suspicious "
        "authentication patterns."
    )

    uploaded_file = st.file_uploader(
        "Upload authentication logs",
        type=["csv"],
        help="Required columns: event_id, timestamp, account, computer, event",
    )

    if uploaded_file is not None:
        file_bytes = uploaded_file.getvalue()
        current_hash = hashlib.sha256(file_bytes).hexdigest()

        # Remove stale results whenever a different file is uploaded.
        if st.session_state.get("analysis_hash") != current_hash:
            clear_analysis()

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
                    st.dataframe(
                        df.head(100),
                        use_container_width=True,
                        hide_index=True,
                    )

                with st.expander("Active detection settings"):
                    st.write(
                        f"Failed-login threshold: "
                        f"**{st.session_state.failed_threshold}**"
                    )
                    st.write(
                        f"Detection window: "
                        f"**{st.session_state.window_minutes} minutes**"
                    )
                    st.write(
                        f"Lab hours: "
                        f"**{st.session_state.opening_hour:02d}:00–"
                        f"{st.session_state.closing_hour:02d}:00**"
                    )

                if st.button("Run Security Analysis", type="primary"):
                    try:
                        incidents = analyze_events(
                            df,
                            failed_threshold=st.session_state.failed_threshold,
                            window_minutes=st.session_state.window_minutes,
                            opening_hour=st.session_state.opening_hour,
                            closing_hour=st.session_state.closing_hour,
                        )

                        st.session_state["incidents"] = incidents
                        st.session_state["event_count"] = len(df)
                        st.session_state["analysis_hash"] = current_hash

                        st.success("Analysis completed.")
                    except Exception as exc:
                        st.error(f"Analysis failed: {exc}")

                # Show results only for the currently uploaded file.
                if (
                    st.session_state.get("analysis_hash") == current_hash
                    and "incidents" in st.session_state
                ):
                    show_metrics(
                        st.session_state["incidents"],
                        st.session_state["event_count"],
                    )
                    st.divider()
                    show_incidents(st.session_state["incidents"])

        except Exception as exc:
            st.error(f"Could not read the uploaded CSV: {exc}")


# -------------------- SETTINGS --------------------

elif page == "Settings":
    st.markdown("## Detection Settings")
    st.write(
        "Adjust the rules used to flag suspicious logins. Changes apply "
        "to the next analysis."
    )

    with st.form("detection_settings"):
        st.markdown("### Repeated Login Failures")

        threshold = st.number_input(
            "Minimum failed attempts",
            min_value=1,
            max_value=20,
            value=st.session_state.failed_threshold,
            help="Minimum failures before a successful login to trigger an alert.",
        )

        window = st.number_input(
            "Detection window (minutes)",
            min_value=1,
            max_value=120,
            value=st.session_state.window_minutes,
        )

        st.divider()
        st.markdown("### Lab Operating Hours")

        opening = st.number_input(
            "Opening hour (24-hour format)",
            min_value=0,
            max_value=23,
            value=st.session_state.opening_hour,
        )

        closing = st.number_input(
            "Closing hour (24-hour format)",
            min_value=1,
            max_value=24,
            value=st.session_state.closing_hour,
            help="24 means midnight at the end of the day.",
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

                # Results from previous settings should not be treated as current.
                clear_analysis()

                st.success("Settings saved. Run your analysis again.")

    st.divider()
    st.caption(
        "These rules flag events for review; they do not prove malicious "
        "activity or block accounts."
    )
