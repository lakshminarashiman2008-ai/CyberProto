
import streamlit as st
import pandas as pd
import plotly.express as px

from detector import analyze_events
from validator import validate_csv


st.set_page_config(
    page_title="Cyber Sentinels",
    page_icon="🛡️",
    layout="wide",
)


# -------------------- CUSTOM STYLING --------------------

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

html, body, [data-testid="stAppViewContainer"] {
    background: var(--bg);
    color: var(--text);
    font-family: 'Inter', sans-serif;
}

[data-testid="stSidebar"] {
    background: var(--sidebar);
    border-right: 1px solid rgba(60, 73, 76, 0.45);
}

h1, h2, h3 {
    font-family: 'Plus Jakarta Sans', sans-serif !important;
    color: var(--cyan-soft) !important;
}

[data-testid="stMetric"] {
    background: var(--card);
    border: 1px solid rgba(60, 73, 76, 0.65);
    padding: 18px;
    border-radius: 12px;
}

[data-testid="stMetricLabel"] {
    color: var(--muted);
}

[data-testid="stMetricValue"] {
    color: var(--cyan-soft);
}

.stButton > button,
.stDownloadButton > button {
    background: var(--cyan);
    color: #00363E;
    border: none;
    border-radius: 8px;
    font-weight: 600;
}

.stButton > button:hover,
.stDownloadButton > button:hover {
    background: var(--cyan-soft);
    color: #00161A;
    border: none;
}

[data-testid="stFileUploader"] {
    background: var(--card);
    border: 1px dashed var(--cyan);
    border-radius: 12px;
    padding: 12px;
}

[data-testid="stDataFrame"],
[data-testid="stTable"] {
    border: 1px solid rgba(60, 73, 76, 0.65);
    border-radius: 10px;
}

hr {
    border-color: rgba(60, 73, 76, 0.5);
}
</style>
""", unsafe_allow_html=True)


# -------------------- PAGE HEADER --------------------

st.title("🛡️ Cyber Sentinels")
st.caption("Explainable authentication monitoring for shared labs")


# -------------------- NAVIGATION --------------------

st.sidebar.header("Navigation")

page = st.sidebar.radio(
    "Go to",
    ["Dashboard", "Analyze Logs"],
)


# -------------------- DASHBOARD --------------------

if page == "Dashboard":
    st.subheader("Security Overview")
    st.info(
        "Upload authentication logs from the Analyze Logs page "
        "to begin monitoring."
    )

    if "incidents" in st.session_state:
        incidents = st.session_state["incidents"]
        total = st.session_state.get("event_count", 0)

        affected = (
            incidents["account"].nunique()
            if not incidents.empty and "account" in incidents.columns
            else 0
        )

        col1, col2, col3 = st.columns(3)

        col1.metric("Events Analyzed", total)
        col2.metric("Incidents Detected", len(incidents))
        col3.metric("Affected Accounts", affected)

        st.divider()
        st.subheader("Recent Incidents")

        if incidents.empty:
            st.success("No incidents detected.")
        else:
            st.dataframe(
                incidents.drop(
                    columns=["start_time", "end_time"],
                    errors="ignore",
                ),
                use_container_width=True,
                hide_index=True,
            )


# -------------------- ANALYZE LOGS --------------------

else:
    st.subheader("Analyze Authentication Logs")

    uploaded_file = st.file_uploader(
        "Upload your authentication CSV",
        type=["csv"],
        key="authentication_csv",
    )

    if uploaded_file is not None:
        try:
            df = pd.read_csv(uploaded_file)

            errors, warnings = validate_csv(df)

            for warning in warnings:
                st.warning(warning)

            if errors:
                for error in errors:
                    st.error(error)

            else:
                st.success(f"Validated {len(df)} login events.")

                # -------------------- BROWSE LOGIN EVENTS --------------------

                st.divider()
                st.subheader("Browse Login Events")

                view_by = st.selectbox(
                    "View records by",
                    ["Lab Number", "Event Number"],
                    key="view_by",
                )

                if view_by == "Lab Number":

                    if "computer" not in df.columns:
                        st.error(
                            "CSV is missing the 'computer' column."
                        )

                    else:
                        labs = sorted(
                            df["computer"]
                            .dropna()
                            .astype(str)
                            .unique()
                            .tolist()
                        )

                        if labs:
                            selected_lab = st.selectbox(
                                "Select Lab / Computer",
                                labs,
                                key="selected_lab",
                            )

                            filtered_df = df[
                                df["computer"].astype(str) == selected_lab
                            ]

                            st.caption(
                                f"{len(filtered_df)} records found "
                                f"for {selected_lab}"
                            )

                            st.dataframe(
                                filtered_df,
                                use_container_width=True,
                                hide_index=True,
                            )
                        else:
                            st.info("No lab records are available.")

                else:
                    if "event_id" not in df.columns:
                        st.error(
                            "CSV is missing the 'event_id' column."
                        )

                    else:
                        event_ids = (
                            df["event_id"]
                            .dropna()
                            .astype(str)
                            .unique()
                            .tolist()
                        )

                        event_ids = sorted(event_ids)

                        if event_ids:
                            selected_event = st.selectbox(
                                "Select Event Number",
                                event_ids,
                                key="selected_event",
                            )

                            filtered_df = df[
                                df["event_id"].astype(str)
                                == selected_event
                            ]

                            st.caption(
                                f"{len(filtered_df)} record(s) found "
                                f"for event {selected_event}"
                            )

                            st.dataframe(
                                filtered_df,
                                use_container_width=True,
                                hide_index=True,
                            )
                        else:
                            st.info("No event records are available.")

                # -------------------- SECURITY ANALYSIS --------------------

                st.divider()
                st.subheader("Security Analysis")

                if st.button(
                    "Run Security Analysis",
                    type="primary",
                ):
                    try:
                        incidents = analyze_events(df)

                        st.session_state["incidents"] = incidents
                        st.session_state["event_count"] = len(df)
                        st.session_state["analysis_complete"] = True

                    except Exception as exc:
                        st.error(f"Analysis failed: {exc}")

                # Show results after analysis has been run
                if st.session_state.get("analysis_complete", False):
                    incidents = st.session_state["incidents"]
                    total = st.session_state["event_count"]

                    incident_count = len(incidents)

                    affected = (
                        incidents["account"].nunique()
                        if not incidents.empty
                        and "account" in incidents.columns
                        else 0
                    )

                    st.divider()
                    st.subheader("Security Overview")

                    col1, col2, col3 = st.columns(3)

                    col1.metric("Events Analyzed", total)
                    col2.metric("Incidents Detected", incident_count)
                    col3.metric("Affected Accounts", affected)

                    st.divider()
                    st.subheader("Incident Details")

                    if incidents.empty:
                        st.success("No incidents detected.")
                    else:
                        display_incidents = incidents.drop(
                            columns=["start_time", "end_time"],
                            errors="ignore",
                        )

                        st.dataframe(
                            display_incidents,
                            use_container_width=True,
                            hide_index=True,
                        )

                        # -------------------- INCIDENT CHART --------------------

                        st.subheader("Incident Distribution")

                        if "rule" in incidents.columns:
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
                                hole=0.6,
                                color_discrete_sequence=[
                                    "#22D3EE",
                                    "#5FF7AF",
                                    "#FFB1C7",
                                    "#8AEBFF",
                                ],
                            )

                            fig.update_layout(
                                paper_bgcolor="#00161A",
                                plot_bgcolor="#00161A",
                                font_color="#C4E9F0",
                                legend_title_text="Detection Rule",
                            )

                            st.plotly_chart(
                                fig,
                                use_container_width=True,
                            )

                        # -------------------- EXPORT INCIDENTS --------------------

                        st.download_button(
                            "Export Incidents as CSV",
                            data=incidents.to_csv(index=False),
                            file_name="cyber_sentinels_incidents.csv",
                            mime="text/csv",
                        )

        except Exception as exc:
            st.error(f"Could not read the uploaded CSV: {exc}")