
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

st.title("🛡️ Cyber Sentinels")
st.caption("Explainable authentication monitoring for shared labs")

st.sidebar.header("Navigation")
page = st.sidebar.radio(
    "Go to",
    ["Dashboard", "Analyze Logs"],
)

if page == "Dashboard":
    st.subheader("Security Overview")
    st.info("Upload authentication logs from the Analyze Logs page to begin.")

else:
    st.subheader("Analyze Authentication Logs")

    uploaded_file = st.file_uploader(
        "Upload your authentication CSV",
        type=["csv"],
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

                if st.button("Run Security Analysis", type="primary"):
                    try:
                        incidents = analyze_events(df)

                        st.session_state["incidents"] = incidents
                        st.session_state["event_count"] = len(df)

                    except Exception as exc:
                        st.error(f"Analysis failed: {exc}")

                if "incidents" in st.session_state:
                    incidents = st.session_state["incidents"]

                    total = st.session_state["event_count"]
                    incident_count = len(incidents)
                    affected = (
                        incidents["account"].nunique()
                        if not incidents.empty else 0
                    )

                    col1, col2, col3 = st.columns(3)
                    col1.metric("Events Analyzed", total)
                    col2.metric("Incidents Detected", incident_count)
                    col3.metric("Affected Accounts", affected)

                    st.divider()
                    st.subheader("Incident Details")

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

                        st.subheader("Incident Distribution")

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
                        )

                        st.plotly_chart(
                            fig,
                            use_container_width=True,
                        )

                        st.download_button(
                            "Export Incidents as CSV",
                            data=incidents.to_csv(index=False),
                            file_name="cyber_sentinels_incidents.csv",
                            mime="text/csv",
                        )

        except Exception as exc:
            st.error(f"Could not read the uploaded CSV: {exc}")
