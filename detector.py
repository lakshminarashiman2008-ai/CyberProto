
import pandas as pd

REQUIRED_COLUMNS = {
    "event_id", "timestamp", "account", "computer", "event"
}

INCIDENT_COLUMNS = [
    "account", "computer", "rule", "severity",
    "start_time", "end_time", "event_ids",
    "evidence", "recommendation",
]


def analyze_events(
    df,
    failed_threshold=3,
    window_minutes=10,
    opening_hour=8,
    closing_hour=18,
    consecutive_threshold=5,
):
    """Detect suspicious login patterns with explainable evidence."""

    missing = REQUIRED_COLUMNS - set(df.columns)
    if missing:
        raise ValueError(
            f"Missing required columns: {', '.join(sorted(missing))}"
        )

    if failed_threshold < 1 or consecutive_threshold < 1:
        raise ValueError("Failed-login thresholds must be at least 1.")

    if window_minutes < 1:
        raise ValueError("Detection window must be at least 1 minute.")

    if not (
        0 <= opening_hour <= 23
        and 1 <= closing_hour <= 24
        and opening_hour < closing_hour
    ):
        raise ValueError("Invalid lab hours.")

    df = df.copy()
    df["timestamp"] = pd.to_datetime(
        df["timestamp"], errors="coerce"
    )

    if df["timestamp"].isna().any():
        raise ValueError("Some timestamps are invalid.")

    df["event"] = df["event"].astype(str).str.strip().str.lower()

    unknown = set(df["event"].unique()) - {"success", "failure"}
    if unknown:
        raise ValueError(
            f"Unsupported event types: {', '.join(sorted(unknown))}"
        )

    df = df.sort_values("timestamp").reset_index(drop=True)
    incidents = []

    # Rule 1: Repeated failures followed by a successful login.
    for (account, computer), group in df.groupby(
        ["account", "computer"], dropna=False, sort=False
    ):
        failures_seen = group[group["event"] == "failure"]

        for _, success in group[group["event"] == "success"].iterrows():
            start = success["timestamp"] - pd.Timedelta(
                minutes=window_minutes
            )
            failures = failures_seen[
                (failures_seen["timestamp"] >= start)
                & (failures_seen["timestamp"] < success["timestamp"])
            ]

            if len(failures) >= failed_threshold:
                incidents.append({
                    "account": account,
                    "computer": computer,
                    "rule": "Repeated failures followed by success",
                    "severity": "High",
                    "start_time": failures["timestamp"].min(),
                    "end_time": success["timestamp"],
                    "event_ids": ", ".join(
                        failures["event_id"].astype(str).tolist()
                        + [str(success["event_id"])]
                    ),
                    "evidence": (
                        f"{len(failures)} failed login attempts occurred "
                        f"within {window_minutes} minutes before a "
                        "successful login."
                    ),
                    "recommendation": (
                        "Verify whether the login was expected and check "
                        "with the account owner."
                    ),
                })

    # Rule 2: Successful logins outside configured lab hours.
    for _, event in df[df["event"] == "success"].iterrows():
        hour = event["timestamp"].hour

        if hour < opening_hour or hour >= closing_hour:
            incidents.append({
                "account": event["account"],
                "computer": event["computer"],
                "rule": "Successful login outside lab hours",
                "severity": "Medium",
                "start_time": event["timestamp"],
                "end_time": event["timestamp"],
                "event_ids": str(event["event_id"]),
                "evidence": (
                    f"Successful login at "
                    f"{event['timestamp'].strftime('%H:%M')} occurred "
                    f"outside lab hours ({opening_hour:02d}:00–"
                    f"{closing_hour:02d}:00)."
                ),
                "recommendation": (
                    "Confirm whether after-hours access was authorized."
                ),
            })

    # Rule 3: Consecutive failures without a successful login.
    # A streak followed by success within the window is handled by Rule 1.
    for (account, computer), group in df.groupby(
        ["account", "computer"], dropna=False, sort=False
    ):
        group = group.sort_values("timestamp")
        streak = []

        def add_failure_incident(failures):
            if len(failures) < consecutive_threshold:
                return

            count = len(failures)
            if count >= 10:
                severity = "Critical Review"
            elif count >= 8:
                severity = "High"
            else:
                severity = "Medium"

            incidents.append({
                "account": account,
                "computer": computer,
                "rule": "Consecutive failed login attempts",
                "severity": severity,
                "start_time": failures[0]["timestamp"],
                "end_time": failures[-1]["timestamp"],
                "event_ids": ", ".join(
                    str(item["event_id"]) for item in failures
                ),
                "evidence": (
                    f"{count} consecutive failed login attempts occurred "
                    f"within a {window_minutes}-minute window, with no "
                    "successful login ending the sequence."
                ),
                "recommendation": (
                    "Review the authentication records and verify the "
                    "activity with the account owner. Critical cases "
                    "require urgent human review."
                ),
            })

    
        for _, event in group.iterrows():
            if streak:
                span = (
                    event["timestamp"] - streak[0]["timestamp"]
                ).total_seconds() / 60

                if span > window_minutes:
                    add_failure_incident(streak)
                    streak = []

            if event["event"] == "failure":
                streak.append(event.to_dict())
            else:
                if streak:
                    gap_to_success = (
                        event["timestamp"] - streak[-1]["timestamp"]
                    ).total_seconds() / 60

                    if gap_to_success <= window_minutes:
                        # Rule 1 handles this failure-to-success sequence.
                        streak = []
                    else:
                        add_failure_incident(streak)
                        streak = []

        # Process any remaining streak after the loop finishes.
        add_failure_incident(streak)


    return pd.DataFrame(incidents, columns=INCIDENT_COLUMNS)
