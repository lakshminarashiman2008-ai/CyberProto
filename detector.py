
import pandas as pd

FAILED_THRESHOLD = 3
WINDOW_MINUTES = 10

REQUIRED_COLUMNS = {
    "event_id",
    "timestamp",
    "account",
    "computer",
    "event",
}


def analyze_events(df):
    """Detect suspicious login patterns and return explainable incidents."""

    missing = REQUIRED_COLUMNS - set(df.columns)
    if missing:
        raise ValueError(
            f"Missing required columns: {', '.join(sorted(missing))}"
        )

    df = df.copy()
    df["timestamp"] = pd.to_datetime(
        df["timestamp"], errors="coerce"
    )

    if df["timestamp"].isna().any():
        raise ValueError("Some timestamps are invalid.")

    df["event"] = df["event"].astype(str).str.strip().str.lower()

    allowed_events = {"success", "failure"}
    unknown = set(df["event"].unique()) - allowed_events

    if unknown:
        raise ValueError(
            f"Unsupported event types: {', '.join(sorted(unknown))}. "
            "Use 'success' or 'failure'."
        )

    df = df.sort_values("timestamp").reset_index(drop=True)
    incidents = []

    # Rule 1: Repeated failures followed by a successful login.
    for (account, computer), group in df.groupby(
        ["account", "computer"], dropna=False
    ):
        group = group.sort_values("timestamp")

        for _, success in group[group["event"] == "success"].iterrows():
            start = success["timestamp"] - pd.Timedelta(
                minutes=WINDOW_MINUTES
            )

            failures = group[
                (group["event"] == "failure")
                & (group["timestamp"] >= start)
                & (group["timestamp"] <= success["timestamp"])
            ]

            if len(failures) >= FAILED_THRESHOLD:
                incidents.append({
                    "account": account,
                    "computer": computer,
                    "rule": "Repeated failures followed by success",
                    "severity": "High",
                    "start_time": failures["timestamp"].min(),
                    "end_time": success["timestamp"],
                    "event_ids": (
                        failures["event_id"].astype(str).tolist()
                        + [str(success["event_id"])]
                    ),
                    "evidence": (
                        f"{len(failures)} failed login attempts occurred "
                        f"within {WINDOW_MINUTES} minutes before a "
                        "successful login."
                    ),
                    "recommendation": (
                        "Verify whether the login was expected and "
                        "check with the account owner."
                    ),
                })

    # Rule 2: Successful logins outside lab hours.
    opening_hour = 8
    closing_hour = 18

    successful = df[df["event"] == "success"]

    for _, event in successful.iterrows():
        hour = event["timestamp"].hour

        if hour < opening_hour or hour >= closing_hour:
            incidents.append({
                "account": event["account"],
                "computer": event["computer"],
                "rule": "Successful login outside lab hours",
                "severity": "Medium",
                "start_time": event["timestamp"],
                "end_time": event["timestamp"],
                "event_ids": [str(event["event_id"])],
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

    return pd.DataFrame(incidents)
