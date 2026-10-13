
import pandas as pd

REQUIRED_COLUMNS = {
    "event_id", "timestamp", "account", "computer", "event"
}


def analyze_events(
    df,
    failed_threshold=3,
    window_minutes=10,
    opening_hour=8,
    closing_hour=18,
):
    """Detect suspicious login patterns with explainable evidence."""

    missing = REQUIRED_COLUMNS - set(df.columns)
    if missing:
        raise ValueError(
            f"Missing required columns: {', '.join(sorted(missing))}"
        )

    if not (1 <= failed_threshold):
        raise ValueError("Failed-login threshold must be at least 1.")

    if window_minutes < 1:
        raise ValueError("Detection window must be at least 1 minute.")

    if not (0 <= opening_hour <= 23 and 1 <= closing_hour <= 24):
        raise ValueError("Invalid lab hours.")

    if opening_hour >= closing_hour:
        raise ValueError("Opening hour must be earlier than closing hour.")

    df = df.copy()
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")

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
        ["account", "computer"], dropna=False
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

    columns = [
        "account", "computer", "rule", "severity",
        "start_time", "end_time", "event_ids",
        "evidence", "recommendation",
    ]

    return pd.DataFrame(incidents, columns=columns)
