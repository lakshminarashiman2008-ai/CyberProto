
import pandas as pd

REQUIRED_COLUMNS = {
    "event_id",
    "timestamp",
    "account",
    "computer",
    "event",
}

ALLOWED_EVENTS = {"success", "failure"}


def validate_csv(df):
    """Validate uploaded authentication logs."""

    errors = []
    warnings = []

    missing = REQUIRED_COLUMNS - set(df.columns)

    if missing:
        errors.append(
            "Missing required columns: "
            + ", ".join(sorted(missing))
        )
        return errors, warnings

    if df.empty:
        errors.append("The uploaded CSV contains no records.")
        return errors, warnings

    if df[list(REQUIRED_COLUMNS)].isnull().any().any():
        errors.append(
            "Some required fields contain empty values."
        )

    timestamps = pd.to_datetime(
        df["timestamp"], errors="coerce"
    )

    if timestamps.isna().any():
        errors.append(
            f"{timestamps.isna().sum()} invalid timestamp(s) found."
        )

    events = df["event"].astype(str).str.strip().str.lower()
    unknown = set(events.unique()) - ALLOWED_EVENTS

    if unknown:
        errors.append(
            "Unsupported event type(s): "
            + ", ".join(sorted(unknown))
            + ". Expected 'success' or 'failure'."
        )

    if df["event_id"].duplicated().any():
        warnings.append(
            "Duplicate event IDs detected. Review these records."
        )

    if not errors and timestamps.is_monotonic_decreasing:
        warnings.append(
            "Events are not in chronological order. "
            "They will be sorted during analysis."
        )

    return errors, warnings
