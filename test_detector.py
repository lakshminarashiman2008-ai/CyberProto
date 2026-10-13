
import pandas as pd
from detector import analyze_events


def make_df(events):
    return pd.DataFrame(events, columns=[
        "event_id", "timestamp", "account", "computer", "event"
    ])


def test_detects_failures_followed_by_success():
    df = make_df([
        ("E1", "2026-10-13 09:00:00", "student1", "PC1", "failure"),
        ("E2", "2026-10-13 09:01:00", "student1", "PC1", "failure"),
        ("E3", "2026-10-13 09:02:00", "student1", "PC1", "failure"),
        ("E4", "2026-10-13 09:03:00", "student1", "PC1", "success"),
    ])

    incidents = analyze_events(df)

    assert not incidents.empty
    assert "Repeated failures followed by success" in incidents["rule"].values


def test_detects_after_hours_login():
    df = make_df([
        ("E1", "2026-10-13 22:00:00", "student1", "PC1", "success"),
    ])

    incidents = analyze_events(df)

    assert not incidents.empty
    assert "Successful login outside lab hours" in incidents["rule"].values


def test_detects_consecutive_failures_without_success():
    df = make_df([
        ("E1", "2026-10-13 09:00:00", "student1", "PC1", "failure"),
        ("E2", "2026-10-13 09:01:00", "student1", "PC1", "failure"),
        ("E3", "2026-10-13 09:02:00", "student1", "PC1", "failure"),
        ("E4", "2026-10-13 09:03:00", "student1", "PC1", "failure"),
        ("E5", "2026-10-13 09:04:00", "student1", "PC1", "failure"),
    ])

    incidents = analyze_events(df)

    matches = incidents[
        incidents["rule"] == "Consecutive failed login attempts"
    ]

    assert len(matches) == 1
    assert matches.iloc[0]["severity"] == "Medium"


def test_too_few_consecutive_failures_do_not_trigger_rule_three():
    df = make_df([
        ("E1", "2026-10-13 09:00:00", "student1", "PC1", "failure"),
        ("E2", "2026-10-13 09:01:00", "student1", "PC1", "failure"),
        ("E3", "2026-10-13 09:02:00", "student1", "PC1", "failure"),
        ("E4", "2026-10-13 09:03:00", "student1", "PC1", "failure"),
    ])

    incidents = analyze_events(df)

    assert "Consecutive failed login attempts" not in incidents["rule"].values
