
import pandas as pd
from validator import validate_csv


def test_valid_csv_passes_validation():
    df = pd.DataFrame({
        "event_id": ["E1", "E2"],
        "timestamp": ["2026-10-13 09:00:00", "2026-10-13 09:01:00"],
        "account": ["student1", "student1"],
        "computer": ["PC1", "PC1"],
        "event": ["failure", "success"],
    })

    errors, warnings = validate_csv(df)

    assert errors == []


def test_missing_required_column_fails_validation():
    df = pd.DataFrame({
        "event_id": ["E1"],
        "timestamp": ["2026-10-13 09:00:00"],
        "account": ["student1"],
        "event": ["success"],
    })

    errors, warnings = validate_csv(df)

    assert len(errors) > 0
