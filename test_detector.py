
import pandas as pd
from detector import analyze_events

df = pd.read_csv("sample_data.csv")
incidents = analyze_events(df)

if incidents.empty:
    print("No incidents detected.")
else:
    for number, (_, incident) in enumerate(
        incidents.iterrows(), start=1
    ):
        print(f"\n{'=' * 45}")
        print(f"INCIDENT #{number}")
        print(f"{'=' * 45}")

        print(f"Account        : {incident['account']}")
        print(f"Computer       : {incident['computer']}")
        print(f"Rule           : {incident['rule']}")
        print(f"Severity       : {incident['severity']}")
        print(f"Event IDs      : {', '.join(incident['event_ids'])}")
        print(f"Evidence       : {incident['evidence']}")
        print(f"Recommendation : {incident['recommendation']}")

    print(f"\nTotal incidents detected: {len(incidents)}")
