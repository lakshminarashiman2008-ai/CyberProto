
import pandas as pd
from validator import validate_csv

df = pd.read_csv("sample_data.csv")
errors, warnings = validate_csv(df)

if errors:
    print("VALIDATION FAILED")
    for error in errors:
        print("-", error)
else:
    print("VALIDATION PASSED")

for warning in warnings:
    print("WARNING:", warning)
