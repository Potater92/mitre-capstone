
from pathlib import Path

import pandas as pd


# Project paths
ROOT = Path(__file__).resolve().parents[2]
INPUT_FILE = ROOT / "output" / "multi_user_features_large.csv"
OUTPUT_FILE = ROOT / "output" / "sigma_detection_results.csv"
SUMMARY_FILE = ROOT / "output" / "sigma_detection_summary.csv"

# Load existing behavioral features
df = pd.read_csv(INPUT_FILE)

# Required fields
required = [
    "attack",
    "new_destination",
    "destination_frequency",
    "unique_destinations_5min",
    "auth_events_5min",
]

missing = [col for col in required if col not in df.columns]
if missing:
    raise ValueError(f"Missing columns: {missing}")

# Experimental detection rules
df["rule_unusual_destination"] = (
    (df["new_destination"] == 1)
    & (df["destination_frequency"] <= 2)
).astype(int)

df["rule_multiple_destinations"] = (
    df["unique_destinations_5min"] >= 5
).astype(int)

df["rule_authentication_burst"] = (
    df["auth_events_5min"] >= 10
).astype(int)

rules = [
    "rule_unusual_destination",
    "rule_multiple_destinations",
    "rule_authentication_burst",
]

# Flag events matching at least one rule
df["any_rule_matched"] = df[rules].any(axis=1).astype(int)

# Evaluate the rules
summary = []

for rule in rules + ["any_rule_matched"]:
    matched = df[rule] == 1
    attacks = df["attack"] == 1

    true_positives = int((matched & attacks).sum())
    unmatched_attacks = int((~matched & attacks).sum())
    other_alerts = int((matched & ~attacks).sum())

    precision = (
        true_positives / (true_positives + other_alerts)
        if true_positives + other_alerts else 0
    )

    recall = (
        true_positives / (true_positives + unmatched_attacks)
        if true_positives + unmatched_attacks else 0
    )

    summary.append({
        "rule": rule,
        "total_alerts": int(matched.sum()),
        "known_attacks_detected": true_positives,
        "known_attacks_missed": unmatched_attacks,
        "other_events_flagged": other_alerts,
        "precision_vs_labels": round(precision, 4),
        "recall_vs_labels": round(recall, 4),
    })

summary_df = pd.DataFrame(summary)

# Save results without overwriting existing files
df.to_csv(OUTPUT_FILE, index=False)
summary_df.to_csv(SUMMARY_FILE, index=False)

print("\nSIGMA-INSPIRED DETECTION RESULTS")
print("=" * 45)
print("Total events:", len(df))
print("Known red-team events:", int(df["attack"].sum()))
print("\n", summary_df.to_string(index=False))
print("\nSaved:", OUTPUT_FILE)
print("Saved:", SUMMARY_FILE)
