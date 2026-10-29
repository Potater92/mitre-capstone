from pathlib import Path
import pandas as pd

ROOT = Path(__file__).resolve().parents[2]

df = pd.read_csv(
    ROOT / "output" / "multi_user_features_large.csv"
)

df = df.sort_values("time", kind="stable").copy()

df["prior_source_count"] = df.groupby(
    ["source_user", "source_computer"]
).cumcount()

df["prior_destination_count"] = df.groupby(
    ["source_user", "destination_computer"]
).cumcount()

attacks = df["attack"] == 1
total_attacks = int(attacks.sum())

results = []

for threshold in [1, 2, 3, 5, 10, 15, 20, 25]:
    matched = (
        (df["prior_source_count"] < threshold)
        & (df["prior_destination_count"] < threshold)
    )

    detected = int((matched & attacks).sum())
    other = int((matched & ~attacks).sum())

    results.append({
        "threshold": threshold,
        "known_attacks_detected": detected,
        "total_known_attacks": total_attacks,
        "other_events_flagged": other,
        "total_alerts": int(matched.sum()),
        "recall_percent": round(
            detected / total_attacks * 100, 2
        ) if total_attacks else 0,
    })

summary = pd.DataFrame(results)

output = ROOT / "output" / "rarity_threshold_comparison.csv"
summary.to_csv(output, index=False)

print("\nRARITY THRESHOLD COMPARISON")
print(summary.to_string(index=False))
print("\nSaved:", output)
