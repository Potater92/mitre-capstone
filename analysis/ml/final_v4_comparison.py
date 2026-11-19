from pathlib import Path
import runpy
import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[2]

# Reuse the existing comparison code and saved V4 predictions.
results = runpy.run_path(
    str(ROOT / "analysis/ml/compare_models.py")
)

partner_scores = results["partner_scores"]
v4_scores = results["v4_scores"]
labels = results["y"]
test = results["test"].reset_index(drop=True)

assert np.array_equal(labels, results["v4_labels"])
assert len(test) == len(labels)

print("\n========== MATCHED FALSE-ALERT COMPARISON ==========")

def evaluate_budget(name, scores, budget):
    negative_scores = scores[labels == 0]
    threshold = np.partition(
        negative_scores, -budget
    )[-budget]

    predictions = scores >= threshold

    tp = int(((labels == 1) & predictions).sum())
    fp = int(((labels == 0) & predictions).sum())

    print(
        f"{name}: threshold={threshold:.6f}, "
        f"attacks={tp}/132, other alerts={fp}, "
        f"recall={tp/132:.2%}"
    )
    return tp, fp

# Diagnostic comparison using test-set negative-score cutoffs.
# These thresholds are NOT for deployment.
for budget in [582, 1008]:
    print(f"\nFalse-alert budget: approximately {budget}")
    evaluate_budget("Partner", partner_scores, budget)
    evaluate_budget("V4     ", v4_scores, budget)

print("\n========== V4 MISSED ATTACKS ==========")

v4_threshold = 0.159469
missed = (labels == 1) & (v4_scores < v4_threshold)

details = test.loc[
    missed,
    ["time", "src_user", "src_comp", "dst_comp"]
].copy()

details["V4_score"] = v4_scores[missed]
details["Partner_score"] = partner_scores[missed]

print(details.to_string(index=False))
print("\nTotal missed:", int(missed.sum()))

print("\nFINAL COMPARISON COMPLETE")
