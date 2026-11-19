from pathlib import Path
import importlib.util
import numpy as np
import pandas as pd
import torch
from sklearn.metrics import roc_auc_score, average_precision_score

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location(
    "v4", ROOT / "analysis/ml/per_user_lstm_supervised_v4.py"
)
v4 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(v4)

print("Loading dataset...", flush=True)
df = pd.read_csv(ROOT / "data/auth_attack_final.csv")
df = df.sort_values(["src_user", "time"], kind="stable").reset_index(drop=True)

# Confirm chronological split boundaries.
parts = {s: df[df.split == s] for s in (0, 1, 2)}
assert parts[0].time.max() < parts[1].time.min()
assert parts[1].time.max() < parts[2].time.min()
print("PASS: Chronological split boundaries", flush=True)

ckpt = torch.load(
    ROOT / "analysis/ml/model/supervised_lstm_v4.pt",
    map_location="cpu",
    weights_only=False,
)

assert ckpt["feats"] == v4.FEATS
assert ckpt["col_event"] == v4.COL_EVENT
print("PASS: Checkpoint feature configuration", flush=True)

print("Computing behavioral features...", flush=True)
df = v4.add_features(df)

print("Building test sequences...", flush=True)
X, F, y = v4.make_windows(df, ckpt["vocabs"], 2)
F = ((F - ckpt["mu"]) / ckpt["sd"]).astype(np.float32)

model = v4.SupervisedAttackLSTM(ckpt["vocab_sizes"])
model.load_state_dict(ckpt["state_dict"])
model = model.to(v4.device)
model.eval()

print("Scoring test events...", flush=True)
scores = v4.predict_probs(model, X, F, y)

test = df[df.split == 2]
train_val = df[df.split.isin([0, 1])]
known_prior_attackers = set(
    train_val.loc[train_val.label == 1, "src_user"]
)
seen = test.src_user.isin(known_prior_attackers).to_numpy()

print("\n=== TEST RESULTS ===")
print("ROC-AUC:", round(roc_auc_score(y, scores), 4))
print("PR-AUC:", round(average_precision_score(y, scores), 4))

threshold = ckpt["thresholds"][0.001]
print("\nThreshold:", round(threshold, 5))

for name, mask in [
    ("Previously labeled attackers", seen),
    ("No prior labeled attacks", ~seen),
]:
    labels = y[mask]
    predictions = scores[mask] >= threshold
    tp = int(((labels == 1) & predictions).sum())
    fp = int(((labels == 0) & predictions).sum())
    total = int((labels == 1).sum())

    print(f"\n{name}")
    print("Events:", len(labels))
    print("Known attacks detected:", f"{tp}/{total}")
    print("Other events flagged:", fp)
    if total and len(np.unique(labels)) == 2:
        print("PR-AUC:", round(average_precision_score(labels, scores[mask]), 4))

np.savez_compressed(
    ROOT / "analysis/ml/v4_test_predictions.npz",
    scores=scores,
    labels=y,
)
print("\nSaved test predictions for later comparison.")
print("AUDIT COMPLETE")
