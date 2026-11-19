from pathlib import Path
import importlib.util
import numpy as np
import pandas as pd
import torch
from sklearn.metrics import roc_auc_score, average_precision_score

ROOT = Path(__file__).resolve().parents[2]
ML = ROOT / "analysis" / "ml"

def import_model(name, filename):
    spec = importlib.util.spec_from_file_location(name, ML / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

partner = import_model(
    "partner",
    "per_user_lstm_supervised_features.py"
)

print("Loading partner checkpoint...", flush=True)
ckpt = torch.load(
    ML / "model" / "supervised_lstm.pt",
    map_location="cpu",
    weights_only=False
)

print("Loading V4 predictions...", flush=True)
saved = np.load(ML / "v4_test_predictions.npz")
v4_scores = saved["scores"]
v4_labels = saved["labels"]

print("Loading identical test dataset...", flush=True)
df = pd.read_csv(ROOT / "data" / "auth_attack_final.csv")
df = df.sort_values(
    ["src_user", "time"], kind="stable"
).reset_index(drop=True)

print("Preparing partner's features...", flush=True)
df = partner.add_features(df)

test = df[df["split"] == 2].reset_index(drop=True)

X, F, y = partner.make_windows(
    test, ckpt["vocabs"]
)

F = ((F - ckpt["mu"]) / ckpt["sd"]).astype(np.float32)

assert len(y) == len(v4_labels)
assert np.array_equal(y, v4_labels)
print("PASS: Same test events and labels")

print("Scoring partner's model...", flush=True)
model = partner.SupervisedAttackLSTM(
    ckpt["vocab_sizes"]
)
model.load_state_dict(ckpt["state_dict"])
model = model.to(partner.device)
model.eval()

partner_scores = partner.predict_probs(
    model, X, F, y
)

def report(name, scores, labels, threshold):
    predicted = scores >= threshold
    tp = int(((labels == 1) & predicted).sum())
    fp = int(((labels == 0) & predicted).sum())
    positives = int(labels.sum())

    print(f"\n{name}")
    print("ROC-AUC:", round(roc_auc_score(labels, scores), 4))
    print("PR-AUC:", round(average_precision_score(labels, scores), 4))
    print("Threshold:", round(float(threshold), 6))
    print("Attacks detected:", f"{tp}/{positives}")
    print("Other events flagged:", fp)
    print("Precision:", round(tp / (tp + fp), 4) if tp + fp else 0)
    print("Recall:", round(tp / positives, 4))
    print("Actual FPR:", round(fp / (len(labels) - positives), 6))

v4_ckpt = torch.load(
    ML / "model" / "supervised_lstm_v4.pt",
    map_location="cpu",
    weights_only=False
)

print("\n========== MODEL COMPARISON ==========")

report(
    "PARTNER MODEL",
    partner_scores,
    y,
    ckpt["thresholds"][0.001]
)

report(
    "YOUR V4 MODEL",
    v4_scores,
    v4_labels,
    v4_ckpt["thresholds"][0.001]
)

print("\nCOMPARISON COMPLETE")
