import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from numpy.lib.stride_tricks import sliding_window_view
from sklearn.metrics import roc_auc_score, average_precision_score
from torch.utils.data import DataLoader, TensorDataset
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PATH = ROOT / "data" / "auth_attack_final.csv"
COL_TIME = "time"
COL_USER = "src_user"
COL_EVENT = ["src_comp", "dst_comp", "auth_type", "logon_type"]
COL_LABEL = "label"
COL_SPLIT = "split"

WINDOW = 10
MAX_VOCAB = 20000
EMB, HIDDEN, LAYERS = 64, 128, 1
DROPOUT = 0.3
BATCH, EPOCHS, LR = 1024, 8, 1e-3
MAX_POS_WEIGHT = 500.0 # Cap pos_weight so gradients stay stable despite extreme class imbalance
FPR_TARGETS = [1e-2, 1e-3, 1e-4]
PAD, UNK = 0, 1

device = "cuda" if torch.cuda.is_available() else "cpu"


def load(path):
    df = pd.read_csv(path)
    df["token"] = (
        df[COL_EVENT].astype(str).agg("|".join, axis=1)
        if len(COL_EVENT) > 1
        else df[COL_EVENT[0]].astype(str)
    )
    df = df.sort_values([COL_USER, COL_TIME], kind="stable").reset_index(drop=True)
    return df


def build_vocab(train_df):
    counts = train_df["token"].value_counts().head(MAX_VOCAB - 2)
    return {tok: i + 2 for i, tok in enumerate(counts.index)}


def make_windows(df, vocab):
    """Returns X (n, WINDOW) including the target event at the end, and binary labels y (n,)."""
    ids_all = df["token"].map(vocab).fillna(UNK).astype(np.int64).to_numpy()
    labels_all = df[COL_LABEL].astype(np.float32).to_numpy()
    users = df[COL_USER].to_numpy()

    change = np.flatnonzero(users[1:] != users[:-1]) + 1
    starts = np.r_[0, change]
    ends = np.r_[change, len(df)]

    Xs, ys = [], []
    for s, e in zip(starts, ends):
        ids = ids_all[s:e]
        # Pad WINDOW - 1 tokens so each window of length WINDOW ends on the current event
        padded = np.concatenate([np.full(WINDOW - 1, PAD, dtype=np.int64), ids])
        w = sliding_window_view(padded, WINDOW)
        Xs.append(w)
        ys.append(labels_all[s:e])
    return np.concatenate(Xs), np.concatenate(ys)


class SupervisedAttackLSTM(nn.Module):
    def __init__(self, vocab_size):
        super().__init__()
        self.emb = nn.Embedding(vocab_size, EMB, padding_idx=PAD)
        self.drop = nn.Dropout(DROPOUT)
        self.lstm = nn.LSTM(EMB, HIDDEN, LAYERS, batch_first=True)
        self.head = nn.Sequential(
            nn.Dropout(DROPOUT),
            nn.Linear(HIDDEN, 1),
        )

    def forward(self, x):
        x = self.drop(self.emb(x))
        h, _ = self.lstm(x)
        return self.head(h[:, -1]).squeeze(-1)


def loader(X, y, shuffle):
    ds = TensorDataset(torch.from_numpy(X), torch.from_numpy(y))
    return DataLoader(
        ds,
        batch_size=BATCH,
        shuffle=shuffle,
        pin_memory=(device == "cuda"),
    )


@torch.no_grad()
def predict_probs(model, X, y):
    model.eval()
    probs = []
    for xb, _ in loader(X, y, shuffle=False):
        logits = model(xb.to(device))
        probs.append(torch.sigmoid(logits).cpu().numpy())
    return np.concatenate(probs)


def train(model, Xtr, ytr, Xva, yva):
    n_pos = max(float(ytr.sum()), 1.0)
    n_neg = float(len(ytr) - n_pos)
    raw_weight = n_neg / n_pos
    pos_weight = torch.tensor([min(raw_weight, MAX_POS_WEIGHT)], device=device)
    print(f"Train positives: {int(n_pos):,} / {len(ytr):,} | using pos_weight: {pos_weight.item():.1f}")

    opt = torch.optim.Adam(model.parameters(), lr=LR)
    bce = nn.BCEWithLogitsLoss(pos_weight=pos_weight)
    best_pr_auc, best_state = -1.0, None

    for epoch in range(EPOCHS):
        model.train()
        total, n = 0.0, 0
        for xb, yb in loader(Xtr, ytr, shuffle=True):
            xb, yb = xb.to(device), yb.to(device)
            opt.zero_grad()
            loss = bce(model(xb), yb)
            loss.backward()
            nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            opt.step()
            total += loss.item() * len(xb)
            n += len(xb)

        val_probs = predict_probs(model, Xva, yva)
        val_roc = roc_auc_score(yva, val_probs)
        val_pr = average_precision_score(yva, val_probs)
        print(
            f"epoch {epoch + 1}: train loss {total / n:.4f} | "
            f"val ROC-AUC {val_roc:.4f} | val PR-AUC {val_pr:.4f}"
        )
        # Checkpoint by validation PR-AUC rather than raw loss
        if val_pr > best_pr_auc:
            best_pr_auc = val_pr
            best_state = {k: v.clone() for k, v in model.state_dict().items()}

    model.load_state_dict(best_state)
    return model


def evaluate(val_scores, val_labels, test_scores, test_labels):
    print(f"\nTest set: {len(test_labels):,} events, {int(test_labels.sum())} red team")
    print(f"Event-level ROC-AUC: {roc_auc_score(test_labels, test_scores):.4f}")
    print(f"Event-level PR-AUC:  {average_precision_score(test_labels, test_scores):.4f}")

    benign_val = val_scores[val_labels == 0]
    for fpr in FPR_TARGETS:
        thr = np.quantile(benign_val, 1 - fpr)
        alerts = test_scores >= thr
        tp = int((alerts & (test_labels == 1)).sum())
        fp = int((alerts & (test_labels == 0)).sum())
        print(
            f"target FPR {fpr:g}: threshold {thr:.4f} | "
            f"caught {tp}/{int(test_labels.sum())} red events | "
            f"false alerts {fp:,} | actual FPR {fp / (test_labels == 0).sum():.5f}"
        )


def main():
    print(f"Using device: {device}")
    df = load(PATH)

    # Keep ALL events (benign + red team) in split 0 for supervised training
    train_df = df[df[COL_SPLIT] == 0]
    vocab = build_vocab(train_df)
    print(f"vocab size: {len(vocab) + 2}")

    data = {}
    for s in (0, 1, 2):
        part = df[df[COL_SPLIT] == s].reset_index(drop=True)
        X, y = make_windows(part, vocab)
        data[s] = (X, y)
        print(f"split {s}: {len(X):,} samples ({int(y.sum())} red team)")

    model = SupervisedAttackLSTM(len(vocab) + 2).to(device)
    model = train(model, data[0][0], data[0][1], data[1][0], data[1][1])

    val_scores = predict_probs(model, data[1][0], data[1][1])
    test_scores = predict_probs(model, data[2][0], data[2][1])
    evaluate(val_scores, data[1][1], test_scores, data[2][1])


if __name__ == "__main__":
    main()
