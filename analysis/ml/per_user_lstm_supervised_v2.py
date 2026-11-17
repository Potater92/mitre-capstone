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

# Per-event novelty / timing features (computed on the full history, before splitting)
FEATS = ["f_dst_new", "f_edge_new", "f_src_new", "f_same", "f_dt", "f_hs", "f_hc", "f_new_rate"]

WINDOW = 10
MAX_VOCAB = 20000
EMB, HIDDEN, LAYERS = 64, 128, 1
DROPOUT = 0.3
BATCH, EPOCHS, LR = 1024, 8, 1e-3
MAX_POS_WEIGHT = 500.0  # Cap pos_weight so gradients stay stable despite extreme class imbalance
FPR_TARGETS = [1e-2, 1e-3, 1e-4]
PAD, UNK = 0, 1

device = "cuda" if torch.cuda.is_available() else "cpu"


def add_features(df):
    """Requires df sorted by (user, time). Uses only past/current info per user."""
    df["f_dst_new"] = (df.groupby([COL_USER, "dst_comp"]).cumcount() == 0).astype(np.float32)
    df["f_edge_new"] = (df.groupby([COL_USER, "src_comp", "dst_comp"]).cumcount() == 0).astype(np.float32)
    df["f_src_new"] = (df.groupby([COL_USER, "src_comp"]).cumcount() == 0).astype(np.float32)
    df["f_same"] = (df["src_comp"] == df["dst_comp"]).astype(np.float32)
    df["f_dt"] = np.log1p(df.groupby(COL_USER)[COL_TIME].diff().fillna(1e5)) / 12
    hour = (df[COL_TIME] % 86400) / 3600
    df["f_hs"] = np.sin(2 * np.pi * hour / 24)
    df["f_hc"] = np.cos(2 * np.pi * hour / 24)
    df["f_new_rate"] = (
        df.groupby(COL_USER)["f_dst_new"].transform(lambda s: s.rolling(10, min_periods=1).mean())
    )
    df[FEATS] = df[FEATS].astype(np.float32)
    return df


def load(path):
    df = pd.read_csv(path)
    df["token"] = (
        df[COL_EVENT].astype(str).agg("|".join, axis=1)
        if len(COL_EVENT) > 1
        else df[COL_EVENT[0]].astype(str)
    )
    df = df.sort_values([COL_USER, COL_TIME], kind="stable").reset_index(drop=True)
    # Features must be computed on the full sorted frame (incl. warm-up rows, split == -1)
    return add_features(df)


def build_vocab(train_df):
    counts = train_df["token"].value_counts().head(MAX_VOCAB - 2)
    return {tok: i + 2 for i, tok in enumerate(counts.index)}


def make_windows(df, vocab):
    """Returns X (n, WINDOW) incl. target event at the end, F (n, len(FEATS)) for the target event, y (n,)."""
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
    # df is already in (user, time) order, so features line up row-for-row with the windows
    F = df[FEATS].to_numpy(np.float32)
    return np.concatenate(Xs), F, np.concatenate(ys)


class SupervisedAttackLSTM(nn.Module):
    def __init__(self, vocab_size):
        super().__init__()
        self.emb = nn.Embedding(vocab_size, EMB, padding_idx=PAD)
        self.drop = nn.Dropout(DROPOUT)
        self.lstm = nn.LSTM(EMB, HIDDEN, LAYERS, batch_first=True)
        self.head = nn.Sequential(
            nn.Dropout(DROPOUT),
            nn.Linear(HIDDEN + len(FEATS), 1),
        )

    def forward(self, x, f):
        x = self.drop(self.emb(x))
        h, _ = self.lstm(x)
        return self.head(torch.cat([h[:, -1], f], dim=1)).squeeze(-1)


def loader(X, F, y, shuffle):
    ds = TensorDataset(torch.from_numpy(X), torch.from_numpy(F), torch.from_numpy(y))
    return DataLoader(
        ds,
        batch_size=BATCH,
        shuffle=shuffle,
        pin_memory=(device == "cuda"),
    )


@torch.no_grad()
def predict_probs(model, X, F, y):
    model.eval()
    probs = []
    for xb, fb, _ in loader(X, F, y, shuffle=False):
        logits = model(xb.to(device), fb.to(device))
        probs.append(torch.sigmoid(logits).cpu().numpy())
    return np.concatenate(probs)


def train(model, Xtr, Ftr, ytr, Xva, Fva, yva):
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
        for xb, fb, yb in loader(Xtr, Ftr, ytr, shuffle=True):
            xb, fb, yb = xb.to(device), fb.to(device), yb.to(device)
            opt.zero_grad()
            loss = bce(model(xb, fb), yb)
            loss.backward()
            nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            opt.step()
            total += loss.item() * len(xb)
            n += len(xb)

        val_probs = predict_probs(model, Xva, Fva, yva)
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

    # Keep ALL events (benign + red team) in split 0 for supervised training.
    # Warm-up rows (split == -1) are excluded here but already contributed to the history features.
    train_df = df[df[COL_SPLIT] == 0]
    vocab = build_vocab(train_df)
    print(f"vocab size: {len(vocab) + 2}")

    data = {}
    for s in (0, 1, 2):
        part = df[df[COL_SPLIT] == s].reset_index(drop=True)
        X, F, y = make_windows(part, vocab)
        data[s] = (X, F, y)
        print(f"split {s}: {len(X):,} samples ({int(y.sum())} red team)")

    # --- Fix 1 diagnostic: how often is the current event an unseen token? (delete once checked) ---
    for s, (X, F, y) in data.items():
        last = X[:, -1]
        print(
            f"split {s} UNK rate | benign: {(last[y == 0] == UNK).mean():.4f} "
            f"| red: {(last[y == 1] == UNK).mean():.4f}"
        )

    model = SupervisedAttackLSTM(len(vocab) + 2).to(device)
    # data[0] = (Xtr, Ftr, ytr), data[1] = (Xva, Fva, yva)
    model = train(model, *data[0], *data[1])

    val_scores = predict_probs(model, *data[1])
    test_scores = predict_probs(model, *data[2])
    evaluate(val_scores, data[1][2], test_scores, data[2][2])


if __name__ == "__main__":
    main()
