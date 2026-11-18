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
COL_EVENT = ["src_comp", "dst_comp", "auth_type", "logon_type"]  # each gets its own vocab + embedding
COL_LABEL = "label"
COL_SPLIT = "split"

# Per-event features. The first 8 are per-user history; the last 3 add rarity / burst context.
FEATS = [
    "f_dst_new", "f_edge_new", "f_src_new", "f_same", "f_dt", "f_hs", "f_hc", "f_new_rate"
]

WINDOW = 10
MAX_VOCAB = 20000
MIN_COUNT = 5                 # tokens seen fewer times in train become UNK, so UNK is learnable
MASK_P = 0.05                 # random token -> UNK masking during training
EMB_DIMS = [32, 32, 8, 8]     # one entry per field in COL_EVENT
HIDDEN, LAYERS = 128, 1
DROPOUT = 0.3
BATCH, EPOCHS, LR = 1024, 8, 1e-3
MAX_POS_WEIGHT = 500.0  # Cap pos_weight so gradients stay stable despite extreme class imbalance
FPR_TARGETS = [1e-2, 1e-3, 1e-4]
PAD, UNK = 0, 1

device = "cuda" if torch.cuda.is_available() else "cpu"


# features
def window_features(users, times, dsts, win_distinct=3600, win_count=300):
    """Per-user sliding-window features. Inputs must be sorted by (user, time).
    Returns (distinct dst in last `win_distinct` s incl. current, events in previous `win_count` s)."""
    n = len(times)
    distinct = np.zeros(n, np.float32)
    count = np.zeros(n, np.float32)
    users, times, dsts = users.tolist(), times.tolist(), dsts.tolist()
    counts, lo_h, lo_c = {}, 0, 0
    for i in range(n):
        if i > 0 and users[i] != users[i - 1]:
            counts, lo_h, lo_c = {}, i, i
        t, d = times[i], dsts[i]
        counts[d] = counts.get(d, 0) + 1
        while times[lo_h] <= t - win_distinct:
            dd = dsts[lo_h]
            counts[dd] -= 1
            if counts[dd] == 0:
                del counts[dd]
            lo_h += 1
        while times[lo_c] <= t - win_count:
            lo_c += 1
        distinct[i] = len(counts)
        count[i] = i - lo_c
    return distinct, count


def add_features(df):
    """df must be sorted by (user, time) with a RangeIndex. Everything here uses only past/current events."""
    # --- per-user history ---
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

    # --- network-wide rarity: distinct prior users per destination (needs global time order) ---
    order = np.argsort(df[COL_TIME].to_numpy(), kind="stable")
    tdf = df.iloc[order]
    first = (~tdf.duplicated(subset=["dst_comp", COL_USER])).astype(np.int32)
    prior_users = first.groupby(tdf["dst_comp"]).cumsum() - first   # excludes this user's own first visit
    df["f_dst_users"] = np.log1p(prior_users)                        # aligned back to df by index

    # --- per-user windowed burst features ---
    dst_codes = pd.factorize(df["dst_comp"])[0]
    distinct, count = window_features(df[COL_USER].to_numpy(), df[COL_TIME].to_numpy(), dst_codes)
    df["f_user_dsts_1h"] = np.log1p(distinct)
    df["f_user_cnt_5m"] = np.log1p(count)

    df[FEATS] = df[FEATS].astype(np.float32)
    return df


def load(path):
    df = pd.read_csv(path)
    df = df.sort_values([COL_USER, COL_TIME], kind="stable").reset_index(drop=True)
    # Features are computed on the full sorted frame, including warm-up rows (split == -1)
    return add_features(df)


def build_vocabs(train_df):
    """One vocab per event field. Rare values (< MIN_COUNT in train) fall through to UNK."""
    vocabs = []
    for c in COL_EVENT:
        counts = train_df[c].value_counts()
        counts = counts[counts >= MIN_COUNT].head(MAX_VOCAB - 2)
        vocabs.append({v: i + 2 for i, v in enumerate(counts.index)})
    return vocabs


def make_windows(df, vocabs):
    """Returns X (n, WINDOW, n_fields) with the target event last, F (n, len(FEATS)), y (n,)."""
    ids_all = np.stack(
        [df[c].map(v).fillna(UNK).astype(np.int32).to_numpy() for c, v in zip(COL_EVENT, vocabs)],
        axis=1,
    )
    labels_all = df[COL_LABEL].astype(np.float32).to_numpy()
    users = df[COL_USER].to_numpy()

    change = np.flatnonzero(users[1:] != users[:-1]) + 1
    starts = np.r_[0, change]
    ends = np.r_[change, len(df)]
    n_fields = len(COL_EVENT)

    Xs, ys = [], []
    for s, e in zip(starts, ends):
        ids = ids_all[s:e]
        # Pad WINDOW - 1 rows so each window of length WINDOW ends on the current event
        padded = np.concatenate([np.full((WINDOW - 1, n_fields), PAD, dtype=np.int32), ids])
        w = sliding_window_view(padded, WINDOW, axis=0)      # (len, n_fields, WINDOW)
        Xs.append(w.transpose(0, 2, 1))                       # -> (len, WINDOW, n_fields)
        ys.append(labels_all[s:e])
    # df is already in (user, time) order, so features line up row-for-row with the windows
    X = np.ascontiguousarray(np.concatenate(Xs))
    F = df[FEATS].to_numpy(np.float32)
    return X, F, np.concatenate(ys)


class SupervisedAttackLSTM(nn.Module):
    def __init__(self, vocab_sizes):
        super().__init__()
        self.embs = nn.ModuleList(
            [nn.Embedding(v, d, padding_idx=PAD) for v, d in zip(vocab_sizes, EMB_DIMS)]
        )
        self.drop = nn.Dropout(DROPOUT)
        self.lstm = nn.LSTM(sum(EMB_DIMS), HIDDEN, LAYERS, batch_first=True)
        self.head = nn.Sequential(
            nn.Dropout(DROPOUT),
            nn.Linear(HIDDEN + len(FEATS), 1),
        )

    def forward(self, x, f):
        x = x.long()
        x = torch.cat([emb(x[..., i]) for i, emb in enumerate(self.embs)], dim=-1)
        x = self.drop(x)
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
            # Token masking: randomly turn real tokens (any field, any position) into UNK so the
            # model learns what an unseen host / auth type looks like
            mask = (torch.rand(xb.shape, device=device) < MASK_P) & (xb != PAD)
            xb = xb.masked_fill(mask, UNK)
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


# evaluation
def user_level(users, times, scores, labels, thr):
    """Did we flag each compromised user, how fast, and how many clean users did we bother?"""
    d = pd.DataFrame({"u": users, "t": times, "s": scores, "y": labels})
    red = d[d.y == 1]
    red_users = red.u.unique()
    hits = red[red.s >= thr]
    first_red = red.groupby("u").t.min()
    first_hit = hits.groupby("u").t.min()
    delay_min = (first_hit - first_red.loc[first_hit.index]) / 60
    benign = d[~d.u.isin(red_users)]
    ben_alerted = benign.loc[benign.s >= thr, "u"].nunique()
    return {
        "flagged": len(first_hit),
        "total": len(red_users),
        "median_delay_min": float(delay_min.median()) if len(delay_min) else float("nan"),
        "ben_alerted": ben_alerted,
        "ben_total": benign.u.nunique(),
    }


def evaluate(val_scores, val_labels, test_scores, test_labels, test_users, test_times):
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
        u = user_level(test_users, test_times, test_scores, test_labels, thr)
        print(
            f"    user-level: flagged {u['flagged']}/{u['total']} red users "
            f"(median time to first flag {u['median_delay_min']:.1f} min) | "
            f"clean users alerted {u['ben_alerted']}/{u['ben_total']}"
        )


#main
def main():
    print(f"Using device: {device}")
    df = load(PATH)

    # Keep ALL events (benign + red team) in split 0 for supervised training.
    # Warm-up rows (split == -1) are excluded here but already contributed to the history features.
    train_df = df[df[COL_SPLIT] == 0]
    vocabs = build_vocabs(train_df)
    vocab_sizes = [len(v) + 2 for v in vocabs]
    print("vocab sizes per field:", dict(zip(COL_EVENT, vocab_sizes)))

    parts, data = {}, {}
    for s in (0, 1, 2):
        parts[s] = df[df[COL_SPLIT] == s].reset_index(drop=True)
        data[s] = make_windows(parts[s], vocabs)
        X, _, y = data[s]
        print(f"split {s}: {len(X):,} samples ({int(y.sum())} red team)")

    ru = {s: set(parts[s].loc[parts[s][COL_LABEL] == 1, COL_USER]) for s in (0, 1, 2)}
    print("red users per split:", {s: len(v) for s, v in ru.items()})
    print("train∩val:", len(ru[0] & ru[1]), "| train∩test:", len(ru[0] & ru[2]),
          "| val∩test:", len(ru[1] & ru[2]))
    test_red = parts[2][parts[2][COL_LABEL] == 1]
    seen = test_red[COL_USER].isin(ru[0] | ru[1])
    print(f"test red events from users with red events in train/val: {int(seen.sum())}/{len(test_red)}")

    # Standardize features using train statistics only
    mu = data[0][1].mean(axis=0)
    sd = data[0][1].std(axis=0)
    sd[sd < 1e-6] = 1.0
    for s in data:
        X, F, y = data[s]
        data[s] = (X, ((F - mu) / sd).astype(np.float32), y)

    # Diagnostic: how often is the current event's field value unseen? (can be deleted)
    for s, (X, _, y) in data.items():
        last = X[:, -1, :]
        for i, c in enumerate(COL_EVENT):
            print(
                f"split {s} UNK rate {c:<10} | benign: {(last[y == 0, i] == UNK).mean():.4f} "
                f"| red: {(last[y == 1, i] == UNK).mean():.4f}"
            )

    model = SupervisedAttackLSTM(vocab_sizes).to(device)
    # data[0] = (Xtr, Ftr, ytr), data[1] = (Xva, Fva, yva)
    model = train(model, *data[0], *data[1])

    val_scores = predict_probs(model, *data[1])
    test_scores = predict_probs(model, *data[2])
    evaluate(
        val_scores, data[1][2], test_scores, data[2][2],
        parts[2][COL_USER].to_numpy(), parts[2][COL_TIME].to_numpy(),
    )
    # Save the model to the model folder
    benign_val = val_scores[data[1][2] == 0]
    thresholds = {fpr: float(np.quantile(benign_val, 1 - fpr)) for fpr in FPR_TARGETS}
    torch.save(
        {
            "state_dict": model.state_dict(),
            "vocabs": vocabs,
            "vocab_sizes": vocab_sizes,
            "mu": mu,
            "sd": sd,
            "feats": FEATS,
            "col_event": COL_EVENT,
            "window": WINDOW,
            "emb_dims": EMB_DIMS,
            "hidden": HIDDEN,
            "layers": LAYERS,
            "dropout": DROPOUT,
            "thresholds": thresholds,
        },
        ROOT / "analysis" / "ml" / "model" / "supervised_lstm.pt",
    )
    print("saved model to", ROOT / "models" / "supervised_lstm.pt")


if __name__ == "__main__":
    main()