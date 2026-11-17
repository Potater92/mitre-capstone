
from pathlib import Path
import copy
import random

import numpy as np
import pandas as pd
import torch
import torch.nn as nn

from numpy.lib.stride_tricks import sliding_window_view
from sklearn.metrics import (
    roc_auc_score,
    average_precision_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
)
from torch.utils.data import DataLoader, TensorDataset


# -----------------------------------
# Configuration
# -----------------------------------

ROOT = Path(__file__).resolve().parents[2]
PATH = Path.home() / "Desktop" / "mitre-lanl" / "lanl-final-run" / "auth_attack_final.csv"

COL_TIME = "time"
COL_USER = "src_user"
COL_EVENT = [
    "src_comp",
    "dst_comp",
    "auth_type",
    "logon_type",
]
COL_LABEL = "label"
COL_SPLIT = "split"

FEATS = [
    "f_dst_new",
    "f_edge_new",
    "f_src_new",
    "f_same",
    "f_dt",
    "f_hs",
    "f_hc",
    "f_new_rate",
]

WINDOW = 10
MAX_VOCAB = 20000

EMB = 64
HIDDEN = 128
LAYERS = 1
DROPOUT = 0.3

BATCH = 1024
EPOCHS = 8
LR = 1e-3

MAX_POS_WEIGHT = 500.0

FPR_TARGETS = [
    1e-2,
    1e-3,
    1e-4,
]

PAD = 0
UNK = 1
SEED = 42

device = (
    "cuda"
    if torch.cuda.is_available()
    else "mps"
    if torch.backends.mps.is_available()
    else "cpu"
)


# -----------------------------------
# Reproducibility
# -----------------------------------

def set_seed(seed=SEED):
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)

    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(seed)


# -----------------------------------
# Behavioral Features
# -----------------------------------

def add_features(df):
    """
    Calculate behavioral features using
    past and current activity for each user.
    """

    df["f_dst_new"] = (
        df.groupby([COL_USER, "dst_comp"])
        .cumcount()
        .eq(0)
        .astype(np.float32)
    )

    df["f_edge_new"] = (
        df.groupby([
            COL_USER,
            "src_comp",
            "dst_comp",
        ])
        .cumcount()
        .eq(0)
        .astype(np.float32)
    )

    df["f_src_new"] = (
        df.groupby([COL_USER, "src_comp"])
        .cumcount()
        .eq(0)
        .astype(np.float32)
    )

    df["f_same"] = (
        df["src_comp"] == df["dst_comp"]
    ).astype(np.float32)

    time_diff = (
        df.groupby(COL_USER)[COL_TIME]
        .diff()
        .fillna(1e5)
        .clip(lower=0)
    )

    df["f_dt"] = (
        np.log1p(time_diff) / 12
    ).astype(np.float32)

    hour = (
        df[COL_TIME] % 86400
    ) / 3600

    df["f_hs"] = np.sin(
        2 * np.pi * hour / 24
    ).astype(np.float32)

    df["f_hc"] = np.cos(
        2 * np.pi * hour / 24
    ).astype(np.float32)

    df["f_new_rate"] = (
        df.groupby(COL_USER)["f_dst_new"]
        .transform(
            lambda s: s.rolling(
                WINDOW,
                min_periods=1,
            ).mean()
        )
        .astype(np.float32)
    )

    return df


# -----------------------------------
# Load Data
# -----------------------------------

def load(path):
    print("Loading dataset...")

    df = pd.read_csv(path)

    required = [
        COL_TIME,
        COL_USER,
        COL_LABEL,
        COL_SPLIT,
        *COL_EVENT,
    ]

    missing = [
        c for c in required
        if c not in df.columns
    ]

    if missing:
        raise ValueError(
            f"Missing columns: {missing}"
        )

    df["token"] = (
        df[COL_EVENT]
        .astype(str)
        .agg("|".join, axis=1)
    )

    df = df.sort_values(
        [COL_USER, COL_TIME],
        kind="stable",
    ).reset_index(drop=True)

    print(f"Loaded {len(df):,} events")

    # Check chronological split ordering.
    # -1 = warm-up, 0 = train,
    # 1 = validation, 2 = test.
    splits = df[COL_SPLIT].to_numpy()

    if not np.isin(
        splits, [-1, 0, 1, 2]
    ).all():
        raise ValueError(
            "Unexpected data split values."
        )

    # Each user must move forward through
    # the splits, never backward.
    bad_order = (
        df.groupby(COL_USER)[COL_SPLIT]
        .diff()
        .dropna()
        .lt(0)
        .any()
    )

    if bad_order:
        raise ValueError(
            "Non-chronological splits detected. "
            "Check split assignments before "
            "preserving event history."
        )

    # Also check chronological time boundaries
    # across the full dataset.
    time_ranges = (
        df[df[COL_SPLIT].isin([0, 1, 2])]
        .groupby(COL_SPLIT)[COL_TIME]
        .agg(["min", "max"])
    )

    for earlier, later in [(0, 1), (1, 2)]:
        if earlier in time_ranges.index and later in time_ranges.index:
            if (
                time_ranges.loc[earlier, "max"]
                > time_ranges.loc[later, "min"]
            ):
                raise ValueError(
                    "Training, validation, and test "
                    "time ranges overlap or are "
                    "not globally chronological."
                )

    print("Chronological split check passed")

    print("Calculating behavioral features...")
    df = add_features(df)

    return df


# -----------------------------------
# Vocabulary
# -----------------------------------

def build_vocab(train_df):
    counts = (
        train_df["token"]
        .value_counts()
        .head(MAX_VOCAB - 2)
    )

    return {
        token: i + 2
        for i, token in enumerate(counts.index)
    }


# -----------------------------------
# Event Sequences - V3 Improvement
# -----------------------------------

def make_windows(df, vocab, target_split):
    """
    Build event sequences while preserving
    earlier authentication history.

    Each event receives its own sequence.
    Only rows in target_split are returned.
    """

    Xs = []
    Fs = []
    ys = []

    for _, group in df.groupby(
        COL_USER,
        sort=False,
    ):
        ids = (
            group["token"]
            .map(vocab)
            .fillna(UNK)
            .astype(np.int64)
            .to_numpy()
        )

        padded = np.concatenate([
            np.full(
                WINDOW - 1,
                PAD,
                dtype=np.int64,
            ),
            ids,
        ])

        windows = sliding_window_view(
            padded,
            WINDOW,
        )

        mask = (
            group[COL_SPLIT].to_numpy()
            == target_split
        )

        if not mask.any():
            continue

        Xs.append(
            windows[mask].copy()
        )

        Fs.append(
            group.loc[
                mask, FEATS
            ].to_numpy(np.float32)
        )

        ys.append(
            group.loc[
                mask, COL_LABEL
            ].to_numpy(np.float32)
        )

    if not Xs:
        raise ValueError(
            f"No events for split {target_split}"
        )

    return (
        np.concatenate(Xs),
        np.concatenate(Fs),
        np.concatenate(ys),
    )


# -----------------------------------
# Supervised LSTM Model
# -----------------------------------

class SupervisedAttackLSTM(nn.Module):

    def __init__(self, vocab_size):
        super().__init__()

        self.emb = nn.Embedding(
            vocab_size,
            EMB,
            padding_idx=PAD,
        )

        self.drop = nn.Dropout(DROPOUT)

        self.lstm = nn.LSTM(
            input_size=EMB,
            hidden_size=HIDDEN,
            num_layers=LAYERS,
            batch_first=True,
        )

        self.head = nn.Sequential(
            nn.Dropout(DROPOUT),
            nn.Linear(
                HIDDEN + len(FEATS),
                1,
            ),
        )

    def forward(self, x, f):
        x = self.drop(self.emb(x))

        h, _ = self.lstm(x)

        last_hidden = h[:, -1, :]

        combined = torch.cat(
            [last_hidden, f],
            dim=1,
        )

        return self.head(
            combined
        ).squeeze(-1)


# -----------------------------------
# Data Loader
# -----------------------------------

def loader(X, F, y, shuffle=False):

    dataset = TensorDataset(
        torch.from_numpy(X),
        torch.from_numpy(F),
        torch.from_numpy(y),
    )

    return DataLoader(
        dataset,
        batch_size=BATCH,
        shuffle=shuffle,
        pin_memory=(device == "cuda"),
    )


# -----------------------------------
# Predictions
# -----------------------------------

@torch.no_grad()
def predict_probs(model, X, F, y):

    model.eval()
    probs = []

    for xb, fb, _ in loader(
        X, F, y, shuffle=False
    ):
        xb = xb.to(device)
        fb = fb.to(device)

        logits = model(xb, fb)

        predictions = torch.sigmoid(
            logits
        ).cpu().numpy()

        probs.append(predictions)

    return np.concatenate(probs)


# -----------------------------------
# Training
# -----------------------------------

def train(
    model,
    Xtr, Ftr, ytr,
    Xva, Fva, yva,
):

    n_pos = float(ytr.sum())

    if n_pos == 0:
        raise ValueError(
            "No positive training examples."
        )

    n_neg = float(len(ytr) - n_pos)

    raw_weight = n_neg / n_pos

    pos_weight = torch.tensor(
        [min(raw_weight, MAX_POS_WEIGHT)],
        device=device,
    )

    print(
        f"Training positives: {int(n_pos):,}"
        f" / {len(ytr):,}"
    )

    print(
        f"Positive weight: "
        f"{pos_weight.item():.2f}"
    )

    optimizer = torch.optim.Adam(
        model.parameters(),
        lr=LR,
    )

    criterion = nn.BCEWithLogitsLoss(
        pos_weight=pos_weight
    )

    best_pr_auc = -1.0
    best_state = None

    for epoch in range(EPOCHS):

        model.train()

        total_loss = 0.0
        total_samples = 0

        for xb, fb, yb in loader(
            Xtr, Ftr, ytr, shuffle=True
        ):

            xb = xb.to(device)
            fb = fb.to(device)
            yb = yb.to(device)

            optimizer.zero_grad()

            logits = model(xb, fb)

            loss = criterion(
                logits,
                yb,
            )

            loss.backward()

            nn.utils.clip_grad_norm_(
                model.parameters(),
                1.0,
            )

            optimizer.step()

            total_loss += (
                loss.item() * len(xb)
            )

            total_samples += len(xb)

        val_probs = predict_probs(
            model, Xva, Fva, yva
        )

        val_roc = roc_auc_score(
            yva, val_probs
        )

        val_pr = average_precision_score(
            yva, val_probs
        )

        avg_loss = (
            total_loss / total_samples
        )

        print(
            f"Epoch {epoch + 1}/{EPOCHS} | "
            f"Loss: {avg_loss:.4f} | "
            f"ROC-AUC: {val_roc:.4f} | "
            f"PR-AUC: {val_pr:.4f}"
        )

        if val_pr > best_pr_auc:

            best_pr_auc = val_pr

            best_state = copy.deepcopy(
                model.state_dict()
            )

            print("  New best model")

    model.load_state_dict(best_state)

    print(
        f"\nBest validation PR-AUC: "
        f"{best_pr_auc:.4f}"
    )

    return model


# -----------------------------------
# Evaluation - V3 Improvement
# -----------------------------------

def evaluate(
    val_scores,
    val_labels,
    test_scores,
    test_labels,
):

    print("\n" + "=" * 50)
    print("V3 TEST RESULTS")
    print("=" * 50)

    print(
        f"Test events: {len(test_labels):,}"
    )

    print(
        f"Red-team events: "
        f"{int(test_labels.sum()):,}"
    )

    roc = roc_auc_score(
        test_labels,
        test_scores,
    )

    pr = average_precision_score(
        test_labels,
        test_scores,
    )

    print(f"\nROC-AUC: {roc:.4f}")
    print(f"PR-AUC:  {pr:.4f}")

    benign_val = val_scores[
        val_labels == 0
    ]

    print("\nThreshold comparison:")

    for target_fpr in FPR_TARGETS:

        threshold = np.quantile(
            benign_val,
            1 - target_fpr,
        )

        predictions = (
            test_scores >= threshold
        ).astype(int)

        tn, fp, fn, tp = confusion_matrix(
            test_labels,
            predictions,
            labels=[0, 1],
        ).ravel()

        precision = precision_score(
            test_labels,
            predictions,
            zero_division=0,
        )

        recall = recall_score(
            test_labels,
            predictions,
            zero_division=0,
        )

        f1 = f1_score(
            test_labels,
            predictions,
            zero_division=0,
        )

        actual_fpr = (
            fp / (fp + tn)
            if fp + tn > 0
            else 0
        )

        print("\n" + "-" * 40)

        print(
            f"Target FPR: {target_fpr:g}"
        )

        print(
            f"Threshold: {threshold:.4f}"
        )

        print(
            f"Attacks detected: "
            f"{tp}/{int(test_labels.sum())}"
        )

        print(
            f"Missed attacks: {fn}"
        )

        print(
            f"False alerts: {fp:,}"
        )

        print(
            f"Actual FPR: {actual_fpr:.5f}"
        )

        print(
            f"Precision: {precision:.4f}"
        )

        print(
            f"Recall: {recall:.4f}"
        )

        print(
            f"F1 score: {f1:.4f}"
        )


# -----------------------------------
# Main
# -----------------------------------

def main():

    set_seed()

    print("=" * 50)
    print("MITRE SUPERVISED LSTM - VERSION 3")
    print("=" * 50)

    print(f"Using device: {device}")

    df = load(PATH)

    # Training vocabulary only.
    train_df = df[
        df[COL_SPLIT] == 0
    ]

    vocab = build_vocab(train_df)

    print(
        f"Vocabulary size: "
        f"{len(vocab) + 2:,}"
    )

    # Preserve chronological history.
    data = {}

    for split in (0, 1, 2):

        X, F, y = make_windows(
            df,
            vocab,
            split,
        )

        data[split] = (X, F, y)

        print(
            f"Split {split}: "
            f"{len(X):,} samples | "
            f"{int(y.sum())} red-team"
        )

    # Check unseen event tokens.
    print("\nUnknown token rates:")

    for split, (X, F, y) in data.items():

        last_tokens = X[:, -1]

        benign = last_tokens[y == 0]
        attacks = last_tokens[y == 1]

        benign_rate = (
            np.mean(benign == UNK)
            if len(benign)
            else float("nan")
        )

        attack_rate = (
            np.mean(attacks == UNK)
            if len(attacks)
            else float("nan")
        )

        print(
            f"Split {split} | "
            f"Benign: {benign_rate:.4f} | "
            f"Red-team: {attack_rate:.4f}"
        )

    # Initialize model.
    model = SupervisedAttackLSTM(
        len(vocab) + 2
    ).to(device)

    # Train.
    model = train(
        model,
        *data[0],
        *data[1],
    )

    # Predict.
    val_scores = predict_probs(
        model,
        *data[1],
    )

    test_scores = predict_probs(
        model,
        *data[2],
    )

    # Evaluate.
    evaluate(
        val_scores,
        data[1][2],
        test_scores,
        data[2][2],
    )


if __name__ == "__main__":
    main()
