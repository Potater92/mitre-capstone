
"""Run the saved LSTM on test data and export predictions."""

from __future__ import annotations
import csv
import hashlib
import importlib.util
import json
import math
import sqlite3
import tempfile
from collections import deque
from pathlib import Path
import numpy as np
import torch


ROOT = Path(__file__).resolve().parents[1]
DATA_FILE = ROOT / "data" / "auth_attack_final.csv"
MODEL_FILE = (
    ROOT / "analysis" / "ml" / "model" / "supervised_lstm.pt"
    )
MODEL_SOURCE = (
    ROOT / "analysis" / "ml" / "per_user_lstm_supervised_features.py"
    )
OUTPUT_FILE = ROOT / "output" / "lstm_predictions_test.csv"
FEATURE_NAMES = [
    "f_dst_new",
    "f_edge_new",
    "f_src_new",
    "f_same",
    "f_dt",
    "f_hs",
    "f_hc",
    "f_new_rate",
]
OUTPUT_COLUMNS = [
    "event_id",
    "time",
    "src_user",
    "src_comp",
    "dst_comp",
    "auth_type",
    "logon_type",
    "label",
    "attack_score",
    "f_dst_new",
    "f_edge_new",
    "f_src_new",
    "f_same",
    "seconds_since_previous",
    "f_new_rate",
]

def load_checkpoint(path):
    """Load our saved PyTorch checkpoint safely."""

    try:
        from numpy._core.multiarray import _reconstruct
    except ImportError:
        from numpy.core.multiarray import _reconstruct
    allowed = [
        _reconstruct,
        np.ndarray,
        np.dtype,
        type(np.dtype("float32")),
        type(np.dtype("float64")),
    ]
    with torch.serialization.safe_globals(allowed):
        return torch.load(
            path,
            map_location="cpu",
            weights_only=True,
        )

def load_model():
    """Load the model architecture matching the checkpoint."""

    if not MODEL_SOURCE.exists():
        raise FileNotFoundError(
            f"Missing model code: {MODEL_SOURCE}"
        )
    spec = importlib.util.spec_from_file_location(
        "supervised_features",
        MODEL_SOURCE,
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    checkpoint = load_checkpoint(MODEL_FILE)
    required = {
        "state_dict",
        "vocabs",
        "vocab_sizes",
        "mu",
        "sd",
        "feats",
        "col_event",
        "window",
        "thresholds",
        "emb_dims",
        "hidden",
        "layers",
    }
    missing = required - set(checkpoint)

    if missing:
        raise ValueError(
            f"Checkpoint is missing: {sorted(missing)}"
        )

    if list(checkpoint["feats"]) != FEATURE_NAMES:
        raise ValueError("Model feature definitions do not match.")

    if list(checkpoint["col_event"]) != [
        "src_comp",
        "dst_comp",
        "auth_type",
        "logon_type",
    ]:
        raise ValueError("Model event fields do not match.")

    if list(checkpoint["emb_dims"]) != list(module.EMB_DIMS):
        raise ValueError("Embedding dimensions do not match.")

    if (
        checkpoint["window"] != module.WINDOW
        or checkpoint["hidden"] != module.HIDDEN
        or checkpoint["layers"] != module.LAYERS
    ):
        raise ValueError("Model architecture does not match.")
    model = module.SupervisedAttackLSTM(
        list(checkpoint["vocab_sizes"])
    )
    model.load_state_dict(
        checkpoint["state_dict"],
        strict=True,
    )
    model.cpu()
    model.eval()

    return model, checkpoint

def create_database(connection):
    """Create a temporary database for sorting authentication events."""

    connection.execute(
        """
        CREATE TABLE auth (
            event_id INTEGER PRIMARY KEY,
            time INTEGER NOT NULL,
            src_user TEXT NOT NULL,
            src_comp TEXT,
            dst_comp TEXT,
            auth_type TEXT,
            logon_type TEXT,
            label INTEGER NOT NULL,
            split INTEGER NOT NULL
        )
        """
    )

def index_dataset(connection):
    """Read CSV into SQLite without loading everything into RAM."""

    print("Reading authentication dataset...", flush=True)
    connection.execute("PRAGMA journal_mode=OFF")
    connection.execute("PRAGMA synchronous=OFF")
    create_database(connection)
    count = 0
    batch = []
    with DATA_FILE.open(
        "r",
        newline="",
        encoding="utf-8",
    ) as stream:
        reader = csv.DictReader(stream)
        required = {
            "time",
            "src_user",
            "src_comp",
            "dst_comp",
            "auth_type",
            "logon_type",
            "label",
            "split",
        }
        missing = required - set(reader.fieldnames or [])

        if missing:
            raise ValueError(
                f"Dataset missing columns: {sorted(missing)}"
            )

        for count, row in enumerate(reader, start=1):
            batch.append(
                (
                    count - 1,
                    int(row["time"]),
                    row["src_user"],
                    row["src_comp"],
                    row["dst_comp"],
                    row["auth_type"],
                    row["logon_type"],
                    int(row["label"]),
                    int(row["split"]),
                )
            )
            if len(batch) >= 20000:
                connection.executemany(
                    "INSERT INTO auth VALUES (?,?,?,?,?,?,?,?,?)",
                    batch,
                )

                connection.commit()
                batch.clear()

            if count % 1000000 == 0:
                print(
                    f"Indexed {count:,} events",
                    flush=True,
                )

        if batch:
            connection.executemany(
                "INSERT INTO auth VALUES (?,?,?,?,?,?,?,?,?)",
                batch,
            )
            connection.commit()
    connection.execute(
        "CREATE INDEX by_user_time "
        "ON auth(src_user, time, event_id)"
    )
    connection.commit()

    print(f"Total dataset rows: {count:,}", flush=True)

    return count


def file_hash(path):
    """Identify exactly which model and dataset were used."""

    digest = hashlib.sha256()

    with path.open("rb") as stream:
        while True:
            block = stream.read(4 * 1024 * 1024)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()


def export_predictions():
    """Score test events using the saved trained LSTM."""

    if not DATA_FILE.exists():
        raise FileNotFoundError(DATA_FILE)

    if not MODEL_FILE.exists():
        raise FileNotFoundError(MODEL_FILE)
    model, checkpoint = load_model()
    vocabs = checkpoint["vocabs"]
    mu = np.asarray(
        checkpoint["mu"],
        dtype=np.float32,
    )
    sd = np.asarray(
        checkpoint["sd"],
        dtype=np.float32,
    )
    if (
        len(vocabs) != 4
        or len(mu) != 8
        or len(sd) != 8
        or np.any(sd == 0)
    ):
        raise ValueError("Unexpected model feature statistics.")
    thresholds = {
        str(float(key)): float(value)
        for key, value in checkpoint["thresholds"].items()
    }
    minimum_threshold = min(thresholds.values())
    window = int(checkpoint["window"])
    OUTPUT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True,
    )
    summary_file = OUTPUT_FILE.with_name(
        "lstm_predictions_test_summary.json"
    )
    with tempfile.TemporaryDirectory(
        prefix="mitre_lstm_"
    ) as temp_folder:
        database_path = Path(temp_folder) / "events.sqlite3"
        connection = sqlite3.connect(database_path)
        total_rows = index_dataset(connection)
        cursor = connection.execute(
            """
            SELECT
                event_id,
                time,
                src_user,
                src_comp,
                dst_comp,
                auth_type,
                logon_type,
                label,
                split
            FROM auth
            ORDER BY src_user, time, event_id
            """
        )
        current_user = None
        current_split = None
        seen_destinations = set()
        seen_connections = set()
        seen_sources = set()

        recent_new = deque(maxlen=10)
        recent_tokens = deque(maxlen=window)
        previous_time = None

        total_test_events = 0
        known_attacks = 0
        saved_events = 0

        tokens_batch = []
        features_batch = []
        rows_batch = []
        padding = (0, 0, 0, 0)

        def score_batch(writer):
            nonlocal saved_events
            if not rows_batch:
                return
            features = np.asarray(
                features_batch,
                dtype=np.float32,
            )
            features = (
                (features - mu) / sd
            ).astype(np.float32)
            tokens = torch.from_numpy(
                np.asarray(
                    tokens_batch,
                    dtype=np.int64,
                )
            )
            feature_tensor = torch.from_numpy(features)

            with torch.inference_mode():
                scores = torch.sigmoid(
                    model(tokens, feature_tensor)
                ).numpy()

            for row_data, score in zip(
                rows_batch,
                scores,
            ):
                score = float(score)

                # Keep every known red-team event and
                # every event that could be flagged
                # by any saved detection threshold.
                if (
                    int(row_data[7]) == 1
                    or score >= minimum_threshold
                ):
                    writer.writerow(
                        (
                            *row_data[:8],
                            score,
                            *row_data[8:],
                        )
                    )
                    saved_events += 1
            tokens_batch.clear()
            features_batch.clear()
            rows_batch.clear()

        with OUTPUT_FILE.open(
            "w",
            newline="",
            encoding="utf-8",
        ) as output:
            writer = csv.writer(output)
            writer.writerow(OUTPUT_COLUMNS)
            for row in cursor:
                (
                    event_id,
                    event_time,
                    user,
                    source,
                    destination,
                    auth_type,
                    logon_type,
                    label,
                    split,
                ) = row

                if user != current_user:
                    current_user = user
                    current_split = None
                    seen_destinations = set()
                    seen_connections = set()
                    seen_sources = set()

                    recent_new = deque(maxlen=10)
                    recent_tokens = deque(maxlen=window)
                    previous_time = None

                if split != current_split:
                    current_split = split
                    # The original LSTM constructs
                    # separate windows for each split.
                    recent_tokens.clear()

                destination_new = float(
                    destination not in seen_destinations
                )
                connection_key = (
                    source,
                    destination,
                )
                connection_new = float(
                    connection_key not in seen_connections
                )
                source_new = float(
                    source not in seen_sources
                )

                same_computer = float(
                    source == destination
                )

                seconds = (
                    100000
                    if previous_time is None
                    else max(0, event_time - previous_time)
                )
                hour = (
                    event_time % 86400
                ) / 3600
                recent_new.append(destination_new)

                new_rate = (
                    sum(recent_new) / len(recent_new)
                )
                feature_vector = [
                    destination_new,
                    connection_new,
                    source_new,
                    same_computer,
                    math.log1p(seconds) / 12,
                    math.sin(2 * math.pi * hour / 24),
                    math.cos(2 * math.pi * hour / 24),
                    new_rate,
                ]
                seen_destinations.add(destination)
                seen_sources.add(source)
                seen_connections.add(connection_key)
                previous_time = event_time

                # Only export testing split (split 2).
                # Earlier records still contribute to
                # historical authentication features.
                if split != 2:
                    continue

                total_test_events += 1
                known_attacks += int(label)
                fields = (
                    source,
                    destination,
                    auth_type,
                    logon_type,
                )
                token = tuple(
                    vocabulary.get(value, 1)
                    for vocabulary, value in zip(
                        vocabs,
                        fields,
                    )
                )
                recent_tokens.append(token)

                padded = (
                    [padding] * (window - len(recent_tokens))
                    + list(recent_tokens)
                )
                tokens_batch.append(padded)
                features_batch.append(feature_vector)

                rows_batch.append(
                    (
                        event_id,
                        event_time,
                        user,
                        source,
                        destination,
                        auth_type,
                        logon_type,
                        label,
                        int(destination_new),
                        int(connection_new),
                        int(source_new),
                        int(same_computer),
                        float(seconds),
                        float(new_rate),
                    )
                )
                if len(rows_batch) >= 2048:
                    score_batch(writer)

                if total_test_events % 250000 == 0:
                    print(
                        f"Scored {total_test_events:,} test events",
                        flush=True,
                    )
            score_batch(writer)
        connection.close()
    if total_test_events == 0:
        raise ValueError("No testing events found.")

    summary = {
        "split": 2,
        "total_scored_events": total_test_events,
        "known_red_team_events": known_attacks,
        "other_events": total_test_events - known_attacks,
        "saved_rows": saved_events,
        "thresholds": thresholds,
        "model_checkpoint_sha256": file_hash(MODEL_FILE),
        "data_csv_sha256": file_hash(DATA_FILE),
        "data_csv_rows": total_rows,
        "notes": (
            "Label 0 means no known red-team match. "
            "The LSTM score is not a calibrated probability."
        ),
    }

    summary_file.write_text(
        json.dumps(summary, indent=2),
        encoding="utf-8",
    )

    print()
    print("Prediction export complete!")
    print(f"Test events scored: {total_test_events:,}")
    print(f"Known red-team events: {known_attacks:,}")
    print(f"Saved prediction rows: {saved_events:,}")
    print(f"CSV: {OUTPUT_FILE}")
    print(f"Summary: {summary_file}")

if __name__ == "__main__":
    export_predictions()
