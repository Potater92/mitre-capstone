
from pathlib import Path
import pandas as pd

ROOT = Path(__file__).resolve().parents[2]

AUTH_FILE = ROOT / "output/multi_user_features_large.csv"
PROC_FILE = ROOT.parent / "proc_attack_window_large.txt"
OUTPUT_FILE = ROOT / "output/process_attack_correlation.csv"

PROC_COLUMNS = [
    "time", "user", "computer", "process_name", "event_type"
]

# Load the known red-team authentication events.
auth = pd.read_csv(AUTH_FILE)

attacks = auth.loc[
    auth["attack"] == 1,
    ["time", "source_user", "source_computer",
     "destination_computer"]
].drop_duplicates().reset_index(drop=True)

print("Known attack events:", len(attacks))

# Prepare one observation window for each attack computer.
windows = []

for attack_id, row in attacks.iterrows():
    for role in ["source", "destination"]:
        computer = row[f"{role}_computer"]

        windows.append({
            "attack_id": attack_id,
            "time": int(row["time"]),
            "source_user": row["source_user"],
            "role": role,
            "computer": computer,
            "starts": 0,
            "ends": 0,
            "processes": set()
        })

target_computers = {w["computer"] for w in windows}

# Read the process data without loading it all at once.
for chunk in pd.read_csv(
    PROC_FILE,
    names=PROC_COLUMNS,
    chunksize=200_000
):
    chunk = chunk[
        chunk["computer"].isin(target_computers)
    ]

    for window in windows:
        nearby = chunk[
            (chunk["computer"] == window["computer"])
            & (chunk["time"] >= window["time"] - 300)
            & (chunk["time"] <= window["time"] + 300)
        ]

        starts = nearby[
            nearby["event_type"] == "Start"
        ]

        window["starts"] += len(starts)
        window["ends"] += (
            nearby["event_type"] == "End"
        ).sum()

        window["processes"].update(
            starts["process_name"].dropna()
        )

# Save the results.
results = []

for window in windows:
    results.append({
        "attack_id": window["attack_id"],
        "time": window["time"],
        "source_user": window["source_user"],
        "role": window["role"],
        "computer": window["computer"],
        "process_starts": window["starts"],
        "process_ends": window["ends"],
        "unique_started_processes": len(
            window["processes"]
        )
    })

df = pd.DataFrame(results)
df.to_csv(OUTPUT_FILE, index=False)

print("\nPROCESS ATTACK CORRELATION")
print("=" * 40)
print("Known attacks:", len(attacks))
print("Computer windows analyzed:", len(df))
print("\nProcess starts near attack events:")
print(df.groupby("role")["process_starts"].describe())
print("\nFirst 10 results:")
print(df.head(10).to_string(index=False))
print("\nSaved:", OUTPUT_FILE)

