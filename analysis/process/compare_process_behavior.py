
from pathlib import Path
from collections import defaultdict
from bisect import bisect_left, bisect_right

import pandas as pd

ROOT = Path(__file__).resolve().parents[2]

AUTH_FILE = ROOT / "output/multi_user_features_large.csv"
PROC_FILE = ROOT.parent / "proc_attack_window_large.txt"
OUTPUT_FILE = ROOT / "output/process_behavior_comparison.csv"

WINDOW = 300

auth = pd.read_csv(AUTH_FILE)
auth = auth.sort_values("time").reset_index(drop=True)

attacks = auth[auth["attack"] == 1].copy()
other_events = auth[auth["attack"] == 0].copy()

print("Known attack events:", len(attacks))
print("Other authentication events:", len(other_events))

# Only compare destination computers where process data exists.
process_times = defaultdict(list)
process_names = defaultdict(list)

target_computers = set(auth["destination_computer"].dropna())

columns = [
    "time", "user", "computer", "process_name", "event_type"
]

for chunk in pd.read_csv(
    PROC_FILE, names=columns, chunksize=200_000
):
    chunk = chunk[
        (chunk["computer"].isin(target_computers))
        & (chunk["event_type"] == "Start")
    ]

    for computer, group in chunk.groupby("computer"):
        process_times[computer].extend(group["time"].tolist())
        process_names[computer].extend(
            group["process_name"].tolist()
        )

# Sort timestamps and associated processes together.
for computer in process_times:
    pairs = sorted(
        zip(process_times[computer], process_names[computer])
    )
    process_times[computer] = [t for t, p in pairs]
    process_names[computer] = [p for t, p in pairs]

attack_locations = [
    (int(row.time), row.destination_computer)
    for row in attacks.itertuples()
]

def overlaps_known_attack(time, computer):
    return any(
        computer == attack_computer
        and abs(time - attack_time) <= 2 * WINDOW
        for attack_time, attack_computer in attack_locations
    )

def measure_event(row, label):
    computer = row["destination_computer"]

    if computer not in process_times:
        return None

    time = int(row["time"])
    times = process_times[computer]
    names = process_names[computer]

    left = bisect_left(times, time - WINDOW)
    right = bisect_right(times, time + WINDOW)

    return {
        "time": time,
        "computer": computer,
        "group": label,
        "process_starts": right - left,
        "unique_processes": len(set(names[left:right]))
    }

results = []

for _, row in attacks.iterrows():
    result = measure_event(row, "known_attack")
    if result is not None:
        results.append(result)

for _, row in other_events.iterrows():
    if overlaps_known_attack(
        int(row["time"]), row["destination_computer"]
    ):
        continue

    result = measure_event(row, "unlabeled")
    if result is not None:
        results.append(result)

df = pd.DataFrame(results)
df.to_csv(OUTPUT_FILE, index=False)

print("\nPROCESS BEHAVIOR COMPARISON")
print("=" * 40)

if not df.empty:
    print("Events analyzed:", len(df))
    print("\nEvent counts:")
    print(df["group"].value_counts())

    print("\nAverage process activity:")
    print(
        df.groupby("group")[
            ["process_starts", "unique_processes"]
        ].mean().round(2)
    )
else:
    print("No matching events with process telemetry.")

print("\nSaved:", OUTPUT_FILE)
