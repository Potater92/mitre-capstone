
from pathlib import Path
from collections import Counter
import pandas as pd

ROOT = Path(__file__).resolve().parents[2]
DATA_FILE = ROOT.parent / "proc_attack_window_large.txt"
OUTPUT_FILE = ROOT / "output" / "process_frequency.csv"

columns = [
    "time",
    "user",
    "computer",
    "process_name",
    "event_type"
]

total_events = 0
event_counts = Counter()
process_counts = Counter()
computer_counts = Counter()

users = set()
processes = set()

print("Analyzing LANL process activity...")

for chunk in pd.read_csv(
    DATA_FILE,
    names=columns,
    chunksize=200_000
):
    total_events += len(chunk)

    event_counts.update(
        chunk["event_type"].value_counts().to_dict()
    )

    process_counts.update(
        chunk.loc[
            chunk["event_type"] == "Start",
            "process_name"
        ].value_counts().to_dict()
    )

    computer_counts.update(
        chunk["computer"].value_counts().to_dict()
    )

    users.update(chunk["user"].dropna().unique())
    processes.update(chunk["process_name"].dropna().unique())

summary = pd.DataFrame(
    process_counts.most_common(),
    columns=["process_name", "start_count"]
)

summary.to_csv(OUTPUT_FILE, index=False)

print("\nPROCESS ACTIVITY ANALYSIS")
print("=" * 40)

print("Total events:", total_events)
print("Process starts:", event_counts["Start"])
print("Process ends:", event_counts["End"])
print("Unique users:", len(users))
print("Unique computers:", len(computer_counts))
print("Unique process identifiers:", len(processes))

print("\nTOP 10 MOST COMMON PROCESSES")
print(summary.head(10).to_string(index=False))

print("\nTOP 10 MOST ACTIVE COMPUTERS")
for computer, count in computer_counts.most_common(10):
    print(computer, count)

print("\nSaved:", OUTPUT_FILE)
