from pathlib import Path
from collections import Counter

import pandas as pd

ROOT = Path(__file__).resolve().parents[2]
DNS_FILE = ROOT / "data" / "dns.csv"
redteam_columns = ["time", "user", "source_computer", "destination_computer"]
redteam = pd.read_csv(ROOT / "data" / "redteam.csv", names=redteam_columns)  # adjust name/format to match your file

print("Total red team events:", len(redteam))
print("Distinct users:", redteam["user"].nunique())
print("Distinct source computers:", redteam["source_computer"].nunique())
print("Distinct destination computers:", redteam["destination_computer"].nunique())

print("\nEvents per source computer:")
print(redteam["source_computer"].value_counts())

print("\nEvents per user:")
print(redteam["user"].value_counts())

all_red_sources = set(redteam["source_computer"])
all_red_dests = set(redteam["destination_computer"])

dns_columns = ["time", "source_computer", "resolved_computer"]

# Computers to look for  from the red team dataset
RED_TEAM_COMPUTERS = all_red_sources | all_red_dests

total_rows = 0
min_time, max_time = None, None
null_counts = Counter()
sources = set()
resolved = set()
not_c_prefix = 0
rows_per_day = Counter()
source_activity = Counter()
red_as_source = Counter()
red_as_resolved = Counter()

for chunk in pd.read_csv(DNS_FILE, names=dns_columns, chunksize=1_000_000):
    total_rows += len(chunk)

    t_min, t_max = chunk["time"].min(), chunk["time"].max()
    min_time = t_min if min_time is None else min(min_time, t_min)
    max_time = t_max if max_time is None else max(max_time, t_max)

    for col in dns_columns:
        null_counts[col] += chunk[col].isna().sum()

    sources.update(chunk["source_computer"].dropna().unique())
    resolved.update(chunk["resolved_computer"].dropna().unique())

    not_c_prefix += (~chunk["resolved_computer"].astype(str).str.startswith("C")).sum()

    rows_per_day.update((chunk["time"] // 86400).value_counts().to_dict())
    source_activity.update(chunk["source_computer"].value_counts().to_dict())

    red_as_source.update(chunk.loc[chunk["source_computer"].isin(RED_TEAM_COMPUTERS), "source_computer"].value_counts().to_dict())
    red_as_resolved.update(chunk.loc[chunk["resolved_computer"].isin(RED_TEAM_COMPUTERS), "resolved_computer"].value_counts().to_dict())

 
print("\n" + "=" * 40)
print("DNS PROFILE")
print("=" * 40)
print(f"Total rows:                 {total_rows:,}")
print(f"Time range (seconds):       {min_time:,} to {max_time:,}")
print(f"Days covered:               {(max_time - min_time) / 86400:.1f}")
print(f"Missing values:             {dict(null_counts)}")
print(f"Unique source computers:    {len(sources):,}")
print(f"Unique resolved computers:  {len(resolved):,}")
print(f"Resolved names not starting with 'C': {not_c_prefix:,}")
 
print("\nRed team computers in DNS:")
print(f"  Computers checked:          {len(RED_TEAM_COMPUTERS):,}")
print(f"  Seen as source:             {len(red_as_source):,} computers, "
      f"{sum(red_as_source.values()):,} rows")
print(f"  Seen as resolved:           {len(red_as_resolved):,} computers, "
      f"{sum(red_as_resolved.values()):,} rows")
 
print("\nTop 10 red team computers as source:")
for name, count in red_as_source.most_common(10):
    print(f"  {name:<10} {count:>10,}")
 
print("\nTop 10 busiest source computers (all):")
for name, count in source_activity.most_common(10):
    print(f"  {name:<10} {count:>10,}")
 
max_day = max(rows_per_day)
missing_days = [d for d in range(max_day + 1) if d not in rows_per_day]
print(f"\nDays with no rows: {missing_days if missing_days else 'none'}")
 
print("\nRows per day (day index):")
for day in sorted(rows_per_day):
    print(f"  {day:>3}  {rows_per_day[day]:>10,}")
