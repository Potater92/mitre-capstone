
import gzip
from pathlib import Path
from urllib.request import urlopen

URL = "https://lanl.ma.ic.ac.uk/data/cyber1/proc.txt.gz"

START_TIME = 150000
END_TIME = 230000

ROOT = Path(__file__).resolve().parents[2]
OUTPUT = ROOT.parent / "proc_attack_window_large.txt"

total_events = 0
saved_events = 0

print("Reading LANL process data...")

with urlopen(URL, timeout=120) as response:
    with gzip.GzipFile(fileobj=response) as source:
        with OUTPUT.open("w", encoding="utf-8") as output:
            for raw_line in source:
                line = raw_line.decode("utf-8").strip()

                if not line:
                    continue

                time = int(line.split(",", 1)[0])
                total_events += 1

                if time < START_TIME:
                    continue

                if time > END_TIME:
                    break

                output.write(line + "\n")
                saved_events += 1

print("\nPROCESS DATA EXTRACTION")
print("=" * 40)
print("Time range:", START_TIME, "to", END_TIME)
print("Events read:", total_events)
print("Events saved:", saved_events)
print("Output:", OUTPUT)
