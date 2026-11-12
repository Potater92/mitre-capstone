
import gzip
from pathlib import Path
from urllib.request import urlopen

# LANL authentication dataset
URL = "https://lanl.ma.ic.ac.uk/data/cyber1/auth.txt.gz"

# New validation window
START_TIME = 390001
END_TIME = 470000

ROOT = Path(__file__).resolve().parents[2]

# Save outside the repository, separate from original data
OUTPUT = ROOT.parent / "auth_validation_390001_470000.txt"

total_events = 0
saved_events = 0

print("Extracting LANL authentication validation data...")

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

print("\nVALIDATION DATA EXTRACTION")
print("=" * 45)
print("Time range:", START_TIME, "to", END_TIME)
print("Events read:", total_events)
print("Events saved:", saved_events)
print("Output:", OUTPUT)
