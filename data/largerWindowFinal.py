import gzip, zlib, requests
import pandas as pd
from pathlib import Path
URL = "https://lanl.ma.ic.ac.uk/data/cyber1/auth.txt.gz"
OUT = r"auth_attack_final.csv"
SAMPLE_PERCENT = 5            # keep 5% of non-red-team users
SPLITS = [(0, 1078024), (1078024, 1177988), (1177988, 2557048)]  # half-open [a, b) to avoid window overlap
MAX_T = SPLITS[-1][1]

red = pd.read_csv(r"redteam.txt",
                  names=["time", "user", "src", "dst"])
red_users = set(red.user)
red_events = set(zip(red.time, red.user, red.src, red.dst))

def split_id(t):
    for i, (a, b) in enumerate(SPLITS):
        if a <= t < b:
            return i
    return -1

def keep_user(u):
    if u in red_users:
        return True
    return zlib.crc32(u.encode()) % 100 < SAMPLE_PERCENT  # stable across runs, so we should all get the exact same final dataset

with requests.get(URL, stream=True) as r, \
     gzip.open(r.raw, "rt") as f, \
     open(OUT, "w") as out:
    out.write("time,src_user,dst_user,src_comp,dst_comp,auth_type,"
              "logon_type,orientation,outcome,label,split\n")
    for line in f:
        p = line.rstrip("\n").split(",")
        t = int(p[0])
        if t >= MAX_T:
            break
        if not keep_user(p[1]):
            continue
        label = int((t, p[1], p[3], p[4]) in red_events)
        out.write(f"{line.rstrip()},{label},{split_id(t)}\n")