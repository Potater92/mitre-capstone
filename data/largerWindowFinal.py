import gzip, zlib, requests
import pandas as pd
from pathlib import Path
URL = "https://lanl.ma.ic.ac.uk/data/cyber1/auth.txt.gz"
OUT = r"auth_attack_final2.csv"
SAMPLE_PERCENT = 5            # keep 0.5% of non-red-team users
SPLITS = [(150000, 864000), (864000, 1123200), (1123200, 2225000)]  # half-open [a, b) to avoid window overlap
# Training split goes up to day 9, validation is day 10-12, and test is day 13 onward
MIN_T = 0
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

def is_automated_user(u):
    #checks for automated users or scanners
    return u.split("@")[0].endswith("$")

def keep_user(u):
    if u in red_users:
        return True
    if is_automated_user(u):
        return False
    return (zlib.crc32(u.encode()) % 1000) < (SAMPLE_PERCENT * 10)  # stable across runs, so we should all get the exact same final dataset

with requests.get(URL, stream=True) as r, \
     gzip.open(r.raw, "rt") as f, \
     open(OUT, "w") as out:
    out.write("time,src_user,dst_user,src_comp,dst_comp,auth_type,"
              "logon_type,orientation,outcome,label,split\n")
    for line in f:
        p = line.rstrip("\n").split(",")
        t = int(p[0])
        if t < MIN_T: #skips writing before the first window
            continue
        if t >= MAX_T: #stops the loop if we reach the end of the test window
            break
        if p[7] != "LogOn": #skips any event that isn't a logon, since attacks are only logging in, and not logging out
            continue
        if not keep_user(p[1]):
            continue
        label = int((t, p[1], p[3], p[4]) in red_events)
        out.write(f"{line.rstrip()},{label},{split_id(t)}\n")