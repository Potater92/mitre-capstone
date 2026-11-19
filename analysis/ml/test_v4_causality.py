import importlib.util
import numpy as np
import pandas as pd
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
path = ROOT / "analysis/ml/per_user_lstm_supervised_v4.py"

spec = importlib.util.spec_from_file_location("v4", path)
v4 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(v4)

rows = [
    (100, "U1", "C1", "D1", 0),
    (120, "U2", "C2", "D1", 0),
    (200, "U1", "C1", "D2", 0),
    (250, "U2", "C2", "D3", 0),
    (300, "U1", "C1", "D2", 1),
    (350, "U2", "C2", "D4", 1),
    (400, "U1", "C3", "D5", 2),
    (450, "U2", "C2", "D1", 2),
]

df = pd.DataFrame(
    rows,
    columns=["time", "src_user", "src_comp", "dst_comp", "split"]
)
df["auth_type"] = "NTLM"
df["logon_type"] = "Network"
df["label"] = 0

def prepare(data):
    data = data.sort_values(
        ["src_user", "time"], kind="stable"
    ).reset_index(drop=True)
    return v4.add_features(data)

# Compare earlier features with and without future events.
full = prepare(df.copy())
past = prepare(df[df.time <= 350].copy())

keys = ["time", "src_user"]
earlier = full[full.time <= 350].sort_values(keys)
past_sorted = past.sort_values(keys)

np.testing.assert_allclose(
    earlier[v4.FEATS].to_numpy(),
    past_sorted[v4.FEATS].to_numpy(),
    rtol=0,
    atol=1e-6
)
print("PASS: Future events do not change earlier features")

vocabs = [
    {"C1": 2, "C2": 3, "C3": 4},
    {"D1": 2, "D2": 3, "D3": 4, "D4": 5, "D5": 6},
    {"NTLM": 2},
    {"Network": 2},
]

X_full, F_full, y_full = v4.make_windows(full, vocabs, 1)
X_past, F_past, y_past = v4.make_windows(past, vocabs, 1)

np.testing.assert_array_equal(X_full, X_past)
np.testing.assert_allclose(F_full, F_past)
np.testing.assert_array_equal(y_full, y_past)

print("PASS: Future events do not change earlier LSTM inputs")
print("PASS: Earlier labels remain aligned")
print("CAUSALITY TEST COMPLETE")
