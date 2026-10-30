"Checking for lateral movement T1021 (Remote Services)"
from pathlib import Path

import pandas as pd
import yaml
import operator
ROOT = Path(__file__).resolve().parents[2]
AUTH_FILE_PATH = ROOT / "data" / "auth_attack_window_large.txt"
RULES_DIRECTORY = ROOT / "analysis" / "sigmaRuleYAMLs" / "t1021"
REDTEAM_FILE_PATH = ROOT / "data" / "redteam.txt"


AUTH_COLUMNS = ["time", "source_user", "destination_user", "source_computer",
                "destination_computer", "authentication_type", "logon_type",
                "orientation", "result"]
LOAD_COLUMNS = ["time", "source_user", "source_computer", "destination_computer",
                "authentication_type", "logon_type", "orientation", "result"]

# Sigma-style field name -> column name. The ONLY place column names are mapped.
FIELD_MAP = {
    "User": "source_user",
    "SrcComputer": "source_computer",
    "DstComputer": "destination_computer",
    "NewDestination": "new_destination",
    "PriorPairCount": "prior_pair_count",
    "AuthType": "authentication_type",
    "LogonType": "logon_type",
    "Orientation": "orientation",
    "Outcome": "result",
}
UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400}
NUMERIC_OPS = {"lt": operator.lt, "lte": operator.le, "gt": operator.gt, "gte": operator.ge}


def parse_timespan(text: str) -> int:
    return int(text[:-1]) * UNITS[text[-1]]


def field_mask(df, key, expected):
    """Evaluate one 'Field' or 'Field|modifier' entry; a list means OR."""
    field, _, modifier = key.partition("|")
    series = df[FIELD_MAP[field]]
    values = expected if isinstance(expected, list) else [expected]
    if modifier in NUMERIC_OPS:                      # lt / lte / gt / gte
        return NUMERIC_OPS[modifier](pd.to_numeric(series), expected)
    if modifier not in ("", "startswith", "endswith"):
        raise ValueError(f"Unsupported modifier '|{modifier}' in key '{key}'")
    if modifier == "" and pd.api.types.is_numeric_dtype(series):
        return series.isin(values)                   # numeric exact match, e.g. NewDestination: 1
    col = series.astype(str)
    mask = pd.Series(False, index=df.index)
    for v in values:
        v = str(v)
        if modifier == "startswith":
            mask |= col.str.startswith(v)
        elif modifier == "endswith":
            mask |= col.str.endswith(v)
        else:
            mask |= col == v
    return mask


def block_mask(df, block):
    """All fields in a selection/filter block must match (AND)."""
    mask = pd.Series(True, index=df.index)
    for key, expected in block.items():
        mask &= field_mask(df, key, expected)
    return mask


def apply_base_rule(df, rule):
    det = rule["detection"]
    mask = block_mask(df, det["selection"])
    # Minimal condition support: "selection and not <filter> and not <filter> ..."
    for name, block in det.items():
        if name.startswith("filter") and f"not {name}" in det["condition"]:
            mask &= ~block_mask(df, block)
    return df[mask]


def apply_correlation(hits, rule):
    corr = rule["correlation"]
    span = parse_timespan(corr["timespan"])
    group = [FIELD_MAP[f] for f in corr["group-by"]]
    count_field = FIELD_MAP[corr["condition"]["field"]]
    threshold = corr["condition"]["gte"]

    # Tumbling windows: simple, but a burst can be split across a boundary.
    hits = hits.assign(window=hits["time"] // span)
    counts = (hits.groupby(group + ["window"])[count_field]
                  .nunique().rename("distinct_count").reset_index())
    alerts = counts[counts["distinct_count"] >= threshold].copy()
    alerts["techniques"] = ",".join(t for t in rule["tags"] if t.startswith("attack.t"))
    alerts["rule"] = rule["name"]
    return alerts, hits, group


def detect(df, rule_path):
    with open(rule_path) as f:
        docs = list(yaml.safe_load_all(f))
    base = docs[0]
    hits = apply_base_rule(df, base)
    if len(docs) > 1:                                # correlation rule: count over a window
        alerts, hits, group = apply_correlation(hits, docs[1])
        flagged = hits.merge(alerts[group + ["window"]], on=group + ["window"])
    else:                                            # event-level rule: every match is an alert
        hits = hits.assign(window=range(len(hits)))  # unique id, so each event is its own alert
        alerts = hits.copy()
        alerts["distinct_count"] = 1                 # keeps the sort in __main__ working
        alerts["techniques"] = ",".join(t for t in base.get("tags", []) if t.startswith("attack.t"))
        alerts["rule"] = base["name"]
        flagged = hits
    return alerts, flagged, hits


def _pct(num, den):
    return f"{100 * num / den:.2f}%" if den else "n/a"


def evaluate(df, alerts, flagged, hits, redteam_path):
    """Print precision/recall and supporting diagnostics against redteam.txt."""
    USER, SRC, DST = FIELD_MAP["User"], FIELD_MAP["SrcComputer"], FIELD_MAP["DstComputer"]
    keys = ["time", USER, SRC, DST]

    rt = pd.read_csv(redteam_path, header=None, names=["time", "user", SRC, DST])
    rt = rt.rename(columns={"user": USER})
    t0, t1 = df["time"].min(), df["time"].max()
    rt_all = len(rt)
    rt = rt[(rt["time"] >= t0) & (rt["time"] <= t1)].drop_duplicates(keys)
    n_rt = len(rt)

    # Event-level counts (deduplicated on the join keys)
    in_auth = rt.merge(df[keys].drop_duplicates(), on=keys)
    passed_base = rt.merge(hits[keys].drop_duplicates(), on=keys)
    flagged_keys = flagged[keys].drop_duplicates()
    caught = rt.merge(flagged_keys, on=keys)

    tp, n_flagged = len(caught), len(flagged_keys)
    fp = n_flagged - tp
    fn = n_rt - tp
    precision = tp / n_flagged if n_flagged else 0.0
    recall = tp / n_rt if n_rt else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0

    days = max((t1 - t0) / 86400, 1e-9)

    print("=" * 60)
    print(f"Window: time {t0} to {t1}  ({days:.2f} days, {len(df):,} auth events)")
    print(f"Red team events: {rt_all} in file, {n_rt} inside this window")
    print(f"  base rate: {n_rt / len(df):.2e} ({n_rt / len(df) * 1e6:.2f} per million events)")

    print("\n-- Label sanity check --")
    print(f"Red team events found in auth data:   {len(in_auth)} / {n_rt} ({_pct(len(in_auth), n_rt)})")
    print(f"Red team events passing the base rule: {len(passed_base)} / {n_rt} ({_pct(len(passed_base), n_rt)})")

    print("\n-- Event-level performance --")
    print(f"Flagged events: {n_flagged:,}   TP: {tp}   FP: {fp:,}   FN: {fn}")
    print(f"Precision: {precision:.4f}   Recall: {recall:.4f}   F1: {f1:.4f}")

    print("\n-- Alert-level (user-window) performance --")
    fl = flagged.merge(rt[keys].assign(is_rt=1), on=keys, how="left")
    fl["is_rt"] = fl["is_rt"].fillna(0)
    per_alert = fl.groupby([USER, "window"])["is_rt"].max()
    n_alerts, good_alerts = len(alerts), int(per_alert.sum())
    print(f"Alerts: {n_alerts}   containing >=1 red team event: {good_alerts}   "
          f"alert precision: {_pct(good_alerts, n_alerts)}")
    print(f"Alerts per day: {n_alerts / days:.1f}")

    print("\n-- User-level --")
    rt_users, alert_users = set(rt[USER]), set(alerts[USER])
    print(f"Red team users in window: {len(rt_users)}   triggering any alert: "
          f"{len(rt_users & alert_users)}   alerting users overall: {len(alert_users)}")

    print("\n-- Who dominates the alerts? (check for scanners/service accounts) --")
    top = flagged[USER].value_counts().head(5)
    for user, n in top.items():
        print(f"  {user}: {n:,} flagged events ({_pct(n, len(flagged))} of all flagged)")
    print("=" * 60)

def add_history_features(df):
    """Causal features: how many times has this user already logged into this destination?"""
    USER, DST = FIELD_MAP["User"], FIELD_MAP["DstComputer"]
    df = df.sort_values("time", kind="stable").copy()
    df["prior_pair_count"] = df.groupby([USER, DST]).cumcount()   # 0 = first time seen
    df["new_destination"] = (df["prior_pair_count"] == 0).astype(int)
    return df

if __name__ == "__main__":
    df = pd.read_csv(AUTH_FILE_PATH, header=None, names=AUTH_COLUMNS,
                     usecols=LOAD_COLUMNS, dtype={"time": "int64"})
    df = add_history_features(df)
    missing = [c for c in FIELD_MAP.values() if c not in df.columns]
    if missing:
        raise ValueError(f"FIELD_MAP refers to columns not in the data: {missing}")

    for rule_path in sorted(RULES_DIRECTORY.glob("*.yml")):
        alerts, flagged, hits = detect(df, rule_path)
        print(f"\n### {rule_path.name}: {len(alerts)} alerts, {len(flagged):,} flagged events")
        if REDTEAM_FILE_PATH is not None and len(alerts) > 0:
            evaluate(df, alerts, flagged, hits, REDTEAM_FILE_PATH)