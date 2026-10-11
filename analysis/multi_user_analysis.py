import pandas as pd
from collections import deque, Counter

# -----------------------------
# Column names
# -----------------------------

auth_columns = [
    "time",
    "source_user",
    "destination_user",
    "source_computer",
    "destination_computer",
    "authentication_type",
    "logon_type",
    "orientation",
    "result"
]

redteam_columns = [
    "time",
    "user",
    "source_computer",
    "destination_computer"
]

# -----------------------------
# Load data
# -----------------------------

auth = pd.read_csv(
    "auth_attack_window.txt",
    names=auth_columns
)

redteam = pd.read_csv(
    "redteam.txt",
    names=redteam_columns
)

# Only keep red-team events inside our auth window
start_time = auth["time"].min()
end_time = auth["time"].max()

redteam_window = redteam[
    (redteam["time"] >= start_time) &
    (redteam["time"] <= end_time)
].copy()

# Label attacks

redteam_match = redteam_window.rename(
    columns={"user": "source_user"}
)

redteam_match["attack"] = 1

auth = auth.merge(
    redteam_match[
        [
            "time",
            "source_user",
            "source_computer",
            "destination_computer",
            "attack"
        ]
    ],
    on=[
        "time",
        "source_user",
        "source_computer",
        "destination_computer"
    ],
    how="left"
)

auth["attack"] = auth["attack"].fillna(0).astype(int)

# Find every attacked user

attack_users = auth.loc[
    auth["attack"] == 1,
    "source_user"
].unique()

print("\nUsers with known attacks:")

for user in attack_users:
    print(user)

# Only analyze users that have at least one known attack
df = auth[
    auth["source_user"].isin(attack_users)
].copy()

df = df.sort_values(
    ["source_user", "time"]
).reset_index(drop=True)

# General behavioral features

# Has this user used this destination before?
df["new_destination"] = (
    ~df.duplicated(
        subset=[
            "source_user",
            "destination_computer"
        ]
    )
).astype(int)

# Has this user used this source before?
df["new_source"] = (
    ~df.duplicated(
        subset=[
            "source_user",
            "source_computer"
        ]
    )
).astype(int)

# How often does this user use this source computer?
df["source_frequency"] = (
    df.groupby(
        [
            "source_user",
            "source_computer"
        ]
    )["time"]
    .transform("count")
)

# How often does this user access this destination?
df["destination_frequency"] = (
    df.groupby(
        [
            "source_user",
            "destination_computer"
        ]
    )["time"]
    .transform("count")
)

# NTLM indicator
df["uses_ntlm"] = (
    df["authentication_type"] == "NTLM"
).astype(int)

# 5-minute activity features

df["auth_events_5min"] = 0
df["unique_destinations_5min"] = 0

for user, group in df.groupby("source_user"):

    window = deque()
    destination_counts = Counter()

    for index, row in group.iterrows():

        current_time = row["time"]

        # Remove events older than 5 minutes
        while window and window[0][0] < current_time - 300:

            old_time, old_destination = window.popleft()

            destination_counts[old_destination] -= 1

            if destination_counts[old_destination] == 0:
                del destination_counts[old_destination]

        # Add current event
        destination = row["destination_computer"]

        window.append(
            (
                current_time,
                destination
            )
        )

        destination_counts[destination] += 1

        df.loc[
            index,
            "auth_events_5min"
        ] = len(window)

        df.loc[
            index,
            "unique_destinations_5min"
        ] = len(destination_counts)

# Save expanded data

df.to_csv(
    "multi_user_features.csv",
    index=False
)

# Summary by user

print("\n=================================")
print("MULTI-USER ATTACK ANALYSIS")
print("=================================")

for user in attack_users:

    user_df = df[
        df["source_user"] == user
    ]

    attacks = user_df[
        user_df["attack"] == 1
    ]

    normal = user_df[
        user_df["attack"] == 0
    ]

    print("\n---------------------------------")
    print("User:", user)
    print("---------------------------------")

    print("Total events:", len(user_df))
    print("Known attacks:", len(attacks))
    print("Normal events:", len(normal))

    print(
        "Unique source computers:",
        user_df["source_computer"].nunique()
    )

    print(
        "Unique destination computers:",
        user_df["destination_computer"].nunique()
    )

    if len(attacks) > 0:

        print(
            "Attack new destination %:",
            round(
                attacks["new_destination"].mean() * 100,
                2
            )
        )

        print(
            "Attack average destinations / 5 min:",
            round(
                attacks[
                    "unique_destinations_5min"
                ].mean(),
                2
            )
        )

        print(
            "Attack NTLM %:",
            round(
                attacks["uses_ntlm"].mean() * 100,
                2
            )
        )

    if len(normal) > 0:

        print(
            "Normal new destination %:",
            round(
                normal["new_destination"].mean() * 100,
                2
            )
        )

        print(
            "Normal average destinations / 5 min:",
            round(
                normal[
                    "unique_destinations_5min"
                ].mean(),
                2
            )
        )

        print(
            "Normal NTLM %:",
            round(
                normal["uses_ntlm"].mean() * 100,
                2
            )
        )

print(
    "\nSaved expanded feature data to "
    "multi_user_features.csv"
)