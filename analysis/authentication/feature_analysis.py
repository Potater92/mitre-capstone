import pandas as pd

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

auth = pd.read_csv(
    "auth_attack_window.txt",
    names=auth_columns
)

redteam = pd.read_csv(
    "redteam.txt",
    names=redteam_columns
)

# Focus on U748
user = "U748@DOM1"

user_activity = auth[
    auth["source_user"] == user
].copy()

# Sort by time
user_activity = user_activity.sort_values("time")

# Known red-team event keys
redteam_keys = set(
    zip(
        redteam["time"],
        redteam["user"],
        redteam["source_computer"],
        redteam["destination_computer"]
    )
)

user_activity["attack"] = user_activity.apply(
    lambda row: int(
        (
            row["time"],
            row["source_user"],
            row["source_computer"],
            row["destination_computer"]
        ) in redteam_keys
    ),
    axis=1
)

# ------------------------------------------------
# FEATURE 1:
# Is C17693 being used as the source computer?
# ------------------------------------------------

user_activity["source_is_C17693"] = (
    user_activity["source_computer"] == "C17693"
).astype(int)

# ------------------------------------------------
# FEATURE 2:
# How many unique destinations did the user
# access during the previous 5 minutes?
#
# Dataset time is in seconds.
# 5 minutes = 300 seconds
# ------------------------------------------------

destinations_5min = []

for _, row in user_activity.iterrows():

    start_time = row["time"] - 300

    recent = user_activity[
        (user_activity["time"] >= start_time) &
        (user_activity["time"] <= row["time"])
    ]

    destinations_5min.append(
        recent["destination_computer"].nunique()
    )

user_activity["unique_destinations_5min"] = destinations_5min

# ------------------------------------------------
# FEATURE 3:
# Was this destination seen previously by U748?
# ------------------------------------------------

seen_destinations = set()
new_destination = []

for _, row in user_activity.iterrows():

    destination = row["destination_computer"]

    if destination in seen_destinations:
        new_destination.append(0)
    else:
        new_destination.append(1)
        seen_destinations.add(destination)

user_activity["new_destination"] = new_destination

# ------------------------------------------------
# Show known attacks with features
# ------------------------------------------------

attacks = user_activity[
    user_activity["attack"] == 1
]

print("\nKNOWN U748 ATTACKS WITH FEATURES\n")

print(
    attacks[
        [
            "time",
            "source_computer",
            "destination_computer",
            "authentication_type",
            "source_is_C17693",
            "unique_destinations_5min",
            "new_destination",
            "attack"
        ]
    ].to_string(index=False)
)

# Save results
user_activity.to_csv(
    "u748_features.csv",
    index=False
)

print("\nSaved full feature data to u748_features.csv")