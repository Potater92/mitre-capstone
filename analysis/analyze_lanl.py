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

redteam_keys = set(
    zip(
        redteam["time"],
        redteam["user"],
        redteam["source_computer"],
        redteam["destination_computer"]
    )
)

auth["attack"] = auth.apply(
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

# Focus on U748
user = "U748@DOM1"

user_activity = auth[
    auth["source_user"] == user
].copy()

print("\nU748 ACTIVITY")
print("Total events:", len(user_activity))

print("\nUnique source computers:")
print(user_activity["source_computer"].nunique())

print("\nUnique destination computers:")
print(user_activity["destination_computer"].nunique())

print("\nFailed logins:")
print((user_activity["result"] == "Fail").sum())

print("\nKnown attacks:")
print(user_activity["attack"].sum())

print("\nAll U748 events:")
print(
    user_activity[
        [
            "time",
            "source_computer",
            "destination_computer",
            "authentication_type",
            "logon_type",
            "result",
            "attack"
        ]
    ].to_string(index=False)
)