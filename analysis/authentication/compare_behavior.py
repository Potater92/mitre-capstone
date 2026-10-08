import pandas as pd

df = pd.read_csv("u748_features.csv")

print("\n==============================")
print("ATTACK VS NORMAL COMPARISON")
print("==============================")

attacks = df[df["attack"] == 1]
normal = df[df["attack"] == 0]

print("\nTotal events")
print("Normal:", len(normal))
print("Attack:", len(attacks))

print("\nAverage unique destinations in previous 5 minutes")
print("Normal:", round(normal["unique_destinations_5min"].mean(), 2))
print("Attack:", round(attacks["unique_destinations_5min"].mean(), 2))

print("\nNew destination percentage")
print(
    "Normal:",
    round(normal["new_destination"].mean() * 100, 2),
    "%"
)

print(
    "Attack:",
    round(attacks["new_destination"].mean() * 100, 2),
    "%"
)

print("\nC17693 usage")
print(
    "Normal:",
    normal["source_is_C17693"].sum()
)

print(
    "Attack:",
    attacks["source_is_C17693"].sum()
)

print("\nAuthentication types - NORMAL")
print(normal["authentication_type"].value_counts())

print("\nAuthentication types - ATTACK")
print(attacks["authentication_type"].value_counts())

print("\nNormal NTLM events from C17693")
print(
    normal[
        (normal["source_computer"] == "C17693") &
        (normal["authentication_type"] == "NTLM")
    ][
        [
            "time",
            "source_computer",
            "destination_computer",
            "unique_destinations_5min",
            "new_destination"
        ]
    ].to_string(index=False)
)