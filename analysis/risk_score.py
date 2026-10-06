import pandas as pd

df = pd.read_csv("u748_features.csv")

# -----------------------------------------
# Build a simple explainable risk score
# -----------------------------------------

df["risk_score"] = 0

# New destination is relatively uncommon in normal activity
df.loc[df["new_destination"] == 1, "risk_score"] += 35

# NTLM appears in attacks, but also normal traffic
df.loc[df["authentication_type"] == "NTLM", "risk_score"] += 20

# Source computer is unusual if it has been used very few times
source_counts = df["source_computer"].value_counts()

df["source_frequency"] = df["source_computer"].map(source_counts)

df.loc[df["source_frequency"] <= 2, "risk_score"] += 25

# Destination is unusual if it has been used very few times
destination_counts = df["destination_computer"].value_counts()

df["destination_frequency"] = df["destination_computer"].map(
    destination_counts
)

df.loc[df["destination_frequency"] <= 2, "risk_score"] += 20

# Limit score to 100
df["risk_score"] = df["risk_score"].clip(upper=100)

# -----------------------------------------
# Compare attack and normal scores
# -----------------------------------------

attacks = df[df["attack"] == 1]
normal = df[df["attack"] == 0]

print("\n==============================")
print("RISK SCORE ANALYSIS")
print("==============================")

print("\nAverage risk score:")
print("Normal:", round(normal["risk_score"].mean(), 2))
print("Attack:", round(attacks["risk_score"].mean(), 2))

print("\nKnown attacks:")
print(
    attacks[
        [
            "time",
            "source_computer",
            "destination_computer",
            "authentication_type",
            "new_destination",
            "source_frequency",
            "destination_frequency",
            "risk_score"
        ]
    ].to_string(index=False)
)

print("\nHighest scoring NORMAL events:")
print(
    normal.sort_values(
        "risk_score",
        ascending=False
    )[
        [
            "time",
            "source_computer",
            "destination_computer",
            "authentication_type",
            "new_destination",
            "source_frequency",
            "destination_frequency",
            "risk_score"
        ]
    ].head(15).to_string(index=False)
)

df.to_csv(
    "u748_risk_scores.csv",
    index=False
)

print("\nSaved results to u748_risk_scores.csv")