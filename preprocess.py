import pandas as pd

df = pd.read_csv("redteam.csv", skipinitialspace=True)

# Split user@domain into two columns (Who the user is, and which domain they belong to)
df[["user", "domain"]] = df["user_domain"].str.split("@", n=1, expand=True)
df = df.drop(columns="user_domain") # don't need to keep user_domain since we just split it into two different columns

# Human-readable time: seconds since the start of data collection NOTE: We cannot use the elasped time in a model, we still need to use the time column, this is just for readabliity
df["time"] = pd.to_numeric(df["time"])                  # make sure our time column is treated as a number and not a string
df["elapsed"] = pd.to_timedelta(df["time"], unit="s")   # e.g. 1 days 17:54:45
df["day"] = df["time"] // 86400                          # day number, starting at 0
df["hour"] = (df["time"] % 86400) // 3600                # hour of day, 0-23

dupes = df.duplicated().sum() # look for any duplicates in our data and print them
print(f"Duplicate rows: {dupes} of {len(df)}")
print(df[df.duplicated(keep=False)].head(20))
df = df[["time", "elapsed", "day", "hour", "user", "domain", "src_computer", "dst_computer"]]

df.to_csv("data_formatted.csv", index=False) #export the data to a new csv file
print(df.head())
df.info()
print(df.isna().sum()) # prints the counts of columns missing values (This should be 0 for all columns, we have no entries missing data)