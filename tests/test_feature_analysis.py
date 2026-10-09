from pathlib import Path
import pandas as pd

project_root_directory = Path(__file__).resolve().parents[1]

feature_analysis_file_path = project_root_directory / "output" / "u748_features.csv"

feature_analysis_dataframe = pd.read_csv(feature_analysis_file_path)

def test_feature_analysis_data_exists():
    assert len(feature_analysis_dataframe) > 0

def test_source_computer_feature_is_correct():
    expected_source_computer_flags = (feature_analysis_dataframe["source_computer"] == "C17693").astype(int)

    actual_source_computer_flags = feature_analysis_dataframe["source_is_C17693"]

    assert (actual_source_computer_flags == expected_source_computer_flags).all()

def test_new_destination_feature_is_correct():
    previously_seen_destinations = set()
    expected_new_destination_flags = []

    for destination_computer in feature_analysis_dataframe["destination_computer"]:
        if destination_computer in previously_seen_destinations:
            expected_new_destination_flags.append(0)
        else:
            expected_new_destination_flags.append(1)
            previously_seen_destinations.add(destination_computer)

    actual_new_destination_flags = feature_analysis_dataframe["new_destination"].tolist()

    assert actual_new_destination_flags == expected_new_destination_flags

def test_unique_destinations_within_five_minutes():
    for authentication_event in feature_analysis_dataframe.itertuples(index=False):
        current_event_time = int(authentication_event.time)
        five_minute_window_start = current_event_time - 300

        authentication_events_in_window = (feature_analysis_dataframe[
                (feature_analysis_dataframe["time"] >= five_minute_window_start)
                & (feature_analysis_dataframe["time"] <= current_event_time)
            ]
        )
        expected_unique_destination_count = authentication_events_in_window["destination_computer"].nunique()

        actual_unique_destination_count = authentication_event.unique_destinations_5min

        assert actual_unique_destination_count == expected_unique_destination_count

print(type(feature_analysis_dataframe["time"].iloc[0]))
print(feature_analysis_dataframe["time"].iloc[0])