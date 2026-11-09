from pathlib import Path
import pandas as pd

project_root_directory = Path(__file__).resolve().parents[1]

authentication_feature_file_path = project_root_directory / "output" / "multi_user_features_large.csv"
red_team_file_path = project_root_directory / "data" / "redteam.txt"

def test_known_attack_labels_match_red_team_events():

    authentication_data = pd.read_csv(authentication_feature_file_path)

    red_team_data = pd.read_csv(
        red_team_file_path,
        names=["time", "source_user", "source_computer", "destination_computer"],
    )

    matching_columns = ["time", "source_user", "source_computer", "destination_computer"]

    # Each known redteam event should match an authentation record
    known_red_team_events = red_team_data[matching_columns].drop_duplicates().copy()
    known_red_team_events["known_red_team_match"] = 1

    labeled_authentication_data = authentication_data.merge(
        known_red_team_events, on=matching_columns, how="left", validate="many_to_one"
    )

    expected_attack_flags = labeled_authentication_data["known_red_team_match"].fillna(0).astype(int)
    actual_attack_flags = labeled_authentication_data["attack"]

    assert len(labeled_authentication_data) > 0
    assert actual_attack_flags.isin([0, 1]).all()
    assert actual_attack_flags.tolist() == expected_attack_flags.tolist()