from pathlib import Path
import runpy
import pandas as pd

project_root_directory = Path(__file__).resolve().parents[1]
sigma_detection_file_path = project_root_directory / "analysis" / "authentication" / "sigma_detection.py"

def test_sigma_detection_rule_thresholds(tmp_path, monkeypatch):
    # Create a temporary CSV file with test data
    authentication_test_data = pd.DataFrame({
        "attack": [0, 1, 0, 1],
        "new_destination": [0, 0, 1, 1],
        "destination_frequency": [3, 3, 2, 3],
        "unique_destinations_5min": [4, 5, 1, 1],
        "auth_events_5min": [9, 9, 10, 10]
    })
    authentication_test_file = tmp_path / "multi_user_features_large.csv"
    authentication_test_data.to_csv(authentication_test_file, index=False)

    original_read_csv = pd.read_csv

    def read_test_data(file_path, *arguments, **keyword_arguments):
        if Path(file_path).name == "multi_user_features_large.csv":
            file_path = authentication_test_file
        return original_read_csv(file_path, *arguments, **keyword_arguments)

    monkeypatch.setattr(pd, "read_csv", read_test_data)

    monkeypatch.setattr(
        pd.DataFrame, "to_csv", lambda self, *args, **kwargs: None
    )

    script_results = runpy.run_path(str(sigma_detection_file_path))
    processed_authentication_data = script_results["df"]

    assert processed_authentication_data["rule_unusual_destination"].tolist() == [0, 0, 1, 0]
    assert processed_authentication_data["rule_multiple_destinations"].tolist() == [0, 1, 0, 0]
    assert processed_authentication_data["rule_authentication_burst"].tolist() == [0, 0, 1, 1]
    assert processed_authentication_data["any_rule_matched"].tolist() == [0, 1, 1, 1]

#Test 2
def test_sigma_detection_summary_does_not_double_count(tmp_path, monkeypatch):
    # Create a temporary CSV file with test data
    authentication_test_data = pd.DataFrame({
        "attack": [1, 1, 0, 0],
        "new_destination": [0, 1, 0, 0],
        "destination_frequency": [3, 2, 3, 3],
        "unique_destinations_5min": [5, 1, 1, 1],
        "auth_events_5min": [10, 1, 10, 1]
    })
    authentication_test_file = tmp_path / "multi_user_features_large.csv"
    authentication_test_data.to_csv(authentication_test_file, index=False)

    original_read_csv = pd.read_csv

    def read_test_data(file_path, *arguments, **keyword_arguments):
        if Path(file_path).name == "multi_user_features_large.csv":
            file_path = authentication_test_file
        return original_read_csv(file_path, *arguments, **keyword_arguments)

    monkeypatch.setattr(pd, "read_csv", read_test_data)

    saved_dataframes = {}

    def capture_csv_output(dataframe, file_path, *arguments, **keyword_arguments):
        saved_dataframes[Path(file_path).name] = dataframe.copy()

    monkeypatch.setattr(pd.DataFrame, "to_csv", capture_csv_output)

    script_results = runpy.run_path(str(sigma_detection_file_path))
    processed_authentication_data = script_results["df"]

    detection_summary = saved_dataframes["sigma_detection_summary.csv"]

    combined_rule_summary = detection_summary[detection_summary["rule"] == "any_rule_matched"].iloc[0]

    assert processed_authentication_data["any_rule_matched"].tolist() == [1, 1, 1, 0]

    assert combined_rule_summary["total_alerts"] == 3
    assert combined_rule_summary["known_attacks_detected"] == 2
    assert combined_rule_summary["known_attacks_missed"] == 0
    assert combined_rule_summary["other_events_flagged"] == 1