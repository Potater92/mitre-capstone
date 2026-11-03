from pathlib import Path
import runpy 
import pandas as pd

project_root_directory = Path(__file__).resolve().parents[1]

multi_user_analysis_file_path = project_root_directory / "analysis" / "multi_user_analysis.py"

sigma_detection_file_path = project_root_directory / "analysis" / "authentication" / "sigma_detection.py"

def test_multi_user_features_feed_into_sigma_detection(tmp_path, monkeypatch):
    # Five destinations for U100 and two events for U200
    authentication_test_data = [
        "100,U100@DOM1,U100@DOM1,C100,C500,NTLM,Network,LogOn,Success",
        "150,U100@DOM1,U100@DOM1,C100,C600,NTLM,Network,LogOn,Success",
        "200,U100@DOM1,U100@DOM1,C100,C700,NTLM,Network,LogOn,Success",
        "250,U100@DOM1,U100@DOM1,C100,C800,NTLM,Network,LogOn,Success",
        "300,U100@DOM1,U100@DOM1,C100,C900,NTLM,Network,LogOn,Success",
        "120,U200@DOM1,U200@DOM1,C200,C500,NTLM,Network,LogOn,Success",
        "130,U200@DOM1,U200@DOM1,C200,C500,NTLM,Network,LogOn,Success"
    ]

    red_team_test_data = [
        "100,U100@DOM1,C100,C500",
        "120,U200@DOM1,C200,C500"
    ]

    authentication_test_file = tmp_path / "auth_attack_window_large.txt"
    red_team_test_file = tmp_path / "redteam.txt"

    authentication_test_file.write_text("\n".join(authentication_test_data), encoding="utf-8")
    red_team_test_file.write_text("\n".join(red_team_test_data), encoding="utf-8")

    original_read_csv = pd.read_csv
    generated_dataframes = {}

    def read_test_data(file_path, *arguments, **keyword_arguments):
        file_name = Path(file_path).name
        if file_name == "auth_attack_window_large.txt":
            file_path = authentication_test_file
        elif file_name == "redteam.txt":
            file_path = red_team_test_file
        elif file_name == "multi_user_features_large.csv" and file_name in generated_dataframes:
            return generated_dataframes[file_name].copy()

        return original_read_csv(file_path, *arguments, **keyword_arguments)

    def capture_csv_output(dataframe, file_path, *arguments, **keyword_arguments):
        generated_dataframes[Path(file_path).name] = dataframe.copy()

    monkeypatch.setattr(pd, "read_csv", read_test_data)
    monkeypatch.setattr(pd.DataFrame, "to_csv", capture_csv_output)

    # First component: raw authentication events become behavevioral features
    runpy.run_path(str(multi_user_analysis_file_path))

    feature_dataframe = generated_dataframes["multi_user_features_large.csv"]

    assert len(feature_dataframe) == 7
    assert feature_dataframe["attack"].sum() == 2

    # Second component: detection uses the features generated above
    runpy.run_path(str(sigma_detection_file_path))

    detection_dataframe = generated_dataframes["sigma_detection_results.csv"]
    detection_summary = generated_dataframes["sigma_detection_summary.csv"]

    user_100_results = detection_dataframe[detection_dataframe["source_user"] == "U100@DOM1"]

    # U100 reaches five destinations on the fifth event
    assert user_100_results["unique_destinations_5min"].tolist() == [1, 2, 3, 4, 5]
    assert user_100_results["rule_multiple_destinations"].tolist() == [0, 0, 0, 0, 1]

    # U200 repeated destination is counted independently
    user_200_results = detection_dataframe[detection_dataframe["source_user"] == "U200@DOM1"]
    assert user_200_results["unique_destinations_5min"].tolist() == [1, 1]

    combined_rule_summary = detection_summary[detection_summary["rule"] == "any_rule_matched"].iloc[0]

    assert combined_rule_summary["total_alerts"] == 6
    assert combined_rule_summary["known_attacks_detected"] == 2
    assert combined_rule_summary["known_attacks_missed"] == 0
    assert combined_rule_summary["other_events_flagged"] == 4