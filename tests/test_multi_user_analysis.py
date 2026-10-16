from pathlib import Path
import runpy
import pandas as pd

project_root_directory = Path(__file__).resolve().parents[1]
multi_user_analysis_file_path = project_root_directory / "analysis" / "multi_user_analysis.py"

def test_new_destination_are_tracked_per_user(tmp_path, monkeypatch):
    authentication_test_data = [
        "100,U100@DOM1,U100@DOM1,C100,C500,NTLM,Network,LogOn,Success",
        "110,U200@DOM1,U200@DOM1,C200,C500,NTLM,Network,LogOn,Success",
        "120,U100@DOM1,U100@DOM1,C100,C500,NTLM,Network,LogOn,Success",
        "130,U200@DOM1,U200@DOM1,C200,C600,NTLM,Network,LogOn,Success"
    ]

    red_team_test_data = [
        "100,U100@DOM1,C100,C500",
        "110,U200@DOM1,C200,C500"
    ]

    authentication_test_file = tmp_path / "auth_attack_window_large.txt"
    red_team_test_file = tmp_path / "redteam.txt"

    authentication_test_file.write_text("\n".join(authentication_test_data), encoding="utf-8")
    red_team_test_file.write_text("\n".join(red_team_test_data), encoding="utf-8")
    orginal_read_csv = pd.read_csv

    def read_test_data(file_path, *arguments, **keyword_arguments):
        file_name = Path(file_path).name
        if file_name == "auth_attack_window_large.txt":
            file_path = authentication_test_file
        elif file_name == "redteam.txt":
            file_path = red_team_test_file
        return orginal_read_csv(file_path, *arguments, **keyword_arguments)
    monkeypatch.setattr(pd, "read_csv", read_test_data)

    monkeypatch.setattr(pd.DataFrame, "to_csv", lambda self, *arguments, **keyword_arguments: None)
    script_results = runpy.run_path(str(multi_user_analysis_file_path))
    processed_authentication_data = script_results["df"]
    actual_destination_flags = processed_authentication_data["new_destination"].tolist()
    expected_destination_flags = [1, 0, 1, 1]

    assert actual_destination_flags == expected_destination_flags
    assert len(processed_authentication_data) == 4

#Test 2: Verify new source computers are tracked per user
def test_new_source_computers_are_tracked_per_user(tmp_path, monkeypatch):
    authentication_test_data = [
        "100,U100@DOM1,U100@DOM1,C100,C500,NTLM,Network,LogOn,Success",
        "110,U200@DOM1,U200@DOM1,C100,C600,NTLM,Network,LogOn,Success",
        "120,U100@DOM1,U100@DOM1,C100,C700,NTLM,Network,LogOn,Success",
        "130,U100@DOM1,U100@DOM1,C300,C800,NTLM,Network,LogOn,Success"
    ]

    red_team_test_data = [
        "100,U100@DOM1,C100,C500",
        "110,U200@DOM1,C100,C600"
    ]

    authentication_test_file = tmp_path / "auth_attack_window_large.txt"
    red_team_test_file = tmp_path / "redteam.txt"

    authentication_test_file.write_text("\n".join(authentication_test_data), encoding="utf-8")
    red_team_test_file.write_text("\n".join(red_team_test_data), encoding="utf-8")
    orginal_read_csv = pd.read_csv

    def read_test_data(file_path, *arguments, **keyword_arguments):
        file_name = Path(file_path).name
        if file_name == "auth_attack_window_large.txt":
            file_path = authentication_test_file
        elif file_name == "redteam.txt":
            file_path = red_team_test_file
        return orginal_read_csv(file_path, *arguments, **keyword_arguments)
    monkeypatch.setattr(pd, "read_csv", read_test_data)

    monkeypatch.setattr(pd.DataFrame, "to_csv", lambda self, *arguments, **keyword_arguments: None)
    script_results = runpy.run_path(str(multi_user_analysis_file_path))
    processed_authentication_data = script_results["df"]
    actual_source_flags = processed_authentication_data["new_source"].tolist()
    expected_source_flags = [1, 0, 1, 1]

    assert actual_source_flags == expected_source_flags
    assert len(processed_authentication_data) == 4

#Test 3:
def test_new_source_and_destination_frequencies_per_user(tmp_path, monkeypatch):
    authentication_test_data = [
        "100,U100@DOM1,U100@DOM1,C100,C500,NTLM,Network,LogOn,Success",
        "110,U100@DOM1,U100@DOM1,C100,C500,NTLM,Network,LogOn,Success",
        "120,U100@DOM1,U100@DOM1,C100,C600,NTLM,Network,LogOn,Success",
        "130,U200@DOM1,U200@DOM1,C100,C500,NTLM,Network,LogOn,Success"
    ]

    red_team_test_data = [
        "100,U100@DOM1,C100,C500",
        "130,U200@DOM1,C100,C500"
    ]

    authentication_test_file = tmp_path / "auth_attack_window_large.txt"
    red_team_test_file = tmp_path / "redteam.txt"

    authentication_test_file.write_text("\n".join(authentication_test_data), encoding="utf-8")
    red_team_test_file.write_text("\n".join(red_team_test_data), encoding="utf-8")
    orginal_read_csv = pd.read_csv

    def read_test_data(file_path, *arguments, **keyword_arguments):
        file_name = Path(file_path).name
        if file_name == "auth_attack_window_large.txt":
            file_path = authentication_test_file
        elif file_name == "redteam.txt":
            file_path = red_team_test_file
        return orginal_read_csv(file_path, *arguments, **keyword_arguments)
    monkeypatch.setattr(pd, "read_csv", read_test_data)

    monkeypatch.setattr(pd.DataFrame, "to_csv", lambda self, *arguments, **keyword_arguments: None)
    script_results = runpy.run_path(str(multi_user_analysis_file_path))
    processed_authentication_data = script_results["df"]
    actual_source_frequencies = processed_authentication_data["source_frequency"].tolist()
    actual_destination_frequencies = processed_authentication_data["destination_frequency"].tolist()
    expected_source_frequencies = [3, 3, 3, 1]
    expected_destination_frequencies = [2, 2, 1, 1]
    
    assert actual_source_frequencies == expected_source_frequencies
    assert actual_destination_frequencies == expected_destination_frequencies
    assert len(processed_authentication_data) == 4

#Test 4: Five-minute authentication activity
def test_five_minute_activity_is_tracked_per_user(tmp_path, monkeypatch):
    authentication_test_data = [
        "100,U100@DOM1,U100@DOM1,C100,C500,NTLM,Network,LogOn,Success",
        "200,U100@DOM1,U100@DOM1,C100,C600,NTLM,Network,LogOn,Success",
        "300,U100@DOM1,U100@DOM1,C100,C500,NTLM,Network,LogOn,Success",
        "401,U100@DOM1,U100@DOM1,C100,C700,NTLM,Network,LogOn,Success",
        "150,U200@DOM1,U200@DOM1,C200,C800,NTLM,Network,LogOn,Success"
    ]

    red_team_test_data = [
        "100,U100@DOM1,C100,C500",
        "150,U200@DOM1,C200,C800"
    ]

    authentication_test_file = tmp_path / "auth_attack_window_large.txt"
    red_team_test_file = tmp_path / "redteam.txt"

    authentication_test_file.write_text("\n".join(authentication_test_data), encoding="utf-8")
    red_team_test_file.write_text("\n".join(red_team_test_data), encoding="utf-8")
    orginal_read_csv = pd.read_csv

    def read_test_data(file_path, *arguments, **keyword_arguments):
        file_name = Path(file_path).name
        if file_name == "auth_attack_window_large.txt":
            file_path = authentication_test_file
        elif file_name == "redteam.txt":
            file_path = red_team_test_file
        return orginal_read_csv(file_path, *arguments, **keyword_arguments)
    monkeypatch.setattr(pd, "read_csv", read_test_data)

    monkeypatch.setattr(pd.DataFrame, "to_csv", lambda self, *arguments, **keyword_arguments: None)
    script_results = runpy.run_path(str(multi_user_analysis_file_path))
    processed_authentication_data = script_results["df"]
    actual_authentication_counts = processed_authentication_data["auth_events_5min"].tolist()
    actual_unique_destination_counts = processed_authentication_data["unique_destinations_5min"].tolist()
    expected_authentication_counts = [1, 2, 3, 3, 1]
    expected_unique_destination_counts = [1, 2, 2, 3, 1]

    assert actual_authentication_counts == expected_authentication_counts
    assert actual_unique_destination_counts == expected_unique_destination_counts
    assert len(processed_authentication_data) == 5