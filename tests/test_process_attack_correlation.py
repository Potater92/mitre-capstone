from pathlib import Path
import runpy
import pandas as pd

project_root_directory = Path(__file__).resolve().parents[1]

process_correlation_file_path = project_root_directory / "analysis" / "process" /"process_attack_correlation.py"

def test_process_activity_is_counted_near_known_attacks(tmp_path, monkeypatch):

    authentication_test_data = pd.DataFrame({
        "time": [1000, 1500],
        "source_user": ["U100@DOM1", "U200@DOM1"],
        "source_computer": ["C100", "C300"],
        "destination_computer": ["C200", "C400"],
        "attack": [1, 0]
    })

    process_test_data = [
        "699,U100,C100,P1,Start",
        "700,U100,C100,P1,Start",
        "1000,U100,C100,P1,End",
        "1300,U100,C100,P2,Start",
        "1301,U100,C100,P3,Start",
        "800,U100,C200,P4,Start",
        "900,U100,C200,P4,Start",
        "1100,U100,C200,P4,End",
        "1000,U100,C999,P5,Start",
        "1000,U200,C300,P6,Start"
    ]

    authentication_test_file = tmp_path / "multi_user_features_large.csv"
    process_test_file = tmp_path / "proc_attack_window_large.txt"

    authentication_test_data.to_csv(authentication_test_file, index=False)
    process_test_file.write_text("\n".join(process_test_data), encoding="utf-8")

    original_read_csv = pd.read_csv
    saved_dataframes = {}

    def read_test_data(file_path, *arguments, **keyword_arguments):
        file_name = Path(file_path).name
        if file_name == "multi_user_features_large.csv":
            file_path = authentication_test_file
        elif file_name == "proc_attack_window_large.txt":
            file_path = process_test_file

        return original_read_csv(file_path, *arguments, **keyword_arguments)

    def capture_csv_output(dataframe, file_path, *arguments, **keyword_arguments):
        saved_dataframes[Path(file_path).name] = dataframe.copy()

    monkeypatch.setattr(pd, "read_csv", read_test_data)
    monkeypatch.setattr(pd.DataFrame, "to_csv", capture_csv_output)

    runpy.run_path(str(process_correlation_file_path))

    correlation_results = saved_dataframes.get("process_attack_correlation.csv")

    assert len(correlation_results) == 2

    source_result = correlation_results[correlation_results["role"] == "source"].iloc[0]
    
    destination_result = correlation_results[correlation_results["role"] == "destination"].iloc[0]

    assert source_result["computer"] == "C100"
    assert source_result["process_starts"] == 2
    assert source_result["process_ends"] == 1
    assert source_result["unique_started_processes"] == 2

    assert destination_result["computer"] == "C200"
    assert destination_result["process_starts"] == 2
    assert destination_result["process_ends"] == 1
    assert destination_result["unique_started_processes"] == 1

def test_overlapping_attack_windows(tmp_path, monkeypatch):

    authentication_test_data = pd.DataFrame({
        "time": [1000, 1100, 1800],
        "source_user": ["U100@DOM1", "U100@DOM1", "U200@DOM1"],
        "source_computer": ["C100", "C100", "C300"],
        "destination_computer": ["C200", "C200", "C400"],
        "attack": [1, 1, 0]
    })

    process_test_data = [
        "750,U100,C100,P1,Start",
        "1050,U100,C100,P2,Start",
        "1050,U100,C100,P2,End",
        "1350,U100,C100,P3,Start",
        "1050,U100,C200,P4,Start",
        "750,U100,C200,P5,End",
        "1350,U100,C200,P6,Start",
        "1050,U100,C999,P7,Start",
        "1050,U200,C300,P8,Start"
    ]

    authentication_test_file = tmp_path / "multi_user_features_large.csv"
    process_test_file = tmp_path / "proc_attack_window_large.txt"

    authentication_test_data.to_csv(authentication_test_file, index=False)
    process_test_file.write_text("\n".join(process_test_data), encoding="utf-8")

    original_read_csv = pd.read_csv
    saved_dataframes = {}

    def read_test_data(file_path, *arguments, **keyword_arguments):
        file_name = Path(file_path).name
        if file_name == "multi_user_features_large.csv":
            file_path = authentication_test_file
        elif file_name == "proc_attack_window_large.txt":
            file_path = process_test_file

        return original_read_csv(file_path, *arguments, **keyword_arguments)

    def capture_csv_output(dataframe, file_path, *arguments, **keyword_arguments):
        saved_dataframes[Path(file_path).name] = dataframe.copy()

    monkeypatch.setattr(pd, "read_csv", read_test_data)
    monkeypatch.setattr(pd.DataFrame, "to_csv", capture_csv_output)

    runpy.run_path(str(process_correlation_file_path))

    correlation_results = saved_dataframes.get("process_attack_correlation.csv")

    assert len(correlation_results) == 4

    actual_process_counts = {}
    
    for result in correlation_results.itertuples(index=False):
        attack_key = (result.time, result.role)

        actual_process_counts[attack_key] = (
            result.computer,
            result.process_starts,
            result.process_ends,
            result.unique_started_processes
        )

    expected_process_counts = {
        (1000, "source"): ("C100", 2, 1, 2),
        (1000, "destination"): ("C200", 1, 1, 1),
        (1100, "source"): ("C100", 2, 1, 2),
        (1100, "destination"): ("C200", 2, 0, 2)
    }

    assert actual_process_counts == expected_process_counts