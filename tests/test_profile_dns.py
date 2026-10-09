from pathlib import Path
import runpy
import pandas as pd

project_root_directory = Path(__file__).resolve().parents[1]
dns_analysis_file_path = project_root_directory / 'analysis' / "dns" /'profile_dns.py'

def test_dns_event_counts(tmp_path, monkeypatch):
    dns_test_data = [
        "100,C17693,C728",
        "200,C17693,C500",
        "300,C100,C200"
    ]

    red_team_test_data = [
        "100,U748@DOM1,C17693,C728"
    ]

    dns_test_file = tmp_path / "dns.csv"
    red_team_test_file = tmp_path / 'redteam.csv'

    dns_test_file.write_text(
        "\n".join(dns_test_data),
        encoding="utf-8"
    )

    red_team_test_file.write_text(
        "\n".join(red_team_test_data),
        encoding="utf-8"
    )

    original_read_csv = pd.read_csv

    def read_test_data(file_path, *arguments, **keyword_arguments):
        file_name = Path(file_path).name
        if file_name == "dns.csv":
            file_path = dns_test_file
        elif file_name == "redteam.csv":
            file_path = red_team_test_file
        return original_read_csv(file_path, *arguments, **keyword_arguments)

    monkeypatch.setattr(pd, "read_csv", read_test_data)
    script_results = runpy.run_path(
        str(dns_analysis_file_path)
    )

    #Verify DNS event counts
    assert script_results["total_rows"] == 3
    assert len(script_results["sources"]) == 2
    assert len(script_results["resolved"]) == 3
    # Verify red team event counts
    assert len(script_results["RED_TEAM_COMPUTERS"]) == 2
    assert sum(script_results["red_as_source"].values()) == 2
    assert sum(script_results["red_as_resolved"].values()) == 1

# Test 2: verify missing DNS values
def test_dns_missing_values(tmp_path, monkeypatch):
    dns_test_data = [
        "100,C17693,C728",
        "200,,C500",
        "300,C100,"
    ]

    red_team_test_data = [
        "100,U748@DOM1,C17693,C728"
    ]

    dns_test_file = tmp_path / "dns.csv"
    red_team_test_file = tmp_path / 'redteam.csv'

    dns_test_file.write_text(
        "\n".join(dns_test_data),
        encoding="utf-8"
    )

    red_team_test_file.write_text(
        "\n".join(red_team_test_data),
        encoding="utf-8"
    )

    original_read_csv = pd.read_csv

    def read_test_data(file_path, *arguments, **keyword_arguments):
        file_name = Path(file_path).name
        if file_name == "dns.csv":
            file_path = dns_test_file
        elif file_name == "redteam.csv":
            file_path = red_team_test_file
        return original_read_csv(file_path, *arguments, **keyword_arguments)

    monkeypatch.setattr(pd, "read_csv", read_test_data)
    script_results = runpy.run_path(
        str(dns_analysis_file_path)
    )

    missing_value_counts = script_results["null_counts"]
    assert missing_value_counts["time"] == 0
    assert missing_value_counts["source_computer"] == 1
    assert missing_value_counts["resolved_computer"] == 1

#Test 3 : Verify DNS events are assigned to the correct day
def test_dns_events_are_grouped_by_day(tmp_path, monkeypatch):
    dns_test_data = [
        "0,C100,C200",
        "86399,C100,C300",
        "86400,C200,C400",
        "172800,C300,C500"
    ]

    red_team_test_data = [
        "0,U748@DOM1,C100,C200"
    ]
    dns_test_file = tmp_path / "dns.csv"
    red_team_test_file = tmp_path / 'redteam.csv'

    dns_test_file.write_text(
        "\n".join(dns_test_data),
        encoding="utf-8"
    )

    red_team_test_file.write_text(
        "\n".join(red_team_test_data),
        encoding="utf-8"
    )

    original_read_csv = pd.read_csv

    def read_test_data(file_path, *arguments, **keyword_arguments):
        file_name = Path(file_path).name
        if file_name == "dns.csv":
            file_path = dns_test_file
        elif file_name == "redteam.csv":
            file_path = red_team_test_file
        return original_read_csv(file_path, *arguments, **keyword_arguments)

    monkeypatch.setattr(pd, "read_csv", read_test_data)
    script_results = runpy.run_path(
        str(dns_analysis_file_path)
    )

    actual_events_per_day = dict(script_results["rows_per_day"])
    expected_events_per_day = {
        0: 2,
        1: 1,
        2: 1
    }
    assert actual_events_per_day == expected_events_per_day