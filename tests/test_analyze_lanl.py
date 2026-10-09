from pathlib import Path
import runpy

project_root_directory = Path(__file__).resolve().parents[1]

authentication_analysis_file_path = (
    project_root_directory
    / "analysis"
    / "authentication"
    / "analyze_lanl.py"
)

def test_known_red_team_events_are_identified(tmp_path, monkeypatch):
    authentication_test_data = [
        "100,U748@DOM1,U748@DOM1,C17693,C728,NTLM,Network,LogOn,Success",
        "200,U748@DOM1,U748@DOM1,C17693,C500,NTLM,Network,LogOn,Success",
        "300,U999@DOM1,U999@DOM1,C100,C200,NTLM,Network,LogOn,Success"
    ]

    red_team_test_data = [
        "100,U748@DOM1,C17693,C728"
    ]

    authentication_test_file = tmp_path / "auth_attack_window.txt"
    red_team_test_file = tmp_path / "redteam.txt"

    authentication_test_file.write_text(
        "\n".join(authentication_test_data),
        encoding="utf-8"
    )
    red_team_test_file.write_text(
        "\n".join(red_team_test_data),
        encoding="utf-8"
    )

    monkeypatch.chdir(tmp_path)

    script_results = runpy.run_path(
        str(authentication_analysis_file_path)
    )

    processed_authentication_data = script_results["auth"]
    actual_attack_labels = processed_authentication_data["attack"].tolist()
    expected_attack_labels = [1, 0, 0]
    assert actual_attack_labels == expected_attack_labels

#Test 2: Verify failed login counts
def test_failed_login_count(tmp_path, monkeypatch, capsys):
    authentication_test_data = [
        "100,U748@DOM1,U748@DOM1,C17693,C728,NTLM,Network,LogOn,Success",
        "200,U748@DOM1,U748@DOM1,C17693,C500,NTLM,Network,LogOn,Fail",
        "300,U748@DOM1,U748@DOM1,C17693,C600,NTLM,Network,LogOn,Fail",
        "400,U999@DOM1,U999@DOM1,C100,C200,NTLM,Network,LogOn,Fail"
    ]

    red_team_test_data = [
        "100,U748@DOM1,C17693,C728"
    ]

    authentication_test_file = tmp_path / 'auth_attack_window.txt'
    red_team_test_file = tmp_path / 'redteam.txt'

    authentication_test_file.write_text(
        "\n".join(authentication_test_data),
        encoding="utf-8"
    )
    red_team_test_file.write_text(
        "\n".join(red_team_test_data),
        encoding="utf-8"
    )

    monkeypatch.chdir(tmp_path)

    runpy.run_path(str(authentication_analysis_file_path))
    captured_output = capsys.readouterr().out
    assert "Failed logins:\n2" in captured_output

#Test 3: Verify that only U748 events are selected
def test_u748_authentication_filter(tmp_path, monkeypatch):
    authentication_test_data = [
        "100,U748@DOM1,U748@DOM1,C17693,C728,NTLM,Network,LogOn,Success",
        "200,U999@DOM1,U999@DOM1,C100,C200,NTLM,Network,LogOn,Success",
        "300,U748@DOM1,U748@DOM1,C17693,C500,NTLM,Network,LogOn,Fail",
        "400,U500@DOM1,U500@DOM1,C300,C400,NTLM,Network,LogOn,Success"
    ]

    red_team_test_data = [
        "100,U748@DOM1,C17693,C728"
    ]

    authentication_test_file = tmp_path / 'auth_attack_window.txt'
    red_team_test_file = tmp_path / 'redteam.txt'

    authentication_test_file.write_text(
        "\n".join(authentication_test_data),
        encoding="utf-8"
    )
    red_team_test_file.write_text(
        "\n".join(red_team_test_data),
        encoding="utf-8"
    )

    monkeypatch.chdir(tmp_path)

    script_results = runpy.run_path(
        str(authentication_analysis_file_path)
    )

    processed_authentication_data = script_results["auth"]
    u748_authentication_events = processed_authentication_data[
        processed_authentication_data["source_user"] == "U748@DOM1"
    ]

    assert len(u748_authentication_events) == 2
    assert len(processed_authentication_data) == 4

#Test 4: Verify the U748 summary excludes other users
def test_u748_summary_excludes_other_users(tmp_path, monkeypatch, capsys):
    authentication_test_data = [
        "100,U748@DOM1,U748@DOM1,C17693,C728,NTLM,Network,LogOn,Success",
        "200,U999@DOM1,U999@DOM1,C100,C200,NTLM,Network,LogOn,Fail",
        "300,U748@DOM1,U748@DOM1,C17693,C500,NTLM,Network,LogOn,Fail",
        "400,U500@DOM1,U500@DOM1,C300,C400,NTLM,Network,LogOn,Success"
    ]

    red_team_test_data = [
        "100,U748@DOM1,C17693,C728"
    ]

    authentication_test_file = tmp_path / 'auth_attack_window.txt'
    red_team_test_file = tmp_path / 'redteam.txt'

    authentication_test_file.write_text(
        "\n".join(authentication_test_data),
        encoding="utf-8"
    )
    red_team_test_file.write_text(
        "\n".join(red_team_test_data),
        encoding="utf-8"
    )

    monkeypatch.chdir(tmp_path)

    runpy.run_path(str(authentication_analysis_file_path))
    captured_output = capsys.readouterr().out
    assert "Total events: 2" in captured_output
    assert "Failed logins:\n1" in captured_output
    assert "Known attacks:\n1" in captured_output