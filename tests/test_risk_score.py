from pathlib import Path
import pandas as pd

project_root_directory = Path(__file__).resolve().parents[1]

risk_scores_file_path = (
    project_root_directory / "output" / "u748_risk_scores.csv"
)

risk_scores_dataframe = pd.read_csv(risk_scores_file_path)

def test_risk_score_data_exists():
    assert len(risk_scores_dataframe) > 0

def test_risk_scores_are_within_valid_range():
    assert risk_scores_dataframe['risk_score'].notna().all()
    assert risk_scores_dataframe["risk_score"].between(0, 100).all()

def test_risk_score_calculation_matches_rules():
    expected_risk_scores = (
        35 * (risk_scores_dataframe["new_destination"] == 1)
        + 20 * (risk_scores_dataframe["authentication_type"] == "NTLM")
        + 25 * (risk_scores_dataframe["source_frequency"] <= 2)
        + 20 * (risk_scores_dataframe["destination_frequency"] <= 2)
    )

    expected_risk_scores = expected_risk_scores.clip(upper=100)
    actual_risk_scores = risk_scores_dataframe["risk_score"]
    assert (actual_risk_scores == expected_risk_scores).all()