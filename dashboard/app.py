from pathlib import Path
import json
import streamlit as st
from model_results import render_model_results

st.set_page_config(
    page_title="MITRE Capstone",
    page_icon="",
    layout="wide",
)

st.title("Mitre Capstone")
st.write("AI-powered authentication threat detection")

# Read the saved LSTM testing summary instead of the large dataset
SUMMARY_FILE = (
    Path(__file__).resolve().parents[1]
    / "output"
    / "lstm_predictions_test_summary.json"
)

if not SUMMARY_FILE.exists():
    st.error(f"Model summary not found: {SUMMARY_FILE}")
    st.stop()

with SUMMARY_FILE.open("r", encoding="utf-8") as file:
    summary = json.load(file)

# Dashboard displays held-out testing results
split = 2

total_events = int(summary["total_scored_events"])
known_attacks = int(summary["known_red_team_events"])
other_events = int(summary["other_events"])

st.subheader("Authentication Activity Overview")
col1, col2, col3 = st.columns(3)
col1.metric("Total Authentication Events", f"{total_events:,}")
col2.metric("Known Red-Team Events", f"{known_attacks:,}")
col3.metric("No Known Attack Match", f"{other_events:,}")

st.caption(
    "Other evetns have no known red-team match. "
    "They are not necessarily verfied benign"
)

render_model_results(split) 