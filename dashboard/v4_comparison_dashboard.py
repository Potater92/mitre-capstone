import pandas as pd
import streamlit as st

st.set_page_config(
    page_title="MITRE Model Comparison",
    page_icon="📊",
    layout="wide",
)

st.title("MITRE Model Comparison")
st.write("Comparing supervised learning models for cyberattack detection")

st.subheader("Model Performance Overview")

results = pd.DataFrame({
    "Metric": [
        "ROC-AUC",
        "PR-AUC",
        "Attacks Detected",
        "Known Attacks Missed",
        "Unconfirmed Alerts",
        "Precision",
        "Recall",
    ],
    "Aaron's LSTM": [
        "1.0000",
        "0.6341",
        "132 / 132",
        "0",
        "1,008",
        "11.58%",
        "100.00%",
    ],
    "Supervised V4": [
        "0.9999",
        "0.6344",
        "126 / 132",
        "6",
        "582",
        "17.80%",
        "95.45%",
    ],
})

st.dataframe(results, hide_index=True, use_container_width=True)

st.divider()
st.subheader("Attack Detection Comparison")

col1, col2 = st.columns(2)

with col1:
    st.write("Known Attacks Detected")
    detected = pd.DataFrame({
        "Model": ["Aaron's LSTM", "Supervised V4"],
        "Detected": [132, 126],
    }).set_index("Model")
    st.bar_chart(detected)

with col2:
    st.write("Unconfirmed Alerts")
    alerts = pd.DataFrame({
        "Model": ["Aaron's LSTM", "Supervised V4"],
        "Alerts": [1008, 582],
    }).set_index("Model")
    st.bar_chart(alerts)

st.divider()
st.subheader("Key Findings")

st.write(
    "**Aaron's LSTM:** Detected all 132 known attacks "
    "but generated 1,008 unconfirmed alerts."
)

st.write(
    "**Supervised V4:** Detected 126 of 132 known attacks "
    "with 582 unconfirmed alerts."
)

st.write(
    "**V4 reduced unconfirmed alerts by 42.3%, "
    "while its known attack detection rate decreased "
    "from 100% to 95.45%.**"
)

st.caption(
    "Results are from previously completed tests on the same "
    "held-out dataset, using each model's selected threshold. "
    "Unconfirmed alerts are not necessarily verified false positives."
)
