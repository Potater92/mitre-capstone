"""Display saved LSTM predictions in the Streamlit dashboard."""

import json
from pathlib import Path
import numpy as np
import pandas as pd
import plotly.graph_objects as go
import streamlit as st

ROOT = Path(__file__).resolve().parents[1]

PRED_FILE = (
    ROOT / "output" / "lstm_predictions_test.csv"
)

META_FILE = (
    ROOT / "output" / "lstm_predictions_test_summary.json"
)

BEHAVIORS = {
    "New destination computer": "f_dst_new",
    "New computer connection": "f_edge_new",
    "New source computer": "f_src_new",
    "Rapid authentication (60 sec)": "rapid_login",
    "Many recent new destinations": "many_new_destinations",
}

@st.cache_data(show_spinner="Loading LSTM predictions...")
def load_predictions(
    prediction_path,
    prediction_modified,
    summary_path,
    summary_modified,
):
    predictions = pd.read_csv(prediction_path)

    summary = json.loads(
        Path(summary_path).read_text(
            encoding="utf-8"
        )
    )

    required = {
        "f_dst_new",
        "f_edge_new",
        "f_src_new",
        "event_id",
        "label",
        "attack_score",
        "src_user",
        "src_comp",
        "dst_comp",
        "auth_type",
        "time",
        "seconds_since_previous",
        "f_new_rate",
    }

    missing = required - set(predictions.columns)

    if missing:
        raise ValueError(
            f"Missing prediction columns: {sorted(missing)}"
        )

    # Same user authenticated again within 60 seconds.
    predictions["rapid_login"] = (
        predictions["seconds_since_previous"] <= 60
    ).astype(int)

    # At least half of the user's recent authentication
    # events involved new destination computers.
    predictions["many_new_destinations"] = (
        predictions["f_new_rate"] >= 0.5
    ).astype(int)

    return predictions, summary

def render_model_results(selected_split):

    st.divider()

    st.subheader("LSTM Attack Detection Results")

    if selected_split != 2:
        st.info(
            "Model predictions currently cover the Testing "
            "dataset only. Select Testing above."
        )
        return

    if not PRED_FILE.exists() or not META_FILE.exists():
        st.info(
            "Predictions have not been exported yet. "
            "Run `python dashboard/export_predictions.py` "
            "to generate the model results."
        )
        return

    try:
        df, summary = load_predictions(
            str(PRED_FILE),
            PRED_FILE.stat().st_mtime_ns,
            str(META_FILE),
            META_FILE.stat().st_mtime_ns,
        )

    except (
        OSError,
        ValueError,
        KeyError,
        json.JSONDecodeError,
    ) as error:
        st.error(f"Unable to load predictions: {error}")
        return

    if int(summary["split"]) != 2:
        st.error(
            "Prediction file is not from the testing dataset."
        )
        return

    thresholds = {
        float(key): float(value)
        for key, value in summary["thresholds"].items()
    }

    options = sorted(thresholds)

    default_index = min(
        range(len(options)),
        key=lambda i: abs(options[i] - 0.001),
    )

    selected_fpr = st.selectbox(
        "Detection setting",
        options,
        index=default_index,
        format_func=lambda value: f"Target FPR {value:g}",
    )

    threshold = thresholds[selected_fpr]

    known_attack = df["label"] == 1

    flagged = df["attack_score"] >= threshold

    detected = int(
        (known_attack & flagged).sum()
    )

    missed = int(
        (known_attack & ~flagged).sum()
    )

    unconfirmed = int(
        (~known_attack & flagged).sum()
    )

    total_known = int(
        summary["known_red_team_events"]
    )

    if int(known_attack.sum()) != total_known:
        st.error(
            "Some known red-team predictions are missing. "
            "Regenerate the prediction export."
        )
        return

    recall = (
        detected / total_known
        if total_known > 0
        else float("nan")
    )

    other_events = int(summary["other_events"])

    not_flagged_other = other_events - unconfirmed

    if not_flagged_other < 0:
        st.error("The prediction counts are inconsistent.")
        return

    # Dashboard summary metrics
    a, b, c, d = st.columns(4)

    a.metric(
        "Known Attack Detection Rate",
        f"{recall:.1%}"
        if np.isfinite(recall)
        else "N/A",
    )

    b.metric(
        "Known Attacks Detected",
        f"{detected:,} / {total_known:,}",
    )

    c.metric(
        "Known Attacks Missed",
        f"{missed:,}",
    )

    d.metric(
        "Unconfirmed Alerts",
        f"{unconfirmed:,}",
    )

    st.caption(f"Detection threshold: {threshold:.4f}")

    # Authentication behavior heatmap
    st.subheader(
        "Authentication Behavior in AI Detection Results"
    )

    st.write("Compare authentication behaviors across detection outcomes.")

    groups = {
        "Known attacks detected": df[
            known_attack & flagged
        ],
        "Known attacks missed": df[
            known_attack & ~flagged
        ],
        "Unconfirmed alerts": df[
            ~known_attack & flagged
        ],
    }
    
    # Hide heatmap columns with no events.
    groups = {
        name: events
        for name, events in groups.items()
        if not events.empty
    }

    columns = list(groups.keys())

    heatmap_values = []
    heatmap_labels = []
    heatmap_hover = []
    for behavior_name, feature_column in BEHAVIORS.items():

        values_row = []
        labels_row = []
        hover_row = []

        for group_name, events in groups.items():

            total = len(events)

            count = int(
                (events[feature_column] == 1).sum()
            )

            if total > 0:

                percentage = 100 * count / total

                values_row.append(percentage)

                labels_row.append(
                    f"{percentage:.1f}%"
                )

                hover_row.append(
                    f"{behavior_name}<br>"
                    f"{group_name}<br>"
                    f"{count:,} of {total:,} events "
                    f"({percentage:.1f}%)"
                )

            else:

                values_row.append(None)
                labels_row.append("N/A")

                hover_row.append(
                    f"{behavior_name}<br>"
                    f"{group_name}<br>"
                    "No events in this category"
                )

        heatmap_values.append(values_row)
        heatmap_labels.append(labels_row)
        heatmap_hover.append(hover_row)

    fig = go.Figure(
        go.Heatmap(
            z=heatmap_values,
            x=columns,
            y=list(BEHAVIORS.keys()),
            text=heatmap_labels,
            texttemplate="%{text}",
            customdata=heatmap_hover,
            hovertemplate="%{customdata}<extra></extra>",
            colorscale="Blues",
            zmin=0,
            zmax=100,
            colorbar=dict(
                title="% of events"
            ),
            xgap=3,
            ygap=3,
            hoverongaps=False,
        )
    )

    fig.update_layout(
        height=370,
        margin=dict(
            l=0,
            r=0,
            t=18,
            b=10,
        ),
        xaxis=dict(side="top"),
        yaxis=dict(autorange="reversed"),
    )

    st.plotly_chart(
        fig,
        use_container_width=True,
    )

    st.caption("Darker blue = more frequent behavior | N/A = no events")