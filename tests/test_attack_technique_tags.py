import pandas as pd

from analysis.authentication.lateral_movement import (
    RULES_DIRECTORY,
    add_attack_technique,
    add_history_features,
    tag_techniques,
)

def test_attack_technique_requires_confirmed_attack():
    authentication_events = pd.DataFrame({
        "time": [1000, 1100, 1200, 1300],
        "source_user": ["U100@DOM1", "U200@DOM1", "U300@DOM1", "U400@DOM1"],
        "source_computer": ["C100", "C300", "C500", "C700"],
        "destination_computer": ["C200", "C400", "C600", "C800"],
        "authentication_type": ["NTLM"] * 4,
        "logon_type": ["Network"] * 4,
        "orientation": ["LogOn", "LogOn", "LogOff", "LogOff"],
        "result": ["Success", "Success", "Fail", "Fail"],
        "attack": [1, 0, 1, 0],
    })

    authentication_events = add_history_features(authentication_events)
    tagged_events, rule_hit_columns = tag_techniques(authentication_events, RULES_DIRECTORY)
    labeled_events = add_attack_technique(tagged_events)

    assert len(labeled_events) == 4
    assert len(rule_hit_columns) == 4

    confirmed_attack_with_rule = labeled_events.iloc[0]
    unconfirmed_event_with_rule = labeled_events.iloc[1]
    confirmed_attack_without_rule = labeled_events.iloc[2]
    unconfirmed_event_without_rule = labeled_events.iloc[3]

    assert confirmed_attack_with_rule["techniques"] != ""
    assert confirmed_attack_with_rule["attack_technique"] == confirmed_attack_with_rule["techniques"]

    assert unconfirmed_event_with_rule["techniques"] != ""
    assert unconfirmed_event_with_rule["attack_technique"] == ""

    assert confirmed_attack_without_rule["techniques"] == ""
    assert confirmed_attack_without_rule["attack_technique"] == "unmapped"

    assert unconfirmed_event_without_rule["techniques"] == ""
    assert unconfirmed_event_without_rule["attack_technique"] == ""

def test_technique_do_not_depend_on_attack_label():
    authentication_events = pd.DataFrame({
        "time": [1000],
        "source_user": ["U100@DOM1"],
        "source_computer": ["C100"],
        "destination_computer": ["C200"],
        "authentication_type": ["NTLM"],
        "logon_type": ["Network"],
        "orientation": ["LogOn"],
        "result": ["Success"],
        "attack": [1],
    })

    authentication_events = add_history_features(authentication_events)

    with_attack, _ = tag_techniques(authentication_events, RULES_DIRECTORY)

    authentication_events["attack"] = 0
    without_attack, _ = tag_techniques(authentication_events, RULES_DIRECTORY)

    assert with_attack["techniques"].tolist() == without_attack["techniques"].tolist()