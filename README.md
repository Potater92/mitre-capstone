# MITRE Capstone

## Project Overview

This project focuses on creating a machine learning system that analyzes system telemetry data and determines:

- The confidence that a cyberattack is occurring
- The confidence that a system can no longer function correctly

The system will use telemetry data to help distinguish between cyberattacks, equipment malfunctions, false alerts, and other possible causes of system disruption.

The project will also use MITRE ATT&CK and MITRE ATLAS to help connect detected activity to known tactics and techniques. The final prototype will display results using confidence scores and visualizations to help explain what may be happening within the system.

## Team

**Nick Palmgren – Project Manager / Client Liaison**  
Responsible for helping keep the team on schedule, dividing work, and communicating with the MITRE sponsor.

**Aaron Hoover – Requirements Analyst / Scribe**  
Responsible for documenting project requirements, meeting notes, decisions, and project updates.

**Kameela Lawbaugh – Architect / Technical Lead / Lead Researcher**  
Responsible for helping make technical and architectural decisions and leading research involving MITRE ATT&CK, MITRE ATLAS, cybersecurity, machine learning, and data analysis.

**Michael Cea-Garcia – Quality Assurance / Testing Lead**  
Responsible for planning testing, checking system functionality, and helping make sure the different parts of the prototype work correctly.

## Main Project Areas

The project is currently divided into five main areas:

1. **Data Collection and Processing**
   - Understand the provided telemetry data
   - Clean and organize the data
   - Prepare the data for analysis
   Link to data source: https://lanl.ma.ic.ac.uk/data/cyber1/

2. **Analysis and Detection**
   - Analyze telemetry data
   - Identify unusual system behavior
   - Develop machine learning models for detecting possible disruptions

3. **MITRE Mapping and Context**
   - Map relevant activity to MITRE ATT&CK
   - Explore MITRE ATLAS mappings when applicable
   - Add cybersecurity context to detected behavior

4. **Risk and Impact**
   - Estimate cyberattack confidence
   - Estimate system functionality confidence
   - Evaluate the possible impact of detected activity

5. **Visualization and Reporting**
   - Display confidence scores
   - Show ATT&CK and ATLAS mappings
   - Create visualizations that help explain system activity

## Current LANL Analysis

We have started testing the project approach using the Los Alamos National Laboratory cybersecurity dataset.

The LANL dataset includes authentication, process, DNS, network-flow, and red-team activity. The current analysis focuses on authentication data and known red-team events.

The red-team data gives us known malicious activity that can be used as ground truth. This allows us to compare confirmed attack activity with normal authentication behavior.

Because the full authentication dataset is very large, a smaller time window was extracted around the first known red-team attacks. The selected authentication window contains 1,248,709 events and 10 known red-team events.

### Current Analysis Pipeline

```text
LANL authentication data
        +
red-team ground truth
        ↓
label known attacks
        ↓
extract behavioral features
        ↓
compare attack vs normal behavior
        ↓
calculate basic risk score
        ↓
MITRE ATT&CK mapping and interpretation
```

### Initial User Analysis

The first analysis focused on the user `U748@DOM1` because the account appeared in several known red-team events.

For this user, the selected window contained:

- 224 authentication events
- 30 unique source computers
- 31 unique destination computers
- 0 failed logins
- 7 known attack events

### Multi-User Analysis

The authentication analysis was expanded from only `U748@DOM1` to all users with known red-team events in the selected time window.

The users included are:

- `U620@DOM1`
- `U748@DOM1`
- `U6115@DOM1`
- `U636@DOM1`

Together, these users contain all 10 known red-team events in the selected authentication window.

The expanded analysis uses more general behavioral features so the system does not depend on a specific user or computer. These include:

- New source computer
- New destination computer
- Source computer frequency
- Destination computer frequency
- NTLM usage
- Number of authentication events within five minutes
- Number of unique destination computers within five minutes

All 10 known red-team events used NTLM. However, NTLM also appeared during normal activity, so it cannot be used alone to identify an attack.

Other features varied between users. For example, some attacks involved new destinations while others did not. This shows that no single feature consistently identifies every attack and supports combining multiple behavioral signals when calculating a cyberattack confidence score.

### Behavioral Features

Several behavioral features were first created for the U748 analysis and were later expanded into more general features that could be applied across multiple users:

- New source computer
- New destination computer
- Source computer frequency
- Destination computer frequency
- Authentication type
- NTLM usage
- Number of authentication events within five minutes
- Number of unique destinations accessed within five minutes

The `C17693` feature was useful for investigating this specific attack window because all seven known U748 attacks originated from that computer. However, this would not be a good final machine learning feature by itself because the model could simply memorize that computer instead of learning more general attack behavior.

The feature analysis showed that a new destination may be a useful signal. In the current sample, 57.14% of known attacks involved a new destination compared with 12.44% of normal events.

All seven known U748 attacks in this window also used NTLM. However, NTLM also appeared in normal activity, so it cannot be treated as an attack by itself.

### Basic Risk Score

A basic explainable risk score was created to test whether several weaker indicators could be combined.

The current score considers:

- New destination
- NTLM authentication
- Rare source computer
- Rare destination computer

The initial results were:

```text
Average normal risk score: 9.95
Average attack risk score: 40.0
```

Some normal events still received high scores and some known attacks received lower scores. This shows that authentication data alone is not enough to reliably identify an attack.

### Next Steps for the LANL Analysis

The authentication analysis has now been expanded across multiple attacked users. The next goal is to expand the amount and types of telemetry being analyzed.

This includes correlating authentication events with other LANL telemetry sources, especially:

- Process activity
- DNS activity
- Network-flow activity

Instead of only looking at one suspicious login, the system could eventually look for a sequence of related activity such as:

```text
Suspicious authentication
        ↓
Unusual process activity
        ↓
Network communication
        ↓
Related activity on another system
```

This would give the system stronger evidence when calculating a cyberattack confidence score.

## Technologies

Planned technologies include:

- Python
- PyTorch
- pandas
- NumPy
- Matplotlib
- pytest
- GitHub
- MITRE ATT&CK
- MITRE ATLAS

Additional tools and libraries may be added as the project develops.

## Project Milestones

### Milestone 1 – Requirements and Research
- Understand the project goal
- Meet with the MITRE sponsor
- Identify requirements
- Research ATT&CK, ATLAS, and CALDERA
- Define the scope of the prototype

### Milestone 2 – System Design and Data
- Create the initial system architecture
- Select software tools
- Understand the dataset format
- Begin data processing
- Define the initial ATT&CK and ATLAS mapping approach

### Milestone 3 – Core Prototype
- Develop the initial data analysis system
- Begin disruption classification
- Add basic ATT&CK and ATLAS mappings
- Create initial confidence scores
- Begin dashboard or frontend development

### Milestone 4 – Integration and Testing
- Connect the major system components
- Improve risk and impact assessment
- Improve confidence scoring
- Add visualizations
- Test multiple disruption scenarios

### Milestone 5 – Final Prototype
- Fully integrate the main system
- Complete detection and classification
- Display ATT&CK and ATLAS mappings
- Display confidence scores
- Complete visualizations
- Fix major bugs
- Complete testing and documentation

### Stretch Goal – Apache CALDERA

If time allows, Apache CALDERA may be used to simulate attacks against a virtual machine. The system can then be tested to determine whether the machine learning model correctly identifies and maps the simulated activity.

## Repository Structure

```text
mitre-capstone/
├── analysis/
│   ├── authentication/
│   │   ├── analyze_lanl.py
│   │   ├── compare_behavior.py
│   │   ├── feature_analysis.py
│   │   └── risk_score.py
│   │
│   ├── dns/
│   │
│   └── multi_user_analysis.py
│
├── data/
│
├── output/
│   ├── multi_user_features.csv
│   ├── u748_features.csv
│   └── u748_risk_scores.csv
│
├── tests/
├── .gitignore
├── README.md
└── requirements.txt
```

## Current Analysis Files

**`analysis/authentication/analyze_lanl.py`**  
Loads the authentication and red-team data, matches known red-team activity to authentication events, and analyzes U748 authentication activity.

**`analysis/authentication/feature_analysis.py`**  
Creates behavioral features for the U748 authentication activity and saves the results to `u748_features.csv`.

**`analysis/authentication/compare_behavior.py`**  
Compares normal and known attack activity to identify behavioral differences.

**`analysis/authentication/risk_score.py`**  
Creates a basic explainable risk score using several behavioral indicators.

**`analysis/multi_user_analysis.py`**  
Expands the authentication analysis to all users with known red-team activity in the selected time window and creates more general behavioral features.

**`output/u748_features.csv`**  
Contains the behavioral features created for the U748 analysis.

**`output/u748_risk_scores.csv`**  
Contains the calculated risk scores for the analyzed U748 events.

**`output/multi_user_features.csv`**  
Contains the behavioral features for all users with known red-team events in the selected authentication window.