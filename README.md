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
   - Link to data source: https://lanl.ma.ic.ac.uk/data/cyber1/

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

Because the full authentication dataset is very large, smaller authentication windows are being used during development. The current expanded window covers `150000` to `230000` seconds and contains 23 known red-team events.

### Recreating the Large Authentication Window

The expanded authentication window used for the multi-user analysis is not stored in the repository because the file is approximately 954 MB.

#### Windows PowerShell

Open PowerShell.

Go to the folder where you want to save the LANL files:

```powershell
cd $HOME\Desktop\mitre-lanl
```

Download part of the compressed LANL authentication dataset:

```powershell
curl.exe -L -H "Range: bytes=0-1200000000" https://lanl.ma.ic.ac.uk/data/cyber1/auth.txt.gz -o auth_partial.gz
```

Decompress the file:

```powershell
gzip -dc auth_partial.gz > auth_partial.txt
```

Filter the authentication data to timestamps `150000` through `230000`:

```powershell
Get-Content auth_partial.txt | Where-Object {
    $time = [int](($_ -split ',')[0])
    $time -ge 150000 -and $time -le 230000
} | Set-Content auth_attack_window_large.txt
```

Check that the file was created:

```powershell
Get-Item auth_attack_window_large.txt
```

Check the last few rows:

```powershell
Get-Content auth_attack_window_large.txt -Tail 3
```

The final rows should have timestamps around:

```text
230000
```

The generated file is used by:

```text
analysis/multi_user_analysis.py
```

The analysis also requires:

```text
redteam.txt
```

## How to Use

1. Clone the repo and create a virtual environment:
   python -m venv venv

   .\venv\Scripts\Activate.ps1

   pip install -r requirements.txt
2. Recreate the data window (see "Recreating the Large Authentication Window").
3. Download redteam.txt from https://lanl.ma.ic.ac.uk/data/cyber1/ and place it in data/.
4. Run the analysis:
   python analysis/multi_user_analysis.py
5. Run tests:
   pytest

## Release notes

### What is working in this submission
- Authentication analysis of the LANL dataset using red-team events as ground truth
- Per-user behavioral feature extraction (new source/destination, frequency,
  NTLM usage, 5-minute activity counts), generalized across all attacked users
- Multi-user analysis over the 150000–230000 window (23 red-team events, 5 users)
- Basic explainable risk score (avg normal 9.95 vs. avg attack 40.0)
- DNS profiling script
- Output CSVs in /output; tests in /tests

### Not yet implemented (differs from Milestone 3 plan)
- ML model (PyTorch) for detection/classification: currently rule-based scoring
- MITRE ATT&CK / ATLAS mapping in code: currently interpretation only
- System functionality confidence score
- Dashboard / frontend; visualizations are limited
- Correlation with process, DNS, and network-flow data

### Known limitations
- Authentication data alone doesn't reliably separate attacks (some normal events
  score high, some attacks score low)
- The 954 MB data window is not in the repo and must be regenerated

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

For this user, the original selected window contained:

- 224 authentication events
- 30 unique source computers
- 31 unique destination computers
- 0 failed logins
- 7 known attack events

### Multi-User Analysis

The authentication analysis was expanded to a larger time window from `150000` to `230000`.

The larger analysis includes 23 known red-team events across five attacked users:

- `U620@DOM1`
- `U748@DOM1`
- `U6115@DOM1`
- `U636@DOM1`
- `U1723@DOM1`

The analysis compares known attack activity with normal authentication behavior for each user.

The behavioral features include:

- New source computer
- New destination computer
- Source computer frequency
- Destination computer frequency
- NTLM usage
- Number of authentication events within five minutes
- Number of unique destination computers within five minutes

All 23 known red-team events in the larger window used NTLM. However, NTLM also appeared in normal activity, so it cannot be used alone to identify an attack.

Other features varied between users. Some attacks involved new source or destination computers while others did not. Attack activity also often involved source or destination computers that were used less frequently than during normal activity.

The larger sample continues to show that no single feature consistently identifies every attack. This supports combining multiple behavioral indicators when calculating a cyberattack confidence score.

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

The `C17693` feature was useful for investigating the original attack window because all seven known U748 attacks originated from that computer. However, this would not be a good final machine learning feature by itself because the model could simply memorize that computer instead of learning more general attack behavior.

The feature analysis showed that a new destination may be a useful signal, but it is not consistent across every attacked user.

NTLM appeared in all known red-team events in the larger window, but it also appeared during normal activity. This means NTLM is useful as supporting evidence but cannot be treated as an attack by itself.

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

The authentication analysis has now been expanded across multiple attacked users and a larger time window.

The next goal is to improve the confidence scoring and begin correlating authentication events with other LANL telemetry sources, especially:

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
│   │   └── profile_dns.py
│   │
│   └── multi_user_analysis.py
│
├── data/
│
├── output/
│   ├── multi_user_features.csv
│   ├── multi_user_features_large.csv
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
Creates behavioral features for U748 authentication activity and saves the results to `u748_features.csv`.

**`analysis/authentication/compare_behavior.py`**  
Compares normal authentication activity with known attack activity to identify behavioral differences.

**`analysis/authentication/risk_score.py`**  
Calculates a basic explainable risk score using multiple behavioral indicators.

**`analysis/multi_user_analysis.py`**  
Expands the authentication analysis to all users with known red-team activity in the selected time window. Calculates behavioral features for each user.

**`analysis/dns/profile_dns.py`**  
Profiles DNS telemetry for future integration with authentication and other system activity.

**`analysis/authentication/sigma_detection.py`**  
Tests three experimental detection rules: unusual destinations, multiple destinations within five minutes, and authentication bursts. Compares rule matches with known red-team events.

**`analysis/authentication/rarity_threshold_analysis.py`**  
Tests source and destination rarity using previous authentication events. Compares different frequency thresholds to determine how many known attacks are detected and how many additional events are flagged.

## Current Output Files

**`output/u748_features.csv`**  
Contains the behavioral features generated for U748 authentication activity.

**`output/u748_risk_scores.csv`**  
Contains the risk scores calculated for U748 authentication events.

**`output/multi_user_features.csv`**  
Contains behavioral features for users with known red-team events in the original selected authentication window.

**`output/multi_user_features_large.csv`**  
Contains behavioral features from the expanded authentication window covering timestamps 150000–230000, including 23 known red-team events across five attacked users.

**`output/sigma_detection_results.csv`**  
Contains authentication events with the results of each experimental detection rule.

**`output/sigma_detection_summary.csv`**  
Summarizes the number of alerts, known attacks detected, missed attacks, and detection performance for each rule.

**`output/rarity_threshold_comparison.csv`**  
Contains the results of testing eight different source and destination rarity thresholds.

## Experimental Authentication Detection

The authentication analysis was expanded to test additional detection rules inspired by the Sigma framework.

The SigmaHQ repository was downloaded, and PySigma 2.0.1 was installed to support future rule integration.

The current detection scripts use custom behavioral rules. Official SigmaHQ detection rules have not yet been executed against the LANL dataset.

### Initial Detection Results

The initial experiments analyzed 3,811 authentication events, including 23 known red-team events.

Three detection rules were tested:

- **Unusual destination:** Identifies a newly observed destination with low destination frequency.
- **Multiple destinations:** Identifies activity involving at least five unique destination computers within five minutes.
- **Authentication burst:** Identifies at least ten authentication events within five minutes.

The combined rules detected 15 of the 23 known attacks, or 65.22%. However, they generated 2,678 total alerts.

These results suggested that authentication volume alone was not a reliable way to distinguish known attacks from other activity.

### Rarity-Based Detection

Additional analysis showed that known red-team events generally involved source and destination computers with lower overall usage frequencies.

New detection conditions were tested using previous observations rather than total frequency counts from the entire dataset. This reduced the use of future information when evaluating an event.

Eight rarity thresholds were compared.

| Threshold | Known Attacks Detected | Other Events Flagged | Recall |
|---|---|---|---|
| 1 | 3/23 | 27 | 13.04% |
| 2 | 3/23 | 93 | 13.04% |
| 3 | 7/23 | 132 | 30.43% |
| 5 | 10/23 | 238 | 43.48% |
| 10 | 15/23 | 456 | 65.22% |
| 15 | 16/23 | 640 | 69.57% |
| 20 | 20/23 | 837 | 86.96% |
| 25 | 23/23 | 1,016 | 100.00% |

A threshold of 20 detected 20 of the 23 known attacks while flagging 837 other events.

A threshold of 25 detected all 23 known attacks but generated 1,016 alerts from events without known red-team labels.

The results show a tradeoff between detecting known attacks and reducing the number of alerts.

### Running the Detection Scripts

From the repository root, activate the Python virtual environment and install the required dependencies.

The experiments use the existing `output/multi_user_features_large.csv` file.

Run the initial detection analysis:

```bash
python analysis/authentication/sigma_detection.py
```

Run the rarity threshold comparison:

```bash
python analysis/authentication/rarity_threshold_analysis.py
```

Both scripts save their results to the `output` directory.

### Limitations

- The experiments were conducted using a limited authentication window containing 23 known red-team events.
- Results have not been validated using an independent dataset.
- Events without red-team labels are not necessarily harmless.
- Rarity counts begin at the start of the selected analysis window.
- Events with identical timestamps are evaluated in their existing row order.
- The current analysis focuses only on users associated with known red-team activity.
- Detection thresholds are experimental and require further testing.
- The scripts do not yet execute official SigmaHQ detection rules.

### Next Steps

- Test detection performance using separate training and evaluation windows.
- Identify SigmaHQ authentication rules compatible with LANL data.
- Use PySigma to parse and adapt supported detection rules.
- Improve detection accuracy while reducing unnecessary alerts.
- Combine authentication results with DNS, process, and network-flow activity.
- Map supported detections to MITRE ATT&CK techniques.
- Integrate detection results into the project's confidence scoring and visualization system.
