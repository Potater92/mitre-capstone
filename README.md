
# MITRE Capstone

## Project Overview

Our project focuses on using system telemetry data to identify possible cyberattacks and system disruptions. We want to build a machine learning system that can estimate how likely an attack is occurring and whether a system is still functioning correctly.

The system will eventually use different types of data to help determine whether unusual activity is caused by a cyberattack, equipment malfunction, false alert, or something else.

We also plan to use MITRE ATT&CK and MITRE ATLAS to help explain detected activity. Our final goal is to display confidence scores and visualizations that make the results easier to understand.

## Team

**Nick Palmgren – Project Manager / Client Liaison**

Helps keep the team organized, manages project tasks, and communicates with our MITRE sponsor.

**Aaron Hoover – Requirements Analyst / Scribe**

Documents requirements, meeting notes, project decisions, and updates.

**Kameela Lawbaugh – Architect / Technical Lead / Lead Researcher**

Helps make technical decisions and leads research involving cybersecurity, data analysis, machine learning, MITRE ATT&CK, and MITRE ATLAS.

**Michael Cea-Garcia – Quality Assurance / Testing Lead**

Handles testing plans, checks functionality, and helps make sure the different parts of the project work correctly.

## Main Project Areas

Our project is divided into five areas:

1. **Data Collection and Processing**
   - Understand the telemetry data
   - Clean and organize datasets
   - Extract data from different time ranges
   - Prepare data for analysis

2. **Analysis and Detection**
   - Look for unusual system behavior
   - Compare known attacks with other activity
   - Test detection rules
   - Develop machine learning approaches

3. **MITRE Mapping**
   - Connect findings to relevant MITRE ATT&CK techniques
   - Research MITRE ATLAS when applicable
   - Explain why certain behavior may be suspicious

4. **Risk and Impact**
   - Estimate attack confidence
   - Estimate system functionality confidence
   - Evaluate how detected activity may affect a system

5. **Visualization**
   - Display detection results
   - Show confidence scores
   - Present MITRE mappings
   - Make system activity easier to understand

## LANL Dataset

We are currently working with the Los Alamos National Laboratory (LANL) cybersecurity dataset.

Dataset: https://lanl.ma.ic.ac.uk/data/cyber1/

The dataset contains:

- Authentication data
- Process data
- DNS data
- Network-flow data
- Red-team data

We started with authentication data and have since added process analysis. Our next step is to look at network-flow data.

The red-team file contains known attack activity, which allows us to check whether our detection methods are identifying those events.

Events that are not labeled as attacks are not automatically considered harmless.

### Current Time Range

Our current analysis uses timestamps `150000` through `230000`.

We chose a smaller section of the dataset because the full files are very large and difficult to work with all at once.

We plan to move this window to different timestamps to see whether our findings are consistent across other parts of the dataset.

---

## Authentication Analysis

### Initial Analysis

We started by analyzing authentication activity for `U748@DOM1`, one of the users with known red-team activity.

The original window contained:

- 224 authentication events
- 30 unique source computers
- 31 unique destination computers
- 7 known attack events

We compared the known attacks with the user's other authentication activity to look for differences.

### Expanded Analysis

We later expanded the analysis to include five users with known red-team activity:

- `U620@DOM1`
- `U748@DOM1`
- `U6115@DOM1`
- `U636@DOM1`
- `U1723@DOM1`

Results:

| Metric | Result |
|---|---:|
| Total authentication events | 3,811 |
| Known attacks | 23 |
| Other events | 3,788 |
| Users analyzed | 5 |

These users were selected because they appeared in the red-team data during our chosen time range.

### Authentication Features

We created several features to compare authentication behavior:

- New source computer
- New destination computer
- Source computer frequency
- Destination computer frequency
- Authentication type
- NTLM usage
- Authentication events within five minutes
- Unique destinations within five minutes

These features help us look at how a user's behavior changes during known attacks.

### What We Found

All 23 known attacks in this window used NTLM authentication.

However, NTLM also appeared in other activity, so we cannot use it alone to determine whether something is an attack.

We also found that attacks sometimes involved computers that users rarely connected to.

For example, all seven of the original U748 attacks came from computer `C17693`.

This was useful for investigating those events, but we do not want a future model to simply memorize that computer.

Our goal is to identify patterns that could also work on different computers and time ranges.

## Initial Risk Score

We created a basic risk score using:

- New destinations
- NTLM authentication
- Rare source computers
- Rare destination computers

Results:

| Activity | Average Risk Score |
|---|---:|
| Other authentication activity | 9.95 |
| Known attacks | 40.00 |

Known attacks generally received higher scores, but there was still overlap between the two groups.

Some events without known attack labels received high scores, and some known attacks received lower scores.

This showed us that we need more information than authentication data alone.

The current risk score is experimental and is not an actual probability of an attack.

---

## Sigma-Inspired Detection

We installed PySigma 2.0.1 and downloaded the SigmaHQ rules repository.

We have not run the official SigmaHQ rules against the LANL dataset yet. Instead, we created a few custom detection rules based on similar ideas.

### Detection Rules

We tested three rules:

1. **Unusual Destination:** Checks for newly observed destinations with low usage frequency.
2. **Multiple Destinations:** Checks whether a user connects to at least five different destinations within five minutes.
3. **Authentication Burst:** Checks whether at least ten authentication events occur within five minutes.

### Results

| Metric | Result |
|---|---:|
| Events analyzed | 3,811 |
| Known attacks | 23 |
| Attacks detected | 15 |
| Attacks missed | 8 |
| Total alerts | 2,678 |
| Recall | 65.22% |

The combined rules detected 15 out of 23 known attacks.

The problem was that they also flagged a lot of other events.

This helped us see that simply counting authentication activity was not enough.

## Rarity Threshold Analysis

We then tested whether uncommon source and destination computers were better indicators of suspicious activity.

Instead of using the total number of times a computer appeared in the entire dataset, we counted how often it had appeared previously.

This keeps the analysis from using future events to evaluate earlier ones.

We tested eight thresholds.

### Results

| Threshold | Attacks Detected | Other Events Flagged | Recall |
|---|---|---:|---:|
| 1 | 3/23 | 27 | 13.04% |
| 2 | 3/23 | 93 | 13.04% |
| 3 | 7/23 | 132 | 30.43% |
| 5 | 10/23 | 238 | 43.48% |
| 10 | 15/23 | 456 | 65.22% |
| 15 | 16/23 | 640 | 69.57% |
| 20 | 20/23 | 837 | 86.96% |
| 25 | 23/23 | 1,016 | 100.00% |

At a threshold of 20, we detected 20 of the 23 known attacks.

At 25, we detected all 23 attacks, but also flagged 1,016 events without known attack labels.

The higher threshold detected more attacks but also produced more alerts.

These results are based only on our selected time window, so we still need to test whether the same thresholds work elsewhere.

---

## Process Data Analysis

After working with authentication data, we started looking at process activity.

The process dataset records when processes start and end on different computers.

We wanted to see whether there were differences in process activity around known attacks.

Process dataset: https://lanl.ma.ic.ac.uk/data/cyber1/proc.txt.gz

### Extracting the Process Data

We created `extract_process_window.py` to extract process events from timestamps `150000` through `230000`.

Results:

| Metric | Result |
|---|---:|
| Events read | 17,855,081 |
| Events saved | 5,588,686 |

The extracted file is called `proc_attack_window_large.txt` and is approximately 186 MB.

We keep this file outside the GitHub repository because of its size.

### Process Analysis Results

We created `process_analysis.py` to look at process starts, ends, users, computers, and process frequencies.

| Metric | Result |
|---|---:|
| Total process events | 5,588,686 |
| Process starts | 4,392,157 |
| Process ends | 1,196,529 |
| Unique users | 14,991 |
| Unique computers | 6,470 |
| Unique process identifiers | 4,413 |

### Most Common Processes

| Process | Starts |
|---|---:|
| P16 | 1,224,889 |
| P5 | 504,709 |
| P14 | 223,922 |
| P13 | 210,503 |
| P25 | 174,242 |
| P7 | 140,261 |
| P8 | 124,987 |
| P10 | 122,504 |
| P21 | 86,639 |
| P9 | 86,564 |

The LANL dataset uses anonymized process identifiers, so we do not know the actual program names.

For now, we are focusing on how often processes appear and whether that activity changes around attacks.

## Comparing Process Activity with Known Attacks

We created `process_attack_correlation.py` to look at process activity around the 23 known red-team authentication events.

For each event, we checked the source and destination computers within five minutes before and after the authentication.

Results:

| Metric | Result |
|---|---:|
| Known attacks | 23 |
| Computer windows analyzed | 46 |
| Average destination process starts | 26.30 |
| Median destination process starts | 16 |
| Maximum destination process starts | 79 |
| Average source process starts | 0 |

One thing we noticed was that computer `C17693`, which appeared as the source of the known attacks, did not have any process records in our extracted dataset.

That does not mean the computer had no processes running. It just means we do not have process data for it in this window.

We did find process activity on destination computers.

For example, computer `C231` had 77 process starts near one known attack and 79 near another.

## Process Behavior Comparison

We then created `compare_process_behavior.py` to compare process activity around known attacks with other authentication activity.

We excluded events without the needed destination process data. We also excluded unlabeled events that occurred too close to known attacks on the same destination computer.

This left us with:

- 22 known attacks
- 3,381 other authentication events
- 3,403 total events

### Results

| Metric | Known Attacks | Other Events |
|---|---:|---:|
| Average process starts | 27.50 | 4.75 |
| Average unique processes | 13.68 | 2.75 |

We found that known attack windows had about 5.8 times more process starts on average.

They also had more unique process identifiers.

This is interesting because it suggests process activity could help us identify suspicious behavior.

However, we still need to check whether the difference is related to the attacks or whether some computers are naturally more active than others.

The windows also overlap in some cases, so these results are not enough to confirm that increased process activity is a reliable attack indicator.

---

## Current Analysis Files

### Authentication

**`analysis/authentication/analyze_lanl.py`**

Loads authentication and red-team data and analyzes U748 activity.

**`analysis/authentication/feature_analysis.py`**

Creates authentication features for U748.

**`analysis/authentication/compare_behavior.py`**

Compares known attacks with other authentication activity.

**`analysis/authentication/risk_score.py`**

Calculates our initial authentication risk score.

**`analysis/multi_user_analysis.py`**

Expands the authentication analysis across multiple users.

**`analysis/authentication/sigma_detection.py`**

Tests our three Sigma-inspired detection rules.

**`analysis/authentication/rarity_threshold_analysis.py`**

Tests different source and destination rarity thresholds.

### Process

**`analysis/process/extract_process_window.py`**

Extracts process data from the selected timestamp window.

**`analysis/process/process_analysis.py`**

Analyzes process starts, ends, and frequencies.

**`analysis/process/process_attack_correlation.py`**

Looks at process activity around known red-team events.

**`analysis/process/compare_process_behavior.py`**

Compares process activity near known attacks with other authentication events.

### DNS

**`analysis/dns/profile_dns.py`**

Profiles DNS data for future analysis.

## Current Output Files

### Authentication

- `output/u748_features.csv`
- `output/u748_risk_scores.csv`
- `output/multi_user_features.csv`
- `output/multi_user_features_large.csv`
- `output/sigma_detection_results.csv`
- `output/sigma_detection_summary.csv`
- `output/rarity_threshold_comparison.csv`

### Process

- `output/process_frequency.csv`
- `output/process_attack_correlation.csv`
- `output/process_behavior_comparison.csv`

The CSV files contain the results from our analysis scripts.

---

## How to Run

Clone the repository:

```bash
git clone https://github.com/Potater92/mitre-capstone.git
cd mitre-capstone
```

### Create a Virtual Environment

On macOS or Linux:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

On Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

Install dependencies:

```bash
pip install -r requirements.txt
```

### Data Setup

Download the required data from:

https://lanl.ma.ic.ac.uk/data/cyber1/

The current analysis uses:

- `auth.txt.gz`
- `proc.txt.gz`
- `redteam.txt.gz`

The large extracted authentication and process files are kept locally and are not included in the repository.

The scripts require the relevant input files to be available at their configured paths.

### Run Authentication Analysis

```bash
python analysis/multi_user_analysis.py
```

### Run Sigma-Inspired Detection

```bash
python analysis/authentication/sigma_detection.py
```

### Run Rarity Threshold Analysis

```bash
python analysis/authentication/rarity_threshold_analysis.py
```

### Run Process Analysis

```bash
python analysis/process/process_analysis.py
```

### Run Process Attack Correlation

```bash
python analysis/process/process_attack_correlation.py
```

### Run Process Comparison

```bash
python analysis/process/compare_process_behavior.py
```

The process scripts require the extracted process window, and some scripts also use authentication output files generated earlier.

### Run Tests

```bash
pytest
```

---

## Current Project Status

### What We Have Working

- Authentication analysis
- Multi-user authentication features
- Matching authentication events with red-team data
- Basic risk scoring
- Sigma-inspired detection rules
- Rarity threshold testing
- Process data extraction
- Process frequency analysis
- Authentication and process correlation
- Process behavior comparison
- Initial DNS profiling

### What We Still Need

- Network-flow analysis
- Testing different timestamp windows
- Better comparison of normal and suspicious behavior
- Combining features from multiple telemetry sources
- Machine learning detection and classification
- MITRE ATT&CK and ATLAS mapping in code
- System functionality confidence scoring
- Dashboard and visualizations
- More testing and validation

---

## Next Steps

### 1. Look at Network-Flow Data

Our next step is to work with the LANL network-flow dataset:

https://lanl.ma.ic.ac.uk/data/cyber1/flows.txt.gz

We want to see what information is available and whether network communication can help explain the activity we are finding in the authentication and process data.

We plan to:

- Download and inspect the network-flow dataset
- Extract records from our selected timestamp window
- Look at communication between computers
- Compare network activity around known attacks
- See whether network-flow patterns support what we found in the other datasets

### 2. Move the Timestamp Window

We also want to move beyond timestamps `150000` through `230000`.

We plan to select different time ranges and repeat parts of our analysis.

This will help us see whether our current findings are consistent or whether they only appear in the original window.

We want to:

- Select new timestamp ranges
- Find known red-team activity in those ranges
- Extract matching authentication, process, and network-flow data
- Compare the results with our current window
- Retest the rarity thresholds
- Check whether the same process activity patterns appear elsewhere

### 3. Improve Process Analysis

We found more process activity around known attacks, but we still need to compare that activity with what is normal for each computer.

We also want to look into rare processes, new process identifiers, and changes in process frequency over time.

### 4. Combine the Data

So far, authentication and process data have mostly been analyzed separately, with some initial correlation between them.

We want to bring the different sources together so we can look at related events instead of evaluating each event by itself.

### 5. Improve Detection and MITRE Mapping

Once we have more data, we plan to improve our detection rules and confidence scoring.

We also want to connect relevant findings to MITRE ATT&CK techniques where the evidence supports a mapping.

---

## Technologies

- Python
- pandas
- NumPy
- PySigma
- PyTorch (planned)
- Matplotlib
- pytest
- GitHub
- MITRE ATT&CK
- MITRE ATLAS
- Apache CALDERA (stretch goal)

## Project Milestones

### Milestone 1 – Requirements and Research

- Understand the project goals
- Meet with the MITRE sponsor
- Identify requirements
- Research ATT&CK, ATLAS, and CALDERA
- Define the project scope

### Milestone 2 – System Design and Data

- Design the initial architecture
- Select tools
- Understand the LANL datasets
- Begin processing data
- Plan the MITRE mapping approach

### Milestone 3 – Core Prototype

- Build the initial analysis system
- Begin disruption classification
- Add basic ATT&CK and ATLAS mappings
- Create confidence scoring
- Begin dashboard development

### Milestone 4 – Integration and Testing

- Connect different system components
- Improve confidence scoring
- Add visualizations
- Test different scenarios
- Improve detection results

### Milestone 5 – Final Prototype

- Integrate the system
- Complete detection and classification
- Display MITRE mappings
- Display confidence scores
- Complete visualizations
- Finish testing and documentation

### Stretch Goal – Apache CALDERA

If time allows, we may use Apache CALDERA to simulate attacks on a virtual machine and test whether our system can recognize the activity.

---

## Repository Structure

```text
mitre-capstone/
├── analysis/
│   ├── authentication/
│   │   ├── analyze_lanl.py
│   │   ├── compare_behavior.py
│   │   ├── feature_analysis.py
│   │   ├── risk_score.py
│   │   ├── sigma_detection.py
│   │   └── rarity_threshold_analysis.py
│   │
│   ├── process/
│   │   ├── extract_process_window.py
│   │   ├── process_analysis.py
│   │   ├── process_attack_correlation.py
│   │   └── compare_process_behavior.py
│   │
│   ├── dns/
│   │   └── profile_dns.py
│   │
│   └── multi_user_analysis.py
│
├── data/
├── output/
│   ├── u748_features.csv
│   ├── u748_risk_scores.csv
│   ├── multi_user_features.csv
│   ├── multi_user_features_large.csv
│   ├── sigma_detection_results.csv
│   ├── sigma_detection_summary.csv
│   ├── rarity_threshold_comparison.csv
│   ├── process_frequency.csv
│   ├── process_attack_correlation.csv
│   └── process_behavior_comparison.csv
│
├── tests/
├── .gitignore
├── README.md
└── requirements.txt
```

## Known Limitations

- We are only using a small portion of the full LANL dataset.
- Our current authentication window contains 23 known red-team events.
- The accounts analyzed were selected based on known red-team activity.
- Events without known attack labels are not necessarily normal.
- Detection thresholds still need more testing.
- Process names are anonymized.
- Some computers do not have recorded process data.
- More process starts do not automatically mean an attack occurred.
- Some of our process observation windows overlap.
- We have not yet tested whether the results hold across different timestamp windows.
- We have not built the complete machine learning model or dashboard.

## Summary

So far, we have analyzed authentication activity, tested different detection rules, and started comparing process activity around known attacks.

Our authentication experiments showed that no single indicator was enough to reliably identify all attacks. The rarity thresholds improved recall, but also flagged a large number of other events.

When we added process data, we found that known attack windows had more process activity on average. We still need to determine whether that difference is meaningful when comparing the same computers over time.

Next, we are going to look at the network-flow dataset and move the timestamp window to see what we find in other parts of the LANL data. These results will help us decide which features are worth using as we continue building the detection system.
