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

The repository structure will be updated as development begins.

```text
mitre-capstone/
├── data/
├── docs/
├── notebooks/
├── src/
├── tests/
├── .gitignore
├── README.md
└── requirements.txt
