# Windows Event Log Analyzer

The **Windows Event Log Analyzer** is a Python script designed to analyze Windows event logs and generate CSV files containing relevant event information. This tool can be used to extract event data from local event logs on a Windows machine or from log files stored elsewhere.

## Features

- **Analyze Local Event Logs**: Connects to the Windows Event Log on a local machine and extracts event information.
- **Analyze Log Files**: Analyzes event log files stored in CSV format.
- **Export to CSV**: Generates CSV files containing event data for further analysis or reporting.
- **Sort by Column**: Option to sort the generated CSV files by a specific column.
- **User-Friendly Interface**: Prompts users for mode selection, log information, output file path, and sorting preferences.

## Installation

1. **Clone the Repository**: Download or clone the repository to your local machine.
2. **Install Dependencies**: Ensure you have Python installed, and install the required dependencies using pip:
   ```bash
   pip install pywin32

## Usage

1. **Mode Selection**: Select the mode of operation (1 for local computer, 2 for log file analysis, or 'exit' to quit).
2. **Log Information**: Depending on the selected mode, provide the name of the Windows Event Log to analyze or the path to the log file.
3. **Output File**: Enter the path to save the generated CSV file.
4. **Sorting**: Optionally specify a column to sort the CSV file by (Event ID, Time Generated, Source Name, or Message).
5. **Repeat Analysis**: Choose to analyze another log or exit the program.

**Run the Script: Execute the event_log_analyzer.py script using Python:**:
python event_log_analyzer.py

## Contributors
SomeRandomStranger

## License

This project is licensed under the GNU License - see the [LICENSE](LICENSE) file for details.
