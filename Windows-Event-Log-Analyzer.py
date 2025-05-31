#SomeRandomStranger
#5/2/2024

import csv
import win32evtlog
import os.path

def analyze_windows_event_logs(log_name, output_file, sort_by=None):
    """
    Analyzes Windows event logs and saves the results to a CSV file.

    Args:
        log_name (str): The name of the Windows Event Log to analyze (e.g., 'Security').
        output_file (str): The path to save the CSV file.
        sort_by (str, optional): The column to sort the CSV file by. Defaults to None.

    Raises:
        ValueError: If the log name is invalid or if the output file does not have a '.csv' extension.
    """
    handle = win32evtlog.OpenEventLog(None, log_name)

    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    read_from_record = 0

    with open(output_file, 'w', newline='') as csvfile:
        fieldnames = ['Event ID', 'Time Generated', 'Source Name', 'Message']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        events = win32evtlog.ReadEventLog(handle, flags, read_from_record)

        for event in events:
            event_id = event.EventID
            event_time = event.TimeGenerated.Format()
            event_source = event.SourceName
            event_message = event.StringInserts

            writer.writerow({'Event ID': event_id,
                             'Time Generated': event_time,
                             'Source Name': event_source,
                             'Message': event_message})

    win32evtlog.CloseEventLog(handle)

    if sort_by:
        sort_csv_file(output_file, sort_by)

def sort_csv_file(csv_file, sort_by):
    """
    Sorts a CSV file by a specific column.

    Args:
        csv_file (str): The path to the CSV file.
        sort_by (str): The column to sort by.
    """
    rows = []
    with open(csv_file, 'r', newline='') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            rows.append(row)

    sorted_rows = sorted(rows, key=lambda x: x.get(sort_by))

    with open(csv_file, 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(sorted_rows)

def validate_log_name(log_name):
    """
    Validates the log name.

    Args:
        log_name (str): The name of the log.

    Raises:
        ValueError: If the log name is not one of the valid log names.
    """
    valid_log_names = ['Application', 'System', 'Security']
    if log_name not in valid_log_names:
        raise ValueError(f"Invalid log name. Please enter one of the following: {', '.join(valid_log_names)}")
    return log_name

def validate_output_file(output_file):
    """
    Validates the output file path.

    Args:
        output_file (str): The path to the output file.

    Raises:
        ValueError: If the output file does not have a '.csv' extension.
    """
    if not output_file.endswith('.csv'):
        raise ValueError("Output file must be a CSV file with a .csv extension")
    return output_file

def validate_sort_by(sort_by):
    """
    Validates the column to sort by.

    Args:
        sort_by (str): The column to sort by.

    Returns:
        str: The validated column name.
    """
    valid_sort_columns = ['Event ID', 'Time Generated', 'Source Name', 'Message', '']
    while True:
        if sort_by == '':
            return sort_by
        elif sort_by not in valid_sort_columns:
            print("Invalid column to sort by. Please enter one of the following: {}, or leave blank.".format(', '.join(valid_sort_columns)))
            sort_by = input("Enter 'Event ID', 'Time Generated', 'Source Name', 'Message', or leave blank: ").strip()
        else:
            return sort_by.strip()

def validate_file_path(file_path):
    """
    Validates the file path.

    Args:
        file_path (str): The path to the file.

    Raises:
        FileNotFoundError: If the file does not exist.
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")
    return file_path

def prompt_mode_selection():
    """
    Prompts the user to select the mode (1 for local computer, 2 for log file, or 'exit' to quit).

    Returns:
        str: The selected mode.
    """
    while True:
        mode = input("Select mode (1 for local computer, 2 for log file, or 'exit' to quit): ")
        if mode in ['1', '2', 'exit']:
            return mode
        print("Invalid mode selected. Please enter '1', '2', or 'exit'.")

def prompt_log_information(mode):
    """
    Prompts the user for log information based on the selected mode.

    Args:
        mode (str): The selected mode.

    Returns:
        str: The log name or file path.
    """
    if mode == '1':
        while True:
            log_name = input("Enter the name of the Windows Event Log to analyze (e.g., 'Security'): ")
            try:
                log_name = validate_log_name(log_name)
                return log_name
            except ValueError as e:
                print(e)
    elif mode == '2':
        log_file_path = input("Enter the path to the log file to analyze: ")
        log_file_path = validate_file_path(log_file_path)
        return log_file_path

def prompt_additional_analysis():
    """
    Prompts the user for additional analysis or to exit.

    Returns:
        bool: True if the user wants to analyze another log, False otherwise.
    """
    while True:
        choice = input("Do you want to analyze another log? (yes/no): ").lower()
        if choice in ['yes', 'no']:
            return choice == 'yes'
        print("Invalid choice. Please enter 'yes' or 'no'.")

# Main loop
while True:
    mode = prompt_mode_selection()

    if mode == 'exit':
        break

    log_info = prompt_log_information(mode)
    
    while True:
        output_file = input("Enter the path to save the CSV file (e.g., 'event_logs.csv'): ")
        try:
            output_file = validate_output_file(output_file)
            break
        except ValueError as e:
            print(e)

    sort_by = input("Do you want to sort the CSV file by a specific column? (Enter 'Event ID', 'Time Generated', 'Source Name', 'Message', or leave blank): ").strip()
    sort_by = validate_sort_by(sort_by)

    if mode == '1':
        analyze_windows_event_logs(log_info, output_file, sort_by)

    if not prompt_additional_analysis():
        break
