# README.txt

## Overview

This ZIP Security Analysis Tool is a graphical application designed to scan and analyze the contents of ZIP files. It checks for specific keywords, verifies files using VirusTotal, and generates detailed reports. Additionally, it can handle password-protected ZIP files and create a final encrypted ZIP file containing the analyzed content.

## Methods and Their Functions

### Class: ZipSecurityAnalysisTool

#### `__init__(self, master)`
Initializes the main application window and its components:
- Configures the main window.
- Sets up labels, buttons, entry fields, and their styles.

#### `choose_file(self)`
Opens a file dialog to select a ZIP file for analysis:
- Verifies if the selected file is a ZIP file and exists.
- Enables the "Start Scan" button if the file is valid.

#### `log_message(self, message)`
Logs messages to the log text area in the log window:
- Displays the message in the log text area.
- Updates the log window and pauses briefly.

#### `start_scan_thread(self)`
Starts the scan in a separate thread:
- Opens a new window with a progress bar and log text area.
- Starts the `start_scan` method in a separate thread.

#### `start_scan(self)`
Performs the main scan and analysis process:
- Extracts and verifies passwords for the ZIP file.
- Unzips files and calculates their checksums.
- Searches for keywords and email addresses in the unzipped files.
- Generates a detailed report and creates a final encrypted ZIP file.
- Cleans up temporary files and directories.

### Utility Functions

#### `requires_password(zip_path)`
Checks if the ZIP file requires a password for extraction.

#### `check_zip_password(zip_path, password_file)`
Tries common passwords from a list to unlock the ZIP file.

#### `unzip_and_checksum(zip_path, password)`
Extracts files from the ZIP and calculates their SHA-256 checksums.

#### `virustotal_check(file_hash)`
Checks a file's hash against VirusTotal's database to get a scan result.

#### `search_keywords(content, keywords)`
Searches for specified keywords and email addresses in the content.

#### `generate_report(checksums, keywords_report, file_list, zip_password)`
Generates a detailed report of file checksums and keyword occurrences.

#### `clean_up(paths)`
Deletes specified files and directories to clean up temporary data.

### Main Execution Block

#### `if __name__ == "__main__"`
Initializes and runs the application.

## Imports and Their Usage

- `os`: Used for file and directory operations such as checking file existence, removing files, and creating directories.
- `zipfile`: Handles reading, writing, and extracting ZIP files.
- `hashlib`: Generates SHA-256 checksums for files.
- `requests`: Sends HTTP requests to the VirusTotal API to check file hashes.
- `time`: Measures execution time and pauses execution briefly.
- `logging`: Logs messages and errors to a log file for debugging and tracking purposes.
- `json`: Handles JSON data, primarily for formatting reports.
- `shutil`: Performs high-level file operations such as removing directories.
- `PyPDF2`: Extracts text from PDF files for keyword searching.
- `re`: Handles regular expressions for keyword and email searches.
- `pyzipper`: Creates encrypted ZIP files.
- `tkinter`: Provides the graphical user interface components.
- `threading`: Runs the scanning process in a separate thread to keep the GUI responsive.

## Usage

1. Launch the application.
2. Choose a ZIP file to analyze.
3. Enter keywords to search within the files.
4. Enter a password for the final encrypted ZIP file.
5. Click "Start Scan" to begin the analysis.
6. View the progress and logs in the new window.
7. After the scan completes, the final encrypted ZIP file will be saved to the Downloads folder.

## Notes

- Ensure you have the required dependencies installed (`PyPDF2`, `pyzipper`, `requests`, `tkinter`).
- Replace the `VIRUSTOTAL_API_KEY` with your actual VirusTotal API key.
- The password file (`10k-most-common.txt`) should be in the script's directory or adjust the path accordingly.
