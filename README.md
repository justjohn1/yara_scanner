# Yara Scanner

## Description
Yara Scanner is a comprehensive tool for scanning files and processes on a system using YARA rules. It's designed to detect malware, suspicious activities, and specific patterns in files and running processes.

## Features
- Scan files and directories with YARA rules.
- Customizable scanning options, including file type and directory exclusions.
- Concurrent scanning using threading for efficient resource utilization.
- Detailed scanning metrics and logging.
- MacOS, Linux and Windows machines

## Installation
(Provide instructions on how to install your tool. Include steps to install YARA and any other dependencies.)

## Usage
Adjust threads and directory containing yara files (example below)

<img width="664" alt="image" src="https://github.com/justjohn1/yara_scanner/assets/17276975/00ded30b-86af-4e76-8c7a-a79c095f95f0">




Next adjust the settings shown below:

scan_directory_path
include_dirs: dirs to include in the scan. Only these dirs will be scanned.
exclude_dirs: dirs to exclude from the scan. These dirs will be skipped.
include_files: filenames to include in the scan. Only these files will be scanned.
exclude_files: filenames to exclude from the scan. These files will be skipped.
verbose = True - shows files scanned in real-time or False for no output

<img width="665" alt="image" src="https://github.com/justjohn1/yara_scanner/assets/17276975/805532c4-95f9-496f-9e16-93d3435803c9">


## Contributing
Contributions to the project are welcome. Please refer to `CONTRIBUTING.md` for contribution guidelines.

## License
This project is licensed under the MIT.
