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

num_threads = X ##Change to your preference
yara_rules_directory = "/path/to/your/directory/holding/yara/files/file_name.yar" ##folder should contain .yar||.yara files

## Configuration


Specifying Directories and Files to Include or Exclude
You can specify which directories and files to include or exclude in the scan. This is useful for focusing the scan on relevant areas or avoiding unnecessary areas.

include_dirs: List of directories to specifically include in the scan. Only these directories will be scanned.
exclude_dirs: List of directories to exclude from the scan. These directories will be skipped.
include_files: List of specific filenames to include in the scan. Only these files will be scanned.
exclude_files: List of specific filenames to exclude from the scan. These files will be skipped.

## Contributing
Contributions to the project are welcome. Please refer to `CONTRIBUTING.md` for contribution guidelines.

## License
This project is licensed under the MIT.
