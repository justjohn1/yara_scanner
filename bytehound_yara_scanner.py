import os
import yara
import psutil
import pycdlib
import binwalk
import time
import smtplib
from email.message import EmailMessage
import concurrent.futures
import math
import logging
from tqdm import tqdm
import argparse
from collections import defaultdict, Counter
import hashlib
import requests
import json
import pefile

###Enable logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


###num_threads = 1##pulled from argparse
yara_rules_directory = os.environ.get('YARA_RULES_DIR', '/home/user/Downloads/yars/')
VIRUSTOTAL_API_KEY = 'YOUR_API_KEY_HERE'  ###your VT API key
WHITELIST_FILE = 'whitelist.json'

scanning_metrics = {
    'files_scanned': 0,
    'matches_found': 0,
    'errors': 0,
    'skipped_files': [],
    'matched_rules': defaultdict(list),
    'invalid_rules': defaultdict(list),
    'risk_classifications': defaultdict(int),
    'file_types': defaultdict(int),
    'total_file_size': 0,
    'flagged_files': defaultdict(list)
}



def create_summary(matched_rules):
    summary = defaultdict(lambda: defaultdict(list))
    for rule, files in matched_rules.items():
        for file in files:
            dir_path = os.path.dirname(file)
            file_name = os.path.basename(file)
            summary[dir_path][rule].append(file_name)
    return summary


def analyze_iso(file_path):
    iso = pycdlib.PyCdlib()
    iso.open(file_path)
    files = []
    for dirname, dirlist, filelist in iso.walk(iso_path='/'):
        for file in filelist:
            files.append(f"{dirname}/{file}")
    iso.close()
    return files


def analyze_binary(file_path):
    results = []
    for module in binwalk.scan(file_path, signature=True, quiet=True):
        for result in module.results:
            results.append(f"0x{result.offset:X}: {result.description}")
    return results


def extract_flagged_content(file_path, rule, max_bytes=100):
    with open(file_path, 'rb') as f:
        content = f.read()

    if rule == "contains_base64":
        import base64
        try:
            decoded = base64.b64decode(content).decode('utf-8', errors='ignore')
            return decoded[:max_bytes] + "..." if len(decoded) > max_bytes else decoded
        except:
            return "Failed to decode base64 content"

    elif rule == "Sus_Obf_Enc_Spoof_Hide_PE":
        return f"Hexdump of first {max_bytes} bytes: {content[:max_bytes].hex()}"


    return f"Raw content (first {max_bytes} bytes): {content[:max_bytes]}"


def load_whitelist():
    if os.path.exists(WHITELIST_FILE):
        with open(WHITELIST_FILE, 'r') as f:
            return set(json.load(f))
    return set()


whitelist = load_whitelist()


def save_whitelist():
    with open(WHITELIST_FILE, 'w') as f:
        json.dump(list(whitelist), f)


def calculate_entropy(file_path):
    try:
        with open(file_path, "rb") as f:
            data = f.read()
            if len(data) == 0:
                return 0
            entropy = 0
            for x in range(256):
                p_x = float(data.count(bytes([x]))) / len(data)
                if p_x > 0:
                    entropy += - p_x * math.log2(p_x)
            return entropy
    except Exception as e:
        logging.error(f"Could not calculate entropy for {file_path}: {e}")
        return -1


def get_file_hash(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()


def check_virustotal(file_hash):
    url = 'https://www.virustotal.com/vtapi/v2/file/report'
    params = {'apikey': VIRUSTOTAL_API_KEY, 'resource': file_hash}
    try:
        response = requests.get(url, params=params)
        if response.status_code == 200:
            result = response.json()
            if result['response_code'] == 1:
                return result['positives'] > 0
    except Exception as e:
        logging.error(f"Error checking VirusTotal: {e}")
    return False


def analyze_pe_file(file_path):
    try:
        pe = pefile.PE(file_path)
        suspicious = False
        if pe.OPTIONAL_HEADER.AddressOfEntryPoint != 0x1000:
            suspicious = True
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                if entry.dll.lower() in [b"wininet.dll", b"urlmon.dll"]:
                    suspicious = True
                    break
        return suspicious
    except:
        return False


def calculate_file_score(file_path, matched_rules):
    score = 0
    file_extension = os.path.splitext(file_path)[1].lower()
    file_size = os.path.getsize(file_path)
    entropy = calculate_entropy(file_path)

    if file_extension in ['.exe', '.dll', '.sys', '.bat', '.ps1', '.scr', '.vbs']:
        score += 5
    elif file_extension in ['.doc', '.docx', '.xls', '.xlsx', '.pdf']:
        score += 3
    elif file_extension in ['.mp3', '.wav', '.flac', '.ogg', '.m4a', '.aac']:
        score -= 3

    if file_size > 10 * 1024 * 1024:
        score += 2
    if entropy > 7.5:
        score += 3

    critical_rules = ["Dropper", "Trojan", "Backdoor", "Ransomware", "Keylogger"]
    suspicious_rules = ["Obfuscation", "Packer", "Crypter"]
    common_false_positives = ["IP", "domain", "contains_base64"]

    for rule in matched_rules:
        if rule in critical_rules:
            score += 7
        elif rule in suspicious_rules:
            score += 4
        elif rule not in common_false_positives:
            score += 1
        else:
            score += 0.5

    return score


def classify_risk(score):
    if score >= 15:
        return "High-Risk"
    elif score >= 8:
        return "Medium-Risk"
    else:
        return "Low-Risk"


def scan_file(file_path, compiled_rules, max_file_size=2 * 1024 * 1024 * 1024):
    global scanning_metrics

    try:
        file_size = os.path.getsize(file_path)
        if file_size > max_file_size:
            scanning_metrics['skipped_files'].append(file_path)
            logging.warning(f"Skipping large file: {file_path} ({file_size / (1024 * 1024):.2f} MB)")
            return

        file_hash = get_file_hash(file_path)
        if file_hash in whitelist:
            return

        scanning_metrics['files_scanned'] += 1
        scanning_metrics['total_file_size'] += file_size
        file_extension = os.path.splitext(file_path)[1].lower()
        scanning_metrics['file_types'][file_extension] += 1

        matched_rules = []
        with open(file_path, 'rb') as f:
            data = f.read()
            matches = compiled_rules.match(data=data)
            if matches:
                for match in matches:
                    if match.rule not in matched_rules:
                        matched_rules.append(match.rule)

        if matched_rules:
            score = calculate_file_score(file_path, matched_rules)

            if score > 8:
                if check_virustotal(file_hash):
                    score += 10

                if file_extension in ['.exe', '.dll', '.sys']:
                    if analyze_pe_file(file_path):
                        score += 5

            risk_level = classify_risk(score)
            scanning_metrics['risk_classifications'][risk_level] += 1

            if score > 8:
                logging.info(f"File: {file_path} classified as {risk_level} (Score: {score:.2f})")
                logging.info(f"Matched rules: {', '.join(matched_rules)}")
                scanning_metrics['flagged_files'][file_path] = matched_rules

            scanning_metrics['matches_found'] += len(matched_rules)
            for rule in matched_rules:
                scanning_metrics['matched_rules'][rule].append(file_path)

    except PermissionError:
        scanning_metrics['errors'] += 1
        logging.error(f"Permission denied: {file_path}")
    except Exception as e:
        scanning_metrics['errors'] += 1
        logging.error(f"Error scanning {file_path}: {e}")


def scan_directory(directory, compiled_rules):
    logging.info(f"Scanning directory: {directory}")
    if not os.path.exists(directory):
        logging.error(f"Directory does not exist: {directory}")
        return

    file_count = 0
    for root, _, files in os.walk(directory):
        for file in tqdm(files, desc="Scanning files"):
            file_path = os.path.join(root, file)
            scan_file(file_path, compiled_rules)
            file_count += 1
            if file_count % 100 == 0:
                logging.info(f"Scanned {file_count} files so far in {directory}")


def scan_process(process, compiled_rules):
    try:
        for file in process.open_files():
            if file.path:
                scan_file(file.path, compiled_rules)
    except (psutil.AccessDenied, psutil.NoSuchProcess):
        pass


def scan_all_processes(compiled_rules, num_threads_arg):
    logging.info(f"Scanning all processes with {num_threads_arg} threads...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads_arg) as executor:
        processes = psutil.process_iter(['pid', 'name'])
        futures = [executor.submit(scan_process, process, compiled_rules) for process in processes]
        for future in concurrent.futures.as_completed(futures):
            pass


def find_yara_rules(directory):
    rule_files = []
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith('.yar'):
                rule_files.append(os.path.join(root, file))
    return rule_files


def compile_rules_from_directory(directory):
    total_rules_compiled = 0
    rule_files = find_yara_rules(directory)

    if not rule_files:
        logging.warning(f"No YARA rule files found in {directory} or its subdirectories.")
        return None, total_rules_compiled

    externals = {
        'filepath': "/home/user/",
        'filename': '*',
        'extension': '*',
        'filetype': '*',
        'owner': '*'
    }

    rules_contents = {}
    for rule_file in rule_files:
        try:
            with open(rule_file, 'r') as f:
                rules_contents[rule_file] = f.read()
        except Exception as e:
            logging.error(f"Error reading YARA rule {rule_file}: {e}")

    compiled_rules = {}
    for rule_file, content in rules_contents.items():
        try:
            compiled_rules[rule_file] = yara.compile(source=content, externals=externals)
            total_rules_compiled += 1
        except yara.SyntaxError:
            rule_dir = os.path.dirname(rule_file)
            scanning_metrics['invalid_rules'][rule_dir].append(rule_file)

    if not compiled_rules:
        logging.error("No valid YARA rules were compiled. Exiting...")
        return None, 0

    logging.info(f"Compiled {total_rules_compiled} valid YARA rules from {len(rule_files)} files.")

    return yara.compile(sources={key: rules_contents[key] for key in compiled_rules.keys()},
                        externals=externals), total_rules_compiled


def display_report_and_confirm(rule_files, compiled_count):
    print("\n==================== YARA RULES SUMMARY ====================")
    print(f"🔍 Total Rules Found: {len(rule_files)}")
    print(f"✅ Successfully Compiled: {compiled_count}")
    print(f"❌ Invalid Rules Skipped: {sum(len(files) for files in scanning_metrics['invalid_rules'].values())}")

    if scanning_metrics['invalid_rules']:
        print("\nInvalid YARA Rules Found in These Directories:")
        for rule_dir, files in scanning_metrics['invalid_rules'].items():
            print(f" - {rule_dir} ({len(files)} invalid rules)")

    print("\nDo you want to continue? (yes/no)")
    choice = input().strip().lower()
    if choice not in ["yes", "y"]:
        logging.info("User chose to exit. Aborting scan.")
        exit(0)


def print_final_report():
    print("\n========== ENHANCED SCAN REPORT ==========")
    print(f"Files scanned: {scanning_metrics['files_scanned']}")
    print(f"Total file size scanned: {scanning_metrics['total_file_size'] / (1024 * 1024):.2f} MB")
    print(f"Matches found: {scanning_metrics['matches_found']}")
    print(f"Errors encountered: {scanning_metrics['errors']}")

    print("\nRisk Classifications:")
    for risk_level, count in scanning_metrics['risk_classifications'].items():
        print(f" {risk_level}: {count}")

    print("\nFile Types Encountered:")
    for file_type, count in scanning_metrics['file_types'].items():
        print(f" {file_type}: {count}")

    if scanning_metrics['matches_found'] > 0:
        summary = create_summary(scanning_metrics['matched_rules'])

        print("\nSummary of Suspected Files:")
        for directory, rules in summary.items():
            print(f"\nDirectory: {directory}")
            for rule, files in rules.items():
                print(f"  Rule '{rule}' matched {len(files)} file(s):")
                for file in files:
                    print(f"    - {file}")

        print("\nDetailed analysis is available for flagged files.")
        show_details = input("Would you like to see the detailed analysis? (y/n): ").lower().strip()

        if show_details == 'y':
            for rule, files in scanning_metrics['matched_rules'].items():
                print(f"\nThe \"{rule}\" rule matched {len(files)} file(s):")
                for file_path in files:
                    print(f"\n  File: {file_path}")

                    ###Extract flagged content output only 50b down from 100b
                    flagged_content = extract_flagged_content(file_path, rule, max_bytes=50)
                    print("  Flagged Content Snippet (Hex):")
                    print(f"    {flagged_content.encode().hex()}")
                    print("  Flagged Content Snippet (ASCII):")
                    print(f"    {flagged_content}")

                    if file_path.lower().endswith('.iso'):
                        iso_contents = analyze_iso(file_path)
                        print("  ISO Contents (first 5 items):")
                        for item in iso_contents[:5]:
                            print(f"    - {item}")
                        if len(iso_contents) > 5:
                            print(f"    ... and {len(iso_contents) - 5} more items")

                    elif file_path.lower().endswith(('.bin', '.exe', '.dll')):
                        binary_analysis = analyze_binary(file_path)
                        print("  Binary Analysis (first 5 items):")
                        for item in binary_analysis[:5]:
                            print(f"    - {item}")
                        if len(binary_analysis) > 5:
                            print(f"    ... and {len(binary_analysis) - 5} more items")

                        if file_path.lower().endswith(('.exe', '.dll')):
                            pe_analysis = analyze_pe(file_path)
                            print("  PE File Analysis:")
                            for finding in pe_analysis:
                                print(f"    - {finding}")

                    print("  Commands for manual verification:")
                    if file_path.lower().endswith('.iso'):
                        print("    Linux/macOS: isoinfo -l -i <iso_file>")
                        print(
                            "    Windows: powershell -command \"Get-ChildItem -Path (Mount-DiskImage -ImagePath '<iso_file>' -PassThru | Get-Volume).DriveLetter\"")
                    elif file_path.lower().endswith(('.bin', '.exe', '.dll')):
                        print("    Linux/macOS: xxd <binary_file> | head -n 20")
                        print(
                            "    Windows: powershell -command \"Get-Content -Encoding Byte -Path '<binary_file>' | Format-Hex -Count 320\"")
                    if file_path.lower().endswith(('.exe', '.dll')):
                        print("    All OS with Python: python -m pefile <pe_file>")
                    print("    Linux/macOS: file <filename>")
                    print("    Windows: powershell -command \"Get-Item '<filename>' | Format-List *\"")
                print()

    print("\nNote: Replace <filename>, <iso_file>, <binary_file>, or <pe_file> with the actual file path in the commands above.")


###argparse args
parser = argparse.ArgumentParser(description="Enhanced YARA Malware Scanner")
parser.add_argument("--directory", type=str, help="Directory to scan")
parser.add_argument("--whitelist", type=str, help="Add a file or directory to the whitelist")
parser.add_argument("--scan-processes", action="store_true", help="Scan running processes")
parser.add_argument("--threads", type=int, default=1, help="Number of threads to use (default: 1)")
args = parser.parse_args()

###Whitelist
if args.whitelist:
    if os.path.isfile(args.whitelist):
        whitelist.add(get_file_hash(args.whitelist))
    elif os.path.isdir(args.whitelist):
        for root, _, files in os.walk(args.whitelist):
            for file in files:
                whitelist.add(get_file_hash(os.path.join(root, file)))
    save_whitelist()
    print(f"Added {args.whitelist} to whitelist")
else:
    start_time = time.time()
    all_rule_files = find_yara_rules(yara_rules_directory)
    compiled_rules, total_rules_compiled = compile_rules_from_directory(yara_rules_directory)
    display_report_and_confirm(all_rule_files, total_rules_compiled)

    if compiled_rules:
        logging.info(f"Compiled {total_rules_compiled} valid YARA rules.")

        if args.directory:
            scan_directory(args.directory, compiled_rules)
        else:
            scan_directory("/home/user/Documents/browser_ext", compiled_rules)

        print_final_report()
        ###enabled via argparse to scan active memory...long!!!
        if args.scan_processes:
            scan_all_processes(compiled_rules, args.threads)

    else:
        logging.error("Failed to compile any valid YARA rules.")

    end_time = time.time()
    logging.info(f"Scanning completed in {end_time - start_time:.2f} seconds.")

