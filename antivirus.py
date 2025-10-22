import os
import hashlib
import pyfiglet
import magic
import shutil
import datetime
import argparse

# ---------------------------
# Config / Globals
# ---------------------------
QUARANTINE_FOLDER = "quarantine"
LOG_FILE = "scan_log.txt"
INFECTION_MARKER = "KNOCKOUT-INFECTED"  # if this string appears in a file -> treat as infected
TEST_MODE = False  # will be set from command-line flag

# Ensure quarantine folder exists
if not os.path.exists(QUARANTINE_FOLDER):
    os.makedirs(QUARANTINE_FOLDER)

# ---------------------------
# Banner / UI
# ---------------------------
def display_banner():
    banner = pyfiglet.figlet_format("Knockout Antivirus")
    print(banner)

# ---------------------------
# Utility functions
# ---------------------------
def get_file_hashes(file_path):
    """Return SHA-256 hex digest of the file."""
    with open(file_path, 'rb') as file:
        return hashlib.sha256(file.read()).hexdigest()

def identify_file_type(file_path):
    """Return a mime-like file type string using python-magic (best-effort)."""
    try:
        return magic.from_file(file_path, mime=True)
    except Exception:
        return "Unknown file type"

def log_scan(file_path, result):
    """Append a scan record to the log file."""
    file_name = os.path.basename(file_path)
    file_type = identify_file_type(file_path)
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"{now} | {file_name} | {file_type} | {result}\n"
    with open(LOG_FILE, "a", encoding="utf-8") as log_file:
        log_file.write(log_entry)

def quarantine_file(file_path):
    """Move infected file into the quarantine folder."""
    file_name = os.path.basename(file_path)
    destination = os.path.join(QUARANTINE_FOLDER, file_name)
    shutil.move(file_path, destination)
    print(f"File moved to quarantine: {destination}")

def file_contains_marker(file_path, marker=INFECTION_MARKER):
    """Return True if the file contains the infection marker text (text files only)."""
    try:
        # open in text mode with errors='ignore' to avoid crashes on binary files
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                if marker in line:
                    return True
    except Exception:
        # If we can't read as text, ignore marker check
        pass
    return False

# ---------------------------
# Detection logic
# ---------------------------
# Note: we're NOT requiring a hard-coded hash for testing. Keep the list if you want real signature checks.
VIRUS_SIGNATURES = [
    # Put real SHA-256 hashes here if/when you have them
]

def check_for_virus_signatures(file_path):
    """Return True if file hash matches a known signature (empty list => never matches)."""
    file_hash = get_file_hashes(file_path)
    return file_hash in VIRUS_SIGNATURES

def is_infected(file_path):
    """
    Consolidated decision function:
     - If TEST_MODE is True -> infected (force mode)
     - Else if file contains INFECTION_MARKER -> infected
     - Else if hash matches VIRUS_SIGNATURES -> infected
     - Else -> clean
    """
    # 1) Global force test mode
    if TEST_MODE:
        return True

    # 2) Marker inside file (useful for controlled per-file testing)
    if file_contains_marker(file_path):
        return True

    # 3) Signature-based (real detection if you add hashes)
    if check_for_virus_signatures(file_path):
        return True

    # otherwise clean
    return False

# ---------------------------
# Scan & user loop
# ---------------------------
def scan_file(file_path):
    """Scan a single file: show info, decide infection, quarantine if needed, and log result."""
    print(f"\nScanning file: {file_path}")
    print(f"File Type: {identify_file_type(file_path)}")

    if is_infected(file_path):
        print("Virus detected! Quarantining file...")
        try:
            quarantine_file(file_path)
        except Exception as e:
            print(f"Failed to quarantine file: {e}")
            # Even if quarantine fails, still log as infected
        log_scan(file_path, "Infected")
    else:
        print("File is clean.\n")
        log_scan(file_path, "Clean")

def run_interactive():
    """Main interactive loop asking user for file paths or Q to exit."""
    display_banner()
    print("Test mode is", "ON" if TEST_MODE else "OFF")
    while True:
        file_path = input("Enter file path to scan (or Q to quit): ").strip()
        if file_path.lower() == 'q':
            print("\nExiting Knockout Antivirus. Stay safe!")
            break
        # If user enters blank, prompt again
        if not file_path:
            continue

        # If user provided a relative path and file is in current dir, keep it simple
        if os.path.isfile(file_path):
            scan_file(file_path)
        else:
            # If they provided a path that isn't found, try resolving relative to current working directory
            full_path = os.path.join(os.getcwd(), file_path)
            if os.path.isfile(full_path):
                scan_file(full_path)
            else:
                print(f"Invalid file path. Current working directory is:\n{os.getcwd()}\n")
                print("Tip: put the file in the project folder or provide the full path,")
                print("e.g., C:\\Users\\chada\\antivirus_project\\myfakevirus.txt\n")

# ---------------------------
# CLI / entrypoint
# ---------------------------
def parse_args():
    """Parse command-line args. --simulate enables test mode for forced infection detection."""
    parser = argparse.ArgumentParser(description="Knockout Antivirus (safe test mode available)")
    parser.add_argument("--simulate", "-s", action="store_true",
                        help="Simulate infections: treat every scanned file as infected (for testing).")
    return parser.parse_args()

def main():
    global TEST_MODE
    args = parse_args()
    TEST_MODE = args.simulate
    run_interactive()

if __name__ == "__main__":
    main()
