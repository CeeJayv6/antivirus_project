import os
import hashlib
import pyfiglet
import magic
import shutil  # allows moving files

# Quarantine folder: infected files are moved here
QUARANTINE_FOLDER = "quarantine"

# Ensure the quarantine folder exists
if not os.path.exists(QUARANTINE_FOLDER):
    os.makedirs(QUARANTINE_FOLDER)

# Display a fancy ASCII banner at startup
def display_banner():
    banner = pyfiglet.figlet_format("AntiVirus")
    print(banner)

# Calculate SHA-256 hash of a file
def get_file_hashes(file_path):
    with open(file_path, 'rb') as file:          # Open file in binary mode
        file_data = file.read()                  # Read the entire file
        sha256_hash = hashlib.sha256(file_data).hexdigest()
    return sha256_hash

# Identify the file type using the magic library
def identify_file_type(file_path):
    try:
        file_type = magic.from_file(file_path, mime=True)
        return file_type
    except Exception:
        return "Unknown file type"

# Check if a file matches a known virus signature
def check_for_virus_signatures(file_path):
    file_hash = get_file_hashes(file_path)
    virus_signatures = [
        'c6cf2c91bacbc5894b1391ce461756a07cad51f153a91397daf4f5b38d469ff1'  # test file hash
        # Add more SHA-256 hashes here for real viruses
    ]
    return file_hash in virus_signatures

# Quarantine infected files by moving them to a folder
def quarantine_file(file_path):
    file_name = os.path.basename(file_path)                      # Extract just the file name
    destination = os.path.join(QUARANTINE_FOLDER, file_name)     # Path in quarantine folder
    shutil.move(file_path, destination)                          # Move the file
    print(f"File moved to quarantine: {destination}")            # Inform the user

# Scan a single file
def scan_file(file_path):
    """
    Scans a file, checks its hash, prints status, and quarantines if infected.
    """
    print(f"\nScanning file: {file_path}")
    print(f"File Type: {identify_file_type(file_path)}")          # Optional: show file type

    if check_for_virus_signatures(file_path):   # If the hash matches a virus
        print("Virus detected! Quarantining file...")
        quarantine_file(file_path)
    else:
        print("File is clean.\n")

# Main user interface loop
def main():
    display_banner()

    while True:
        file_path = input("Enter file path to scan (or Q to quit): ")
        if file_path.lower() == 'q':   # Quit the program
            break
        if os.path.isfile(file_path):  # Check if path is a valid file
            scan_file(file_path)
        else:
            print("Invalid file path. Try again.\n")

# Run the program
if __name__ == "__main__":
    main()
