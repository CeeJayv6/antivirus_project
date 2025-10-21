import os
import hashlib
import pyfiglet
import magic
import shutil # allows moving files

QUARANTINE_FOLDER = "quarantine"

# Ensures the quarantine folder exists

if not os.path.exists(QUARANTINE_FOLDER):
    os.markedirs(QUARANTINE_FOLDER)

def display_banner():
    banner = pyfiglet.figlet_format("AntiVirus")
    print(banner)

def get_file_hashes(file_path):
    with open(file_path, 'rb') as file:
        file_data = file.read()
        sha256_hash = hashlib.sha256(file_data).hexdigest()
    return sha256_hash

def identify_file_type(file_path):
    try:
        file_type = magic.from_file(file_path, mime=True)
        return file_type
    except Exception as e:
        return "Unknown file type"

def check_for_virus_signatures(file_path):
    file_hash = get_file_hashes(file_path)
    virus_signatures = [
        'known_virus_hash_1',
        'known_virus_hash_2'
    ]
    return file_hash in virus_signatures

def update_virus_definitions(file_path):
    file_type = identify_file_type(file_path)
    print(f"\nScanning file: {file_path}")
    print(f"File Type: {file_type}")

    if check_for_virus_signatures(file_path):
        print("Virus detected!")
    else:
        print("File is clean.\n")

def main():
    display_banner()

    while True:
        file_path = input("Enter file path to scan (or Q to quit): ")
        if file_path.lower() == 'q':
            break
        if os.path.isfile(file_path):
            update_virus_definitions(file_path)
        else:
            print("Invalid file path. Try again.\n")


def quarantine_file(file_path):

    file_name = os.path.basename(file_path)                      #extract just the file name
    destination = os.path.join(QUARANTINE_FOLDER, file_name)     #path in quarantine folder
    shutil.move(file_path, destination)                          #move the file
    print(f"File moved to quarantine: {destination}")            #inform the user


if __name__ == "__main__":
    main()
