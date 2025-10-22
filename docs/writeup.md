# Antivirus Project

## Overview

This project is a **Python-based antivirus scanner** I developed as part of my cybersecurity learning journey.  

The program scans files for **known virus hashes** using SHA-256, identifies file types with the `python-magic` library, and includes a **quarantine feature** for infected files. The console interface is enhanced with an ASCII banner using `pyfiglet` for a polished user experience.

This project demonstrates hands-on skills in Python, file handling, hashing, and Git/GitHub version control.

---

## Key Features

- **SHA-256 hashing** to detect known viruses  
- **File type detection** using `python-magic`  
- **Quarantine feature** to isolate infected files  
- **Console interface** with ASCII banner  
- **Individual file scanning** via user input  

---

## Skills & Learning

Through this project, I developed experience in:

- File hashing and virus signature detection  
- Identifying file types beyond simple extensions  
- Error handling and user input validation in Python  
- Organizing a Python project with Git and GitHub for version control  

This project also strengthened my **practical cybersecurity skills** in safe malware testing using test hashes.

---

## Challenges

- Installing and configuring `python-magic` on Windows  
- Handling invalid or inaccessible file paths  
- Ensuring SHA-256 hashing works reliably for all file types  

---

## Future Improvements

- Real-time folder monitoring for automatic scanning  
- Automatic virus signature updates via the internet  
- Logging and scan history for audit purposes  
- GUI interface for easier user interaction  

---

## How to Run

1. **Clone the repository**:

```bash
git clone https://github.com/CeeJayv6/antivirus_project.git
cd antivirus_project
