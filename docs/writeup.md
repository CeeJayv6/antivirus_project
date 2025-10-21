\# Antivirus Project Write-Up



\## Project Overview

This project is a Python-based antivirus scanner I developed as part of my cybersecurity learning journey.  

It scans files for known virus hashes and identifies file types using the `python-magic` library. The project also includes a simple ASCII banner using `pyfiglet` for a polished console interface.



\## Features

\- SHA-256 hashing to detect known viruses

\- File type detection using `python-magic`

\- Console interface with ASCII banner

\- Scan individual files by entering their path



\## Learning Experience

Through this project, I learned how antivirus programs identify malicious files, including:  

\- Calculating file hashes to match known virus signatures  

\- Detecting file types reliably beyond just the file extension  

\- Handling user input and file errors in Python  



This project also helped me strengthen my Git and GitHub skills by version-controlling my code and pushing it to a repository.



\## Challenges

\- Setting up `python-magic` on Windows initially  

\- Handling invalid file paths or unreadable files  

\- Ensuring SHA-256 hashing works correctly for all file types



\## Future Improvements

\- Add automatic updates for virus signatures  

\- Add a quarantine feature for detected files  

\- Integrate a GUI for easier interaction  

\- Include real-time scanning capabilities  



\## How to Run

1\. Install dependencies:

```bash

pip install -r requirements.txt



