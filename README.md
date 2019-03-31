# Local Process to VirusTotal Script (PowerShell)
This script is used to dump running processes from the host PC. The processes are retrieved via  the get-process command, followed by obtaining the SHA256 hash. This information is stored in an array table, where the unique values are submitted to VT to check the antivirus score of the file. The results are piped into a CSV on the local file system for analysis. You need a valid API key from VirusTotal for this to work, as well as administrator rights on all machines that you want to dump processes from.

# How to
Add your free VirusTotal API key to the codeline

    ./LocalVirusTotalScanner.ps1

The results file is a CSV output. 
