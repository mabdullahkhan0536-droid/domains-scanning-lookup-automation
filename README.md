#This python script helps you find malicious domains from a list of domains in a .csv file 

#This will help you remove false positives from a list of malicious domains.

How to Use

1) Add your API keys

- Place your VirusTotal API keys and AbuseIPDB API keys into the respective files.
- Since VirusTotal enforces rate limits, the script automatically rotates to the next API key when one is exhausted.
- You can add as many API keys as you want for smoother scanning.

2) Prepare your CSV file

- When you run the script (domain.py) , it will prompt you to provide a CSV file.
- The CSV must contain a header in the first row, and all the IP addresses you want to scan should be listed in the first column under that header.

3) Output

- After scanning, the script will generate two CSV files:
- One containing the results of all successfully scanned IPs.
- Another containing the IPs that failed to scan.
