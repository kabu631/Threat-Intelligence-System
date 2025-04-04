# Threat Intelligence Automation: Quick Start Guide

This quick start guide will help you get the Threat Intelligence Automation System up and running in minutes.

## Installation (5-minute setup)

1. Clone the repository and navigate to the project folder
2. Create and activate a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. Download required data:
   ```bash
   python download_nltk_data.py
   python -m spacy download en_core_web_lg
   ```

## Starting the System

The easiest way to start the system:

```bash
# On Linux/macOS
chmod +x start_system.py
./start_system.py

# On Windows
python start_system.py
```

The dashboard will automatically open in your browser at http://localhost:8082

## Quick Analysis Examples

Here are some quick examples to test the system's functionality:

### IOC Extraction

Copy and paste the text below into the IOC Extraction tool:

```
The attackers used a C2 server at evil-domain.com (IP: 192.168.1.1) and distributed 
malware with the hash 5f4dcc3b5aa765d61d8327deb882cf99. They exploited CVE-2023-1234 
and sent phishing emails from evil@phishing.com.
```

### Topic Analysis

Copy and paste the text below into the Topic Analysis tool:

```
A new ransomware variant has been identified that targets healthcare organizations. 
The malware encrypts medical records and demands payment in Bitcoin. It spreads through 
phishing emails with malicious attachments exploiting a vulnerability in Microsoft Office.
```

### Entity Extraction

Copy and paste the text below into the Entity Extraction tool:

```
APT29, a Russian state-sponsored group, has targeted government agencies in Europe using 
spear-phishing and a new backdoor called DarkHalo. The campaign began in March 2023 and 
has affected organizations in Germany, France, and Italy.
```

## Troubleshooting

If you see a "Server Connection Error":

1. Check that both servers are running
2. Click the "Retry Connection" button
3. If the issue persists, restart using: `pkill -f python` followed by `./start_system.py`

## Next Steps

- For detailed usage examples, see USAGE_GUIDE.md
- For comprehensive documentation, see README.md
- To customize port settings, edit the `.env` file

Happy threat hunting! 