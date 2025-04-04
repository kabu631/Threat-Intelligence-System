# Threat Intelligence Automation System - Usage Guide

This guide provides detailed instructions on how to use the Threat Intelligence Automation System for analyzing security threats and extracting valuable intelligence.

## Getting Started

1. Install the system following the instructions in the README.md file
2. Start the system using `./start_system.py`
3. Access the dashboard at http://localhost:8082

## Analysis Tools

The system provides three primary analytical tools, each designed for specific threat intelligence tasks:

## 1. IOC Extraction

The IOC Extraction tool identifies technical indicators that could be used for threat hunting and security monitoring.

### Supported IOC Types

- IP Addresses (IPv4 and IPv6)
- Domain names
- URLs
- Email addresses
- File hashes (MD5, SHA1, SHA256)
- CVE identifiers (Common Vulnerabilities and Exposures)

### How to Use

1. Navigate to the "IOC Extraction" section of the dashboard
2. Enter or paste text containing potential indicators
3. Click "Extract IOCs"
4. Review the categorized results

### Example Inputs

#### Example 1: Phishing Campaign

```
Security researchers have uncovered a new phishing campaign targeting financial institutions. 
The attackers are using emails from accounts@secure-banking-portal.com with malicious links to 
hxxp://banking-secure-login.info/auth.php. The phishing kit is hosted on the IP address 45.67.89.12 
and uses a command and control server at evil-c2.net. The malware dropper has a SHA256 hash of 
6a9c7f5f3f2d8a87be3819eab007c9001c2579b15f1d84fcafba93f7b70e83ce.
```

#### Example 2: Vulnerability Analysis

```
A critical remote code execution vulnerability (CVE-2023-32829) was discovered in Apache Struts, 
affecting versions 2.5.0 through 2.5.30. Exploitation attempts have been observed from the 
following IPs: 198.51.100.23, 203.0.113.42, and 192.0.2.15. The attackers are using the domain 
struts-exploiter.org to host their payload, with links to https://struts-exploiter.org/payload.jsp. 
For more information, contact threat-intel@example.org.
```

#### Example 3: Threat Report

```
The APT group "Cozy Bear" has been observed using a new backdoor malware "MoonlightMaze" with 
MD5 hash 5f4dcc3b5aa765d61d8327deb882cf99. They have established infrastructure at the following 
IPs: 172.16.254.1, 198.51.100.77, and 203.0.113.99. Their phishing campaign uses emails from 
legitimate-looking@company-portal.com and links to hxxps://document-preview.co/invoice.php. 
The campaign targets CVE-2022-40684 on FortiOS systems.
```

## 2. Topic Analysis

The Topic Analysis tool helps identify the main security themes in a text using advanced NLP and topic modeling techniques.

### How to Use

1. Navigate to the "Topic Analysis" section of the dashboard
2. Enter or paste security-related text
3. Click "Analyze Topics"
4. Review the identified topics with their associated keywords and probability scores

### Example Inputs

#### Example 1: Vulnerability Report

```
Microsoft has released a patch for a critical remote code execution vulnerability (CVE-2023-21746) 
affecting Windows DNS Server. This memory corruption vulnerability allows attackers to run arbitrary 
code in the context of the DNS Server service by sending specially crafted DNS queries. The vulnerability 
has a CVSS score of 8.8 and affects all supported versions of Windows Server. Organizations are advised 
to apply the patch immediately or implement the suggested workaround of configuring DNS Server to block 
recursive queries from untrusted sources using DNS policies.
```

#### Example 2: Ransomware Analysis

```
The BlackCat (ALPHV) ransomware group has evolved their tactics by implementing a triple extortion 
strategy. Beyond the traditional encryption of data and threat of data leaks, they are now conducting 
DDoS attacks against victims who refuse to pay the ransom. Their ransomware, written in Rust, is highly 
customizable and supports command-line arguments that allow operators to configure specific modules during 
execution. The group primarily targets Windows and Linux systems, focusing on organizations in healthcare, 
financial services, and critical infrastructure. Initial access is typically gained through compromised 
credentials, exploiting vulnerabilities in internet-facing applications, or through affiliates who use 
various techniques including phishing and RDP exploitation.
```

#### Example 3: Security Advisory

```
A series of zero-day vulnerabilities in popular IoT devices has exposed millions of smart home products to 
remote exploitation. The vulnerabilities, collectively tracked as "SmartBreak," affect the communication 
protocols implemented by major manufacturers including SmartHome Inc., ConnectAll, and IoSecure. The flaws 
allow attackers to intercept and modify commands sent to affected devices, potentially giving them control over 
smart locks, security cameras, and home automation systems. Security researchers have demonstrated that these 
vulnerabilities can be chained together to create a worm-like attack that spreads automatically across smart 
home networks. Manufacturers are racing to release firmware updates, but many older devices will likely remain 
unpatched due to lack of support.
```

## 3. Entity Extraction

The Entity Extraction tool identifies key named entities in threat reports, helping analysts understand the actors, targets, and methods involved.

### Entity Types

- Threat Actors (APT groups, hackers)
- Organizations (targeted companies, security vendors)
- Locations (countries, regions)
- Software/Malware (names of malicious tools)
- Techniques (attack methods)

### How to Use

1. Navigate to the "Entity Extraction" section of the dashboard
2. Enter or paste text from threat reports or security advisories
3. Click "Extract Entities"
4. Review the categorized entities

### Example Inputs

#### Example 1: APT Campaign Report

```
FireEye researchers have identified a new campaign by APT41, a Chinese state-sponsored threat group, 
targeting telecommunications companies in Southeast Asia, particularly in Malaysia, Thailand, and Vietnam. 
The attackers are using a previously undocumented backdoor called "SideWinder" that communicates with 
command and control servers primarily hosted in Hong Kong. The malware uses Dropbox as a dead drop resolver 
and implements strong encryption for its network communications. The campaign began in October 2023 and 
appears to be focused on espionage, specifically targeting call detail records and subscriber information.
```

#### Example 2: Financial Sector Threats

```
The FIN7 cybercriminal group has shifted focus to target financial technology companies in the United Kingdom, 
Germany, and Switzerland using new techniques. Their recent campaign employs social engineering through LinkedIn, 
where they pose as recruiters from legitimate financial institutions. Upon establishing contact, they send 
malicious documents disguised as job descriptions that contain embedded PowerShell scripts. These scripts deploy 
a new variant of the CARBANAK malware, which has been modified to evade endpoint detection. Several major FinTech 
companies including PaymentTech and FastMoney have reportedly been compromised in this campaign, which began in 
January 2023.
```

#### Example 3: Ransomware Activity

```
Conti ransomware operators, believed to be based in Russia, have intensified attacks against healthcare 
organizations in the United States and Canada. Recent victims include Memorial Hospital System in Chicago, 
Northeastern Medical Center in Boston, and Canadian Health Services in Toronto. The threat actors are exploiting 
vulnerabilities in VPN appliances (specifically Fortinet CVE-2022-42475) to gain initial access, then using 
Cobalt Strike for lateral movement. The FBI and CISA have issued a joint advisory warning organizations in the 
healthcare sector to implement network segmentation and ensure proper backup procedures. Ransom demands have 
ranged from $1.5 million to $4 million, paid in Monero cryptocurrency.
```

## Tips for Effective Analysis

1. **Combine Tools**: For comprehensive analysis, use all three tools on the same text to extract different types of intelligence.

2. **Refine Inputs**: If you don't get meaningful results, try using more specific or detailed text inputs.

3. **Context Matters**: Provide sufficient context in your inputs for more accurate entity and topic identification.

4. **Regular Updates**: Ensure your system is up to date to benefit from improvements to the underlying models.

5. **Validate Results**: Always verify automatically extracted information before using it in security operations.

## Advanced Usage

### API Integration

All dashboard features are available via API endpoints:

- IOC Extraction: `POST /extract-iocs`
- Topic Analysis: `POST /analyze-topics`
- Entity Extraction: `POST /extract-entities`

Example API call using curl:

```bash
curl -X POST http://localhost:9000/extract-iocs \
  -H "Content-Type: application/json" \
  -d '{"text":"Attackers used malicious domain evil.com and IP 192.168.1.1"}'
```

### Batch Processing

For large-scale analysis, you can use the API to process multiple documents in batch:

```python
import requests
import json

# List of documents to analyze
documents = [
    "First threat report...",
    "Second threat report...",
    "Third threat report..."
]

results = []

for doc in documents:
    response = requests.post(
        "http://localhost:9000/extract-entities",
        json={"text": doc}
    )
    results.append(response.json())

# Save results to file
with open("entity_analysis_results.json", "w") as f:
    json.dump(results, f, indent=2)
```

## Interpreting Analysis Results

### IOC Extraction

Results are grouped by IOC type. Use these indicators to:
- Update firewall rules and security monitoring
- Block malicious domains and IPs
- Search for hash matches in your environment
- Prioritize patch deployment for identified CVEs

### Topic Analysis

Topics reveal the main themes in the text. Use these insights to:
- Identify emerging threats relevant to your organization
- Understand attack patterns and trends
- Focus security resources on the most relevant threat categories
- Enhance threat intelligence reporting with theme categorization

### Entity Extraction

Extracted entities help map the threat landscape. Use them to:
- Track known threat actors targeting your industry
- Identify geographic patterns in attacks
- Build relationship graphs between actors, tools, and techniques
- Enhance your threat intelligence database with structured data

## Need Help?

If you encounter any issues or have questions, please:
1. Check the troubleshooting section in README.md
2. Examine the API and dashboard logs for error messages
3. Submit an issue on our GitHub repository with detailed information 