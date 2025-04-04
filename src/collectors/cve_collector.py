"""
CVE Collector Module
This module collects vulnerability data from the NIST NVD API.
If the API is unavailable, it uses mock data for demonstration.
"""

import logging
import os
import json
import requests
from datetime import datetime, timedelta
import random

from .base_collector import BaseCollector

logger = logging.getLogger(__name__)

class CVECollector(BaseCollector):
    """Collector for CVE data from the NIST NVD API."""
    
    def __init__(self, data_dir=None):
        """Initialize the CVE collector."""
        super().__init__('cve', data_dir)
        self.api_key = os.getenv('CVE_API_KEY')
        self.base_url = 'https://services.nvd.nist.gov/rest/json/cves/1.0'
    
    def collect(self, days_back=7, max_items=20):
        """
        Collect CVE data from the NVD API.
        If the API is unavailable, generate mock data.
        
        Args:
            days_back (int): Number of days to look back
            max_items (int): Maximum number of items to collect
            
        Returns:
            list: List of CVE items
        """
        logger.info(f"Collecting CVE data from the past {days_back} days")
        
        # Try the NVD API first
        try:
            api_data = self._collect_from_api(days_back, max_items)
            if api_data:
                return api_data
        except Exception as e:
            logger.warning(f"Could not collect from API: {e}. Using mock data instead.")
        
        # Fall back to mock data
        logger.info("Generating mock CVE data for demonstration")
        return self._generate_mock_data(max_items)
    
    def _collect_from_api(self, days_back, max_items):
        """Attempt to collect data from the NVD API."""
        # Calculate the start date
        start_date = (datetime.now() - timedelta(days=days_back)).strftime('%Y-%m-%dT00:00:00:000 UTC-00:00')
        
        # Build the request parameters
        params = {
            'pubStartDate': start_date,
            'resultsPerPage': min(max_items, 100),  # API limit is 100 per request
        }
        
        headers = {}
        if self.api_key:
            headers['apiKey'] = self.api_key
        
        logger.info(f"Requesting CVEs from {self.base_url}")
        response = requests.get(self.base_url, params=params, headers=headers)
        response.raise_for_status()
        
        data = response.json()
        cve_items = data.get('result', {}).get('CVE_Items', [])
        
        logger.info(f"Collected {len(cve_items)} CVE items from API")
        return cve_items
    
    def _generate_mock_data(self, count=20):
        """Generate mock CVE data for demonstration purposes."""
        mock_cves = []
        
        # Common vulnerabilities for mock data
        vulnerability_types = [
            "SQL Injection", "Cross-Site Scripting (XSS)", "Remote Code Execution", 
            "Authentication Bypass", "Buffer Overflow", "Information Disclosure",
            "Denial of Service", "Privilege Escalation", "Memory Corruption"
        ]
        
        # Generate random mock CVEs
        for i in range(count):
            cve_id = f"CVE-{random.randint(2020, 2025)}-{random.randint(1000, 9999)}"
            vuln_type = random.choice(vulnerability_types)
            
            # Create a mock CVE item matching the structure we need
            mock_cve = {
                'cve': {
                    'CVE_data_meta': {
                        'ID': cve_id
                    },
                    'description': {
                        'description_data': [
                            {
                                'lang': 'en',
                                'value': f"A {vuln_type.lower()} vulnerability in Example Software allows attackers "
                                         f"to {self._get_mock_impact(vuln_type)}. This affects versions prior to 5.{random.randint(0, 9)}."
                            }
                        ]
                    },
                    'references': {
                        'reference_data': [
                            {'url': f"https://example.com/advisories/{cve_id.lower()}"},
                            {'url': f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}"}
                        ]
                    },
                    'problemtype': {
                        'problemtype_data': [
                            {
                                'description': [
                                    {'value': f"CWE-{random.randint(20, 300)}"}
                                ]
                            }
                        ]
                    }
                },
                'publishedDate': (datetime.now() - timedelta(days=random.randint(1, 7))).isoformat(),
                'lastModifiedDate': (datetime.now() - timedelta(days=random.randint(0, 3))).isoformat(),
                'impact': self._generate_mock_impact(vuln_type)
            }
            
            mock_cves.append(mock_cve)
        
        logger.info(f"Generated {len(mock_cves)} mock CVE items")
        return mock_cves
    
    def _get_mock_impact(self, vuln_type):
        """Generate a description of the impact based on vulnerability type."""
        impacts = {
            "SQL Injection": "extract sensitive data from databases or modify database content",
            "Cross-Site Scripting (XSS)": "execute arbitrary JavaScript in users' browsers and potentially steal session cookies",
            "Remote Code Execution": "execute arbitrary code on the affected system",
            "Authentication Bypass": "gain unauthorized access to restricted functionality",
            "Buffer Overflow": "crash the application or execute arbitrary code",
            "Information Disclosure": "access sensitive information that should be protected",
            "Denial of Service": "cause the service to become unavailable to legitimate users",
            "Privilege Escalation": "gain elevated access to resources that should be protected",
            "Memory Corruption": "manipulate program memory and potentially execute arbitrary code"
        }
        return impacts.get(vuln_type, "compromise the affected system")
    
    def _generate_mock_impact(self, vuln_type):
        """Generate mock impact data including CVSS scores."""
        # Map vulnerability types to typical severity levels
        severity_map = {
            "SQL Injection": "HIGH",
            "Cross-Site Scripting (XSS)": "MEDIUM",
            "Remote Code Execution": "CRITICAL",
            "Authentication Bypass": "HIGH",
            "Buffer Overflow": "HIGH",
            "Information Disclosure": "MEDIUM",
            "Denial of Service": "MEDIUM",
            "Privilege Escalation": "HIGH",
            "Memory Corruption": "HIGH"
        }
        
        # Map severity to score ranges
        score_ranges = {
            "LOW": (0.1, 3.9),
            "MEDIUM": (4.0, 6.9),
            "HIGH": (7.0, 8.9),
            "CRITICAL": (9.0, 10.0)
        }
        
        severity = severity_map.get(vuln_type, "MEDIUM")
        score_range = score_ranges[severity]
        base_score = round(random.uniform(*score_range), 1)
        
        # Generate impact data matching the structure we need
        impact = {
            'baseMetricV3': {
                'cvssV3': {
                    'baseScore': base_score,
                    'vectorString': f"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    'attackVector': 'NETWORK',
                    'attackComplexity': 'LOW',
                },
                'exploitabilityScore': round(random.uniform(2.0, 3.9), 1),
                'impactScore': round(random.uniform(2.0, 5.9), 1),
                'severity': severity
            },
            'baseMetricV2': {
                'cvssV2': {
                    'baseScore': max(0.0, base_score - random.uniform(0.1, 1.0)),
                    'vectorString': f"AV:N/AC:L/Au:N/C:P/I:P/A:P"
                },
                'severity': 'HIGH' if severity == 'CRITICAL' else severity
            }
        }
        
        return impact
    
    def process_cve_data(self, cve_items):
        """
        Process and enrich CVE data.
        
        Args:
            cve_items (list): List of CVE items
            
        Returns:
            list: Processed CVE items with additional fields
        """
        processed_items = []
        
        for item in cve_items:
            cve = item.get('cve', {})
            impact = item.get('impact', {})
            # Extract key fields and add additional context
            processed_item = {
                'id': cve.get('CVE_data_meta', {}).get('ID'),
                'published': item.get('publishedDate'),
                'lastModified': item.get('lastModifiedDate'),
                'description': self._get_description(cve),
                'cvss_v3_score': self._get_cvss_score(impact, version='3.0'),
                'cvss_v2_score': self._get_cvss_score(impact, version='2.0'),
                'severity': self._get_severity(impact),
                'references': self._get_references(cve),
                'weak_spots': self._get_weak_spots(cve),
            }
            processed_items.append(processed_item)
        
        return processed_items
    
    def _get_description(self, cve_item):
        """Extract the description from a CVE item."""
        descriptions = cve_item.get('description', {}).get('description_data', [])
        for desc in descriptions:
            if desc.get('lang') == 'en':
                return desc.get('value', '')
        return ''
    
    def _get_cvss_score(self, impact, version='3.0'):
        """Extract the CVSS score for the specified version."""
        if version.startswith('3'):
            base_metric = impact.get('baseMetricV3', {})
            if base_metric:
                cvss_data = base_metric.get('cvssV3', {})
                return cvss_data.get('baseScore')
        else:
            base_metric = impact.get('baseMetricV2', {})
            if base_metric:
                cvss_data = base_metric.get('cvssV2', {})
                return cvss_data.get('baseScore')
        return None
    
    def _get_severity(self, impact):
        """Determine the severity based on CVSS score."""
        base_metric_v3 = impact.get('baseMetricV3', {})
        if base_metric_v3:
            return base_metric_v3.get('severity', 'UNKNOWN')
        
        # Fall back to v2 if available
        base_metric_v2 = impact.get('baseMetricV2', {})
        if base_metric_v2:
            return base_metric_v2.get('severity', 'UNKNOWN')
        
        return 'UNKNOWN'
    
    def _get_references(self, cve_item):
        """Extract references from a CVE item."""
        references_data = cve_item.get('references', {}).get('reference_data', [])
        return [ref.get('url') for ref in references_data if 'url' in ref]
    
    def _get_weak_spots(self, cve_item):
        """Extract weak spots (CWEs) from a CVE item."""
        problemtype_data = cve_item.get('problemtype', {}).get('problemtype_data', [])
        cwe_ids = []
        
        for problemtype in problemtype_data:
            for description in problemtype.get('description', []):
                cwe_id = description.get('value', '')
                if cwe_id and cwe_id.startswith('CWE-'):
                    cwe_ids.append(cwe_id)
        
        return cwe_ids 