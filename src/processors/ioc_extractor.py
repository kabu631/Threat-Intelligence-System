"""
IOC Extractor Module
This module extracts Indicators of Compromise (IOCs) from text using NLP and regex patterns.
"""

import re
import logging
import ipaddress

logger = logging.getLogger(__name__)

class IOCExtractor:
    """Class for extracting IOCs from text."""
    
    def __init__(self):
        """Initialize the IOC extractor."""
        # Regular expressions for common IOC types
        self.ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        self.domain_pattern = r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]\b'
        self.url_pattern = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+'
        self.hash_patterns = {
            'md5': r'\b[a-fA-F0-9]{32}\b',
            'sha1': r'\b[a-fA-F0-9]{40}\b',
            'sha256': r'\b[a-fA-F0-9]{64}\b'
        }
        self.email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        self.cve_pattern = r'CVE-\d{4}-\d{4,7}'
    
    def extract_iocs(self, text):
        """
        Extract all types of IOCs from text.
        
        Args:
            text (str): Text to extract IOCs from
            
        Returns:
            dict: Dictionary of extracted IOCs by type
        """
        if not text:
            return {}
        
        # Initialize results dictionary
        iocs = {
            'ip_addresses': [],
            'domains': [],
            'urls': [],
            'hashes': {
                'md5': [],
                'sha1': [],
                'sha256': []
            },
            'emails': [],
            'cves': []
        }
        
        # Extract IPs
        ip_matches = re.findall(self.ip_pattern, text)
        for ip in ip_matches:
            try:
                # Validate IP address
                ipaddress.ip_address(ip)
                # Skip private and reserved IPs
                if not self._is_private_ip(ip):
                    iocs['ip_addresses'].append(ip)
            except ValueError:
                # Invalid IP address
                pass
        
        # Extract domains (excluding those that are part of URLs)
        urls = re.findall(self.url_pattern, text)
        iocs['urls'] = urls
        
        # Extract domains, but filter out domains that are part of the extracted URLs
        domain_matches = re.findall(self.domain_pattern, text)
        for domain in domain_matches:
            if not any(domain in url for url in urls):
                iocs['domains'].append(domain)
        
        # Extract hashes
        for hash_type, pattern in self.hash_patterns.items():
            iocs['hashes'][hash_type] = re.findall(pattern, text)
        
        # Extract emails
        iocs['emails'] = re.findall(self.email_pattern, text)
        
        # Extract CVEs
        iocs['cves'] = re.findall(self.cve_pattern, text, re.IGNORECASE)
        
        # Remove duplicates
        for key in iocs:
            if isinstance(iocs[key], list):
                iocs[key] = list(set(iocs[key]))
            elif isinstance(iocs[key], dict):
                for subkey in iocs[key]:
                    iocs[key][subkey] = list(set(iocs[key][subkey]))
        
        return iocs
    
    def _is_private_ip(self, ip):
        """
        Check if an IP address is private or reserved.
        
        Args:
            ip (str): IP address to check
            
        Returns:
            bool: True if private or reserved, False otherwise
        """
        try:
            ip_obj = ipaddress.ip_address(ip)
            return (
                ip_obj.is_private or
                ip_obj.is_reserved or
                ip_obj.is_loopback or
                ip_obj.is_link_local or
                ip_obj.is_multicast
            )
        except ValueError:
            return False 