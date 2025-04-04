"""
Run Processors Module
This module orchestrates the processing of collected threat data.
"""

import logging
import os
import json
import glob
from datetime import datetime

from .ioc_extractor import IOCExtractor

logger = logging.getLogger(__name__)

def process_all():
    """Process all collected data."""
    logger.info("Starting processing of all collected data")
    
    # Create processed data directory if it doesn't exist
    os.makedirs('data/processed', exist_ok=True)
    
    # Process threat data with IOC extraction
    process_with_ioc_extraction()
    
    logger.info("Processing completed")

def process_with_ioc_extraction():
    """Extract IOCs from all collected textual data."""
    logger.info("Extracting IOCs from collected data")
    
    # Initialize the IOC extractor
    ioc_extractor = IOCExtractor()
    
    # Get all processed CVE data files
    cve_files = glob.glob('data/processed/cve_processed_*.json')
    
    all_iocs = {}
    
    # Process each CVE file
    for cve_file in cve_files:
        try:
            with open(cve_file, 'r', encoding='utf-8') as f:
                cve_data = json.load(f)
            
            file_iocs = process_cve_data_for_iocs(cve_data, ioc_extractor)
            
            # Merge with all_iocs
            merge_iocs(all_iocs, file_iocs)
            
            logger.info(f"Extracted IOCs from {cve_file}")
        except Exception as e:
            logger.error(f"Error processing {cve_file}: {e}")
    
    # Save all extracted IOCs
    if all_iocs:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_file = os.path.join('data', 'processed', f'extracted_iocs_{timestamp}.json')
        
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(all_iocs, f, indent=2)
            logger.info(f"Saved all extracted IOCs to {output_file}")
        except Exception as e:
            logger.error(f"Error saving IOCs to {output_file}: {e}")

def process_cve_data_for_iocs(cve_data, ioc_extractor):
    """
    Extract IOCs from CVE data.
    
    Args:
        cve_data (list): List of CVE items
        ioc_extractor (IOCExtractor): Initialized IOC extractor
        
    Returns:
        dict: Extracted IOCs with CVE context
    """
    iocs_with_context = {
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
    
    for cve_item in cve_data:
        # Extract text to analyze
        text_to_analyze = cve_item.get('description', '')
        
        # Extract IOCs
        iocs = ioc_extractor.extract_iocs(text_to_analyze)
        
        # Add context to each IOC
        cve_context = {
            'cve_id': cve_item.get('id'),
            'severity': cve_item.get('severity'),
            'cvss_score': cve_item.get('cvss_v3_score') or cve_item.get('cvss_v2_score')
        }
        
        # Add to the consolidated list with context
        for ioc_type, ioc_list in iocs.items():
            if ioc_type != 'hashes' and ioc_list:
                for ioc in ioc_list:
                    iocs_with_context[ioc_type].append({
                        'value': ioc,
                        'context': cve_context
                    })
            elif ioc_type == 'hashes':
                for hash_type, hash_list in ioc_list.items():
                    for hash_value in hash_list:
                        iocs_with_context['hashes'][hash_type].append({
                            'value': hash_value,
                            'context': cve_context
                        })
    
    return iocs_with_context

def merge_iocs(target, source):
    """
    Merge two IOC dictionaries.
    
    Args:
        target (dict): Target IOC dictionary to merge into
        source (dict): Source IOC dictionary to merge from
    """
    for key, value in source.items():
        if key != 'hashes':
            if key not in target:
                target[key] = []
            target[key].extend(value)
        else:
            if key not in target:
                target[key] = {'md5': [], 'sha1': [], 'sha256': []}
            for hash_type, hash_list in value.items():
                target[key][hash_type].extend(hash_list)

if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Run all processors
    process_all() 