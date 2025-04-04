"""
Run Collectors Module
This module provides functionality to run all data collectors.
"""

import logging
import os
from datetime import datetime

from .cve_collector import CVECollector
# Import other collectors as they are implemented
# from .blog_collector import BlogCollector
# from .forum_collector import ForumCollector

logger = logging.getLogger(__name__)

def collect_from_all_sources():
    """Run all data collectors and process the collected data."""
    logger.info("Starting data collection from all sources")
    
    # Create raw and processed data directories if they don't exist
    os.makedirs('data/raw', exist_ok=True)
    os.makedirs('data/processed', exist_ok=True)
    
    # Create a timestamp for this collection run
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    
    # Collect and process CVE data
    try:
        cve_collector = CVECollector()
        cve_data = cve_collector.collect()
        
        if cve_data:
            # Save raw data
            raw_file = cve_collector.save_data(cve_data, f"cve_raw_{timestamp}.json")
            logger.info(f"Saved raw CVE data to {raw_file}")
            
            # Process and save processed data
            processed_data = cve_collector.process_cve_data(cve_data)
            
            # Save processed data directly to the processed directory
            processed_file = f"cve_processed_{timestamp}.json"
            processed_path = os.path.join('data', 'processed', processed_file)
            
            with open(processed_path, 'w', encoding='utf-8') as f:
                import json
                json.dump(processed_data, f, indent=2)
            logger.info(f"Saved processed CVE data to {processed_path}")
    except Exception as e:
        logger.error(f"Error collecting CVE data: {e}")
    
    # Add other collectors here as they are implemented
    # try:
    #     blog_collector = BlogCollector()
    #     blog_data = blog_collector.collect()
    #     # Process and save blog data
    # except Exception as e:
    #     logger.error(f"Error collecting blog data: {e}")
    
    logger.info("Data collection completed")
    
if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Run all collectors
    collect_from_all_sources() 