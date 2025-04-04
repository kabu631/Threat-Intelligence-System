#!/usr/bin/env python3
"""
Threat Intelligence Automation
"""

import os
import logging
import argparse
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='Threat Intelligence Automation')
    parser.add_argument('--collect', action='store_true',
                        help='Run data collection from sources')
    parser.add_argument('--analyze', action='store_true',
                        help='Run threat analysis on collected data')
    parser.add_argument('--api', action='store_true',
                        help='Start the API server')
    parser.add_argument('--all', action='store_true',
                        help='Run all components')
    return parser.parse_args()

def run_collection():
    """Run the data collection process."""
    from collectors import run_collectors
    logger.info("Starting data collection...")
    run_collectors.collect_from_all_sources()

def run_analysis():
    """Run the threat analysis process."""
    from processors import run_processors
    from models import run_models
    
    logger.info("Starting data processing...")
    run_processors.process_all()
    
    logger.info("Starting threat analysis...")
    run_models.analyze_threats()

def start_api():
    """Start the API server."""
    import uvicorn
    from api.app import app
    
    host = os.getenv("API_HOST", "0.0.0.0")
    port = int(os.getenv("API_PORT", 8000))
    log_level = os.getenv("API_LOG_LEVEL", "info")
    
    logger.info(f"Starting API server on {host}:{port}...")
    uvicorn.run(app, host=host, port=port, log_level=log_level)

def main():
    """Main application entry point."""
    args = parse_args()
    
    if args.all or args.collect:
        run_collection()
    
    if args.all or args.analyze:
        run_analysis()
    
    if args.all or args.api:
        start_api()
    
    if not any([args.all, args.collect, args.analyze, args.api]):
        logger.info("No action specified. Use --help for usage information.")

if __name__ == "__main__":
    main() 