#!/usr/bin/env python3
"""
Run Script for Threat Intelligence Automation
This script provides an easy way to run different components of the system.
"""

import argparse
import logging
import os
import sys

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description='Threat Intelligence Automation'
    )
    parser.add_argument(
        'action',
        choices=['collect', 'process', 'analyze', 'api', 'all'],
        help='Action to perform'
    )
    return parser.parse_args()

def main():
    """Main entry point."""
    args = parse_args()
    
    # Add src to the Python path
    sys.path.insert(0, os.path.abspath('src'))
    
    # Perform the requested action
    if args.action == 'collect' or args.action == 'all':
        from collectors.run_collectors import collect_from_all_sources
        collect_from_all_sources()
    
    if args.action == 'process' or args.action == 'all':
        from processors.run_processors import process_all
        process_all()
    
    if args.action == 'analyze' or args.action == 'all':
        from models.run_models import analyze_threats
        analyze_threats()
    
    if args.action == 'api' or args.action == 'all':
        import uvicorn
        from api.app import app
        
        # Get configuration from environment or use defaults
        host = os.getenv("API_HOST", "0.0.0.0")
        port = int(os.getenv("API_PORT", 9000))
        
        logger.info(f"Starting API server on {host}:{port}")
        uvicorn.run(app, host=host, port=port)

if __name__ == "__main__":
    main() 