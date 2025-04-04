"""
Base Collector Module
This module defines the base class for all data collectors.
"""

import logging
from abc import ABC, abstractmethod
from datetime import datetime
import os
import json

logger = logging.getLogger(__name__)

class BaseCollector(ABC):
    """Base class for all data collectors."""
    
    def __init__(self, source_name, data_dir=None):
        """
        Initialize the collector.
        
        Args:
            source_name (str): Name of the data source
            data_dir (str, optional): Directory to store collected data
        """
        self.source_name = source_name
        self.data_dir = data_dir or os.path.join('data', 'raw')
        
        # Create data directory if it doesn't exist
        os.makedirs(self.data_dir, exist_ok=True)
    
    @abstractmethod
    def collect(self):
        """
        Collect data from the source.
        This method must be implemented by subclasses.
        
        Returns:
            list: List of collected items
        """
        pass
    
    def save_data(self, data, filename=None):
        """
        Save collected data to disk.
        
        Args:
            data: Data to save
            filename (str, optional): Custom filename
            
        Returns:
            str: Path to the saved file
        """
        if filename is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"{self.source_name}_{timestamp}.json"
        
        filepath = os.path.join(self.data_dir, filename)
        
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)
            logger.info(f"Saved {len(data)} items to {filepath}")
            return filepath
        except Exception as e:
            logger.error(f"Error saving data to {filepath}: {e}")
            return None 