"""
Server Monitor Module
This module collects security events from Nepalese servers in real-time.
"""

import os
import json
import time
import logging
import random
import ipaddress
import threading
import requests
from datetime import datetime
from typing import List, Dict, Any, Optional
from pathlib import Path

# Configure logging
logger = logging.getLogger(__name__)

# Nepal-specific IP ranges (examples - replace with actual Nepalese IP ranges)
NEPAL_IP_RANGES = [
    "27.34.0.0/15",    # Nepal Telecom 
    "27.116.0.0/15",   # Nepal Telecom
    "103.1.92.0/22",   # WorldLink
    "103.10.28.0/22",  # Mercantile
    "103.28.84.0/22",  # Subisu
    "103.69.124.0/22", # Vianet
    "110.44.112.0/20", # Classic Tech
    "111.119.32.0/19", # CG Net
    "202.63.240.0/20", # Other Nepalese ISPs
    "202.166.192.0/19" # Nepal Telecom
]

# Common Nepalese server types for simulation
NEPAL_SERVER_TYPES = [
    "web-server-ktm",
    "mail-server-pokhara",
    "db-server-biratnagar", 
    "auth-server-birgunj",
    "dns-server-nepal",
    "proxy-server-bhaktapur",
    "file-server-dharan",
    "api-server-nepalganj"
]

# Common attack types
ATTACK_TYPES = [
    "brute_force", 
    "sql_injection",
    "xss", 
    "ddos",
    "port_scan",
    "credential_stuffing",
    "malware_infection",
    "ransomware",
    "data_exfiltration",
    "unauthorized_access"
]

# Paths
DATA_DIR = Path("data/raw/server_events")

class ServerMonitor:
    """Class for monitoring Nepalese servers and collecting security events."""
    
    def __init__(self, 
                 polling_interval: int = 10, 
                 use_real_servers: bool = False,
                 server_list_path: Optional[str] = None):
        """
        Initialize the server monitor.
        
        Args:
            polling_interval: Time in seconds between polls
            use_real_servers: Whether to use real server connections or simulation
            server_list_path: Path to JSON file with server connection details
        """
        self.polling_interval = polling_interval
        self.use_real_servers = use_real_servers
        self.server_list_path = server_list_path
        self.servers = []
        self.is_running = False
        self.monitor_thread = None
        
        # Create data directory if it doesn't exist
        os.makedirs(DATA_DIR, exist_ok=True)
        
        # Load server list if provided
        if use_real_servers and server_list_path:
            self._load_server_list()
    
    def _load_server_list(self):
        """Load the list of servers from a JSON file."""
        try:
            with open(self.server_list_path, 'r') as f:
                self.servers = json.load(f)
                logger.info(f"Loaded {len(self.servers)} servers from {self.server_list_path}")
        except Exception as e:
            logger.error(f"Error loading server list: {e}")
            # Fall back to simulation mode
            self.use_real_servers = False
    
    def start_monitoring(self):
        """Start the monitoring thread."""
        if self.is_running:
            logger.warning("Monitoring already running")
            return
        
        self.is_running = True
        self.monitor_thread = threading.Thread(target=self._monitoring_loop)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
        logger.info("Server monitoring started")
    
    def stop_monitoring(self):
        """Stop the monitoring thread."""
        self.is_running = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=self.polling_interval*2)
        logger.info("Server monitoring stopped")
    
    def _monitoring_loop(self):
        """Main monitoring loop."""
        while self.is_running:
            try:
                if self.use_real_servers:
                    events = self._collect_real_events()
                else:
                    events = self._simulate_events()
                
                if events:
                    self._save_events(events)
            except Exception as e:
                logger.error(f"Error in monitoring loop: {e}")
            
            # Sleep before next poll
            time.sleep(self.polling_interval)
    
    def _simulate_events(self, num_events=1) -> List[Dict[str, Any]]:
        """
        Simulate security events from Nepalese servers.
        
        Args:
            num_events: Number of events to simulate
            
        Returns:
            List of simulated security events
        """
        events = []
        
        for _ in range(random.randint(0, num_events)):
            # Get a random IP from Nepal ranges
            ip_range = random.choice(NEPAL_IP_RANGES)
            network = ipaddress.ip_network(ip_range)
            host = random.randint(0, network.num_addresses - 1)
            ip = str(network[host])
            
            # Create event
            event = {
                "timestamp": datetime.now().isoformat(),
                "server": random.choice(NEPAL_SERVER_TYPES),
                "source_ip": ip,
                "attack_type": random.choice(ATTACK_TYPES),
                "severity": random.choice(["low", "medium", "high", "critical"]),
                "details": self._generate_event_details(),
                "location": {
                    "country": "Nepal",
                    "city": random.choice(["Kathmandu", "Pokhara", "Biratnagar", "Birgunj", "Dharan", "Bhaktapur"])
                }
            }
            events.append(event)
        
        return events
    
    def _generate_event_details(self) -> Dict[str, Any]:
        """Generate realistic event details based on attack type."""
        attack_type = random.choice(ATTACK_TYPES)
        
        if attack_type == "brute_force":
            return {
                "method": "SSH" if random.random() > 0.5 else "RDP",
                "attempts": random.randint(10, 100),
                "usernames": ["admin", "root", "user", "nepal"],
                "duration_seconds": random.randint(30, 300)
            }
        elif attack_type == "sql_injection":
            return {
                "endpoint": random.choice(["/login", "/search", "/api/data"]),
                "payload": "' OR 1=1; --",
                "database": random.choice(["mysql", "postgresql", "oracle"]),
                "success": random.random() > 0.7
            }
        elif attack_type == "ddos":
            return {
                "method": random.choice(["TCP SYN flood", "HTTP flood", "UDP flood"]),
                "traffic_gbps": round(random.random() * 10, 2),
                "packet_count": random.randint(100000, 10000000),
                "duration_minutes": random.randint(5, 60)
            }
        else:
            return {
                "description": f"Potential {attack_type.replace('_', ' ')} attack detected",
                "target": random.choice(["web app", "database", "api", "admin panel"]),
                "indicators": ["suspicious traffic", "unusual access patterns"]
            }
    
    def _collect_real_events(self) -> List[Dict[str, Any]]:
        """
        Collect real security events from Nepalese servers.
        
        Returns:
            List of security events
        """
        events = []
        
        for server in self.servers:
            try:
                # Example: collect events via API
                if server.get("type") == "api":
                    response = requests.get(
                        f"https://{server['host']}:{server['port']}/security/events",
                        headers={"Authorization": f"Bearer {server['token']}"},
                        timeout=5
                    )
                    if response.status_code == 200:
                        server_events = response.json()
                        for event in server_events:
                            event["server"] = server["name"]
                            events.append(event)
                
                # Example: collect events via log file
                elif server.get("type") == "log":
                    # Implementation depends on how logs are accessed
                    # This would typically involve SSH or other protocols
                    pass
                
            except Exception as e:
                logger.error(f"Error collecting events from {server.get('name')}: {e}")
        
        return events
    
    def _save_events(self, events: List[Dict[str, Any]]):
        """
        Save events to a file.
        
        Args:
            events: List of security events to save
        """
        if not events:
            return
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = DATA_DIR / f"events_{timestamp}.json"
        
        try:
            with open(filename, 'w') as f:
                json.dump(events, f, indent=2)
            logger.info(f"Saved {len(events)} events to {filename}")
        except Exception as e:
            logger.error(f"Error saving events: {e}")

    def get_latest_events(self, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Get the latest security events.
        
        Args:
            limit: Maximum number of events to return
            
        Returns:
            List of latest security events
        """
        events = []
        
        # Get all event files, sorted by modification time (newest first)
        event_files = sorted(
            DATA_DIR.glob('events_*.json'),
            key=lambda x: x.stat().st_mtime,
            reverse=True
        )
        
        # Read events from files until we reach the limit
        for file in event_files:
            try:
                with open(file, 'r') as f:
                    file_events = json.load(f)
                    events.extend(file_events)
                    if len(events) >= limit:
                        break
            except Exception as e:
                logger.error(f"Error reading events from {file}: {e}")
        
        # Return only up to the limit
        return events[:limit]

    def get_threat_summary(self) -> Dict[str, Any]:
        """
        Get a summary of current threats.
        
        Returns:
            Dictionary with threat summary statistics
        """
        events = self.get_latest_events(1000)  # Analyze last 1000 events
        
        # Initialize summary
        summary = {
            "total_events": len(events),
            "timestamp": datetime.now().isoformat(),
            "attack_types": {},
            "severities": {
                "low": 0,
                "medium": 0,
                "high": 0,
                "critical": 0
            },
            "top_source_ips": {},
            "top_targets": {},
            "events_by_location": {}
        }
        
        # Process events
        for event in events:
            # Count attack types
            attack_type = event.get("attack_type", "unknown")
            summary["attack_types"][attack_type] = summary["attack_types"].get(attack_type, 0) + 1
            
            # Count severities
            severity = event.get("severity", "unknown")
            if severity in summary["severities"]:
                summary["severities"][severity] += 1
            
            # Count source IPs
            source_ip = event.get("source_ip", "unknown")
            summary["top_source_ips"][source_ip] = summary["top_source_ips"].get(source_ip, 0) + 1
            
            # Count targets
            target = event.get("server", "unknown")
            summary["top_targets"][target] = summary["top_targets"].get(target, 0) + 1
            
            # Count by location
            location = event.get("location", {}).get("city", "unknown")
            summary["events_by_location"][location] = summary["events_by_location"].get(location, 0) + 1
        
        # Sort and limit top entries
        summary["top_source_ips"] = dict(sorted(
            summary["top_source_ips"].items(), 
            key=lambda x: x[1], 
            reverse=True
        )[:10])
        
        summary["top_targets"] = dict(sorted(
            summary["top_targets"].items(), 
            key=lambda x: x[1], 
            reverse=True
        )[:10])
        
        return summary


# Singleton instance
monitor = ServerMonitor()

def start_monitoring():
    """Start server monitoring."""
    monitor.start_monitoring()

def stop_monitoring():
    """Stop server monitoring."""
    monitor.stop_monitoring()

def get_latest_events(limit: int = 100):
    """Get latest events."""
    return monitor.get_latest_events(limit)

def get_threat_summary():
    """Get threat summary."""
    return monitor.get_threat_summary() 