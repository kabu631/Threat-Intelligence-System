#!/usr/bin/env python3
"""
Threat Intelligence System Starter
This script starts both the API server and dashboard server
and ensures proper communication between them.
"""

import os
import sys
import time
import signal
import logging
import subprocess
import threading
import webbrowser
import requests
from urllib.error import URLError
import socket

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger("SystemStarter")

# Define constants
API_HOST = "0.0.0.0"
API_PORT = 9000
DASHBOARD_PORT = 8082
PROCESSES = []
MAX_RETRIES = 5
RETRY_DELAY = 2

def signal_handler(sig, frame):
    """Handle interrupt signals by cleaning up processes."""
    logger.info("Shutdown signal received. Terminating all processes...")
    kill_existing_processes()
    sys.exit(0)

def kill_process(port):
    """Kill any process running on the specified port."""
    try:
        # This works on Unix-like systems
        cmd = f"lsof -ti:{port} | xargs kill -9"
        subprocess.run(cmd, shell=True, stderr=subprocess.PIPE)
        logger.info(f"Killed process using port {port}")
        return True
    except Exception as e:
        logger.error(f"Error killing process on port {port}: {e}")
        return False

def kill_existing_processes():
    """Kill any existing API or dashboard server processes."""
    # Kill any existing global processes we started
    for process in PROCESSES:
        if process.poll() is None:  # Process is still running
            try:
                process.terminate()
                logger.info(f"Terminated process PID {process.pid}")
            except Exception as e:
                logger.error(f"Error terminating process: {e}")

    # Also kill any processes on our ports to be sure
    kill_process(API_PORT)
    kill_process(DASHBOARD_PORT)
    
    # Also try to kill by name
    try:
        subprocess.run("pkill -f 'python run.py api'", shell=True, stderr=subprocess.PIPE)
        subprocess.run("pkill -f 'dashboard_server.py'", shell=True, stderr=subprocess.PIPE)
    except Exception:
        pass

def is_port_in_use(port):
    """Check if a port is already in use."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(('localhost', port)) == 0

def check_api_health(retries=MAX_RETRIES):
    """Check if the API server is healthy."""
    url = f"http://localhost:{API_PORT}/health"
    for i in range(retries):
        try:
            response = requests.get(url, timeout=2)
            if response.status_code == 200:
                data = response.json()
                if data.get("status") == "healthy":
                    logger.info("API server is healthy.")
                    return True
            logger.warning(f"API not healthy yet (attempt {i+1}/{retries})")
        except (requests.RequestException, URLError) as e:
            logger.warning(f"API health check failed (attempt {i+1}/{retries}): {e}")
        
        # Wait before retrying
        time.sleep(RETRY_DELAY)
    
    return False

def start_api_server():
    """Start the API server."""
    if is_port_in_use(API_PORT):
        logger.warning(f"Port {API_PORT} is already in use. Killing process...")
        kill_process(API_PORT)
        time.sleep(1)
    
    logger.info(f"Starting API server on port {API_PORT}...")
    api_process = subprocess.Popen(
        ["python", "run.py", "api"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1
    )
    PROCESSES.append(api_process)
    
    # Start a thread to monitor the API server output
    threading.Thread(
        target=monitor_output,
        args=(api_process, "API"),
        daemon=True
    ).start()
    
    # Wait for API to be healthy
    if not check_api_health():
        logger.error("API server did not start properly.")
        kill_existing_processes()
        sys.exit(1)
    
    return api_process

def start_dashboard_server():
    """Start the dashboard server."""
    if is_port_in_use(DASHBOARD_PORT):
        logger.warning(f"Port {DASHBOARD_PORT} is already in use. Killing process...")
        kill_process(DASHBOARD_PORT)
        time.sleep(1)
    
    logger.info(f"Starting dashboard server on port {DASHBOARD_PORT}...")
    dashboard_process = subprocess.Popen(
        ["python", "dashboard_server.py"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1
    )
    PROCESSES.append(dashboard_process)
    
    # Start a thread to monitor the dashboard server output
    threading.Thread(
        target=monitor_output,
        args=(dashboard_process, "Dashboard"),
        daemon=True
    ).start()
    
    # Give the dashboard time to start
    time.sleep(2)
    
    # Verify the dashboard server is running
    try:
        response = requests.get(f"http://localhost:{DASHBOARD_PORT}", timeout=2)
        if response.status_code == 200:
            logger.info("Dashboard server is running.")
            return dashboard_process
        else:
            logger.error(f"Dashboard server returned status code {response.status_code}")
            return None
    except requests.RequestException as e:
        logger.error(f"Failed to connect to dashboard server: {e}")
        return None

def monitor_output(process, name):
    """Monitor and log the output of a process."""
    for line in process.stdout:
        line = line.strip()
        if line:
            logger.info(f"{name}: {line}")
    
    if process.poll() is not None:
        logger.warning(f"{name} process exited with code {process.returncode}")

def open_dashboard():
    """Open the dashboard in the default web browser."""
    dashboard_url = f"http://localhost:{DASHBOARD_PORT}"
    logger.info(f"Opening dashboard at {dashboard_url}")
    webbrowser.open(dashboard_url)

def main():
    """Main function to start the Threat Intelligence system."""
    # Set up signal handlers for graceful shutdown
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    logger.info("Starting Threat Intelligence Automation system...")
    
    # Kill existing processes
    kill_existing_processes()
    
    # Start the API server
    api_process = start_api_server()
    if api_process is None:
        logger.error("Failed to start API server. Exiting.")
        sys.exit(1)
    
    # Start the dashboard server
    dashboard_process = start_dashboard_server()
    if dashboard_process is None:
        logger.error("Failed to start dashboard server. Exiting.")
        kill_existing_processes()
        sys.exit(1)
    
    # Open dashboard in browser
    open_dashboard()
    
    logger.info("System is now running. Press Ctrl+C to stop.")
    
    # Keep the script running to maintain the processes
    try:
        while all(p.poll() is None for p in PROCESSES):
            time.sleep(1)
        
        # Check if any process died
        for i, process in enumerate(PROCESSES):
            if process.poll() is not None:
                name = "API" if i == 0 else "Dashboard"
                logger.error(f"{name} server exited unexpectedly with code {process.returncode}.")
        
        # Clean up and exit
        kill_existing_processes()
    except KeyboardInterrupt:
        logger.info("Shutting down...")
        kill_existing_processes()

if __name__ == "__main__":
    main() 