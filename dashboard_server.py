#!/usr/bin/env python3
"""
Simple HTTP Server for the Threat Intelligence Dashboard
Serves static files from the 'static' directory and proxies API requests
"""

import http.server
import socketserver
import logging
import os
import sys
import json
import urllib.request
import urllib.error
from urllib.parse import urlparse, parse_qs

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# Define constants
PORT = 8082
DIRECTORY = "static"
API_BASE_URL = "http://localhost:9000"

class DashboardRequestHandler(http.server.SimpleHTTPRequestHandler):
    """Request handler for dashboard requests"""
    
    def __init__(self, *args, **kwargs):
        # Set directory to serve static files from
        super().__init__(*args, directory=DIRECTORY, **kwargs)

    def log_message(self, format, *args):
        """Override to use our logger instead"""
        logger.info("%s - - [%s] %s" %
                    (self.address_string(),
                     self.log_date_time_string(),
                     format % args))
    
    def do_GET(self):
        """Handle GET requests"""
        # Check if this is an API request to proxy
        if self.path.startswith('/api/'):
            # Remove the /api prefix and forward to the actual API
            api_path = self.path.replace('/api', '', 1)
            self.proxy_api_request('GET', api_path)
            return
        
        # Default to index.html if root path is requested
        if self.path == '/':
            self.path = '/index.html'
        
        # Let the parent class handle the rest (static file serving)
        return super().do_GET()
    
    def do_POST(self):
        """Handle POST requests"""
        # Check if this is an API request to proxy
        if self.path.startswith('/api/'):
            # Remove the /api prefix and forward to the actual API
            api_path = self.path.replace('/api', '', 1)
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            self.proxy_api_request('POST', api_path, post_data)
            return
        
        # Not found for all other POST requests
        self.send_response(404)
        self.end_headers()
    
    def proxy_api_request(self, method, path, data=None):
        """Proxy a request to the API server"""
        url = f"{API_BASE_URL}{path}"
        logger.info(f"Proxying {method} request to {url}")
        
        try:
            # Create the request object
            headers = {
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            }
            req = urllib.request.Request(url, data=data, headers=headers, method=method)
            
            # Send the request to the API server
            with urllib.request.urlopen(req) as response:
                # Get the response status and data
                status_code = response.status
                response_data = response.read()
                response_headers = response.info()
                
                # Send the response back to the client
                self.send_response(status_code)
                
                # Add CORS headers
                self.send_header('Access-Control-Allow-Origin', '*')
                self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
                self.send_header('Access-Control-Allow-Headers', 'Content-Type, Accept')
                
                # Add content type header
                self.send_header('Content-Type', response_headers.get('Content-Type', 'application/json'))
                self.send_header('Content-Length', len(response_data))
                self.end_headers()
                
                # Send the response data
                self.wfile.write(response_data)
        
        except urllib.error.HTTPError as e:
            # Handle HTTP errors from the API
            logger.error(f"API returned error: {e.code} - {e.reason}")
            self.send_response(e.code)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            error_data = json.dumps({"error": f"{e.code} - {e.reason}"}).encode('utf-8')
            self.send_header('Content-Length', len(error_data))
            self.end_headers()
            self.wfile.write(error_data)
        
        except Exception as e:
            # Handle other errors
            logger.error(f"Error proxying request: {e}")
            self.send_response(500)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            error_data = json.dumps({"error": "Internal Server Error"}).encode('utf-8')
            self.send_header('Content-Length', len(error_data))
            self.end_headers()
            self.wfile.write(error_data)
    
    def do_OPTIONS(self):
        """Handle OPTIONS requests (CORS preflight)"""
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Accept')
        self.send_header('Access-Control-Max-Age', '86400')  # 24 hours
        self.end_headers()

def run_server():
    """Start the dashboard HTTP server"""
    # Create the server directory if it doesn't exist
    os.makedirs(DIRECTORY, exist_ok=True)
    
    # Ensure all required files are in place
    required_files = [
        os.path.join(DIRECTORY, "index.html"),
        os.path.join(DIRECTORY, "styles.css"),
        os.path.join(DIRECTORY, "dashboard.js")
    ]
    
    missing_files = [f for f in required_files if not os.path.exists(f)]
    if missing_files:
        logger.error(f"Missing required files: {missing_files}")
        logger.error("Please make sure all required files are in the 'static' directory")
        sys.exit(1)
    
    # Start the server
    handler = DashboardRequestHandler
    
    with socketserver.TCPServer(("", PORT), handler) as httpd:
        logger.info(f"Dashboard server started at http://localhost:{PORT}")
        logger.info(f"API server should be running at {API_BASE_URL}")
        logger.info("Press Ctrl+C to stop the server")
        
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            logger.info("Server stopped by user")
        finally:
            httpd.server_close()
            logger.info("Server closed")

if __name__ == "__main__":
    run_server() 