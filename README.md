# Threat Intelligence Dashboard

A comprehensive web-based dashboard for monitoring, analyzing, and responding to cybersecurity threats in real-time.

![Threat Intelligence Dashboard](static/images/dashboard-preview.png)

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Dashboard Sections](#dashboard-sections)
- [Installation](#installation)
- [Usage](#usage)
- [Configuration](#configuration)
- [API Documentation](#api-documentation)
- [Contributing](#contributing)
- [License](#license)

## Overview

The Threat Intelligence Dashboard is an interactive platform designed for security professionals to monitor global and local threats, analyze attack patterns, and access tools for threat intelligence analysis. The dashboard combines real-time data with comprehensive visualization tools to provide actionable insights for cybersecurity teams.

## Features

- **Real-time Threat Monitoring**: Track and visualize global and local security incidents as they occur
- **Interactive Visualizations**: Analyze threat data through comprehensive charts and graphs 
- **CVE Database Integration**: Access and search the latest Common Vulnerabilities and Exposures
- **Threat Analysis Tools**: Extract IOCs, perform topic modeling, and identify entities in security reports
- **Nepal-focused Monitoring**: Dedicated section for monitoring threats specific to Nepal's infrastructure
- **Configurable Settings**: Customize dashboard appearance and behavior through the settings panel
- **Dark Mode Support**: Toggle between light and dark themes for different working environments
- **Real-time Notifications**: Receive alerts about critical security events as they happen

## Dashboard Sections

### Main Dashboard

The main dashboard provides a global overview of threat intelligence, featuring:

- **Threat Distribution Chart**: Breakdown of different threat types
- **Attack Types Chart**: Analysis of various attack methodologies
- **Geographic Distribution**: Visual representation of threat origins
- **Severity Breakdown**: Classification of threats by severity level
- **Recent CVEs**: Latest vulnerabilities from the CVE database
- **Threat Topics**: AI-generated topic clusters from threat intelligence
- **Identified Entities**: Automatically extracted entities from threat reports

### Analysis Tools

Interactive tools for threat intelligence analysis:

- **IOC Extractor**: Extract Indicators of Compromise from text
- **Topic Modeling**: Analyze themes in threat intelligence reports
- **Entity Recognition**: Identify and categorize entities in security documents
- **CVE Search**: Search and filter the CVE database

### Nepal Monitor

Specialized section focused on Nepal's cybersecurity landscape:

- **Nepal Threat Overview**: Visualizations specific to Nepal's threat landscape
- **Latest Events**: Real-time monitoring of security incidents
- **Event Details**: In-depth information about specific security events
- **Top Targeted Servers**: Ranking of most frequently targeted systems
- **Top Attack Sources**: Analysis of primary attack origins

### Settings

Configurable options for dashboard customization:

- **Auto-refresh Interval**: Control data refresh frequency
- **Dark Mode**: Toggle between light and dark themes
- **Real-time Notifications**: Enable/disable security alerts
- **API Configuration**: Configure connection to backend services
- **Connection Status**: Monitor services connectivity

## Installation

### Prerequisites

- Python 3.8 or higher
- Git
- pip (Python package installer)

### Clone the Repository

```bash
git clone https://github.com/yourusername/threat-intelligence-dashboard.git
cd threat-intelligence-dashboard
```

### Set Up Python Virtual Environment

```bash
python -m venv venv
source venv/bin/activate  # On Windows, use: venv\Scripts\activate
```

### Install Dependencies

```bash
pip install -r requirements.txt
```

### Start the Application

#### Method 1: Using the Built-in Script

```bash
python start_system.py
```

#### Method 2: Starting Components Manually

Start the API server:
```bash
cd src
python api_server.py
```

Start the static file server:
```bash
cd static
python -m http.server 8080
```

### Access the Dashboard

Open your browser and navigate to:
```
http://localhost:8080
```

## Usage

### Navigation

Use the navigation menu at the top of the page to switch between different sections:
- **Dashboard**: Global threat overview and intelligence summaries
- **Analysis Tools**: Interactive tools for threat intelligence analysis
- **Nepal Monitor**: Nepal-specific threat monitoring
- **Settings**: Dashboard configuration options

### Dashboard Interaction

- **Charts**: Hover over chart elements to see detailed information
- **Tables**: Click on table rows to see detailed information about entries
- **Search & Filter**: Use search boxes and filters to find specific information
- **Tools**: Enter text into analysis tool sections to process threat intelligence data

### Customization

Access the settings page to customize:
- Set auto-refresh intervals for data
- Toggle between light and dark mode
- Enable or disable real-time notifications
- Configure API connections

## Configuration

### API Configuration

The dashboard connects to a backend API for data. Configure the connection in the Settings page:

1. Navigate to the Settings page
2. Update the "API Base URL" field with your API server address
3. Update the "WebSocket URL" field for real-time data
4. Click "Test Connection" to verify

### Environment Variables

Create a `.env` file in the project root with the following variables:

```
API_PORT=9000
STATIC_PORT=8080
DEBUG=True
API_KEY=your_api_key_here
```

## API Documentation

The backend API supports the following endpoints:

- `/health`: API health check
- `/global/summary`: Get global threat summary
- `/global/events`: Get global threat events
- `/nepal/summary`: Get Nepal-specific threat summary
- `/nepal/events`: Get Nepal-specific threat events
- `/tools/extract-ioc`: Extract IOCs from text
- `/tools/topic-model`: Perform topic modeling on text
- `/tools/extract-entities`: Extract entities from text
- `/cve/search`: Search the CVE database

For full API documentation, see [API.md](API.md).

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details. 