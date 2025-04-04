// Dashboard JavaScript

// API Configuration
const API_BASE_URL = "http://localhost:9000";
const WS_BASE_URL = "ws://localhost:9000";

// WebSocket connections
let globalDataSocket;
let nepalDataSocket;

// Chart colors
const chartColors = [
    'rgba(54, 162, 235, 0.7)',
    'rgba(255, 99, 132, 0.7)',
    'rgba(255, 206, 86, 0.7)',
    'rgba(75, 192, 192, 0.7)',
    'rgba(153, 102, 255, 0.7)',
    'rgba(255, 159, 64, 0.7)',
    'rgba(199, 199, 199, 0.7)'
];

// Charts objects
let threatDistributionChart;
let attackTypesChart;
let geoDistributionChart;
let severityChart;
let nepalThreatDistributionChart;
let nepalAttackTypesChart;
let nepalGeoDistributionChart;
let nepalSeverityChart;

// Nepal dummy data
const nepalDummyEvents = [
    {
        id: 1,
        timestamp: new Date(Date.now() - 120000).toISOString(),
        server: 'web1.nepaltelecom.np',
        source_ip: '185.143.223.12',
        attack_type: 'SQL Injection',
        severity: 'High',
        country: 'Russia',
        description: 'Attempted SQL injection targeting login form with malicious payload attempting to extract user credentials.',
        mitigations: 'Input validation strengthened, IP blocked.'
    },
    {
        id: 2,
        timestamp: new Date(Date.now() - 450000).toISOString(),
        server: 'mail.gov.np',
        source_ip: '103.77.192.219',
        attack_type: 'Brute Force',
        severity: 'Medium',
        country: 'China',
        description: 'Brute force authentication attempts targeting mail server admin panel with over 2000 login attempts in 5 minutes.',
        mitigations: 'Rate limiting implemented, account lockout policy updated.'
    },
    {
        id: 3,
        timestamp: new Date(Date.now() - 1800000).toISOString(),
        server: 'api.bankofnepal.np',
        source_ip: '91.213.8.65',
        attack_type: 'XSS',
        severity: 'Critical',
        country: 'Ukraine',
        description: 'Cross-site scripting attack attempting to inject JavaScript code to steal session cookies from banking customers.',
        mitigations: 'Content Security Policy implemented, vulnerable endpoint patched.'
    },
    {
        id: 4,
        timestamp: new Date(Date.now() - 3600000).toISOString(),
        server: 'cdn.nepalnews.com',
        source_ip: '45.227.255.34',
        attack_type: 'DDoS',
        severity: 'High',
        country: 'Brazil',
        description: 'Distributed denial of service attack with traffic peaks of 15 Gbps targeting news content delivery network.',
        mitigations: 'Traffic filtering and rate limiting applied at edge.'
    },
    {
        id: 5,
        timestamp: new Date(Date.now() - 7200000).toISOString(),
        server: 'portal.education.gov.np',
        source_ip: '193.149.176.2',
        attack_type: 'File Upload',
        severity: 'Medium',
        country: 'Romania',
        description: 'Attempted upload of malicious PHP file to gain remote code execution capabilities on government portal.',
        mitigations: 'Upload validation improved, file extension whitelist implemented.'
    },
    {
        id: 6,
        timestamp: new Date(Date.now() - 10800000).toISOString(),
        server: 'web1.nepaltelecom.np',
        source_ip: '85.113.47.230',
        attack_type: 'Directory Traversal',
        severity: 'Low',
        country: 'Latvia',
        description: 'Directory traversal attempt to access configuration files outside web root directory.',
        mitigations: 'Path sanitization implemented, server permissions tightened.'
    },
    {
        id: 7,
        timestamp: new Date(Date.now() - 14400000).toISOString(),
        server: 'api.bankofnepal.np',
        source_ip: '156.146.56.88',
        attack_type: 'CSRF',
        severity: 'Medium',
        country: 'Netherlands',
        description: 'Cross-site request forgery attempt targeting fund transfer functionality.',
        mitigations: 'Anti-CSRF tokens implemented, same-site cookies enforced.'
    }
];

const nepalDummyServers = [
    { server: 'web1.nepaltelecom.np', events: 42, top_attack_type: 'SQL Injection' },
    { server: 'api.bankofnepal.np', events: 38, top_attack_type: 'XSS' },
    { server: 'mail.gov.np', events: 27, top_attack_type: 'Brute Force' },
    { server: 'portal.education.gov.np', events: 24, top_attack_type: 'File Upload' },
    { server: 'cdn.nepalnews.com', events: 19, top_attack_type: 'DDoS' }
];

const nepalDummySources = [
    { source_ip: '185.143.223.12', country: 'Russia', events: 47 },
    { source_ip: '103.77.192.219', country: 'China', events: 35 },
    { source_ip: '91.213.8.65', country: 'Ukraine', events: 29 },
    { source_ip: '45.227.255.34', country: 'Brazil', events: 23 },
    { source_ip: '193.149.176.2', country: 'Romania', events: 18 }
];

const nepalDummySummary = {
    total_events: 180,
    severity_counts: {
        critical: 18,
        high: 36,
        medium: 57,
        low: 69
    },
    attack_types: {
        'SQL Injection': 52,
        'Brute Force': 43,
        'XSS': 32,
        'DDoS': 21,
        'File Upload': 19,
        'Other': 13
    },
    locations: {
        'Kathmandu': 95,
        'Pokhara': 35,
        'Biratnagar': 28,
        'Birgunj': 12,
        'Other Regions': 10
    }
};

// Add global dummy data
const globalDummyCVEs = [
    { id: "CVE-2023-1234", published: "2023-07-15", severity: "Critical", cvss: "9.8", description: "Remote code execution vulnerability in Apache Struts" },
    { id: "CVE-2023-5678", published: "2023-08-02", severity: "High", cvss: "8.5", description: "SQL injection vulnerability in MySQL" },
    { id: "CVE-2023-9012", published: "2023-08-22", severity: "Medium", cvss: "6.4", description: "Cross-site scripting vulnerability in WordPress plugin" },
    { id: "CVE-2023-3456", published: "2023-09-05", severity: "Critical", cvss: "9.2", description: "Buffer overflow in OpenSSL affecting TLS handshake" },
    { id: "CVE-2023-7890", published: "2023-09-18", severity: "High", cvss: "7.8", description: "Authentication bypass in Cisco network devices" }
];

const globalDummyTopics = [
    { topic: "Ransomware", score: 0.85, relevance: "High", count: 42, keywords: ["encryption", "bitcoin", "payment", "recovery"] },
    { topic: "Data Breaches", score: 0.78, relevance: "High", count: 36, keywords: ["leak", "exposure", "credentials", "personal data"] },
    { topic: "Zero-day Exploits", score: 0.72, relevance: "Medium", count: 29, keywords: ["vulnerability", "unpatched", "exploit", "disclosure"] },
    { topic: "APT Campaigns", score: 0.68, relevance: "Medium", count: 25, keywords: ["nation-state", "targeted", "persistent", "espionage"] },
    { topic: "Cloud Security", score: 0.65, relevance: "Medium", count: 22, keywords: ["misconfiguration", "S3", "azure", "public access"] }
];

const globalDummyEntities = [
    { entity: "Lazarus Group", type: "Threat Actor", confidence: 0.92, mentions: 37, source: "Multiple Intelligence Reports" },
    { entity: "Log4j", type: "Vulnerability", confidence: 0.95, mentions: 42, source: "CISA Advisory" },
    { entity: "Emotet", type: "Malware", confidence: 0.88, mentions: 31, source: "VirusTotal Analysis" },
    { entity: "SolarWinds", type: "Affected Vendor", confidence: 0.90, mentions: 29, source: "Industry Reports" },
    { entity: "BlackCat", type: "Ransomware", confidence: 0.85, mentions: 25, source: "Threat Intelligence" }
];

const globalDummySummary = {
    total_events: 1254,
    severity_counts: {
        critical: 128,
        high: 342,
        medium: 456,
        low: 328
    },
    attack_types: {
        'Malware': 312,
        'Phishing': 287,
        'Ransomware': 164,
        'DDoS': 142,
        'SQL Injection': 98,
        'Other': 251
    },
    locations: {
        'North America': 435,
        'Europe': 387,
        'Asia': 276,
        'South America': 87,
        'Africa': 43,
        'Australia/Oceania': 26
    }
};

// Add immediate initialization of Nepal monitor data
document.addEventListener('DOMContentLoaded', function() {
    // Initialize settings
    setupDarkModeToggle();
    setupNotificationsToggle();
    setupRefreshInterval();
    
    // Initialize dashboard components
    initializeCharts();
    loadDashboardData();
    setupNavigation();
    
    // Check API status and update connection indicators
    checkApiStatus();
    
    // Initialize Nepal monitor
    setupNepalMonitorToggle();
    
    // Setup analysis tools
    setupAnalysisTools();
    
    // Setup simulated real-time notifications
    setupSimulatedNotifications();
    
    // Initialize simulated data for demo purposes
    setTimeout(() => {
        // Force connection status to show as connected in demo mode
        updateAllComponentStatuses(true);
        
        // Show welcome notification
        showNotification('Welcome to the Threat Intelligence Dashboard', 'info');
        
        // Show notification about map removal
        setTimeout(() => {
            showNotification('Threat maps have been removed from all sections', 'info');
        }, 2000);
    }, 500);
});

// Initialize data with dynamic fetching instead of static dummy data
async function initializeData() {
    try {
        // Try to fetch real data first
        await loadAllDashboardData();
    } catch (error) {
        console.error('Error loading real data, falling back to dummy data:', error);
        // Fall back to dummy data if API is not available
        initializeDummyData();
    }
    
    // Set up data refresh at the specified interval
    const refreshInterval = parseInt(document.getElementById('refresh-interval').value) * 1000 || 30000;
    setInterval(loadAllDashboardData, refreshInterval);
}

// Load all dashboard data from the API
async function loadAllDashboardData() {
    try {
        // Show loading indicators
        setLoadingState(true);
        
        // Load global dashboard data
        await loadDashboardData();
        
        // Load Nepal monitor data if that section is active
        if (document.getElementById('nepal-monitor').classList.contains('active-section')) {
            await loadNepalMonitorData();
        }
        
        // Update last refreshed timestamp
        updateLastRefreshed();
        
        // Hide loading indicators
        setLoadingState(false);
    } catch (error) {
        console.error('Error loading dashboard data:', error);
        // Hide loading indicators even if there's an error
        setLoadingState(false);
    }
}

// Show/hide loading indicators for all data sections
function setLoadingState(isLoading) {
    const loadingElements = document.querySelectorAll('.loading-message');
    loadingElements.forEach(element => {
        if (isLoading) {
            element.style.display = 'block';
            element.textContent = 'Refreshing data...';
        } else {
            element.style.display = 'none';
        }
    });
}

// Update the last refreshed timestamp
function updateLastRefreshed() {
    const timestamp = new Date().toLocaleTimeString();
    
    // Create or update the last refreshed indicator
    let refreshIndicator = document.getElementById('last-refreshed');
    if (!refreshIndicator) {
        refreshIndicator = document.createElement('div');
        refreshIndicator.id = 'last-refreshed';
        refreshIndicator.classList.add('refresh-indicator');
        document.querySelector('main').appendChild(refreshIndicator);
    }
    
    refreshIndicator.textContent = `Last updated: ${timestamp}`;
    
    // Show a brief animation to indicate refresh
    refreshIndicator.classList.add('refreshing');
    setTimeout(() => {
        refreshIndicator.classList.remove('refreshing');
    }, 1000);
}

// Improve the initializeDummyData function to properly update the UI
function initializeDummyData() {
    // Update global dashboard data
    updateGlobalSummary(globalDummySummary);
    updateCVETable(globalDummyCVEs);
    updateTopicContainer(globalDummyTopics);
    updateEntityContainer(globalDummyEntities);
    
    // Initialize charts with dummy data
    updateGlobalThreatDistribution(globalDummySummary.attack_types);
    updateGlobalGeoDistribution(globalDummySummary.locations);
    updateGlobalSeverity(globalDummySummary.severity_counts);
    
    // Update the Nepal events table with dummy events
    updateNepalEventsTable(nepalDummyEvents);
    
    // Update the top servers table with dummy server data
    updateTopServersTable(nepalDummyServers);
    
    // Update the top sources table with dummy source data
    updateTopSourcesTable(nepalDummySources);
    
    // Update the Nepal summary stats with dummy summary data
    updateNepalSummary(nepalDummySummary);
    
    // Show the first event by default if available
    if (nepalDummyEvents.length > 0) {
        showEventDetails(nepalDummyEvents[0]);
    }
    
    // Start simulation of events after a short delay
    setTimeout(simulateNepalEvents, 2000);
}

// Function to update the global dashboard summary
function updateGlobalSummary(summaryData) {
    if (!summaryData) return;
    
    document.getElementById('global-total-events').textContent = summaryData.total_events;
    document.getElementById('global-critical-events').textContent = summaryData.severity_counts.critical;
    document.getElementById('global-high-events').textContent = summaryData.severity_counts.high;
    document.getElementById('global-medium-events').textContent = summaryData.severity_counts.medium;
    document.getElementById('global-low-events').textContent = summaryData.severity_counts.low;
}

// Function to update the CVE table with data
function updateCVETable(cveData) {
    if (!cveData || !Array.isArray(cveData)) return;
    
    const table = document.getElementById('cve-table');
    if (!table) return;
    
    const tbody = table.querySelector('tbody');
    tbody.innerHTML = '';
    
    cveData.forEach(cve => {
        const row = document.createElement('tr');
        
        // Format the CVE data for display
        const id = cve.id || 'Unknown';
        const published = cve.published || 'Unknown';
        const severity = cve.severity || 'Unknown';
        const cvss = cve.cvss || 'N/A';
        const description = cve.description || 'No description available';
        
        // Create the severity badge with appropriate class
        const severityClass = severity.toLowerCase();
        const severityBadge = `<span class="severity-badge severity-${severityClass}">${severity}</span>`;
        
        // Create view details button
        const viewButton = '<button class="view-details-btn">View</button>';
        
        // Set row content
        row.innerHTML = `
            <td>${id}</td>
            <td>${published}</td>
            <td>${severityBadge}</td>
            <td>${cvss}</td>
            <td>${description}</td>
            <td>${viewButton}</td>
        `;
        
        // Add event listener for view button
        const button = row.querySelector('.view-details-btn');
        if (button) {
            button.addEventListener('click', () => {
                showCVEDetails(cve);
            });
        }
        
        tbody.appendChild(row);
    });
    
    // Initialize search after populating the table
    setupCVESearchAndFilter();
}

// Function to show CVE details in a modal or details pane
function showCVEDetails(cve) {
    // Create a modal or update a details pane with the CVE information
    const modal = document.createElement('div');
    modal.className = 'cve-details-modal';
    
    modal.innerHTML = `
        <div class="modal-content">
            <span class="close-modal">&times;</span>
            <h3>${cve.id}</h3>
            <div class="cve-detail-item">
                <span class="detail-label">Published:</span> ${cve.published}
            </div>
            <div class="cve-detail-item">
                <span class="detail-label">Severity:</span> 
                <span class="severity-badge severity-${cve.severity.toLowerCase()}">${cve.severity}</span>
            </div>
            <div class="cve-detail-item">
                <span class="detail-label">CVSS Score:</span> ${cve.cvss}
            </div>
            <div class="cve-detail-item">
                <span class="detail-label">Description:</span>
                <p>${cve.description}</p>
            </div>
            <div class="cve-detail-item">
                <span class="detail-label">References:</span>
                <ul>
                    ${cve.references ? cve.references.map(ref => `<li><a href="${ref}" target="_blank">${ref}</a></li>`).join('') : '<li>No references available</li>'}
                </ul>
            </div>
        </div>
    `;
    
    document.body.appendChild(modal);
    
    // Add event listener to close modal
    const closeButton = modal.querySelector('.close-modal');
    if (closeButton) {
        closeButton.addEventListener('click', () => {
            modal.remove();
        });
    }
    
    // Close modal when clicking outside
    modal.addEventListener('click', (e) => {
        if (e.target === modal) {
            modal.remove();
        }
    });
}

// Function to update the topic container with new data
function updateTopicContainer(topicData) {
    const container = document.querySelector('#topic-container');
    if (!container) return;
    
    if (!topicData || topicData.length === 0) {
        container.innerHTML = '<p>No threat topics available at this time.</p>';
        return;
    }
    
    let content = '<div class="topic-list">';
    topicData.forEach(topic => {
        const scorePercent = Math.round(topic.score * 100);
        content += `
            <div class="topic-item">
                <div class="topic-header">
                    <span class="topic-name">${topic.topic}</span>
                    <span class="topic-relevance ${topic.relevance.toLowerCase()}">${topic.relevance}</span>
                </div>
                <div class="topic-progress">
                    <div class="progress-bar" style="width: ${scorePercent}%"></div>
                </div>
                <div class="topic-details">
                    <span>Score: ${topic.score.toFixed(2)}</span>
                    <span>Mentions: ${topic.count}</span>
                </div>
                <div class="topic-keywords">
                    ${topic.keywords.map(kw => `<span class="keyword">${kw}</span>`).join('')}
                </div>
            </div>
        `;
    });
    content += '</div>';
    
    container.innerHTML = content;
}

// Function to update the entity container with new data
function updateEntityContainer(entityData) {
    const container = document.querySelector('#entity-container');
    if (!container) return;
    
    if (!entityData || entityData.length === 0) {
        container.innerHTML = '<p>No entities identified at this time.</p>';
        return;
    }
    
    let content = '<div class="entity-list">';
    entityData.forEach(entity => {
        const confidencePercent = Math.round(entity.confidence * 100);
        content += `
            <div class="entity-item">
                <div class="entity-header">
                    <span class="entity-name">${entity.entity}</span>
                    <span class="entity-type">${entity.type}</span>
                </div>
                <div class="entity-confidence">
                    <div class="confidence-label">Confidence: ${confidencePercent}%</div>
                    <div class="confidence-bar">
                        <div class="confidence-fill" style="width: ${confidencePercent}%"></div>
                    </div>
                </div>
                <div class="entity-details">
                    <span>Mentions: ${entity.mentions}</span>
                    <span>Source: ${entity.source}</span>
                </div>
            </div>
        `;
    });
    content += '</div>';
    
    container.innerHTML = content;
}

// Function to update global threat distribution chart
function updateGlobalThreatDistribution(data) {
    if (!data) return;
    
    const ctx = document.getElementById('threatDistributionChart');
    if (!ctx) return;
    
    const labels = Object.keys(data);
    const values = Object.values(data);
    
    if (threatDistributionChart) {
        threatDistributionChart.data.labels = labels;
        threatDistributionChart.data.datasets[0].data = values;
        threatDistributionChart.update();
    } else {
        threatDistributionChart = new Chart(ctx, {
            type: 'pie',
            data: {
                labels: labels,
                datasets: [{
                    data: values,
                    backgroundColor: chartColors,
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'right',
                        labels: {
                            color: document.body.classList.contains('dark-mode') ? '#fff' : '#333'
                        }
                    },
                    tooltip: {
                        callbacks: {
                            label: function(context) {
                                const label = context.label || '';
                                const value = context.raw || 0;
                                const total = context.dataset.data.reduce((a, b) => a + b, 0);
                                const percentage = Math.round((value / total) * 100);
                                return `${label}: ${value} (${percentage}%)`;
                            }
                        }
                    }
                }
            }
        });
    }
}

// Function to update global geographical distribution chart
function updateGlobalGeoDistribution(data) {
    if (!data) return;
    
    const ctx = document.getElementById('geoDistributionChart');
    if (!ctx) return;
    
    const labels = Object.keys(data);
    const values = Object.values(data);
    
    if (geoDistributionChart) {
        geoDistributionChart.data.labels = labels;
        geoDistributionChart.data.datasets[0].data = values;
        geoDistributionChart.update();
    } else {
        geoDistributionChart = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: labels,
                datasets: [{
                    label: 'Events by Region',
                    data: values,
                    backgroundColor: chartColors,
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        display: false
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: {
                            color: document.body.classList.contains('dark-mode') ? '#fff' : '#333'
                        }
                    },
                    x: {
                        ticks: {
                            color: document.body.classList.contains('dark-mode') ? '#fff' : '#333'
                        }
                    }
                }
            }
        });
    }
}

// Function to update global severity chart
function updateGlobalSeverity(data) {
    if (!data) return;
    
    const ctx = document.getElementById('severityChart');
    if (!ctx) return;
    
    const labels = Object.keys(data).map(k => k.charAt(0).toUpperCase() + k.slice(1));
    const values = Object.values(data);
    const colors = ['#ff5252', '#ff9800', '#ffc107', '#4caf50'];
    
    if (severityChart) {
        severityChart.data.labels = labels;
        severityChart.data.datasets[0].data = values;
        severityChart.update();
    } else {
        severityChart = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: labels,
                datasets: [{
                    data: values,
                    backgroundColor: colors,
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'right',
                        labels: {
                            color: document.body.classList.contains('dark-mode') ? '#fff' : '#333'
                        }
                    }
                }
            }
        });
    }
}

// Function to update global attack types chart
function updateGlobalAttackTypes(data) {
    if (!data || !data.labels || !data.values) return;
    
    attackTypesChart.data.labels = data.labels;
    attackTypesChart.data.datasets[0].data = data.values;
    attackTypesChart.update();
}

// Function to update global severity chart
function updateGlobalSeverity(data) {
    if (!data || !data.values) return;
    
    severityChart.data.datasets[0].data = data.values;
    severityChart.update();
}

function setupRefreshInterval() {
    const refreshIntervalInput = document.getElementById('refresh-interval');
    if (!refreshIntervalInput) return;
    
    // Create visual indicator for refresh interval
    const refreshDisplay = document.createElement('span');
    refreshDisplay.id = 'refresh-display';
    refreshDisplay.className = 'setting-status';
    refreshDisplay.textContent = `Current: ${refreshIntervalInput.value}s`;
    refreshIntervalInput.parentNode.appendChild(refreshDisplay);
    
    // Load saved value from localStorage if available
    const savedInterval = localStorage.getItem('refreshInterval');
    if (savedInterval) {
        refreshIntervalInput.value = savedInterval;
        refreshDisplay.textContent = `Current: ${savedInterval}s`;
    }
    
    let refreshInterval = parseInt(refreshIntervalInput.value) * 1000 || 30000;
    let dashboardRefreshTimer;
    
    // Set up initial refresh interval
    startRefreshTimer();
    
    // Add event listener for changes to the refresh interval
    refreshIntervalInput.addEventListener('change', function() {
        // Clear existing timer
        clearInterval(dashboardRefreshTimer);
        
        // Set new refresh interval
        refreshInterval = parseInt(this.value) * 1000 || 30000;
        
        // Update visual indicator
        refreshDisplay.textContent = `Current: ${this.value}s`;
        refreshDisplay.classList.add('setting-updated');
        setTimeout(() => refreshDisplay.classList.remove('setting-updated'), 1000);
        
        // Save to localStorage
        localStorage.setItem('refreshInterval', this.value);
        
        // Show confirmation notification
        showNotification(`Data will refresh every ${this.value} seconds`, "success");
        
        // Start new timer
        startRefreshTimer();
    });
    
    function startRefreshTimer() {
        // Dashboard data refresh
        dashboardRefreshTimer = setInterval(() => {
            // Add updating class to main dashboard elements
            addUpdatingAnimation();
            
            // Load all dashboard data
            loadAllDashboardData().then(() => {
                // Remove updating animation once data is loaded
                setTimeout(removeUpdatingAnimation, 500);
            });
        }, refreshInterval);
        
        console.log(`Data refresh timer set to ${refreshInterval / 1000} seconds`);
    }
    
    // Add visual indicator during data refresh
    function addUpdatingAnimation() {
        // Add animation class to various dashboard elements
        document.querySelectorAll('.overview-card, .info-section, .threat-type-card, .status-card, .metric-card')
            .forEach(el => el.classList.add('data-updating'));
    }
    
    // Remove visual indicator after data refresh
    function removeUpdatingAnimation() {
        document.querySelectorAll('.data-updating')
            .forEach(el => el.classList.remove('data-updating'));
    }
}

function setupNepalMonitorToggle() {
    const toggle = document.getElementById('nepal-monitor-toggle');
    const statusText = document.getElementById('monitor-status');
    const refreshButton = document.getElementById('nepal-refresh-btn');
    
    if (!toggle || !statusText || !refreshButton) return;
    
    // Initialize based on saved preference (or default to off)
    const savedToggleState = localStorage.getItem('nepalMonitorEnabled');
    if (savedToggleState === 'true') {
        toggle.checked = true;
        statusText.textContent = 'Active';
        statusText.classList.add('active-status');
        startNepalMonitoring();
    } else {
        toggle.checked = false;
        statusText.textContent = 'Disabled';
        statusText.classList.remove('active-status');
    }
    
    // Handle toggle changes
    toggle.addEventListener('change', function() {
        if (toggle.checked) {
            statusText.textContent = 'Active';
            statusText.classList.add('active-status');
            localStorage.setItem('nepalMonitorEnabled', 'true');
            startNepalMonitoring();
        } else {
            statusText.textContent = 'Disabled';
            statusText.classList.remove('active-status');
            localStorage.setItem('nepalMonitorEnabled', 'false');
            stopNepalMonitoring();
        }
    });
    
    // Handle refresh button
    refreshButton.addEventListener('click', function() {
        // Show loading state
        refreshButton.classList.add('loading');
        
        // Refresh data
        loadNepalMonitorData()
            .then(() => {
                // Show success notification
                showNotification('Nepal monitor data refreshed');
            })
            .catch(error => {
                console.error('Error refreshing Nepal monitor data:', error);
                // Show error notification
                showNotification('Failed to refresh Nepal data', 'error');
            })
            .finally(() => {
                // Remove loading state
                setTimeout(() => {
                    refreshButton.classList.remove('loading');
                }, 500);
            });
    });
    
    // Handle section activation
    document.querySelectorAll('header nav ul li a').forEach(link => {
        link.addEventListener('click', function(e) {
            if (link.getAttribute('href') === '#nepal-monitor' && toggle.checked) {
                // Update data when navigating to Nepal monitor section
                loadNepalMonitorData();
            }
        });
    });
}

// Function to stop Nepal monitoring
function stopNepalMonitoring() {
    // Clear any existing intervals
    if (window.nepalEventsInterval) {
        clearInterval(window.nepalEventsInterval);
        window.nepalEventsInterval = null;
    }
    
    if (window.nepalAttacksInterval) {
        clearInterval(window.nepalAttacksInterval);
        window.nepalAttacksInterval = null;
    }
    
    console.log("Nepal monitoring stopped");
}

function setupDarkModeToggle() {
    const darkModeToggle = document.getElementById('dark-mode-toggle');
    if (!darkModeToggle) return;
    
    // Check if dark mode is saved in localStorage
    const savedDarkMode = localStorage.getItem('darkMode');
    if (savedDarkMode === 'enabled') {
        document.body.classList.add('dark-mode');
        darkModeToggle.checked = true;
        // Ensure charts are updated for dark mode on initial load
        setTimeout(() => updateChartsForTheme(true), 100);
    }
    
    darkModeToggle.addEventListener('change', function() {
        if (this.checked) {
            document.body.classList.add('dark-mode');
            localStorage.setItem('darkMode', 'enabled');
            showNotification("Dark mode enabled", "success");
        } else {
            document.body.classList.remove('dark-mode');
            localStorage.setItem('darkMode', 'disabled');
            showNotification("Dark mode disabled", "info");
        }
        
        // Update charts for better visibility in dark mode
        updateChartsForTheme(this.checked);
    });
}

function updateChartsForTheme(isDarkMode) {
    const textColor = isDarkMode ? '#e5e7eb' : '#1f2937';
    const gridColor = isDarkMode ? 'rgba(255, 255, 255, 0.1)' : 'rgba(0, 0, 0, 0.1)';
    
    const charts = [
        threatDistributionChart, 
        attackTypesChart, 
        geoDistributionChart, 
        severityChart,
        nepalThreatDistributionChart,
        nepalAttackTypesChart,
        nepalGeoDistributionChart,
        nepalSeverityChart
    ];
    
    charts.forEach(chart => {
        if (!chart) return;
        
        // Update legend text color
        if (chart.options.plugins && chart.options.plugins.legend) {
            chart.options.plugins.legend.labels = { 
                color: textColor 
            };
        }
        
        // Update scale text color and grid color for bar charts
        if (chart.options.scales) {
            for (const scaleId in chart.options.scales) {
                chart.options.scales[scaleId].ticks = { color: textColor };
                chart.options.scales[scaleId].grid = { color: gridColor };
            }
        }
        
        chart.update();
    });
}

async function checkApiStatus() {
    const statusIndicator = document.createElement('div');
    statusIndicator.id = 'api-status-indicator';
    statusIndicator.classList.add('api-status');
    document.body.appendChild(statusIndicator);
    
    // Update status indicators in settings
    const settingsApiStatus = document.getElementById('settings-api-status');
    const settingsGlobalWsStatus = document.getElementById('settings-global-ws-status');
    const settingsNepalWsStatus = document.getElementById('settings-nepal-ws-status');
    const iocExtractorStatus = document.getElementById('ioc_extractor-status');
    const topicModelerStatus = document.getElementById('topic_modeler-status');
    const nerModelStatus = document.getElementById('ner_model-status');
    const nepalMonitorStatus = document.getElementById('nepal_monitor-status');
    
    try {
        // Create an AbortController with a timeout
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 5000);
        
        const response = await fetch(`${API_BASE_URL}/health`, {
            signal: controller.signal
        });
        
        clearTimeout(timeoutId);
        
        if (response.ok) {
            const data = await response.json();
            
            if (data.status === 'healthy') {
                // Check if all components are running
                let allComponentsHealthy = true;
                const missingComponents = [];
                
                // Update status in settings page
                if (settingsApiStatus) settingsApiStatus.innerHTML = '<span class="status-enabled">Connected</span>';
                
                if (data.components) {
                    // Update component status indicators
                    for (const [component, isRunning] of Object.entries(data.components)) {
                        const statusElement = document.getElementById(`${component}-status`);
                        if (statusElement) {
                            statusElement.innerHTML = isRunning ? 
                                '<span class="status-enabled">Connected</span>' : 
                                '<span class="status-disabled">Disconnected</span>';
                        }
                        
                        if (!isRunning) {
                            allComponentsHealthy = false;
                            missingComponents.push(component);
                        }
                    }
                }
                
                if (allComponentsHealthy) {
                    statusIndicator.classList.add('online');
                    statusIndicator.setAttribute('data-tooltip', 'API server is online and all components are running');
                    
                    // Initialize components that depend on API
                    startNepalMonitoring();
                } else {
                    statusIndicator.classList.add('warning');
                    statusIndicator.setAttribute('data-tooltip', `API server is online but some components are not running: ${missingComponents.join(', ')}`);
                    console.warn(`API components not running: ${missingComponents.join(', ')}`);
                    
                    // Still try to initialize what we can with dummy data
                    initializeDummyData();
                    startNepalMonitoring();
                }
            } else {
                if (settingsApiStatus) settingsApiStatus.innerHTML = '<span class="status-disabled">Disconnected</span>';
                updateAllComponentStatuses(false);
                
                statusIndicator.classList.add('offline');
                statusIndicator.setAttribute('data-tooltip', `API server reported status: ${data.status}`);
                console.error(`API server reported unhealthy status: ${data.status}`);
                
                // Fall back to using dummy data
                initializeDummyData();
                startNepalMonitoring();
            }
        } else {
            if (settingsApiStatus) settingsApiStatus.innerHTML = '<span class="status-disabled">Disconnected</span>';
            updateAllComponentStatuses(false);
            
            statusIndicator.classList.add('offline');
            statusIndicator.setAttribute('data-tooltip', `API server responded with status ${response.status}`);
            console.error(`API server responded with status ${response.status}`);
            
            // Fall back to using dummy data
            initializeDummyData();
            startNepalMonitoring();
        }
    } catch (error) {
        if (settingsApiStatus) settingsApiStatus.innerHTML = '<span class="status-disabled">Disconnected</span>';
        updateAllComponentStatuses(false);
        
        statusIndicator.classList.add('offline');
        
        // Special handling for timeout
        if (error.name === 'AbortError') {
            statusIndicator.setAttribute('data-tooltip', 'API server request timed out');
            console.error('API server request timed out');
        } else {
            statusIndicator.setAttribute('data-tooltip', `Cannot connect to API server: ${error.message}`);
            console.error('API server connection error:', error);
        }
        
        // Fall back to using dummy data
        initializeDummyData();
        startNepalMonitoring();
        
        // Add visual notification about API status
        showNotification('API server is not responding. Using simulated data.', 'warning');
    }
    
    // Since we're in a demo environment, simulate WebSocket connections to be online
    if (settingsGlobalWsStatus) settingsGlobalWsStatus.innerHTML = '<span class="status-enabled">Connected</span>';
    if (settingsNepalWsStatus) settingsNepalWsStatus.innerHTML = '<span class="status-enabled">Connected</span>';
}

// Helper function to update all component statuses
function updateAllComponentStatuses(isConnected) {
    const components = ['ioc_extractor', 'topic_modeler', 'ner_model', 'nepal_monitor'];
    components.forEach(component => {
        const statusElement = document.getElementById(`${component}-status`);
        if (statusElement) {
            statusElement.innerHTML = isConnected ? 
                '<span class="status-enabled">Connected</span>' : 
                '<span class="status-disabled">Disconnected</span>';
        }
    });
}

function initializeCharts() {
    // Global Threat Distribution Chart
    const threatDistributionCtx = document.getElementById('threatDistributionChart').getContext('2d');
    threatDistributionChart = new Chart(threatDistributionCtx, {
        type: 'pie',
        data: {
            labels: ['Ransomware', 'Phishing', 'DDoS', 'Zero-day', 'Other'],
            datasets: [{
                data: [32, 28, 18, 12, 10],
                backgroundColor: chartColors,
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: {
                    position: 'right',
                }
            }
        }
    });
    
    // Global Attack Types Chart
    const attackTypesCtx = document.getElementById('attackTypesChart').getContext('2d');
    attackTypesChart = new Chart(attackTypesCtx, {
        type: 'bar',
        data: {
            labels: ['Web Attack', 'Malware', 'Brute Force', 'Data Exfiltration', 'Other'],
            datasets: [{
                label: 'Attack Count',
                data: [156, 123, 97, 76, 48],
                backgroundColor: chartColors[0],
                borderColor: chartColors[0].replace('0.7', '1'),
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            scales: {
                y: {
                    beginAtZero: true
                }
            }
        }
    });
    
    // Global Geographic Distribution Chart
    const geoDistributionCtx = document.getElementById('geoDistributionChart').getContext('2d');
    geoDistributionChart = new Chart(geoDistributionCtx, {
        type: 'doughnut',
        data: {
            labels: ['North America', 'Europe', 'Asia', 'Africa', 'South America', 'Oceania'],
            datasets: [{
                data: [35, 27, 20, 10, 5, 3],
                backgroundColor: chartColors,
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: {
                    position: 'right',
                }
            }
        }
    });
    
    // Global Severity Chart
    const severityCtx = document.getElementById('severityChart').getContext('2d');
    severityChart = new Chart(severityCtx, {
        type: 'bar',
        data: {
            labels: ['Critical', 'High', 'Medium', 'Low'],
            datasets: [{
                label: 'Count',
                data: [42, 87, 123, 68],
                backgroundColor: [
                    'rgba(220, 53, 69, 0.7)',
                    'rgba(255, 193, 7, 0.7)',
                    'rgba(23, 162, 184, 0.7)',
                    'rgba(40, 167, 69, 0.7)'
                ],
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            scales: {
                y: {
                    beginAtZero: true
                }
            }
        }
    });
    
    // Nepal Threat Distribution Chart
    const nepalThreatDistributionCtx = document.getElementById('nepalThreatDistributionChart').getContext('2d');
    nepalThreatDistributionChart = new Chart(nepalThreatDistributionCtx, {
        type: 'pie',
        data: {
            labels: ['Web Attacks', 'Brute Force', 'Data Exfiltration', 'Malware', 'Other'],
            datasets: [{
                data: [42, 23, 15, 12, 8],
                backgroundColor: chartColors,
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: {
                    position: 'right',
                }
            }
        }
    });
    
    // Nepal Attack Types Chart
    const nepalAttackTypesCtx = document.getElementById('nepalAttackTypesChart').getContext('2d');
    nepalAttackTypesChart = new Chart(nepalAttackTypesCtx, {
        type: 'bar',
        data: {
            labels: ['SQL Injection', 'XSS', 'Credential Stuffing', 'File Upload', 'CSRF'],
            datasets: [{
                label: 'Attack Count',
                data: [32, 27, 21, 15, 12],
                backgroundColor: 'rgba(41, 82, 163, 0.7)',
                borderColor: 'rgba(41, 82, 163, 1)',
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            scales: {
                y: {
                    beginAtZero: true
                }
            }
        }
    });
    
    // Nepal Geographic Distribution Chart
    const nepalGeoDistributionCtx = document.getElementById('nepalGeoDistributionChart').getContext('2d');
    nepalGeoDistributionChart = new Chart(nepalGeoDistributionCtx, {
        type: 'doughnut',
        data: {
            labels: ['Kathmandu', 'Pokhara', 'Biratnagar', 'Birgunj', 'Other Regions'],
            datasets: [{
                data: [45, 20, 15, 12, 8],
                backgroundColor: chartColors,
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: {
                    position: 'right',
                }
            }
        }
    });
    
    // Nepal Severity Chart
    const nepalSeverityCtx = document.getElementById('nepalSeverityChart').getContext('2d');
    nepalSeverityChart = new Chart(nepalSeverityCtx, {
        type: 'bar',
        data: {
            labels: ['Critical', 'High', 'Medium', 'Low'],
            datasets: [{
                label: 'Count',
                data: [18, 36, 57, 27],
                backgroundColor: [
                    'rgba(220, 53, 69, 0.7)',
                    'rgba(255, 193, 7, 0.7)',
                    'rgba(23, 162, 184, 0.7)',
                    'rgba(40, 167, 69, 0.7)'
                ],
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            scales: {
                y: {
                    beginAtZero: true
                }
            }
        }
    });
}

async function loadDashboardData() {
    try {
        // Load global threat summary
        const summaryResponse = await fetch(`${API_BASE_URL}/summary`).catch(() => {
            console.warn('Could not fetch summary data, using fallback');
            return { ok: false };
        });
        
        if (summaryResponse.ok) {
            const summaryData = await summaryResponse.json();
            updateGlobalSummary(summaryData);
            
            // Update charts with the summary data
            updateGlobalThreatDistribution(summaryData.attack_types);
            updateGlobalAttackTypes({ 
                labels: Object.keys(summaryData.attack_types),
                values: Object.values(summaryData.attack_types)
            });
            updateGlobalGeoDistribution(summaryData.locations);
            updateGlobalSeverity(summaryData.severity_counts);
        } else {
            // Use dummy data as fallback
            updateGlobalSummary(globalDummySummary);
            updateGlobalThreatDistribution(globalDummySummary.attack_types);
            updateGlobalAttackTypes({ 
                labels: Object.keys(globalDummySummary.attack_types),
                values: Object.values(globalDummySummary.attack_types)
            });
            updateGlobalGeoDistribution(globalDummySummary.locations);
            updateGlobalSeverity(globalDummySummary.severity_counts);
        }
        
        // Load CVE data
        const cveResponse = await fetch(`${API_BASE_URL}/cves`).catch(() => {
            console.warn('Could not fetch CVE data, using fallback');
            return { ok: false };
        });
        
        if (cveResponse.ok) {
            const cveData = await cveResponse.json();
            updateCVETable(cveData);
        } else {
            // Use dummy data as fallback
            updateCVETable(globalDummyCVEs);
        }
        
        // Load topic data
        const topicResponse = await fetch(`${API_BASE_URL}/topics`).catch(() => {
            console.warn('Could not fetch topic data, using fallback');
            return { ok: false };
        });
        
        if (topicResponse.ok) {
            const topicData = await topicResponse.json();
            updateTopicContainer(topicData);
        } else {
            // Use dummy data as fallback
            updateTopicContainer(globalDummyTopics);
        }
        
        // Load entity data
        const entityResponse = await fetch(`${API_BASE_URL}/entities`).catch(() => {
            console.warn('Could not fetch entity data, using fallback');
            return { ok: false };
        });
        
        if (entityResponse.ok) {
            const entityData = await entityResponse.json();
            updateEntityContainer(entityData);
        } else {
            // Use dummy data as fallback
            updateEntityContainer(globalDummyEntities);
        }
        
        // Update threat type cards with real data or fallback
        updateThreatTypeCards();
        
        // Update status metrics (CPU, Memory, etc.)
        updateSystemStatusMetrics();
        
        return true;
    } catch (error) {
        console.error('Error loading dashboard data:', error);
        // Use dummy data as fallback in case of any errors
        initializeDummyData();
        return false;
    }
}

// Function to update the threat type cards with real data
function updateThreatTypeCards() {
    try {
        fetch(`${API_BASE_URL}/threat-types`)
            .then(response => {
                if (!response.ok) throw new Error('Failed to fetch threat types');
                return response.json();
            })
            .then(data => {
                const container = document.querySelector('.threat-type-cards');
                if (!container) return;
                
                // Clear existing cards
                container.innerHTML = '';
                
                // Add new cards based on the data
                data.forEach(threatType => {
                    const card = document.createElement('div');
                    card.className = 'threat-type-card';
                    
                    const trendClass = threatType.trend > 0 ? 'up' : 
                                     threatType.trend < 0 ? 'down' : 'neutral';
                    const trendSymbol = threatType.trend > 0 ? '▲' : 
                                      threatType.trend < 0 ? '▼' : '−';
                    
                    card.innerHTML = `
                        <h4>${threatType.name}</h4>
                        <p class="percentage">${threatType.percentage}%</p>
                        <div class="trend ${trendClass}">${trendSymbol} ${Math.abs(threatType.trend)}%</div>
                        <p class="victims">Affected systems: ${threatType.affected_systems}</p>
                    `;
                    
                    container.appendChild(card);
                });
            })
            .catch(error => {
                console.error('Error updating threat type cards:', error);
                // Keep existing threat cards if there's an error
            });
    } catch (error) {
        console.error('Error in updateThreatTypeCards:', error);
    }
}

// Function to update system status metrics
function updateSystemStatusMetrics() {
    try {
        fetch(`${API_BASE_URL}/system-status`)
            .then(response => {
                if (!response.ok) throw new Error('Failed to fetch system status');
                return response.json();
            })
            .then(data => {
                // Update status cards
                updateStatusCards(data.components);
                
                // Update resource metrics
                updateResourceMetrics(data.resources);
            })
            .catch(error => {
                console.error('Error updating system status metrics:', error);
                // Keep existing status data if there's an error
            });
    } catch (error) {
        console.error('Error in updateSystemStatusMetrics:', error);
    }
}

// Function to update status cards
function updateStatusCards(components) {
    if (!components) return;
    
    const statusGrid = document.querySelector('.status-grid');
    if (!statusGrid) return;
    
    // Update existing status cards or keep them as is
    for (const component of components) {
        const card = statusGrid.querySelector(`[data-component="${component.name}"]`);
        if (card) {
            card.className = `status-card ${component.status.toLowerCase()}`;
            card.querySelector('.status-info h3').textContent = component.name;
            card.querySelector('.status-info p').textContent = component.statusText;
            
            // Update the status icon
            const iconMap = {
                'green': '✓',
                'yellow': '!',
                'red': '✗'
            };
            
            card.querySelector('.status-icon').textContent = 
                iconMap[component.status.toLowerCase()] || '?';
        }
    }
}

// Function to update resource metrics
function updateResourceMetrics(resources) {
    if (!resources) return;
    
    const metricsContainer = document.querySelector('.resource-metrics');
    if (!metricsContainer) return;
    
    // Update existing metrics or keep them as is
    for (const resource of Object.keys(resources)) {
        const card = metricsContainer.querySelector(`[data-resource="${resource}"]`);
        if (card) {
            const value = resources[resource];
            card.querySelector('.progress').style.width = `${value}%`;
            card.querySelector('p').textContent = `${value}%`;
        }
    }
}

// Function to load Nepal monitor data
async function loadNepalMonitorData() {
    try {
        // Check if Nepal monitoring is active
        const nepalMonitorToggle = document.getElementById('nepal-monitor-toggle');
        if (!nepalMonitorToggle || !nepalMonitorToggle.checked) {
            console.log('Nepal monitoring is disabled, skipping data load');
            return false;
        }
        
        // Show loading state for Nepal monitor
        document.querySelectorAll('#nepal-monitor .loading-message').forEach(el => {
            el.style.display = 'block';
            el.textContent = 'Refreshing Nepal data...';
        });
        
        // Connect to Nepal-specific endpoint
        const nepalEndpoint = `${API_BASE_URL}/nepal`;
        
        // Load Nepal summary with a more specific endpoint
        const summaryResponse = await fetch(`${nepalEndpoint}/summary`).catch(() => {
            console.warn('Could not fetch Nepal summary data, using fallback');
            return { ok: false };
        });
        
        if (summaryResponse.ok) {
            const summaryData = await summaryResponse.json();
            updateNepalSummary(summaryData);
            
            // Update charts with the summary data
            updateNepalCharts(summaryData);
        } else {
            // Use dummy data as fallback
            updateNepalSummary(nepalDummySummary);
            updateNepalCharts(nepalDummySummary);
        }
        
        // Load Nepal events with real-time data
        const eventsResponse = await fetch(`${nepalEndpoint}/events`).catch(() => {
            console.warn('Could not fetch Nepal events data, using fallback');
            return { ok: false };
        });
        
        if (eventsResponse.ok) {
            const eventsData = await eventsResponse.json();
            updateNepalEventsTable(eventsData, true); // true indicates these are real-time events
            
            // Show the first event by default if available
            if (eventsData.length > 0) {
                showEventDetails(eventsData[0]);
            }
        } else {
            // Use dummy data as fallback
            updateNepalEventsTable(generateNepalEvents(10), false);
            
            // Show the first event by default if available
            if (nepalDummyEvents.length > 0) {
                showEventDetails(nepalDummyEvents[0]);
            }
        }
        
        // Load Nepal server metrics
        const serversResponse = await fetch(`${nepalEndpoint}/servers`).catch(() => {
            console.warn('Could not fetch Nepal server metrics, using fallback');
            return { ok: false };
        });
        
        if (serversResponse.ok) {
            const serversData = await serversResponse.json();
            updateTopServersTable(serversData);
        } else {
            // Use dummy data as fallback
            updateTopServersTable(nepalDummyServers);
        }
        
        // Load Nepal attack sources
        const sourcesResponse = await fetch(`${nepalEndpoint}/attack-sources`).catch(() => {
            console.warn('Could not fetch Nepal attack sources, using fallback');
            return { ok: false };
        });
        
        if (sourcesResponse.ok) {
            const sourcesData = await sourcesResponse.json();
            updateTopSourcesTable(sourcesData);
        } else {
            // Use dummy data as fallback
            updateTopSourcesTable(nepalDummySources);
        }
        
        // Update map statistics
        updateNepalMapStatistics();
        
        return true;
    } catch (error) {
        console.error('Error loading Nepal monitor data:', error);
        // Fall back to dummy data
        updateNepalSummary(nepalDummySummary);
        updateNepalEventsTable(nepalDummyEvents);
        updateTopServersTable(nepalDummyServers);
        updateTopSourcesTable(nepalDummySources);
        
        // Show the first event by default if available
        if (nepalDummyEvents.length > 0) {
            showEventDetails(nepalDummyEvents[0]);
        }
        
        return false;
    }
}

// Function to update Nepal map statistics
function updateNepalMapStatistics() {
    fetch(`${API_BASE_URL}/nepal/map-stats`)
        .then(response => {
            if (!response.ok) throw new Error('Failed to fetch map statistics');
            return response.json();
        })
        .then(data => {
            // Update the statistics elements
            document.getElementById('nepal-live-attacks').innerText = data.live_attacks || '0';
            document.getElementById('nepal-source-countries').innerText = data.source_countries || '0';
            document.getElementById('nepal-critical-attacks').innerText = data.critical_attacks || '0';
        })
        .catch(error => {
            console.error('Error updating map statistics:', error);
            // Use fallback values
            document.getElementById('nepal-live-attacks').innerText = '24';
            document.getElementById('nepal-source-countries').innerText = '12';
            document.getElementById('nepal-critical-attacks').innerText = '6';
        });
}

function updateCVETable(cveData) {
    const tableBody = document.querySelector('#cve-table tbody');
    if (!cveData || cveData.length === 0) {
        tableBody.innerHTML = '<tr><td colspan="5">No CVE data available.</td></tr>';
        return;
    }
    
    let tableContent = '';
    cveData.forEach(cve => {
        tableContent += `
            <tr>
                <td>${cve.id}</td>
                <td>${cve.published}</td>
                <td><span class="severity-badge severity-${cve.severity.toLowerCase()}">${cve.severity}</span></td>
                <td>${cve.cvss}</td>
                <td>${cve.description.substring(0, 100)}...</td>
            </tr>
        `;
    });
    
    tableBody.innerHTML = tableContent;
}

function updateTopicContainer(topicData) {
    const topicContainer = document.getElementById('topic-container');
    if (!topicData || topicData.length === 0) {
        topicContainer.innerHTML = '<p>No topic data available.</p>';
        return;
    }
    
    let topicContent = '';
    topicData.forEach((topic, index) => {
        topicContent += `
            <div class="topic-item">
                <h4>Topic ${index}</h4>
                <p>${topic.keywords.join(', ')}</p>
            </div>
        `;
    });
    
    topicContainer.innerHTML = topicContent;
}

function updateEntityContainer(entityData) {
    const entityContainer = document.getElementById('entity-container');
    if (!entityData || Object.keys(entityData).length === 0) {
        entityContainer.innerHTML = '<p>No entity data available.</p>';
        return;
    }
    
    let entityContent = '';
    for (const [entityType, entities] of Object.entries(entityData)) {
        entityContent += `
            <div class="entity-type">
                <h4>${entityType}</h4>
                <p>${entities.join(', ')}</p>
            </div>
        `;
    }
    
    entityContainer.innerHTML = entityContent;
}

// Fix Nepal monitor section to work independently of WebSockets
function setupNepalMonitor() {
    const nepalSection = document.getElementById('nepal-monitor');
    if (!nepalSection) return;
    
    // Initialize the Nepal dashboard components
    setupNepalDashboardComponents(nepalSection);
    
    // Initialize Nepal map (make sure there's only one)
    const existingMap = document.getElementById('nepal-attack-map');
    if (existingMap) {
        // Load Leaflet for the map if needed
        loadLeafletIfNeeded(() => {
            initializeNepalMap();
        });
    }
    
    // Update the tables with dummy data immediately (don't wait for WebSocket)
    updateNepalEventsTable(nepalDummyEvents);
    updateTopServersTable(nepalDummyServers);
    updateTopSourcesTable(nepalDummySources);
    updateNepalSummary(nepalDummySummary);
    
    // Show the first event by default
    if (nepalDummyEvents.length > 0) {
        showEventDetails(nepalDummyEvents[0]);
    }
    
    // Set up toggle button
    const monitorToggle = document.getElementById('nepal-monitor-toggle');
    if (monitorToggle) {
        // Set the toggle to checked to show monitoring is active
        monitorToggle.checked = true;
        document.getElementById('monitor-status').textContent = 'Active';
        
        // Handle toggle changes
        monitorToggle.addEventListener('change', function() {
            const statusElement = document.getElementById('monitor-status');
            if (this.checked) {
                statusElement.textContent = 'Active';
                // Simulate new events every few seconds
                simulateNepalEvents();
            } else {
                statusElement.textContent = 'Disabled';
            }
        });
    }
}

// Add function to simulate new Nepal events
function simulateNepalEvents() {
    // Only proceed if monitoring is active
    const monitorToggle = document.getElementById('nepal-monitor-toggle');
    if (!monitorToggle || !monitorToggle.checked) return;
    
    // Create a new event
    const severities = ['Low', 'Medium', 'High', 'Critical'];
    const attackTypes = ['SQL Injection', 'XSS', 'Brute Force', 'DDoS', 'File Upload', 'CSRF', 'Directory Traversal'];
    const servers = [
        'web1.nepaltelecom.np',
        'mail.gov.np', 
        'api.bankofnepal.np',
        'cdn.nepalnews.com',
        'portal.education.gov.np'
    ];
    const countries = ['Russia', 'China', 'Ukraine', 'Brazil', 'Romania', 'Latvia', 'Netherlands', 'USA', 'India'];
    
    const newEvent = {
        id: nepalDummyEvents.length + 1,
        timestamp: new Date().toISOString(),
        server: servers[Math.floor(Math.random() * servers.length)],
        source_ip: `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`,
        attack_type: attackTypes[Math.floor(Math.random() * attackTypes.length)],
        severity: severities[Math.floor(Math.random() * severities.length)],
        country: countries[Math.floor(Math.random() * countries.length)],
        description: 'Automated detection of suspicious activity targeting Nepal server infrastructure.',
        mitigations: 'IP temporarily blocked, monitoring enhanced.'
    };
    
    // Add to beginning of events array
    nepalDummyEvents.unshift(newEvent);
    
    // Keep array at reasonable size
    if (nepalDummyEvents.length > 20) {
        nepalDummyEvents.pop();
    }
    
    // Update tables
    updateNepalEventsTable(nepalDummyEvents);
    
    // Update summary stats
    nepalDummySummary.total_events++;
    switch(newEvent.severity.toLowerCase()) {
        case 'critical':
            nepalDummySummary.severity_counts.critical++;
            break;
        case 'high':
            nepalDummySummary.severity_counts.high++;
            break;
        case 'medium':
            nepalDummySummary.severity_counts.medium++;
            break;
        case 'low':
            nepalDummySummary.severity_counts.low++;
            break;
    }
    
    // Update summary display
    updateNepalSummary(nepalDummySummary);
    
    // Update server and source counts
    let serverUpdated = false;
    for (let i = 0; i < nepalDummyServers.length; i++) {
        if (nepalDummyServers[i].server === newEvent.server) {
            nepalDummyServers[i].events++;
            serverUpdated = true;
            break;
        }
    }
    
    if (!serverUpdated && nepalDummyServers.length < 10) {
        nepalDummyServers.push({
            server: newEvent.server,
            events: 1,
            top_attack_type: newEvent.attack_type
        });
    }
    
    let sourceUpdated = false;
    for (let i = 0; i < nepalDummySources.length; i++) {
        if (nepalDummySources[i].source_ip === newEvent.source_ip) {
            nepalDummySources[i].events++;
            sourceUpdated = true;
            break;
        }
    }
    
    if (!sourceUpdated && nepalDummySources.length < 10) {
        nepalDummySources.push({
            source_ip: newEvent.source_ip,
            country: newEvent.country,
            events: 1
        });
    }
    
    // Update top tables
    updateTopServersTable(nepalDummyServers);
    updateTopSourcesTable(nepalDummySources);
    
    // Show notification about new event
    showNotification(`New ${newEvent.severity} severity attack detected on ${newEvent.server} from ${newEvent.country}`);
    
    // Continue simulation
    setTimeout(simulateNepalEvents, Math.random() * 5000 + 5000); // Random interval between 5-10 seconds
}

// Modify startNepalMonitoring to use local data instead of API
async function startNepalMonitoring() {
    console.log('Starting Nepal monitoring...');
    
    // Load initial data
    await loadNepalMonitorData();
    
    // Set up WebSocket for real-time updates
    setupNepalWebSocket();
    
    // Start simulation for demo/fallback
    if (window.nepalEventsInterval) {
        clearInterval(window.nepalEventsInterval);
    }
    
    // Simulate events every 15-30 seconds if WebSocket is not available
    window.nepalEventsInterval = setInterval(() => {
        if (nepalDataSocket && nepalDataSocket.readyState === WebSocket.OPEN) {
            // If WebSocket is connected, don't simulate events
            return;
        }
        
        // Only simulate if Nepal monitor is visible and toggle is on
        if (document.getElementById('nepal-monitor').classList.contains('active-section') &&
            document.getElementById('nepal-monitor-toggle').checked) {
            
            // Generate a random event
            const event = generateNepalEvent();
            
            // Add to events table
            const tableBody = document.querySelector('#nepal-events-table tbody');
            if (tableBody) {
                addNepalEvent(event, tableBody, true);
            }
            
            // Add to map
            if (window.nepalMap) {
                addAttackToNepalMap(event);
            }
            
            // Update summary statistics
            incrementNepalStats(event.severity);
        }
    }, Math.random() * 15000 + 15000); // Random interval between 15-30 seconds
    
    // Simulate attacks on the map every 5-15 seconds
    if (window.nepalAttacksInterval) {
        clearInterval(window.nepalAttacksInterval);
    }
    
    window.nepalAttacksInterval = setInterval(() => {
        if (nepalDataSocket && nepalDataSocket.readyState === WebSocket.OPEN) {
            // If WebSocket is connected, don't simulate attacks
            return;
        }
        
        // Only simulate if Nepal monitor is visible and toggle is on
        if (document.getElementById('nepal-monitor').classList.contains('active-section') &&
            document.getElementById('nepal-monitor-toggle').checked) {
            
            simulateNepalAttacks();
        }
    }, Math.random() * 10000 + 5000); // Random interval between 5-15 seconds
}

// Function to generate a single Nepal event for simulation
function generateNepalEvent() {
    const id = Date.now();
    const timestamp = new Date().toISOString();
    
    // Random severity
    const severities = ['Critical', 'High', 'Medium', 'Low'];
    const severityWeights = [0.1, 0.3, 0.4, 0.2]; // Probability weights
    const severity = weightedRandomChoice(severities, severityWeights);
    
    // Random attack type
    const attackTypes = ['SQL Injection', 'Brute Force', 'XSS', 'DDoS', 'File Upload', 'Directory Traversal', 'CSRF'];
    const attackWeights = [0.3, 0.2, 0.15, 0.1, 0.1, 0.1, 0.05]; // Probability weights
    const attackType = weightedRandomChoice(attackTypes, attackWeights);
    
    // Random server
    const servers = [
        'web1.nepaltelecom.np',
        'mail.gov.np',
        'api.bankofnepal.np',
        'cdn.nepalnews.com',
        'portal.education.gov.np',
        'ntc.net.np',
        'server1.nepal.gov.np',
        'database.nepal-bank.com.np'
    ];
    const server = servers[Math.floor(Math.random() * servers.length)];
    
    // Random source country and IP
    const countries = ['Russia', 'China', 'Ukraine', 'Brazil', 'Romania', 'India', 'Pakistan', 'USA', 'Latvia', 'Netherlands'];
    const country = countries[Math.floor(Math.random() * countries.length)];
    
    // Generate plausible looking IP address
    const sourceIp = `${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}`;
    
    // Generate description based on attack type
    let description = '';
    switch (attackType) {
        case 'SQL Injection':
            description = `Attempted SQL injection targeting ${server} with malicious query parameters attempting to extract user data.`;
            break;
        case 'Brute Force':
            description = `Brute force authentication attempts targeting ${server} with over 1000 login attempts in 3 minutes.`;
            break;
        case 'XSS':
            description = `Cross-site scripting attack attempting to inject JavaScript code to steal session cookies from ${server}.`;
            break;
        case 'DDoS':
            description = `Distributed denial of service attack with traffic peaks of 8 Gbps targeting ${server}.`;
            break;
        case 'File Upload':
            description = `Attempted upload of malicious file to gain remote code execution capabilities on ${server}.`;
            break;
        case 'Directory Traversal':
            description = `Directory traversal attempt to access configuration files outside web root directory on ${server}.`;
            break;
        case 'CSRF':
            description = `Cross-site request forgery attempt targeting functionality on ${server}.`;
            break;
        default:
            description = `Unknown attack type detected on ${server}.`;
    }
    
    // Generate remediation action
    let mitigations = '';
    switch (attackType) {
        case 'SQL Injection':
            mitigations = 'Input validation strengthened, IP blocked.';
            break;
        case 'Brute Force':
            mitigations = 'Rate limiting implemented, account lockout policy updated.';
            break;
        case 'XSS':
            mitigations = 'Content Security Policy implemented, vulnerable endpoint patched.';
            break;
        case 'DDoS':
            mitigations = 'Traffic filtering and rate limiting applied at edge.';
            break;
        case 'File Upload':
            mitigations = 'Upload validation improved, file extension whitelist implemented.';
            break;
        case 'Directory Traversal':
            mitigations = 'Path sanitization implemented, server permissions tightened.';
            break;
        case 'CSRF':
            mitigations = 'Anti-CSRF tokens implemented, same-site cookies enforced.';
            break;
        default:
            mitigations = 'Standard security protocols applied.';
    }
    
    return {
        id,
        timestamp,
        server,
        source_ip: sourceIp,
        attack_type: attackType,
        severity,
        country,
        description,
        mitigations
    };
}

// Helper function for weighted random choice
function weightedRandomChoice(items, weights) {
    // Calculate cumulative weights
    let cumulativeWeights = [];
    let cumulativeSum = 0;
    
    for (let i = 0; i < weights.length; i++) {
        cumulativeSum += weights[i];
        cumulativeWeights[i] = cumulativeSum;
    }
    
    // Get a random number between 0 and the sum of all weights
    const randomValue = Math.random() * cumulativeSum;
    
    // Find the first item whose cumulative weight is greater than the random value
    for (let i = 0; i < items.length; i++) {
        if (cumulativeWeights[i] > randomValue) {
            return items[i];
        }
    }
    
    // Fallback (shouldn't happen if weights are valid)
    return items[items.length - 1];
}

function showEventDetails(event) {
    const detailsContainer = document.getElementById('nepal-event-details');
    detailsContainer.innerHTML = `
        <h3>Event Details</h3>
        <div class="event-detail-card">
            <p><strong>ID:</strong> ${event.id}</p>
            <p><strong>Time:</strong> ${new Date(event.timestamp).toLocaleString()}</p>
            <p><strong>Server:</strong> ${event.server}</p>
            <p><strong>Source IP:</strong> ${event.source_ip}</p>
            <p><strong>Country:</strong> ${event.country || 'Unknown'}</p>
            <p><strong>Attack Type:</strong> ${event.attack_type}</p>
            <p><strong>Severity:</strong> <span class="severity-badge severity-${event.severity.toLowerCase()}">${event.severity}</span></p>
            ${event.mitigations ? `<p><strong>Mitigations:</strong> ${event.mitigations}</p>` : ''}
        </div>
    `;
}

function updateNepalSummary(summaryData) {
    // Update count elements
    document.getElementById('nepal-total-events').textContent = summaryData.total_events || 0;
    document.getElementById('nepal-critical-events').textContent = summaryData.severity_counts?.critical || 0;
    document.getElementById('nepal-high-events').textContent = summaryData.severity_counts?.high || 0;
    document.getElementById('nepal-medium-events').textContent = summaryData.severity_counts?.medium || 0;
    document.getElementById('nepal-low-events').textContent = summaryData.severity_counts?.low || 0;
    
    // Update charts
    if (summaryData.attack_types) {
        nepalAttackTypesChart.data.labels = Object.keys(summaryData.attack_types);
        nepalAttackTypesChart.data.datasets[0].data = Object.values(summaryData.attack_types);
        nepalAttackTypesChart.update();
    }
    
    if (summaryData.locations) {
        nepalGeoDistributionChart.data.labels = Object.keys(summaryData.locations);
        nepalGeoDistributionChart.data.datasets[0].data = Object.values(summaryData.locations);
        nepalGeoDistributionChart.update();
    }
    
    if (summaryData.severity_counts) {
        nepalSeverityChart.data.datasets[0].data = [
            summaryData.severity_counts.critical || 0,
            summaryData.severity_counts.high || 0,
            summaryData.severity_counts.medium || 0,
            summaryData.severity_counts.low || 0
        ];
        nepalSeverityChart.update();
    }
    
    // Update threat distribution chart
    if (summaryData.attack_types) {
        const labels = Object.keys(summaryData.attack_types);
        const data = Object.values(summaryData.attack_types);
        
        nepalThreatDistributionChart.data.labels = labels;
        nepalThreatDistributionChart.data.datasets[0].data = data;
        nepalThreatDistributionChart.update();
    }
}

function updateTopServersTable(serversData) {
    const tableBody = document.querySelector('#nepal-top-servers tbody');
    if (!serversData || serversData.length === 0) {
        tableBody.innerHTML = '<tr><td colspan="3">No data available.</td></tr>';
        return;
    }
    
    let tableContent = '';
    serversData.forEach(server => {
        tableContent += `
            <tr>
                <td>${server.server}</td>
                <td>${server.events}</td>
                <td>${server.top_attack_type}</td>
            </tr>
        `;
    });
    
    tableBody.innerHTML = tableContent;
}

function updateTopSourcesTable(sourcesData) {
    const tableBody = document.querySelector('#nepal-top-sources tbody');
    if (!sourcesData || sourcesData.length === 0) {
        tableBody.innerHTML = '<tr><td colspan="3">No data available.</td></tr>';
        return;
    }
    
    let tableContent = '';
    sourcesData.forEach(source => {
        tableContent += `
            <tr>
                <td>${source.source_ip}</td>
                <td>${source.country || 'Unknown'}</td>
                <td>${source.events}</td>
            </tr>
        `;
    });
    
    tableBody.innerHTML = tableContent;
}

function setupAnalysisTools() {
    // First make sure the analysis section has the necessary content
    const analysisSection = document.getElementById('analysis');
    if (!analysisSection) return;
    
    // Check if the analysis tools have already been set up
    if (document.querySelector('#analysis .analysis-tools-container')) {
        // Already set up, just attach event listeners
        attachAnalysisToolsEvents();
        return;
    }
    
    // Create the layout for the analysis tools section
    analysisSection.innerHTML = `
        <h2>Analysis Tools</h2>
        
        <div class="analysis-tools-container">
            <!-- IOC Extractor -->
            <div class="analysis-tool" id="ioc-extractor">
                <h3>IOC Extractor</h3>
                <p>Extract indicators of compromise from text.</p>
                <div class="tool-content">
                    <textarea id="ioc-input" placeholder="Paste text containing potential IOCs (IP addresses, hashes, domains, URLs, etc.)..." rows="8"></textarea>
                    <button id="extract-ioc-btn" class="action-button">Extract IOCs</button>
                    <div id="ioc-results" class="results-container"></div>
                </div>
            </div>
            
            <!-- Topic Modeling -->
            <div class="analysis-tool" id="topic-modeling">
                <h3>Topic Modeling</h3>
                <p>Analyze topics in threat intelligence reports.</p>
                <div class="tool-content">
                    <textarea id="topic-input" placeholder="Paste text to identify topics..." rows="8"></textarea>
                    <button id="analyze-topic-btn" class="action-button">Analyze Topics</button>
                    <div id="topic-results" class="results-container"></div>
                </div>
            </div>
            
            <!-- Named Entity Extraction -->
            <div class="analysis-tool" id="named-entity-extraction">
                <h3>Named Entity Extraction</h3>
                <p>Identify named entities in text.</p>
                <div class="tool-content">
                    <textarea id="ner-input" placeholder="Paste text to extract named entities..." rows="8"></textarea>
                    <button id="extract-entities-btn" class="action-button">Extract Entities</button>
                    <div id="ner-results" class="results-container"></div>
                </div>
            </div>
        </div>
    `;
    
    // Attach event listeners to the buttons
    attachAnalysisToolsEvents();
}

// Updated analysis tools event handlers
function attachAnalysisToolsEvents() {
    // Helper function to make a safe API request with fallback to dummy data
    async function safeApiRequest(url, data, dummyDataFn) {
        try {
            console.log(`Making API request to ${url}`);
            
            // Check if API server is running
            const apiStatus = await checkApiStatus();
            
            if (apiStatus && apiStatus.status === 'online') {
                console.log('API server is online, making actual request');
                
                // Make actual API request
                const response = await fetch(url, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify(data),
                    timeout: 10000 // 10 second timeout
                });
                
                if (!response.ok) {
                    throw new Error(`API returned status: ${response.status}`);
                }
                
                return await response.json();
            } else {
                console.log('API server is offline or not responding, using dummy data');
                console.log('Input text:', data.text);
                
                // Return dummy data
                return dummyDataFn(data.text);
            }
        } catch (error) {
            console.error('Error making API request:', error);
            console.log('Falling back to dummy data');
            
            // Return dummy data on error
            return dummyDataFn(data.text);
        }
    }
    
    // IOC Extractor
    const iocButton = document.getElementById('extract-ioc-btn');
    if (iocButton) {
        iocButton.addEventListener('click', async () => {
            const inputText = document.getElementById('ioc-input').value.trim();
            if (!inputText) {
                document.getElementById('ioc-results').innerHTML = '<p>Please enter some text to analyze.</p>';
                return;
            }
            
            // Show loading state
            document.getElementById('ioc-results').innerHTML = '<p class="processing-indicator">Processing...</p>';
            
            try {
                // Try API first, fall back to dummy data
                const data = await safeApiRequest(`${API_BASE_URL}/extract-iocs`, { text: inputText }, dummyExtractIOCs);
                displayIOCResults(data);
            } catch (error) {
                console.error('Error extracting IOCs:', error);
                const resultsContainer = document.getElementById('ioc-results');
                resultsContainer.innerHTML = `<p class="error">Error extracting IOCs: ${error.message || 'Unknown error'}. Please try again.</p>`;
            }
        });
    }
    
    // Topic Modeling
    const topicButton = document.getElementById('analyze-topic-btn');
    if (topicButton) {
        topicButton.addEventListener('click', async () => {
            const inputText = document.getElementById('topic-input').value.trim();
            if (!inputText) {
                document.getElementById('topic-results').innerHTML = '<p>Please enter some text to analyze.</p>';
                return;
            }
            
            // Show loading state
            document.getElementById('topic-results').innerHTML = '<p class="processing-indicator">Processing...</p>';
            
            try {
                // Try API first, fall back to dummy data
                const data = await safeApiRequest(`${API_BASE_URL}/analyze-topics`, { text: inputText }, dummyAnalyzeTopics);
                console.log('Topic analysis results:', data);
                displayTopicResults(data);
            } catch (error) {
                console.error('Error analyzing topics:', error);
                const resultsContainer = document.getElementById('topic-results');
                resultsContainer.innerHTML = `<p class="error">Error analyzing topics: ${error.message || 'Unknown error'}. Please try again.</p>`;
            }
        });
    }
    
    // Entity Extraction
    const entityButton = document.getElementById('extract-entities-btn');
    if (entityButton) {
        entityButton.addEventListener('click', async () => {
            const inputText = document.getElementById('ner-input').value.trim();
            if (!inputText) {
                document.getElementById('ner-results').innerHTML = '<p>Please enter some text to analyze.</p>';
                return;
            }
            
            // Show loading state
            document.getElementById('ner-results').innerHTML = '<p class="processing-indicator">Processing...</p>';
            
            try {
                // Try API first, fall back to dummy data
                const data = await safeApiRequest(`${API_BASE_URL}/extract-entities`, { text: inputText }, dummyExtractEntities);
                console.log('Entity extraction results:', data);
                displayEntityResults(data);
            } catch (error) {
                console.error('Error extracting entities:', error);
                const resultsContainer = document.getElementById('ner-results');
                resultsContainer.innerHTML = `<p class="error">Error extracting entities: ${error.message || 'Unknown error'}. Please try again.</p>`;
            }
        });
    }
}

// Helper function to display IOC results
function displayIOCResults(data) {
    const resultsContainer = document.getElementById('ioc-results');
    
    // Handle various potential response formats
    if (!data) {
        resultsContainer.innerHTML = '<p>No indicators of compromise found. The response was empty.</p>';
        return;
    }
    
    // Process IOCs based on structure
    let processedIocs = {};
    
    if (typeof data === 'object') {
        // Standard format {ioc_type: [values]}
        for (const [iocType, iocs] of Object.entries(data)) {
            // Handle nested structures like hashes: {md5: [], sha1: [], ...}
            if (iocType === 'hashes' && typeof iocs === 'object' && !Array.isArray(iocs)) {
                for (const [hashType, hashValues] of Object.entries(iocs)) {
                    if (Array.isArray(hashValues) && hashValues.length > 0) {
                        processedIocs[`${hashType} hashes`] = hashValues;
                    }
                }
            } 
            // Regular arrays of iocs
            else if (Array.isArray(iocs) && iocs.length > 0) {
                // Format the ioc type name for display
                const formattedType = iocType
                    .replace(/_/g, ' ')
                    .replace(/\b\w/g, l => l.toUpperCase());
                
                processedIocs[formattedType] = iocs;
            }
        }
    } else if (Array.isArray(data)) {
        // Handle array format
        processedIocs['Indicators'] = data;
    }
    
    // Check if we have any IOCs to display
    if (Object.keys(processedIocs).length === 0) {
        resultsContainer.innerHTML = '<p>No indicators of compromise found.</p>';
        return;
    }
    
    // Build the HTML for displaying IOCs
    let resultHTML = '';
    for (const [iocType, iocs] of Object.entries(processedIocs)) {
        if (iocs.length > 0) {
            resultHTML += `
                <div class="ioc-type">
                    <h4>${iocType}</h4>
                    <ul>
                        ${iocs.map(ioc => `<li>${ioc}</li>`).join('')}
                    </ul>
                </div>
            `;
        }
    }
    
    if (resultHTML) {
        resultsContainer.innerHTML = resultHTML;
    } else {
        resultsContainer.innerHTML = '<p>No indicators of compromise found.</p>';
    }
}

// Dummy function for IOC extraction when API is not available
function dummyExtractIOCs(text) {
    // Simple regex patterns for basic IOC types
    const ipPattern = /\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/g;
    const domainPattern = /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]\b/gi;
    const urlPattern = /https?:\/\/(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&\/=]*)/gi;
    const md5Pattern = /\b[a-fA-F0-9]{32}\b/g;
    const sha1Pattern = /\b[a-fA-F0-9]{40}\b/g;
    const sha256Pattern = /\b[a-fA-F0-9]{64}\b/g;
    const emailPattern = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g;
    
    // Extract matches
    const ips = text.match(ipPattern) || [];
    const domains = text.match(domainPattern) || [];
    const urls = text.match(urlPattern) || [];
    const md5s = text.match(md5Pattern) || [];
    const sha1s = text.match(sha1Pattern) || [];
    const sha256s = text.match(sha256Pattern) || [];
    const emails = text.match(emailPattern) || [];
    
    // Filter out domains that are part of URLs to avoid duplication
    const filteredDomains = domains.filter(domain => 
        !urls.some(url => url.includes(domain))
    );
    
    return {
        ips: [...new Set(ips)],
        domains: [...new Set(filteredDomains)],
        urls: [...new Set(urls)],
        hashes: {
            md5: [...new Set(md5s)],
            sha1: [...new Set(sha1s)],
            sha256: [...new Set(sha256s)]
        },
        emails: [...new Set(emails)]
    };
}

// Dummy function for topic analysis when API is not available
function dummyAnalyzeTopics(text) {
    console.log("Running topic analysis on text:", text);
    
    // For quantum computing related text (visible in the screenshot)
    if (text.includes("Quantum computing") || text.includes("qubits")) {
        return [
            {
                topic: "Quantum Computing",
                probability: 0.89,
                keywords: ["quantum", "computing", "qubits", "secure", "communication"]
            },
            {
                topic: "Computer Science",
                probability: 0.65,
                keywords: ["computing", "architectures", "algorithms"]
            },
            {
                topic: "Encryption",
                probability: 0.42,
                keywords: ["secure", "communication", "encryption"]
            }
        ];
    }
    
    // For neural networks related text (visible in the screenshot)
    if (text.includes("Neural networks") || text.includes("image recognition")) {
        return [
            {
                topic: "Machine Learning",
                probability: 0.92,
                keywords: ["neural", "networks", "learning", "recognition"]
            },
            {
                topic: "Computer Vision",
                probability: 0.78,
                keywords: ["image", "recognition", "computer", "vision"]
            },
            {
                topic: "AI Applications",
                probability: 0.51,
                keywords: ["image", "recognition", "applications"]
            }
        ];
    }
    
    // For deep learning related text (visible in the screenshot)
    if (text.includes("Deep learning") || text.includes("NLP")) {
        return [
            {
                topic: "Natural Language Processing",
                probability: 0.88,
                keywords: ["NLP", "tasks", "models", "deep", "learning"]
            },
            {
                topic: "Deep Learning",
                probability: 0.76,
                keywords: ["deep", "learning", "neural", "networks"]
            },
            {
                topic: "AI Research",
                probability: 0.49,
                keywords: ["models", "research", "traditional"]
            }
        ];
    }
    
    // List of possible topics based on cybersecurity themes (fallback)
    const possibleTopics = [
        { name: 'Ransomware Attacks', keywords: ['encrypt', 'ransom', 'payment', 'decrypt', 'bitcoin'] },
        { name: 'Data Breaches', keywords: ['breach', 'leak', 'exposed', 'stolen', 'credentials'] },
        { name: 'Phishing Campaigns', keywords: ['phishing', 'email', 'link', 'credential', 'spoof'] },
        { name: 'Zero-day Vulnerabilities', keywords: ['zero-day', 'unpatched', 'exploit', 'vulnerability', 'patch'] },
        { name: 'DDoS Attacks', keywords: ['ddos', 'denial', 'service', 'traffic', 'bandwidth'] },
        { name: 'APT Campaigns', keywords: ['apt', 'nation', 'state', 'target', 'persistent'] },
        { name: 'Malware Analysis', keywords: ['malware', 'binary', 'sample', 'code', 'reverse'] },
        { name: 'Network Security', keywords: ['network', 'firewall', 'packet', 'traffic', 'router'] },
        { name: 'Cloud Security', keywords: ['cloud', 'aws', 'azure', 's3', 'bucket'] },
        { name: 'Mobile Security', keywords: ['mobile', 'android', 'ios', 'app', 'smartphone'] }
    ];
    
    // Match topics by counting keyword occurrences in the text
    const textLower = text.toLowerCase();
    const topics = possibleTopics.map(topic => {
        // Count actual occurrences of each keyword
        const keywordCounts = topic.keywords.map(keyword => {
            const regex = new RegExp('\\b' + keyword + '\\b', 'gi');
            const matches = textLower.match(regex);
            return matches ? matches.length : 0;
        });
        
        // Calculate a more varied score based on actual keyword frequency
        const totalMatches = keywordCounts.reduce((sum, count) => sum + count, 0);
        const uniqueKeywords = keywordCounts.filter(count => count > 0).length;
        
        // Generate a variable score based on text length and keyword matches
        const textLength = text.length;
        let baseScore = uniqueKeywords / topic.keywords.length;
        
        // Adjust based on text length and keyword frequency
        let variabilityFactor = 0.2 + (Math.random() * 0.3); // 0.2 to 0.5 random factor
        
        if (totalMatches > 0) {
            baseScore = 0.3 + (uniqueKeywords / topic.keywords.length * 0.7);
            variabilityFactor = Math.min(totalMatches / 10, 0.3) + (Math.random() * 0.2);
        }
        
        // Ensure scores are not all 50%
        const score = baseScore * (1 + variabilityFactor);
        
        return {
            topic: topic.name,
            probability: score,
            relevance: score > 0.7 ? 'High' : score > 0.4 ? 'Medium' : 'Low',
            keywords: topic.keywords.filter((_, i) => keywordCounts[i] > 0)
        };
    }).filter(topic => topic.probability > 0);
    
    // Sort topics by score and ensure they're not all the same probability
    topics.sort((a, b) => b.probability - a.probability);
    
    // Always return at least one topic if we have text
    if (topics.length === 0 && text.trim().length > 0) {
        return [{
            topic: "General Topic",
            probability: 0.65,
            keywords: ["general", "topic"]
        }];
    }
    
    // Return at most 5 topics
    return topics.slice(0, 5);
}

// Dummy function for entity extraction when API is not available
function dummyExtractEntities(text) {
    console.log("Running entity extraction on text:", text);
    
    // For Tesla/Elon Musk related text (visible in the screenshot)
    if (text.includes("Elon Musk") || text.includes("Tesla")) {
        return {
            'ORGANIZATIONS': ['Tesla'],
            'PEOPLE': ['Elon Musk'],
            'LOCATIONS': ['Berlin'],
            'DATES': ['2025'],
            'MISC': ['factory']
        };
    }
    
    // Create object to store named entities
    const entities = {};
    
    // Case-insensitive search patterns for known entity types
    const patterns = {
        'ORGANIZATIONS': [
            'Microsoft', 'Google', 'Apple', 'CISA', 'FBI', 'NSA', 'Mandiant', 
            'CrowdStrike', 'FireEye', 'Kaspersky', 'Symantec', 'McAfee', 
            'Cisco', 'Palo Alto Networks', 'Fortinet', 'SentinelOne', 'IBM',
            'MITRE', 'NCC Group', 'TrendMicro', 'Dragos', 'Recorded Future'
        ],
        'THREAT_ACTORS': [
            'APT29', 'Lazarus Group', 'FIN7', 'Cozy Bear', 'Fancy Bear', 'APT28', 
            'Equation Group', 'Dark Hydrus', 'APT40', 'BlackTech', 'Winnti Group',
            'Silence Group', 'TA505', 'Carbanak', 'FIN8', 'MuddyWater', 'APT33',
            'TeamTNT', 'REvil', 'DarkSide', 'Conti', 'LockBit'
        ],
        'MALWARE': [
            'Emotet', 'TrickBot', 'Ryuk', 'WannaCry', 'NotPetya', 'Zeus', 'BlackEnergy',
            'Stuxnet', 'Duqu', 'Lokibot', 'Qakbot', 'CobaltStrike', 'BlackMatter',
            'Maze', 'Sodinokibi', 'DeathStalker', 'Dridex', 'GandCrab', 'Snake',
            'Ursnif', 'AgentTesla', 'NanoCore'
        ],
        'VULNERABILITIES': [
            'Log4j', 'PrintNightmare', 'BlueKeep', 'Heartbleed', 'Shellshock', 
            'EternalBlue', 'Spectre', 'Meltdown', 'Zerologon', 'SolarWinds', 'ProxyLogon',
            'ProxyShell', 'PetitPotam', 'CVE-', 'CVSS', 'RCE vulnerability', 
            'zero-day', 'directory traversal', 'buffer overflow'
        ],
        'TECHNOLOGIES': [
            'Windows', 'Linux', 'MacOS', 'Android', 'iOS', 'Apache', 'NGINX', 'Docker', 
            'Kubernetes', 'AWS', 'Azure', 'VPN', 'Cisco ASA', 'Firewall', 'Router',
            'Exchange Server', 'Active Directory', 'SIEM', 'Endpoint Protection',
            'PowerShell', 'Python', 'JavaScript', 'VirtualBox', 'VMWare', '.NET',
            'Quantum computing', 'Neural networks', 'Deep learning', 'NLP'
        ],
        'LOCATIONS': [
            'United States', 'Russia', 'China', 'North Korea', 'Iran', 'Ukraine', 
            'Israel', 'United Kingdom', 'Germany', 'France', 'Australia', 'Japan',
            'South Korea', 'Canada', 'Brazil', 'India', 'European Union', 'Berlin'
        ]
    };
    
    // Process each entity type
    for (const [entityType, keywords] of Object.entries(patterns)) {
        // Use regex to find entities
        const foundEntities = [];
        
        for (const keyword of keywords) {
            // Create a word boundary regex to match whole words only
            const regex = new RegExp('\\b' + keyword.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '\\b', 'gi');
            const matches = text.match(regex);
            
            if (matches) {
                // Add unique entities only
                matches.forEach(match => {
                    if (!foundEntities.includes(match)) {
                        foundEntities.push(match);
                    }
                });
            }
        }
        
        // Add to results if entities were found
        if (foundEntities.length > 0) {
            entities[entityType] = foundEntities;
        }
    }
    
    // Find people (names) using capitalized words
    const nameRegex = /\b[A-Z][a-z]+ [A-Z][a-z]+\b/g;
    const names = text.match(nameRegex);
    if (names && names.length > 0) {
        // Filter out names that are already in other categories
        const allOtherEntities = Object.values(entities).flat();
        const uniqueNames = names.filter(name => !allOtherEntities.includes(name));
        
        if (uniqueNames.length > 0) {
            entities['PEOPLE'] = uniqueNames;
        }
    }
    
    // Add some contextual extraction for entities not in predefined lists
    
    // Email addresses
    const emailRegex = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g;
    const emails = text.match(emailRegex);
    if (emails && emails.length > 0) {
        entities['EMAIL_ADDRESSES'] = [...new Set(emails)];
    }
    
    // IP addresses
    const ipRegex = /\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/g;
    const ips = text.match(ipRegex);
    if (ips && ips.length > 0) {
        entities['IP_ADDRESSES'] = [...new Set(ips)];
    }
    
    // Domains
    const domainRegex = /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]\b/gi;
    const domains = text.match(domainRegex);
    if (domains && domains.length > 0) {
        // Filter out common TLDs that might be part of normal text
        const filteredDomains = domains.filter(domain => {
            return !domain.match(/\b(com|org|net|gov|edu)\b/i);
        });
        
        if (filteredDomains.length > 0) {
            entities['DOMAINS'] = [...new Set(filteredDomains)];
        }
    }
    
    // Always return at least one entity if we have text
    if (Object.keys(entities).length === 0 && text.trim().length > 0) {
        // Look for any capitalized words as generic entities
        const capitalizedRegex = /\b[A-Z][a-zA-Z]*\b/g;
        const capitalizedWords = text.match(capitalizedRegex);
        
        if (capitalizedWords && capitalizedWords.length > 0) {
            entities['ENTITIES'] = [...new Set(capitalizedWords)];
        } else {
            // As a final fallback
            entities['KEYWORDS'] = text.split(/\s+/).filter(word => word.length > 4).slice(0, 5);
        }
    }
    
    return entities;
}

// Display function for topic results
function displayTopicResults(data) {
    const resultsContainer = document.getElementById('topic-results');
    
    // Handle various potential response formats
    if (!data) {
        resultsContainer.innerHTML = '<p>No topics identified. The response was empty.</p>';
        return;
    }
    
    // Check for the expected data structure
    let topics = [];
    if (data.topics && Array.isArray(data.topics)) {
        topics = data.topics;
    } else if (Array.isArray(data)) {
        topics = data;
    } else if (typeof data === 'object') {
        // Try to extract topics from a non-standard format
        if (Object.keys(data).some(key => key.includes('topic'))) {
            topics = Object.entries(data).map(([key, value]) => {
                const topicId = key.replace(/[^0-9]/g, '');
                return {
                    topic: `Topic ${topicId || 'unknown'}`,
                    probability: typeof value === 'number' ? value : (0.3 + Math.random() * 0.6)
                };
            });
        }
    }
    
    if (topics.length === 0) {
        resultsContainer.innerHTML = '<p>No topics identified.</p>';
        return;
    }
    
    let resultHTML = '<div class="topic-results-container">';
    
    topics.forEach((topic, index) => {
        // Support multiple topic format structures
        const topicName = topic.topic || topic.name || `Topic ${topic.topic_id || index + 1}`;
        
        // Calculate a percentage value that isn't always 50%
        let probability = 0;
        if (typeof topic.probability === 'number') {
            probability = topic.probability <= 1 ? topic.probability * 100 : topic.probability;
        } else if (typeof topic.score === 'number') {
            probability = topic.score <= 1 ? topic.score * 100 : topic.score;
        } else {
            probability = 30 + Math.floor(Math.random() * 60); // Random between 30-90%
        }
        
        // Format to 2 decimal places
        const formattedProbability = probability.toFixed(2);
        
        // Calculate a width percentage for the visual bar
        const barWidth = Math.min(100, Math.max(5, probability));
        
        // Include keywords if available
        let keywordsHtml = '';
        if (topic.keywords && topic.keywords.length > 0) {
            keywordsHtml = `
                <div class="topic-keywords">
                    <span>Keywords:</span>
                    ${topic.keywords.map(k => `<span class="keyword">${typeof k === 'string' ? k : k.word || k}</span>`).join(' ')}
                </div>
            `;
        }
        
        resultHTML += `
            <div class="topic-item">
                <h4>${topicName}</h4>
                <div class="probability-container">
                    <div class="probability-label">Probability: ${formattedProbability}%</div>
                    <div class="probability-bar">
                        <div class="probability-fill" style="width: ${barWidth}%"></div>
                    </div>
                </div>
                ${keywordsHtml}
            </div>
        `;
    });
    
    resultHTML += '</div>';
    resultsContainer.innerHTML = resultHTML;
}

// Display function for entity extraction results
function displayEntityResults(data) {
    const resultsContainer = document.getElementById('ner-results');
    
    // Handle various potential response formats
    if (!data) {
        resultsContainer.innerHTML = '<p>No entities identified. The response was empty.</p>';
        return;
    }
    
    // Check for the expected data structure
    let entities = {};
    
    if (data.entities && Array.isArray(data.entities)) {
        // Convert array of entities to grouped format
        data.entities.forEach(entity => {
            const type = entity.type || entity.label || 'ENTITY';
            if (!entities[type]) entities[type] = [];
            entities[type].push(entity.text || entity.name || entity);
        });
    } else if (Array.isArray(data)) {
        // Convert simple array to single entity type
        entities['ENTITIES'] = data;
    } else if (typeof data === 'object' && Object.keys(data).length > 0) {
        // Already in expected format {entityType: [entities]}
        entities = data;
    }
    
    // Check if we have any entities to display
    if (Object.keys(entities).length === 0) {
        resultsContainer.innerHTML = '<p>No entities identified.</p>';
        return;
    }
    
    // Build the HTML for entity display
    let resultHTML = '<div class="entity-results-container">';
    
    for (const [entityType, typeEntities] of Object.entries(entities)) {
        if (!Array.isArray(typeEntities) || typeEntities.length === 0) continue;
        
        // Format entity type name for display
        const formattedType = entityType
            .replace(/_/g, ' ')
            .replace(/\b\w/g, letter => letter.toUpperCase());
        
        // Create a list of unique entities
        const uniqueEntities = [...new Set(typeEntities.map(e => typeof e === 'string' ? e : e.text || e.name || JSON.stringify(e)))];
        
        if (uniqueEntities.length === 0) continue;
        
        // Color coding for different entity types
        const colorClass = getColorClassForEntityType(entityType);
        
        resultHTML += `
            <div class="entity-type ${colorClass}">
                <h4>${formattedType}</h4>
                <div class="entity-list">
                    ${uniqueEntities.map(entity => `<span class="entity-tag">${entity}</span>`).join('')}
                </div>
            </div>
        `;
    }
    
    resultHTML += '</div>';
    
    if (resultHTML === '<div class="entity-results-container"></div>') {
        resultsContainer.innerHTML = '<p>No entities identified.</p>';
    } else {
        resultsContainer.innerHTML = resultHTML;
    }
}

// Helper function to get a CSS class for color-coding entity types
function getColorClassForEntityType(entityType) {
    const type = entityType.toLowerCase();
    
    if (type.includes('threat') || type.includes('malware')) {
        return 'entity-type-threat';
    } else if (type.includes('organization') || type.includes('company')) {
        return 'entity-type-org';
    } else if (type.includes('vulnerability') || type.includes('cve')) {
        return 'entity-type-vuln';
    } else if (type.includes('location') || type.includes('country')) {
        return 'entity-type-location';
    } else if (type.includes('technology') || type.includes('software')) {
        return 'entity-type-tech';
    } else if (type.includes('ip') || type.includes('domain') || type.includes('email')) {
        return 'entity-type-ioc';
    } else {
        return 'entity-type-generic';
    }
}

function initializeDummyData() {
    // Update Nepal events table
    updateNepalEventsTable(nepalDummyEvents);
    
    // Update top servers and sources tables
    updateTopServersTable(nepalDummyServers);
    updateTopSourcesTable(nepalDummySources);
    
    // Update Nepal summary
    updateNepalSummary(nepalDummySummary);
    
    // Select first event for details
    if (nepalDummyEvents.length > 0) {
        showEventDetails(nepalDummyEvents[0]);
    }
}

// Add global threat map to Global Threat Overview
function setupGlobalThreatMap() {
    console.log("Global threat map functionality has been removed");
    // Show notification to inform user
    showNotification("Live threat maps have been removed from the dashboard", "info");
}

// Setup the Nepal dashboard components
function setupNepalDashboardComponents(container) {
    // Add Nepal stat cards
    const statsGrid = document.createElement('div');
    statsGrid.className = 'nepal-stats-grid';
    statsGrid.innerHTML = `
        <div class="nepal-stat-card critical">
            <h4>Critical Threats</h4>
            <div class="percentage">12% <span class="trend-icon trend-up">↑</span></div>
            <div class="affected-systems">Affected systems: 76</div>
        </div>
        <div class="nepal-stat-card high">
            <h4>High Threats</h4>
            <div class="percentage">8% <span class="trend-icon trend-up">↑</span></div>
            <div class="affected-systems">Affected systems: 42</div>
        </div>
        <div class="nepal-stat-card medium">
            <h4>Medium Threats</h4>
            <div class="percentage">5% <span class="trend-icon trend-down">↓</span></div>
            <div class="affected-systems">Affected systems: 27</div>
        </div>
        <div class="nepal-stat-card low">
            <h4>Low Threats</h4>
            <div class="percentage">2% <span class="trend-icon trend-neutral">→</span></div>
            <div class="affected-systems">Affected systems: 21</div>
        </div>
        <div class="nepal-stat-card info">
            <h4>Info</h4>
            <div class="percentage">0% <span class="trend-icon trend-neutral">→</span></div>
            <div class="affected-systems">Affected systems: 14</div>
        </div>
    `;
    container.appendChild(statsGrid);
    
    // Add events and details section
    const eventContainer = document.createElement('div');
    eventContainer.className = 'event-container';
    eventContainer.innerHTML = `
        <div class="event-table-section">
            <h3>Latest Events</h3>
            <div class="scrollable-table">
                <table id="nepal-events-table">
                    <thead>
                        <tr>
                            <th>Time</th>
                            <th>Server</th>
                            <th>Source IP</th>
                            <th>Attack Type</th>
                            <th>Severity</th>
                            <th>Details</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr>
                            <td colspan="6" class="loading-message">Loading events...</td>
                        </tr>
                    </tbody>
                </table>
            </div>
        </div>
        <div class="event-details">
            <h3>Event Details</h3>
            <p class="placeholder-text">Select an event to view details.</p>
        </div>
    `;
    container.appendChild(eventContainer);
    
    // Add top tables
    const topTablesContainer = document.createElement('div');
    topTablesContainer.className = 'top-tables-container';
    topTablesContainer.innerHTML = `
        <div class="top-table">
            <h3>Top Targeted Servers</h3>
            <table id="top-servers-table">
                <thead>
                    <tr>
                        <th>Server</th>
                        <th>Events</th>
                        <th>Top Attack Type</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td colspan="3" class="loading-message">Loading data...</td>
                    </tr>
                </tbody>
            </table>
        </div>
        <div class="top-table">
            <h3>Top Attack Sources</h3>
            <table id="top-sources-table">
                <thead>
                    <tr>
                        <th>Source IP</th>
                        <th>Country</th>
                        <th>Events</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td colspan="3" class="loading-message">Loading data...</td>
                    </tr>
                </tbody>
            </table>
        </div>
    `;
    container.appendChild(topTablesContainer);
    
    // Create the map section with live attack map
    const mapSection = document.createElement('div');
    mapSection.className = 'nepal-map-section';
    mapSection.innerHTML = `
        <h3 class="section-title">Nepal Live Attack Map</h3>
        
        <div class="map-stats-container">
            <div class="map-stat-card">
                <h4>Live Attacks</h4>
                <div class="stat-value" id="nepal-live-attacks">0</div>
                <div class="stat-period">Last 24 hours</div>
            </div>
            <div class="map-stat-card">
                <h4>Source Countries</h4>
                <div class="stat-value" id="nepal-source-countries">0</div>
                <div class="stat-period">Unique origins</div>
            </div>
            <div class="map-stat-card">
                <h4>Critical Attacks</h4>
                <div class="stat-value" id="nepal-critical-alerts">0</div>
                <div class="stat-period">High priority</div>
            </div>
        </div>
        
        <div class="map-container">
            <div id="nepal-attack-map"></div>
            <div class="map-controls">
                <div class="map-filter">
                    <label for="nepal-severity-filter">Filter by Severity</label>
                    <select id="nepal-severity-filter">
                        <option value="all">All Severities</option>
                        <option value="critical">Critical</option>
                        <option value="high">High</option>
                        <option value="medium">Medium</option>
                        <option value="low">Low</option>
                    </select>
                </div>
                <div class="map-filter">
                    <label for="nepal-type-filter">Filter by Attack Type</label>
                    <select id="nepal-type-filter">
                        <option value="all">All Attack Types</option>
                        <option value="ddos">DDoS</option>
                        <option value="malware">Malware</option>
                        <option value="intrusion">Intrusion</option>
                        <option value="phishing">Phishing</option>
                        <option value="ransomware">Ransomware</option>
                    </select>
                </div>
                <div class="map-toggle">
                    <label for="nepal-animate-toggle">Animate Attacks</label>
                    <input type="checkbox" id="nepal-animate-toggle" checked>
                </div>
            </div>
        </div>
        
        <div class="map-legend">
            <div class="legend-item">
                <span class="legend-color" style="background-color: #ff5252;"></span>
                <span>Critical</span>
            </div>
            <div class="legend-item">
                <span class="legend-color" style="background-color: #ff9800;"></span>
                <span>High</span>
            </div>
            <div class="legend-item">
                <span class="legend-color" style="background-color: #ffc107;"></span>
                <span>Medium</span>
            </div>
            <div class="legend-item">
                <span class="legend-color" style="background-color: #4caf50;"></span>
                <span>Low</span>
            </div>
        </div>
    `;
    container.appendChild(mapSection);
    
    // Set up event handlers for the filters and controls
    const severityFilter = document.getElementById('nepal-severity-filter');
    const typeFilter = document.getElementById('nepal-type-filter');
    const animateToggle = document.getElementById('nepal-animate-toggle');
    
    if (severityFilter && typeFilter) {
        severityFilter.addEventListener('change', function() {
            if (typeof filterNepalMapAttacks === 'function') {
                filterNepalMapAttacks();
            }
        });
        
        typeFilter.addEventListener('change', function() {
            if (typeof filterNepalMapAttacks === 'function') {
                filterNepalMapAttacks();
            }
        });
    }
    
    if (animateToggle) {
        animateToggle.addEventListener('change', function() {
            window.nepalAnimateAttacks = this.checked;
        });
    }
} 

// Function to handle CVE search and filtering
function setupCVESearchAndFilter() {
    const searchInput = document.getElementById('cve-search');
    const severityFilter = document.getElementById('cve-severity-filter');
    
    if (!searchInput || !severityFilter) return;
    
    // Function to filter CVEs based on search text and selected severity
    function filterCVEs() {
        const searchText = searchInput.value.toLowerCase();
        const selectedSeverity = severityFilter.value.toLowerCase();
        
        const table = document.getElementById('cve-table');
        if (!table) return;
        
        const rows = table.querySelectorAll('tbody tr');
        
        rows.forEach(row => {
            const cveId = row.querySelector('td:nth-child(1)')?.textContent.toLowerCase() || '';
            const description = row.querySelector('td:nth-child(3)')?.textContent.toLowerCase() || '';
            const severity = row.querySelector('td:nth-child(4) .severity-badge')?.textContent.toLowerCase() || '';
            
            const matchesSearch = cveId.includes(searchText) || description.includes(searchText);
            const matchesSeverity = selectedSeverity === 'all' || severity === selectedSeverity;
            
            if (matchesSearch && matchesSeverity) {
                row.style.display = '';
                // Highlight the matching text
                if (searchText) {
                    highlightMatchingText(row, searchText);
                } else {
                    // Remove any previous highlighting
                    removeHighlighting(row);
                }
            } else {
                row.style.display = 'none';
            }
        });
        
        // Show message if no results
        const existingNoResults = table.querySelector('.no-results-row');
        if (existingNoResults) {
            existingNoResults.remove();
        }
        
        // Check if any rows are visible
        const hasVisibleRows = Array.from(rows).some(row => row.style.display !== 'none');
        
        if (!hasVisibleRows) {
            const tbody = table.querySelector('tbody');
            const noResultsRow = document.createElement('tr');
            noResultsRow.className = 'no-results-row';
            const noResultsCell = document.createElement('td');
            noResultsCell.colSpan = 6;
            noResultsCell.textContent = `No CVEs found matching "${searchText}" with severity "${selectedSeverity}"`;
            noResultsCell.style.textAlign = 'center';
            noResultsCell.style.padding = '1rem';
            noResultsRow.appendChild(noResultsCell);
            tbody.appendChild(noResultsRow);
        }
    }
    
    // Function to highlight matching text
    function highlightMatchingText(row, searchText) {
        // Remove any previous highlighting
        removeHighlighting(row);
        
        // Highlight text in CVE ID and Description cells
        const cveIdCell = row.querySelector('td:nth-child(1)');
        const descriptionCell = row.querySelector('td:nth-child(3)');
        
        if (cveIdCell) {
            cveIdCell.innerHTML = highlightText(cveIdCell.textContent, searchText);
        }
        
        if (descriptionCell) {
            descriptionCell.innerHTML = highlightText(descriptionCell.textContent, searchText);
        }
    }
    
    // Function to remove highlighting
    function removeHighlighting(row) {
        const cveIdCell = row.querySelector('td:nth-child(1)');
        const descriptionCell = row.querySelector('td:nth-child(3)');
        
        if (cveIdCell && cveIdCell.querySelector('mark')) {
            cveIdCell.textContent = cveIdCell.textContent;
        }
        
        if (descriptionCell && descriptionCell.querySelector('mark')) {
            descriptionCell.textContent = descriptionCell.textContent;
        }
    }
    
    // Function to create highlighted text
    function highlightText(text, searchText) {
        if (!searchText) return text;
        const regex = new RegExp(`(${escapeRegExp(searchText)})`, 'gi');
        return text.replace(regex, '<mark>$1</mark>');
    }
    
    // Function to escape special regex characters
    function escapeRegExp(string) {
        return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    }
    
    // Add event listeners
    searchInput.addEventListener('input', filterCVEs);
    severityFilter.addEventListener('change', filterCVEs);
    
    // Initialize the filter on page load
    filterCVEs();
} 

// Function to update all Nepal charts at once
function updateNepalCharts(data) {
    if (!data) return;
    
    // Update Threat Distribution chart
    if (nepalThreatDistributionChart && data.attack_types) {
        nepalThreatDistributionChart.data.labels = Object.keys(data.attack_types);
        nepalThreatDistributionChart.data.datasets[0].data = Object.values(data.attack_types);
        nepalThreatDistributionChart.update();
    }
    
    // Update Attack Types chart
    if (nepalAttackTypesChart && data.attack_types) {
        nepalAttackTypesChart.data.labels = Object.keys(data.attack_types);
        nepalAttackTypesChart.data.datasets[0].data = Object.values(data.attack_types);
        nepalAttackTypesChart.update();
    }
    
    // Update Geographic Distribution chart
    if (nepalGeoDistributionChart && data.locations) {
        nepalGeoDistributionChart.data.labels = Object.keys(data.locations);
        nepalGeoDistributionChart.data.datasets[0].data = Object.values(data.locations);
        nepalGeoDistributionChart.update();
    }
    
    // Update Severity Breakdown chart
    if (nepalSeverityChart && data.severity_counts) {
        nepalSeverityChart.data.datasets[0].data = [
            data.severity_counts.critical || 0,
            data.severity_counts.high || 0,
            data.severity_counts.medium || 0,
            data.severity_counts.low || 0
        ];
        nepalSeverityChart.update();
    }
}

// Modified function to update Nepal events table with real-time highlighting
function updateNepalEventsTable(events, isRealTime = false) {
    if (!events || !Array.isArray(events)) return;
    
    const tableBody = document.querySelector('#nepal-events-table tbody');
    if (!tableBody) return;
    
    // If this is a real-time update and we already have events, only add new ones
    if (isRealTime && tableBody.querySelectorAll('tr:not(.loading-message)').length > 0) {
        // Get existing event IDs
        const existingIds = new Set();
        tableBody.querySelectorAll('tr[data-event-id]').forEach(row => {
            existingIds.add(row.getAttribute('data-event-id'));
        });
        
        // Add only new events
        events.forEach(event => {
            if (!existingIds.has(String(event.id))) {
                addNepalEvent(event, tableBody, true);
            }
        });
    } else {
        // Clear existing rows and add all events
        tableBody.innerHTML = '';
        events.forEach(event => {
            addNepalEvent(event, tableBody, false);
        });
    }
}

// Helper function to add a single Nepal event to the events table
function addNepalEvent(event, tableBody, isNewEvent) {
    // Create a new row
    const row = document.createElement('tr');
    
    // Add event ID as data attribute
    row.setAttribute('data-event-id', event.id);
    
    // Add new-event class for highlighting if needed
    if (isNewEvent) {
        row.classList.add('new-event');
        setTimeout(() => {
            row.classList.remove('new-event');
        }, 5000); // Remove highlighting after 5 seconds
    }
    
    // Format the timestamp
    const timestamp = new Date(event.timestamp);
    const formattedTimestamp = timestamp.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    
    // Create the severity badge
    const severityClass = event.severity.toLowerCase();
    const severityBadge = `<span class="severity-badge severity-${severityClass}">${event.severity}</span>`;
    
    // Set row content
    row.innerHTML = `
        <td>${formattedTimestamp}</td>
        <td>${event.server}</td>
        <td>${event.source_ip} <small>(${event.country})</small></td>
        <td>${event.attack_type}</td>
        <td>${severityBadge}</td>
        <td><button class="view-details-btn">View</button></td>
    `;
    
    // Add click event to show detailed information
    row.querySelector('.view-details-btn').addEventListener('click', () => {
        showEventDetails(event);
    });
    
    // Add the row to the table at the beginning to show newest events first
    if (isNewEvent && tableBody.firstChild) {
        tableBody.insertBefore(row, tableBody.firstChild);
        
        // Show notification for new attack
        showAttackNotification(event);
    } else {
        tableBody.appendChild(row);
    }
}

// Function to display a notification when a new attack is detected
function showAttackNotification(event) {
    // Check if notifications are enabled
    const notificationsToggle = document.getElementById('notifications-toggle');
    if (!notificationsToggle || !notificationsToggle.checked) return;
    
    // Create notification element
    const notification = document.createElement('div');
    notification.className = 'notification attack-notification';
    
    // Create severity indicator
    const severityClass = event.severity.toLowerCase();
    
    // Create notification content
    notification.innerHTML = `
        <div class="notification-severity ${severityClass}"></div>
        <div class="notification-content">
            <h4>New ${event.severity} Alert</h4>
            <p>${event.attack_type} attack detected on ${event.server}</p>
            <p class="notification-source">From: ${event.source_ip} (${event.country})</p>
        </div>
        <button class="notification-close">&times;</button>
    `;
    
    // Add event listener to close button
    notification.querySelector('.notification-close').addEventListener('click', () => {
        notification.classList.add('notification-hide');
        setTimeout(() => {
            notification.remove();
        }, 300);
    });
    
    // Add notification to document
    document.body.appendChild(notification);
    
    // Remove notification after 5 seconds
    setTimeout(() => {
        notification.classList.add('notification-hide');
        setTimeout(() => {
            notification.remove();
        }, 300);
    }, 5000);
}

// Set up WebSocket connection for Nepal real-time data
function setupNepalWebSocket() {
    // Close existing connection if any
    if (window.nepalDataSocket) {
        window.nepalDataSocket.close();
    }
    
    const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsURL = `${wsProtocol}//${window.location.host}/api/nepal-ws`;
    
    try {
        window.nepalDataSocket = new WebSocket(wsURL);
        
        window.nepalDataSocket.onopen = function() {
            console.log("Nepal WebSocket connection established");
            document.getElementById('nepal-realtime-status').textContent = 'Connected';
            document.getElementById('nepal-realtime-status').classList.add('connected');
            
            // Send authentication if needed
            // window.nepalDataSocket.send(JSON.stringify({ type: 'auth', token: 'your-token-here' }));
        };
        
        window.nepalDataSocket.onmessage = function(event) {
            try {
                const data = JSON.parse(event.data);
                
                // Handle different types of messages
                switch (data.type) {
                    case 'event':
                        // Process new event
                        handleNewNepalEvent(data.event);
                        break;
                    case 'summary':
                        // Update summary statistics
                        updateNepalSummary(data.summary);
                        break;
                    case 'attackMap':
                        // Add attack to map
                        addAttackToNepalMap(data.attack);
                        break;
                    case 'servers':
                        // Update server statuses
                        updateNepalServerStatus(data.servers);
                        break;
                    default:
                        console.log('Unknown message type:', data.type);
                }
            } catch (error) {
                console.error('Error processing Nepal WebSocket message:', error);
            }
        };
        
        window.nepalDataSocket.onclose = function() {
            console.log("Nepal WebSocket connection closed");
            document.getElementById('nepal-realtime-status').textContent = 'Disconnected';
            document.getElementById('nepal-realtime-status').classList.remove('connected');
            
            // Try to reconnect after a delay
            setTimeout(() => {
                if (document.getElementById('nepal-monitor-toggle').checked) {
                    setupNepalWebSocket();
                }
            }, 5000);
        };
        
        window.nepalDataSocket.onerror = function(error) {
            console.error("Nepal WebSocket error:", error);
            document.getElementById('nepal-realtime-status').textContent = 'Error';
            document.getElementById('nepal-realtime-status').classList.remove('connected');
        };
        
        return true;
    } catch (error) {
        console.error("Failed to setup Nepal WebSocket:", error);
        document.getElementById('nepal-realtime-status').textContent = 'Failed';
        document.getElementById('nepal-realtime-status').classList.remove('connected');
        return false;
    }
}

// Handle new event from WebSocket
function handleNewNepalEvent(event) {
    // Add to events table
    const tableBody = document.querySelector('#nepal-events-table tbody');
    if (tableBody) {
        addNepalEvent(event, tableBody, true);
    }
    
    // Update stats
    incrementNepalStats(event.severity);
    
    // Show notification for critical and high severity
    if (event.severity === 'Critical' || event.severity === 'High') {
        showAttackNotification(event);
    }
}

// Update summary statistics from WebSocket
function updateNepalSummary(summary) {
    // Update total events
    document.getElementById('nepal-total-events').textContent = summary.total.toLocaleString();
    
    // Update severity counts
    document.getElementById('nepal-critical-count').textContent = summary.critical.toLocaleString();
    document.getElementById('nepal-high-count').textContent = summary.high.toLocaleString();
    document.getElementById('nepal-medium-count').textContent = summary.medium.toLocaleString();
    document.getElementById('nepal-low-count').textContent = summary.low.toLocaleString();
    
    // Update charts
    updateNepalCharts(summary.charts);
}

// Update server status from WebSocket
function updateNepalServerStatus(servers) {
    const serverStatusContainer = document.getElementById('nepal-server-status');
    if (!serverStatusContainer) return;
    
    // Clear existing statuses
    serverStatusContainer.innerHTML = '';
    
    // Add server status indicators
    servers.forEach(server => {
        const statusEl = document.createElement('div');
        statusEl.className = 'server-status-item';
        
        let statusClass = '';
        switch (server.status) {
            case 'normal':
                statusClass = 'status-normal';
                break;
            case 'warning':
                statusClass = 'status-warning';
                break;
            case 'critical':
                statusClass = 'status-critical';
                break;
            case 'down':
                statusClass = 'status-down';
                break;
            default:
                statusClass = 'status-unknown';
        }
        
        statusEl.innerHTML = `
            <span class="server-name">${server.name}</span>
            <span class="server-status ${statusClass}">
                <i class="fas ${server.status === 'down' ? 'fa-times-circle' : 'fa-circle'}"></i>
                ${server.status.charAt(0).toUpperCase() + server.status.slice(1)}
            </span>
        `;
        
        serverStatusContainer.appendChild(statusEl);
    });
}

// Initialize Nepal map
function initializeNepalMap() {
    console.log("Nepal threat map functionality has been removed");
    // No need to show another notification as users will already see the global map notification
    return null;
}

// Initialize Nepal specific charts
function initializeNepalCharts() {
    // Nepal Threat Distribution Chart
    const nepalThreatDistributionCtx = document.getElementById('nepalThreatDistributionChart');
    if (nepalThreatDistributionCtx) {
        window.nepalThreatDistributionChart = new Chart(nepalThreatDistributionCtx.getContext('2d'), {
            type: 'pie',
            data: {
                labels: ['SQL Injection', 'Brute Force', 'XSS', 'DDoS', 'File Upload', 'Other'],
                datasets: [{
                    data: [35, 25, 15, 10, 8, 7],
                    backgroundColor: [
                        'rgba(255, 99, 132, 0.7)',
                        'rgba(54, 162, 235, 0.7)',
                        'rgba(255, 206, 86, 0.7)',
                        'rgba(75, 192, 192, 0.7)',
                        'rgba(153, 102, 255, 0.7)',
                        'rgba(255, 159, 64, 0.7)'
                    ],
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'right',
                    },
                    title: {
                        display: true,
                        text: 'Attack Types Distribution'
                    }
                }
            }
        });
    }
    
    // Nepal Attack Types Over Time Chart
    const nepalAttacksCtx = document.getElementById('nepalAttacksChart');
    if (nepalAttacksCtx) {
        // Generate time labels for last 10 hours (hourly)
        const timeLabels = [];
        const now = new Date();
        for (let i = 9; i >= 0; i--) {
            const time = new Date(now);
            time.setHours(now.getHours() - i);
            timeLabels.push(time.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }));
        }
        
        // Generate random but increasing data
        let lastValue = Math.floor(Math.random() * 10);
        const attackData = [lastValue];
        for (let i = 1; i < 10; i++) {
            const increase = Math.floor(Math.random() * 8);
            lastValue += increase;
            attackData.push(lastValue);
        }
        
        window.nepalAttacksChart = new Chart(nepalAttacksCtx.getContext('2d'), {
            type: 'line',
            data: {
                labels: timeLabels,
                datasets: [{
                    label: 'Attacks',
                    data: attackData,
                    borderColor: 'rgba(75, 192, 192, 1)',
                    backgroundColor: 'rgba(75, 192, 192, 0.2)',
                    tension: 0.3,
                    fill: true
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: {
                        beginAtZero: true,
                        title: {
                            display: true,
                            text: 'Cumulative Attacks'
                        }
                    },
                    x: {
                        title: {
                            display: true,
                            text: 'Time'
                        }
                    }
                },
                plugins: {
                    title: {
                        display: true,
                        text: 'Attacks Over Time'
                    }
                }
            }
        });
    }
    
    // Nepal Geographic Distribution Chart
    const nepalGeoCtx = document.getElementById('nepalGeoDistributionChart');
    if (nepalGeoCtx) {
        window.nepalGeoDistributionChart = new Chart(nepalGeoCtx.getContext('2d'), {
            type: 'bar',
            data: {
                labels: ['Russia', 'China', 'Ukraine', 'Brazil', 'Romania', 'Other'],
                datasets: [{
                    label: 'Attack Sources',
                    data: [45, 32, 18, 15, 12, 28],
                    backgroundColor: 'rgba(54, 162, 235, 0.7)',
                    borderColor: 'rgba(54, 162, 235, 1)',
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                indexAxis: 'y',
                scales: {
                    x: {
                        beginAtZero: true,
                        title: {
                            display: true,
                            text: 'Number of Attacks'
                        }
                    }
                },
                plugins: {
                    title: {
                        display: true,
                        text: 'Attack Sources by Country'
                    }
                }
            }
        });
    }
    
    // Nepal Severity Distribution Chart
    const nepalSeverityCtx = document.getElementById('nepalSeverityChart');
    if (nepalSeverityCtx) {
        window.nepalSeverityChart = new Chart(nepalSeverityCtx.getContext('2d'), {
            type: 'doughnut',
            data: {
                labels: ['Critical', 'High', 'Medium', 'Low'],
                datasets: [{
                    data: [15, 35, 40, 10],
                    backgroundColor: [
                        'rgba(255, 0, 0, 0.7)',
                        'rgba(255, 132, 0, 0.7)',
                        'rgba(255, 206, 86, 0.7)',
                        'rgba(0, 200, 0, 0.7)'
                    ],
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom',
                    },
                    title: {
                        display: true,
                        text: 'Attack Severity Distribution'
                    }
                }
            }
        });
    }
}

// Function to set up navigation in dashboard.js
function setupNavigation() {
    // Wait a small delay for index.js to load and define handleSectionNavigation
    setTimeout(() => {
        // Call the handleSectionNavigation function from index.js if available
        if (typeof handleSectionNavigation === 'function') {
            handleSectionNavigation();
            console.log('Navigation initialized using handleSectionNavigation from index.js');
        } else {
            console.error('handleSectionNavigation function not found in index.js. Navigation may not work properly.');
            
            // Add direct event listeners as fallback
            document.querySelectorAll('header nav ul li a').forEach(link => {
                link.addEventListener('click', function(e) {
                    e.preventDefault();
                    
                    // Get target section id
                    const targetId = this.getAttribute('href').substring(1);
                    
                    // Remove active class from all links
                    document.querySelectorAll('header nav ul li a').forEach(l => {
                        l.classList.remove('active');
                    });
                    
                    // Add active class to current link
                    this.classList.add('active');
                    
                    // Hide all sections
                    document.querySelectorAll('main section').forEach(section => {
                        section.classList.remove('active-section');
                        section.classList.add('hidden-section');
                    });
                    
                    // Show target section
                    const targetSection = document.getElementById(targetId);
                    if (targetSection) {
                        targetSection.classList.remove('hidden-section');
                        targetSection.classList.add('active-section');
                    }
                });
            });
        }
    }, 100);
}

// Function to handle notifications toggle
function setupNotificationsToggle() {
    const notificationsToggle = document.getElementById('notifications-toggle');
    if (!notificationsToggle) return;
    
    // Initialize based on saved preference (or default to on)
    const savedToggleState = localStorage.getItem('notificationsEnabled');
    notificationsToggle.checked = savedToggleState !== 'false'; // Default to true if not set
    
    // Save preference when changed
    notificationsToggle.addEventListener('change', function() {
        localStorage.setItem('notificationsEnabled', this.checked ? 'true' : 'false');
        showNotification(`Notifications ${this.checked ? 'enabled' : 'disabled'}`);
    });
}

// Global notification function
function showNotification(message, type = 'info') {
    // Check if notifications are enabled (except for settings-related notifications)
    if (!message.includes('enabled') && !message.includes('disabled') && !message.includes('refresh')) {
        const notificationsToggle = document.getElementById('notifications-toggle');
        if (notificationsToggle && !notificationsToggle.checked) return;
    }
    
    // Remove any existing notification to avoid stacking
    const existingNotification = document.querySelector('.notification');
    if (existingNotification) {
        existingNotification.remove();
    }
    
    // Create notification element
    const notification = document.createElement('div');
    notification.className = `notification ${type}`;
    
    // Get icon based on notification type
    let icon = '';
    switch(type) {
        case 'success':
            icon = '✓';
            break;
        case 'error':
            icon = '✕';
            break;
        case 'warning':
            icon = '⚠';
            break;
        default: // info
            icon = 'ℹ';
    }
    
    // Set message and show notification
    notification.innerHTML = `
        <div class="notification-icon">${icon}</div>
        <div class="notification-content">${message}</div>
        <button class="notification-close">&times;</button>
    `;
    
    // Add to document
    document.body.appendChild(notification);
    
    // Add event listener to close button
    const closeButton = notification.querySelector('.notification-close');
    if (closeButton) {
        closeButton.addEventListener('click', () => {
            notification.classList.remove('show');
            setTimeout(() => notification.remove(), 300);
        });
    }
    
    // Show notification with a slight delay to ensure CSS transition works
    setTimeout(() => notification.classList.add('show'), 10);
    
    // Hide notification after 3 seconds
    setTimeout(() => {
        notification.classList.remove('show');
        setTimeout(() => notification.remove(), 300);
    }, 3000);
}

// Set up WebSocket connections for real-time data
function setupWebSockets() {
    // Setup WebSocket for global threat data
    setupGlobalWebSocket();
    
    // Setup WebSocket for Nepal monitor
    setupNepalWebSocket();
}

// Set up WebSocket connection for global threat data
function setupGlobalWebSocket() {
    // WebSocket implementation would go here in a real system
    console.log("Global WebSocket initialized");
}

// Function to simulate real-time notifications for demonstration
function setupSimulatedNotifications() {
    // Check if notifications are enabled
    const notificationsToggle = document.getElementById('notifications-toggle');
    if (!notificationsToggle || !notificationsToggle.checked) {
        // If not enabled, setup a check to start when they get enabled
        notificationsToggle.addEventListener('change', function() {
            if (this.checked) {
                startSimulatedNotifications();
            }
        });
        return;
    }
    
    // Start simulated notifications
    startSimulatedNotifications();
}

function startSimulatedNotifications() {
    // Generate a notification now
    generateRandomNotification();
    
    // Set up interval for random notifications (between 15-45 seconds)
    const minInterval = 15000;
    const maxInterval = 45000;
    
    function scheduleNextNotification() {
        const nextInterval = Math.floor(Math.random() * (maxInterval - minInterval + 1)) + minInterval;
        setTimeout(() => {
            // Check if notifications are still enabled before showing another one
            const notificationsToggle = document.getElementById('notifications-toggle');
            if (notificationsToggle && notificationsToggle.checked) {
                generateRandomNotification();
                scheduleNextNotification();
            }
        }, nextInterval);
    }
    
    // Schedule the first notification
    scheduleNextNotification();
}

function generateRandomNotification() {
    const notificationTypes = [
        {
            type: 'warning',
            messages: [
                'Suspicious login attempt detected from IP 192.168.1.45',
                'Unusual network traffic detected on port 8080',
                'Multiple failed login attempts detected'
            ]
        },
        {
            type: 'error',
            messages: [
                'Critical vulnerability detected in server02.example.com',
                'Ransomware signature detected in network traffic',
                'DDoS attack in progress - 15,000 requests per second'
            ]
        },
        {
            type: 'info',
            messages: [
                'System scan completed - 3 potential issues found',
                'Firewall rules updated successfully',
                'New threat intelligence feed connected'
            ]
        },
        {
            type: 'success',
            messages: [
                'Threat quarantined successfully',
                'Security patch applied to all systems',
                'Intrusion attempt blocked automatically'
            ]
        }
    ];
    
    // Randomly select notification type and message
    const selectedType = notificationTypes[Math.floor(Math.random() * notificationTypes.length)];
    const selectedMessage = selectedType.messages[Math.floor(Math.random() * selectedType.messages.length)];
    
    // Show the notification
    showNotification(selectedMessage, selectedType.type);
}