// Threat Intelligence Dashboard - Main Entry Point
// This file dynamically loads necessary components and initializes the live attack map view

document.addEventListener('DOMContentLoaded', function() {
    // Load required CSS
    loadStylesheets();
    
    // Load necessary libraries
    loadLibraries().then(() => {
        // Initialize the dashboard
        initializeDashboard();
    });

    // Call the function to handle initial navigation
    handleSectionNavigation();
    
    // Also handle navigation when the hash changes
    window.addEventListener('hashchange', handleSectionNavigation);

    // Set up click handlers for nav links
    document.querySelectorAll('header nav ul li a').forEach(link => {
        link.addEventListener('click', function(e) {
            e.preventDefault(); // Prevent default navigation
            
            // Update the URL hash without triggering a page reload
            const targetHash = this.getAttribute('href');
            window.location.hash = targetHash;
            
            // Handle the navigation manually
            handleSectionNavigation();
        });
    });
});

// Load all required stylesheets
function loadStylesheets() {
    // Load Leaflet CSS for maps
    if (!document.querySelector('link[href*="leaflet.css"]')) {
        const leafletCSS = document.createElement('link');
        leafletCSS.rel = 'stylesheet';
        leafletCSS.href = 'https://unpkg.com/leaflet@1.7.1/dist/leaflet.css';
        document.head.appendChild(leafletCSS);
    }
    
    // Load main stylesheet
    if (!document.querySelector('link[href="styles.css"]')) {
        const mainCSS = document.createElement('link');
        mainCSS.rel = 'stylesheet';
        mainCSS.href = 'styles.css';
        document.head.appendChild(mainCSS);
    }
}

// Load all required JavaScript libraries
async function loadLibraries() {
    // Define libraries to load
    const libraries = [
        {
            id: 'chart-js',
            src: 'https://cdn.jsdelivr.net/npm/chart.js'
        },
        {
            id: 'leaflet-js',
            src: 'https://unpkg.com/leaflet@1.7.1/dist/leaflet.js'
        },
        {
            id: 'leaflet-realtime',
            src: 'https://cdnjs.cloudflare.com/ajax/libs/leaflet-realtime/2.2.0/leaflet-realtime.min.js'
        }
    ];
    
    // Function to load a script
    const loadScript = (script) => {
        return new Promise((resolve, reject) => {
            // Skip if already loaded
            if (document.getElementById(script.id)) {
                resolve();
        return;
    }
    
            const scriptElement = document.createElement('script');
            scriptElement.id = script.id;
            scriptElement.src = script.src;
            scriptElement.onload = resolve;
            scriptElement.onerror = reject;
            document.head.appendChild(scriptElement);
        });
    };
    
    // Load all scripts in sequence
    for (const library of libraries) {
        await loadScript(library);
    }
    
    // Finally load our dashboard.js
    await loadScript({
        id: 'dashboard-js',
        src: 'dashboard.js'
    });
}

// Initialize the dashboard with live attack view
function initializeDashboard() {
    console.log('Initializing live attack dashboard...');
    
    // API Configuration 
    const API_BASE_URL = "http://localhost:9000";
    
    // Check API server status
    checkApiStatus(API_BASE_URL).then(status => {
        if (status) {
            console.log('API server is online');
            // Auto-navigate to dashboard section which includes the live map
            const dashboardLink = document.querySelector('header nav ul li a[href="#dashboard"]');
            if (dashboardLink) {
                dashboardLink.click();
            }
        } else {
            showError('API server is offline. Please start the API server and reload.');
        }
    });
}

// Check if API server is running
async function checkApiStatus(apiUrl) {
    try {
        const response = await fetch(`${apiUrl}/health`, { 
            method: 'GET',
            headers: { 'Accept': 'application/json' },
            mode: 'cors'
        });
        
        if (response.ok) {
            const data = await response.json();
            return data.status === 'healthy';
        }
        
        return false;
        } catch (error) {
        console.error('Error checking API status:', error);
        return false;
    }
}

// Show error message
function showError(message) {
    const errorDiv = document.createElement('div');
    errorDiv.className = 'error-message';
    errorDiv.innerHTML = `
        <h3>Error</h3>
        <p>${message}</p>
        <button class="retry-button" onclick="location.reload()">Retry</button>
    `;
    
    // Insert at the top of the main content
    const mainElement = document.querySelector('main');
    if (mainElement) {
        mainElement.prepend(errorDiv);
    } else {
        document.body.prepend(errorDiv);
    }
}

// Force navigation to the correct section based on URL hash
function handleSectionNavigation() {
    // Get the current hash from the URL (or default to dashboard)
    const currentHash = window.location.hash || '#dashboard';
    
    // Find all navigation links and sections
    const navLinks = document.querySelectorAll('header nav ul li a');
    const sections = document.querySelectorAll('main section');
    
    // Update active link
    navLinks.forEach(link => {
        if (link.getAttribute('href') === currentHash) {
            link.classList.add('active');
        } else {
            link.classList.remove('active');
        }
    });
    
    // Show the correct section
    sections.forEach(section => {
        if (section.id === currentHash.substring(1)) {
            section.classList.remove('hidden-section');
            section.classList.add('active-section');
            
            // Special handling for specific sections
            if (section.id === 'analysis') {
                // Make sure analysis tools are set up
                if (typeof setupAnalysisTools === 'function') {
                    setupAnalysisTools();
                }
            } else if (section.id === 'nepal-monitor') {
                // Make sure Nepal monitor is set up with live data
                if (typeof updateNepalMonitorData === 'function') {
                    // Use setTimeout to ensure the section is visible first
                    setTimeout(() => {
                        updateNepalMonitorData();
                        
                        // Make sure the map is properly sized
                        if (window.nepalMap) {
                            window.nepalMap.invalidateSize();
                        }
                    }, 100);
                }
            }
        } else {
            section.classList.add('hidden-section');
            section.classList.remove('active-section');
        }
    });
} 