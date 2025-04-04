#!/usr/bin/env python3
"""
Simple API Server for the Threat Intelligence Dashboard
Implements the required analysis endpoints with mock responses
"""

import uvicorn
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
import json
import logging
import re
import random
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# Initialize FastAPI application
app = FastAPI(
    title="Simple Threat Intelligence API",
    description="API for providing analysis functionality to the dashboard",
    version="1.0.0"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mock data extraction functions

def extract_mock_iocs(text):
    """Mock IOC extraction"""
    # Simple regex patterns for demo
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    domain_pattern = r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]\b'
    url_pattern = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+'
    md5_pattern = r'\b[a-fA-F0-9]{32}\b'
    sha1_pattern = r'\b[a-fA-F0-9]{40}\b'
    sha256_pattern = r'\b[a-fA-F0-9]{64}\b'
    email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    cve_pattern = r'CVE-\d{4}-\d{4,7}'
    
    return {
        "ip_addresses": re.findall(ip_pattern, text),
        "domains": re.findall(domain_pattern, text),
        "urls": re.findall(url_pattern, text),
        "hashes": {
            "md5": re.findall(md5_pattern, text),
            "sha1": re.findall(sha1_pattern, text),
            "sha256": re.findall(sha256_pattern, text)
        },
        "emails": re.findall(email_pattern, text),
        "cves": re.findall(cve_pattern, text)
    }

def analyze_mock_topics(text):
    """Mock topic analysis"""
    # Generate some plausible topics based on text content
    topics = []
    
    # Create a few mock topics with random probabilities
    for i in range(1, random.randint(3, 6)):
        topics.append({
            "topic_id": i,
            "probability": round(random.random(), 2)
        })
    
    # Sort by probability
    topics.sort(key=lambda x: x["probability"], reverse=True)
    
    return {"topics": topics}

def extract_mock_entities(text):
    """Mock entity extraction"""
    # Define entity types and some common examples
    entity_types = {
        "THREAT_ACTOR": ["APT29", "Lazarus Group", "Fancy Bear", "Cozy Bear", "SolarWinds"],
        "ORGANIZATION": ["Microsoft", "Google", "Apple", "Facebook", "Amazon", "Twitter"],
        "MALWARE": ["WannaCry", "NotPetya", "Emotet", "TrickBot", "Ryuk", "CryptoLocker"],
        "TECHNIQUE": ["Phishing", "SQL Injection", "XSS", "DDoS", "Brute Force", "Zero-day"],
        "LOCATION": ["United States", "Russia", "China", "North Korea", "Iran", "Europe"]
    }
    
    # Generate mock entities by looking for these terms in the text
    entities = []
    
    for entity_type, examples in entity_types.items():
        for example in examples:
            if example.lower() in text.lower():
                # Get the position in text
                start = text.lower().find(example.lower())
                end = start + len(example)
                
                entities.append({
                    "text": text[start:end],
                    "type": entity_type,
                    "start": start,
                    "end": end
                })
    
    return {"entities": entities}

# API endpoints

@app.get("/")
async def root():
    """Root endpoint."""
    return {"message": "Simple Threat Intelligence API"}

@app.post("/extract-iocs")
async def extract_iocs(request: Request):
    """Extract IOCs from text."""
    try:
        data = await request.json()
        text = data.get("text", "")
        iocs = extract_mock_iocs(text)
        return iocs
    except Exception as e:
        logger.error(f"Error extracting IOCs: {e}")
        return {"error": str(e)}

@app.post("/analyze-topics")
async def analyze_topics(request: Request):
    """Analyze topics in text."""
    try:
        data = await request.json()
        text = data.get("text", "")
        topics = analyze_mock_topics(text)
        return topics
    except Exception as e:
        logger.error(f"Error analyzing topics: {e}")
        return {"error": str(e)}

@app.post("/extract-entities")
async def extract_entities(request: Request):
    """Extract named entities from text."""
    try:
        data = await request.json()
        text = data.get("text", "")
        entities = extract_mock_entities(text)
        return entities
    except Exception as e:
        logger.error(f"Error extracting entities: {e}")
        return {"error": str(e)}

@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "components": {
            "ioc_extractor": True,
            "topic_modeler": True,
            "ner_model": True,
            "nepal_monitor": True
        }
    }

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=9000) 