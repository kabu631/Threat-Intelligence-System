"""
API Application Module
This module provides the FastAPI application for the threat intelligence automation system.
"""

import logging
import os
import json
import glob
from typing import List, Dict, Any, Optional
from datetime import datetime

from fastapi import FastAPI, HTTPException, Query, Body, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from processors.ioc_extractor import IOCExtractor
from models.topic_model import TopicModeler
from models.ner_model import ThreatActorNER
from collectors.server_monitor import monitor, start_monitoring, stop_monitoring, get_latest_events, get_threat_summary

logger = logging.getLogger(__name__)

# Initialize FastAPI application
app = FastAPI(
    title="Threat Intelligence Automation API",
    description="API for interacting with the threat intelligence automation system",
    version="1.0.0"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins
    allow_credentials=True,
    allow_methods=["*"],  # Allow all methods
    allow_headers=["*"],  # Allow all headers
)

# Initialize components
ioc_extractor = IOCExtractor()
topic_modeler = TopicModeler()
ner_model = ThreatActorNER()

# Load trained models if available
try:
    topic_modeler.load_model()
except Exception as e:
    logger.warning(f"Could not load topic model: {e}")

# Define Pydantic models for request/response
class IOCRequest(BaseModel):
    """Request model for IOC extraction."""
    text: str = Field(..., description="Text to extract IOCs from")

class AnalyzeTopicsRequest(BaseModel):
    """Request model for topic analysis."""
    text: str = Field(..., description="Text to analyze topics in")

class ExtractEntitiesRequest(BaseModel):
    """Request model for entity extraction."""
    text: str = Field(..., description="Text to extract entities from")

class IOCResponse(BaseModel):
    """Response model for IOC extraction."""
    ip_addresses: List[str] = Field(default_factory=list)
    domains: List[str] = Field(default_factory=list)
    urls: List[str] = Field(default_factory=list)
    hashes: Dict[str, List[str]] = Field(default_factory=dict)
    emails: List[str] = Field(default_factory=list)
    cves: List[str] = Field(default_factory=list)

class TopicResponse(BaseModel):
    """Response model for topic analysis."""
    topics: List[dict] = Field(default_factory=list)

class EntityResponse(BaseModel):
    """Response model for entity extraction."""
    entities: List[dict] = Field(default_factory=list)

class ServerMonitorConfig(BaseModel):
    """Request model for server monitor configuration."""
    polling_interval: int = Field(10, description="Interval between polls in seconds")
    use_real_servers: bool = Field(False, description="Whether to use real server connections")
    server_list_path: Optional[str] = Field(None, description="Path to server list JSON file")

# API endpoints
@app.get("/")
async def root():
    """Root endpoint."""
    return {"message": "Threat Intelligence Automation API"}

@app.post("/extract-iocs", response_model=IOCResponse)
async def extract_iocs(request: IOCRequest):
    """Extract IOCs from text."""
    try:
        iocs = ioc_extractor.extract_iocs(request.text)
        return IOCResponse(
            ip_addresses=iocs.get('ip_addresses', []),
            domains=iocs.get('domains', []),
            urls=iocs.get('urls', []),
            hashes=iocs.get('hashes', {}),
            emails=iocs.get('emails', []),
            cves=iocs.get('cves', [])
        )
    except Exception as e:
        logger.error(f"Error extracting IOCs: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/analyze-topics", response_model=TopicResponse)
async def analyze_topics(request: AnalyzeTopicsRequest):
    """Analyze topics in text."""
    if not topic_modeler.lda_model:
        raise HTTPException(
            status_code=503, 
            detail="Topic model not loaded. Please train or load a model first."
        )
    
    try:
        topic_dist = topic_modeler.analyze_document(request.text)
        return TopicResponse(
            topics=[{"topic_id": int(topic_id), "probability": float(prob)} for topic_id, prob in topic_dist]
        )
    except Exception as e:
        logger.error(f"Error analyzing topics: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/extract-entities", response_model=EntityResponse)
async def extract_entities(request: ExtractEntitiesRequest):
    """Extract entities from text."""
    try:
        entities = ner_model.identify_entities(request.text)
        return EntityResponse(
            entities=[
                {
                    "text": entity[0],
                    "type": entity[1],
                    "start": entity[2],
                    "end": entity[3]
                }
                for entity in entities
            ]
        )
    except Exception as e:
        logger.error(f"Error extracting entities: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/recent-data")
async def get_recent_data(
    data_type: str = Query(..., description="Type of data to retrieve (cve, ioc, topic, entity)")
):
    """Retrieve recent processed data."""
    try:
        pattern = None
        if data_type.lower() == 'cve':
            pattern = 'data/processed/cve_processed_*.json'
        elif data_type.lower() == 'ioc':
            pattern = 'data/processed/extracted_iocs_*.json'
        elif data_type.lower() == 'topic':
            pattern = 'data/processed/topics_*.json'
        elif data_type.lower() == 'entity':
            pattern = 'data/processed/entities_*.json'
        else:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid data type: {data_type}. Must be one of: cve, ioc, topic, entity"
            )
        
        files = sorted(glob.glob(pattern), reverse=True)
        
        if not files:
            return {"data": [], "message": f"No {data_type} data found"}
        
        # Get most recent file
        with open(files[0], 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        return {"data": data, "source_file": files[0]}
    except Exception as e:
        logger.error(f"Error retrieving recent data: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# New endpoints for Nepal server monitoring

@app.post("/nepal/start-monitoring")
async def nepal_start_monitoring(background_tasks: BackgroundTasks, config: ServerMonitorConfig = Body(default=None)):
    """Start monitoring Nepalese servers in the background."""
    try:
        if config:
            # Update monitor configuration
            monitor.polling_interval = config.polling_interval
            monitor.use_real_servers = config.use_real_servers
            monitor.server_list_path = config.server_list_path
            if config.use_real_servers and config.server_list_path:
                monitor._load_server_list()
        
        # Start monitoring in the background
        background_tasks.add_task(start_monitoring)
        return {"status": "success", "message": "Nepalese server monitoring started"}
    except Exception as e:
        logger.error(f"Error starting server monitoring: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/nepal/stop-monitoring")
async def nepal_stop_monitoring():
    """Stop monitoring Nepalese servers."""
    try:
        stop_monitoring()
        return {"status": "success", "message": "Nepalese server monitoring stopped"}
    except Exception as e:
        logger.error(f"Error stopping server monitoring: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/nepal/server-events")
async def nepal_server_events(limit: int = Query(100, description="Maximum number of events to return")):
    """Get the latest server events from Nepal."""
    try:
        events = get_latest_events(limit)
        return {"status": "success", "events": events, "count": len(events)}
    except Exception as e:
        logger.error(f"Error getting server events: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/nepal/threat-summary")
async def nepal_threat_summary():
    """Get a summary of current threats in Nepal."""
    try:
        summary = get_threat_summary()
        return {"status": "success", "summary": summary}
    except Exception as e:
        logger.error(f"Error getting threat summary: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/health")
async def health_check():
    """Health check endpoint."""
    status = {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "components": {
            "ioc_extractor": True,
            "topic_modeler": topic_modeler.lda_model is not None,
            "ner_model": ner_model.model is not None,
            "nepal_monitor": monitor.is_running
        }
    }
    return status

# Startup event to initialize server monitoring
@app.on_event("startup")
async def startup_event():
    """Start background tasks on startup."""
    try:
        # Start Nepal server monitoring
        start_monitoring()
        logger.info("Nepal server monitoring started on API startup")
    except Exception as e:
        logger.error(f"Error starting Nepal monitoring on startup: {e}")

# Shutdown event to clean up resources
@app.on_event("shutdown")
async def shutdown_event():
    """Stop background tasks on shutdown."""
    try:
        # Stop Nepal server monitoring
        stop_monitoring()
        logger.info("Nepal server monitoring stopped on API shutdown")
    except Exception as e:
        logger.error(f"Error stopping Nepal monitoring on shutdown: {e}") 