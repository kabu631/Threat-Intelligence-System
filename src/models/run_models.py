"""
Run Models Module
This module orchestrates the execution of all machine learning models for threat analysis.
"""

import logging
import os
import json
import glob
from datetime import datetime, timedelta

from .topic_model import TopicModeler
from .ner_model import ThreatActorNER

logger = logging.getLogger(__name__)

def analyze_threats():
    """Run threat analysis using machine learning models."""
    logger.info("Starting threat analysis")
    
    # Create output directories if they don't exist
    os.makedirs('data/processed', exist_ok=True)
    os.makedirs('models/trained', exist_ok=True)
    
    # Analyze topics
    analyze_topics()
    
    # Extract threat actors
    extract_threat_actors()
    
    logger.info("Threat analysis completed")

def analyze_topics():
    """Analyze topics in collected threat data."""
    logger.info("Analyzing topics in threat data")
    
    # Initialize topic modeler
    topic_modeler = TopicModeler()
    
    # Get processed CVE data
    cve_files = glob.glob('data/processed/cve_processed_*.json')
    
    if not cve_files:
        logger.warning("No processed CVE data found")
        return
    
    # Collect all descriptions
    descriptions = []
    for cve_file in cve_files:
        try:
            with open(cve_file, 'r', encoding='utf-8') as f:
                cve_data = json.load(f)
            
            for item in cve_data:
                description = item.get('description', '')
                if description:
                    descriptions.append(description)
        except Exception as e:
            logger.error(f"Error reading {cve_file}: {e}")
    
    if not descriptions:
        logger.warning("No descriptions found in CVE data")
        return
    
    logger.info(f"Found {len(descriptions)} descriptions for topic modeling")
    
    # Train topic model
    topic_modeler.train(descriptions, num_topics=10)
    
    # Save model
    topic_modeler.save_model()
    
    # Get topic keywords
    topics = topic_modeler.get_topic_keywords(num_words=15)
    
    # Save topic keywords
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    output_file = os.path.join('data', 'processed', f'topics_{timestamp}.json')
    
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(topics, f, indent=2)
        logger.info(f"Saved topic keywords to {output_file}")
    except Exception as e:
        logger.error(f"Error saving topic keywords: {e}")
    
    # Analyze descriptions for topic distribution
    topic_distributions = []
    for i, description in enumerate(descriptions[:10]):  # Analyze first 10 for example
        topics = topic_modeler.analyze_document(description)
        if topics:
            topic_distributions.append({
                'description_id': i,
                'topics': [(str(topic_id), float(prob)) for topic_id, prob in topics]
            })
    
    # Save topic distributions
    if topic_distributions:
        dist_file = os.path.join('data', 'processed', f'topic_distributions_{timestamp}.json')
        try:
            with open(dist_file, 'w', encoding='utf-8') as f:
                json.dump(topic_distributions, f, indent=2)
            logger.info(f"Saved topic distributions to {dist_file}")
        except Exception as e:
            logger.error(f"Error saving topic distributions: {e}")

def extract_threat_actors():
    """Extract threat actors from threat data using NER."""
    logger.info("Extracting threat actors from threat data")
    
    # Initialize NER model
    ner_model = ThreatActorNER()
    
    # Get processed CVE data
    cve_files = glob.glob('data/processed/cve_processed_*.json')
    
    if not cve_files:
        logger.warning("No processed CVE data found")
        return
    
    # Process each CVE file
    all_entities = []
    for cve_file in cve_files:
        try:
            with open(cve_file, 'r', encoding='utf-8') as f:
                cve_data = json.load(f)
            
            file_entities = []
            for item in cve_data:
                description = item.get('description', '')
                if not description:
                    continue
                
                # Use the default NER model to extract entities
                entities = ner_model.identify_entities(description)
                
                if entities:
                    file_entities.append({
                        'cve_id': item.get('id'),
                        'entities': [
                            {
                                'text': entity[0],
                                'type': entity[1],
                                'start': entity[2],
                                'end': entity[3]
                            }
                            for entity in entities
                        ]
                    })
            
            all_entities.extend(file_entities)
            logger.info(f"Extracted entities from {cve_file}")
        except Exception as e:
            logger.error(f"Error processing {cve_file}: {e}")
    
    # Save extracted entities
    if all_entities:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_file = os.path.join('data', 'processed', f'entities_{timestamp}.json')
        
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(all_entities, f, indent=2)
            logger.info(f"Saved extracted entities to {output_file}")
        except Exception as e:
            logger.error(f"Error saving entities: {e}")

if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Run threat analysis
    analyze_threats() 