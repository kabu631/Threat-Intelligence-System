"""
Named Entity Recognition (NER) Module
This module implements NER for identifying and categorizing threat actors and other entities.
"""

import logging
import os
import json
import spacy
import ssl
from spacy.tokens import DocBin
from spacy.util import minibatch, compounding
from pathlib import Path
import warnings

logger = logging.getLogger(__name__)

class ThreatActorNER:
    """NER model for identifying threat actors and related entities."""
    
    def __init__(self, model_name=None):
        """
        Initialize the NER model.
        
        Args:
            model_name (str, optional): Name of a pre-trained spaCy model to load
        """
        self.model = None
        self.entity_types = [
            "THREAT_ACTOR", "CAMPAIGN", "MALWARE", "TOOL", "TECHNIQUE", "ORGANIZATION"
        ]
        
        # Fix SSL certificate issues
        try:
            _create_unverified_https_context = ssl._create_unverified_context
        except AttributeError:
            pass
        else:
            ssl._create_default_https_context = _create_unverified_https_context
        
        # Try to load specified model or fallback
        if model_name:
            try:
                self.model = spacy.load(model_name)
                logger.info(f"Loaded NER model: {model_name}")
            except Exception as e:
                logger.error(f"Error loading model {model_name}: {e}")
                self._load_fallback_model()
        else:
            self._load_fallback_model()
    
    def _load_fallback_model(self):
        """Load a fallback model if the primary one fails."""
        logger.info("Attempting to load fallback models")
        models_to_try = ["en_core_web_lg", "en_core_web_sm", "en_core_web_md"]
        
        for model_name in models_to_try:
            try:
                self.model = spacy.load(model_name)
                logger.info(f"Loaded fallback model: {model_name}")
                return
            except Exception as e:
                logger.warning(f"Could not load {model_name}: {e}")
        
        # If all models fail, create a blank model
        logger.warning("No spaCy models available. Creating blank model.")
        try:
            self.model = spacy.blank("en")
            # Add NER pipeline
            ner = self.model.add_pipe("ner")
            # Add entity labels
            for entity_type in self.entity_types:
                ner.add_label(entity_type)
            logger.info("Created blank NER model")
        except Exception as e:
            logger.error(f"Failed to create blank model: {e}")
            # Last resort, set to None
            self.model = None
    
    def prepare_training_data(self, training_data):
        """
        Prepare training data for the NER model.
        
        Args:
            training_data (list): List of (text, entities) pairs where entities is a
                                  list of (start, end, label) tuples
            
        Returns:
            DocBin: spaCy DocBin object with training examples
        """
        if self.model is None:
            logger.error("No model available to prepare training data")
            return None
            
        doc_bin = DocBin()
        
        for text, annotations in training_data:
            doc = self.model.make_doc(text)
            ents = []
            
            for start, end, label in annotations:
                span = doc.char_span(start, end, label=label)
                if span:
                    ents.append(span)
            
            doc.ents = ents
            doc_bin.add(doc)
        
        return doc_bin
    
    def train(self, training_data, output_dir='models/trained/ner', n_iter=30):
        """
        Train the NER model on custom data.
        
        Args:
            training_data (list): List of (text, entities) pairs
            output_dir (str): Directory to save the trained model
            n_iter (int): Number of training iterations
            
        Returns:
            bool: True if successful, False otherwise
        """
        if self.model is None:
            logger.error("No model available for training")
            return False
            
        logger.info(f"Training NER model with {len(training_data)} examples")
        
        # Prepare the output directory
        output_path = Path(output_dir)
        if not output_path.exists():
            output_path.mkdir(parents=True)
        
        # Check if NER pipeline exists
        if "ner" not in self.model.pipe_names:
            try:
                ner = self.model.add_pipe("ner", last=True)
            except Exception as e:
                logger.error(f"Could not add NER pipeline: {e}")
                return False
        else:
            ner = self.model.get_pipe("ner")
        
        # Add entity labels
        for entity_type in self.entity_types:
            if entity_type not in ner.labels:
                ner.add_label(entity_type)
        
        # Prepare training data
        train_data = self.prepare_training_data(training_data)
        if train_data is None:
            return False
        
        # Begin training with error handling
        try:
            # Disable other pipelines during training
            other_pipes = [pipe for pipe in self.model.pipe_names if pipe != "ner"]
            with self.model.disable_pipes(*other_pipes):
                optimizer = self.model.begin_training()
                
                # Training loop
                for i in range(n_iter):
                    losses = {}
                    
                    # Batch the examples
                    batches = minibatch(train_data, size=compounding(4.0, 32.0, 1.001))
                    
                    # Update the model
                    for batch in batches:
                        self.model.update(batch, drop=0.5, losses=losses)
                    
                    logger.info(f"Iteration {i+1}/{n_iter}, Loss: {losses.get('ner', 0)}")
        
            # Save the model
            self.model.to_disk(output_path)
            logger.info(f"Saved NER model to {output_path}")
            return True
        except Exception as e:
            logger.error(f"Error during NER model training: {e}")
            return False
    
    def load_model(self, model_dir='models/trained/ner'):
        """
        Load a trained NER model.
        
        Args:
            model_dir (str): Directory containing the model
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            self.model = spacy.load(model_dir)
            logger.info(f"Loaded NER model from {model_dir}")
            return True
        except Exception as e:
            logger.error(f"Error loading model from {model_dir}: {e}")
            self._load_fallback_model()
            return False
    
    def identify_entities(self, text):
        """
        Identify named entities in text.
        
        Args:
            text (str): Text to analyze
            
        Returns:
            list: List of (entity_text, entity_type, start, end) tuples
        """
        if not self.model:
            logger.error("No model loaded")
            return []
        
        try:
            doc = self.model(text)
            entities = [(ent.text, ent.label_, ent.start_char, ent.end_char) for ent in doc.ents]
            return entities
        except Exception as e:
            logger.error(f"Error identifying entities: {e}")
            return []
    
    def extract_threat_actors(self, text):
        """
        Extract threat actors from text.
        
        Args:
            text (str): Text to analyze
            
        Returns:
            list: List of threat actor entities
        """
        entities = self.identify_entities(text)
        
        # Filter for threat actors
        threat_actors = [
            {"text": entity_text, "start": start, "end": end}
            for entity_text, label, start, end in entities
            if label == "THREAT_ACTOR"
        ]
        
        return threat_actors
    
    def generate_training_examples(self, texts, actor_list):
        """
        Generate training examples by matching known threat actors in texts.
        
        Args:
            texts (list): List of text documents
            actor_list (list): List of known threat actor names
            
        Returns:
            list: List of (text, entities) pairs for training
        """
        training_examples = []
        
        for text in texts:
            entities = []
            
            # Find threat actors in text
            for actor in actor_list:
                start = 0
                while True:
                    start = text.find(actor, start)
                    if start == -1:
                        break
                    end = start + len(actor)
                    entities.append((start, end, "THREAT_ACTOR"))
                    start = end
            
            if entities:
                training_examples.append((text, entities))
        
        return training_examples 