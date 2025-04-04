"""
Topic Modeling Module
This module implements LDA (Latent Dirichlet Allocation) for topic modeling of threat data.
"""

import logging
import os
import pickle
import ssl
import re
import numpy as np
from collections import Counter
import nltk
import gensim
from gensim import corpora
from gensim.models import LdaModel

logger = logging.getLogger(__name__)

class TopicModeler:
    """LDA-based topic modeling for threat data."""
    
    def __init__(self):
        """Initialize the topic modeler."""
        # Fix SSL certificate issues for NLTK downloads
        try:
            _create_unverified_https_context = ssl._create_unverified_context
        except AttributeError:
            pass
        else:
            ssl._create_default_https_context = _create_unverified_https_context
            
        # Try to download NLTK data but handle gracefully if it fails
        try:
            nltk.download('stopwords', quiet=True)
            self.stop_words = set(nltk.corpus.stopwords.words('english'))
        except Exception as e:
            logger.warning(f"Could not download NLTK stopwords: {e}. Using built-in stopwords.")
            # Default English stopwords
            self.stop_words = set([
                'i', 'me', 'my', 'myself', 'we', 'our', 'ours', 'ourselves', 'you', 'your', 'yours', 
                'yourself', 'yourselves', 'he', 'him', 'his', 'himself', 'she', 'her', 'hers', 'herself', 
                'it', 'its', 'itself', 'they', 'them', 'their', 'theirs', 'themselves', 'what', 'which', 
                'who', 'whom', 'this', 'that', 'these', 'those', 'am', 'is', 'are', 'was', 'were', 'be', 
                'been', 'being', 'have', 'has', 'had', 'having', 'do', 'does', 'did', 'doing', 'a', 'an', 
                'the', 'and', 'but', 'if', 'or', 'because', 'as', 'until', 'while', 'of', 'at', 'by', 'for', 
                'with', 'about', 'against', 'between', 'into', 'through', 'during', 'before', 'after', 
                'above', 'below', 'to', 'from', 'up', 'down', 'in', 'out', 'on', 'off', 'over', 'under', 
                'again', 'further', 'then', 'once', 'here', 'there', 'when', 'where', 'why', 'how', 'all', 
                'any', 'both', 'each', 'few', 'more', 'most', 'other', 'some', 'such', 'no', 'nor', 'not', 
                'only', 'own', 'same', 'so', 'than', 'too', 'very', 's', 't', 'can', 'will', 'just', 'don', 
                'should', 'now'
            ])
        
        # Add domain-specific stop words
        self.stop_words.update([
            'cve', 'vulnerability', 'exploit', 'attack', 'threat',
            'security', 'vulnerable', 'affected', 'version', 'impact',
            'system', 'software', 'code', 'fix', 'issue', 'patch',
            'vendor', 'product', 'update'
        ])
        
        # Initialize model parameters
        self.num_topics = 10
        self.dictionary = None
        self.lda_model = None
    
    def preprocess_text(self, text):
        """
        Preprocess text for topic modeling.
        
        Args:
            text (str): Raw text to preprocess
            
        Returns:
            list: List of preprocessed tokens
        """
        # Convert to lowercase
        text = text.lower()
        
        # Simple tokenization with regex
        tokens = re.findall(r'\b[a-zA-Z]{3,}\b', text)
        
        # Remove stopwords
        preprocessed = [token for token in tokens if token not in self.stop_words]
        
        return preprocessed
    
    def train(self, documents, num_topics=10, passes=20):
        """
        Train LDA topic model on a collection of documents.
        
        Args:
            documents (list): List of text documents
            num_topics (int): Number of topics to extract
            passes (int): Number of passes through the corpus during training
            
        Returns:
            tuple: (dictionary, lda_model)
        """
        logger.info(f"Training LDA topic model with {len(documents)} documents")
        
        self.num_topics = num_topics
        
        # Preprocess documents
        preprocessed_docs = [self.preprocess_text(doc) for doc in documents]
        
        # Filter out empty documents
        preprocessed_docs = [doc for doc in preprocessed_docs if doc]
        
        if not preprocessed_docs:
            logger.warning("No documents left after preprocessing")
            return None, None
        
        # Create dictionary
        self.dictionary = corpora.Dictionary(preprocessed_docs)
        
        # Filter extremes with more relaxed parameters for small corpora
        min_doc_count = min(2, len(preprocessed_docs) // 2) if len(preprocessed_docs) > 3 else 1
        self.dictionary.filter_extremes(no_below=min_doc_count, no_above=0.95)
        
        # Create document-term matrix
        corpus = [self.dictionary.doc2bow(doc) for doc in preprocessed_docs]
        
        if not corpus:
            logger.warning("Empty corpus after dictionary filtering")
            return None, None
        
        # Train LDA model
        logger.info(f"Training LDA with {len(corpus)} documents, {len(self.dictionary)} terms")
        
        # Adjust number of topics for small corpora
        adjusted_topics = min(num_topics, len(preprocessed_docs) // 2) if len(preprocessed_docs) > 3 else 3
        if adjusted_topics != num_topics:
            logger.info(f"Adjusting number of topics from {num_topics} to {adjusted_topics} due to small corpus size")
            self.num_topics = adjusted_topics
        
        self.lda_model = LdaModel(
            corpus=corpus,
            id2word=self.dictionary,
            num_topics=self.num_topics,
            passes=passes,
            alpha='auto',
            eta='auto'
        )
        
        logger.info("LDA model training completed")
        return self.dictionary, self.lda_model
    
    def save_model(self, model_dir='models/trained'):
        """
        Save the trained model and dictionary.
        
        Args:
            model_dir (str): Directory to save model
            
        Returns:
            bool: True if successful, False otherwise
        """
        if self.lda_model is None or self.dictionary is None:
            logger.error("No model to save")
            return False
        
        os.makedirs(model_dir, exist_ok=True)
        
        try:
            # Save dictionary
            dict_path = os.path.join(model_dir, 'lda_dictionary.pkl')
            self.dictionary.save(dict_path)
            
            # Save model
            model_path = os.path.join(model_dir, 'lda_model.pkl')
            self.lda_model.save(model_path)
            
            logger.info(f"Saved LDA model to {model_path}")
            return True
        except Exception as e:
            logger.error(f"Error saving model: {e}")
            return False
    
    def load_model(self, model_dir='models/trained'):
        """
        Load a trained model and dictionary.
        
        Args:
            model_dir (str): Directory to load model from
            
        Returns:
            bool: True if successful, False otherwise
        """
        dict_path = os.path.join(model_dir, 'lda_dictionary.pkl')
        model_path = os.path.join(model_dir, 'lda_model.pkl')
        
        try:
            # Load dictionary
            self.dictionary = corpora.Dictionary.load(dict_path)
            
            # Load model
            self.lda_model = LdaModel.load(model_path)
            
            logger.info(f"Loaded LDA model from {model_path}")
            return True
        except Exception as e:
            logger.error(f"Error loading model: {e}")
            return False
    
    def analyze_document(self, text):
        """
        Analyze a document to determine its topic distribution.
        
        Args:
            text (str): Document text
            
        Returns:
            list: List of (topic_id, probability) pairs
        """
        if self.lda_model is None or self.dictionary is None:
            logger.error("Model not loaded")
            return None
        
        # Preprocess the document
        preprocessed_doc = self.preprocess_text(text)
        
        if not preprocessed_doc:
            logger.warning("Empty document after preprocessing")
            return []
        
        # Convert to bag of words
        bow = self.dictionary.doc2bow(preprocessed_doc)
        
        if not bow:
            logger.warning("Document has no words in dictionary")
            return []
        
        # Get topic distribution
        topics = self.lda_model[bow]
        
        return sorted(topics, key=lambda x: x[1], reverse=True)
    
    def get_topic_keywords(self, num_words=10):
        """
        Get the top keywords for each topic.
        
        Args:
            num_words (int): Number of words per topic
            
        Returns:
            dict: Dictionary mapping topic IDs to lists of keywords
        """
        if self.lda_model is None:
            logger.error("Model not loaded")
            return {}
        
        topics = {}
        for topic_id in range(self.num_topics):
            topic_words = self.lda_model.show_topic(topic_id, num_words)
            topics[topic_id] = [(word, float(prob)) for word, prob in topic_words]
        
        return topics
    
    def extract_emerging_topics(self, documents, time_periods):
        """
        Analyze documents across time periods to extract emerging topics.
        
        Args:
            documents (list): List of (text, timestamp) pairs
            time_periods (list): List of timestamp boundaries
            
        Returns:
            dict: Dictionary of emerging topics by time period
        """
        # Group documents by time period
        period_docs = {period: [] for period in range(len(time_periods)-1)}
        
        for doc, timestamp in documents:
            for i in range(len(time_periods)-1):
                if time_periods[i] <= timestamp < time_periods[i+1]:
                    period_docs[i].append(doc)
                    break
        
        # Analyze topics for each period
        period_topics = {}
        for period, docs in period_docs.items():
            if not docs:
                continue
            
            # Train a model for this period
            dictionary, model = self.train(docs, num_topics=self.num_topics)
            
            # Get top topics
            period_topics[period] = self.get_topic_keywords()
        
        return period_topics 