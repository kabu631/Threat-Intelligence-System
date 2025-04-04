#!/usr/bin/env python
"""
Download NLTK Data
This script downloads required NLTK data packages with certificate verification disabled.
This is especially useful on macOS where SSL certificate verification can fail.
"""

import ssl
import nltk

try:
    _create_unverified_https_context = ssl._create_unverified_context
except AttributeError:
    pass
else:
    ssl._create_default_https_context = _create_unverified_https_context

print("Downloading NLTK data packages...")
nltk.download('punkt')
nltk.download('stopwords')
nltk.download('wordnet')
print("Download complete!") 