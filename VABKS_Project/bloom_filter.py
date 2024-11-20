# bloom_filter.py
from pybloom_live import BloomFilter
import hashlib

class KeywordBloomFilter:
    def __init__(self, capacity=100, error_rate=0.01):
        # Initialize Bloom filter
        self.bloom_filter = BloomFilter(capacity=capacity, error_rate=error_rate)

    def add_keyword(self, keyword):
        # Hash the keyword and add it to the Bloom filter
        keyword_hash = hashlib.sha256(keyword.encode()).hexdigest()
        self.bloom_filter.add(keyword_hash)

    def check_keyword(self, keyword):
        # Check if keyword exists in the Bloom filter
        keyword_hash = hashlib.sha256(keyword.encode()).hexdigest()
        return keyword_hash in self.bloom_filter
