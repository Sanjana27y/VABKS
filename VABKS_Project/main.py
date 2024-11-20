# main.py
from abe_setup import abe_initialize

if __name__ == "__main__":
    # Initialize ABE system
    abe, master_key, public_key = abe_initialize()
    print("ABE system initialized with master key and public key.")

from bloom_filter import KeywordBloomFilter

if __name__ == "__main__":
    # Initialize ABE
    abe, master_key, public_key = abe_initialize()

    # Initialize Bloom filter for keywords
    bf = KeywordBloomFilter()
    bf.add_keyword("secure_search")
    print("Keyword 'secure_search' added to Bloom filter.")

    # Check if keyword is in Bloom filter
    keyword_exists = bf.check_keyword("secure_search")
    print("Keyword 'secure_search' exists:", keyword_exists)

# main.py (continued)
from encryption import encrypt_keyword

if __name__ == "__main__":
    # Initialize ABE
    abe, master_key, public_key = abe_initialize()

    # Define access policy for encryption
    policy = '((ROLE1 or ROLE2) and DEPARTMENT)'
    encrypted_keyword = encrypt_keyword(abe, public_key, "secure_search", policy)
    print("Encrypted keyword under policy:", encrypted_keyword)

