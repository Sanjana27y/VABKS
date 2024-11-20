# encryption.py
from charm.toolbox.pairinggroup import PairingGroup, G1, GT
from charm.schemes.abenc.abenc_waters09 import CPabe09

def encrypt_keyword(abe, public_key, keyword, policy):
    # Initialize pairing group directly here
    group = PairingGroup('SS512')  # Use the same group as in abe_initialize

    # Hash the keyword into G1
    keyword_g1 = group.hash(keyword, G1)

    # Map the keyword from G1 to GT using pairing
    # Pair with itself or another fixed element in G1 (such as the generator)
    generator_g1 = group.random(G1)  # Example generator element
    keyword_element = group.pair_prod(keyword_g1, generator_g1)  # Result is in GT

    # Encrypt the keyword element under the specified policy
    keyword_cipher = abe.encrypt(public_key, keyword_element, policy)
    return keyword_cipher

    # encryption.py (continued)
def generate_search_token(abe, public_key, master_key, attributes):

    # Generate a decryption key for the user's attributes
    attr_list = list(attributes)
    user_key = abe.keygen(public_key, master_key, attr_list)
    return user_key
