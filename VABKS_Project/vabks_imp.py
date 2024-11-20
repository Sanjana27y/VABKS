from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, GT, pair
from charm.core.math.pairing import hashPair as sha1
from charm.toolbox.hash_module import Hash
from charm.schemes.abenc.abenc_bsw07 import CPabe_BSW07
from charm.toolbox.secretutil import SecretUtil
# from charm.toolbox.IBSig import BLS01
from charm.schemes.pksig.pksig_bls04 import BLS01


import random

group = PairingGroup('SS512')
abe = CPabe_BSW07(group)
sig = BLS01(group)
hash_obj = Hash(group)
util = SecretUtil(group, verbose=False)


def setup():
    (master_key, public_key) = abe.setup()
    sig_key = sig.keygen()
    bloom_filter_size = 1000  # random size for Bloom filter
    return master_key, public_key, sig_key, bloom_filter_size

def create_bloom_filter(keywords, bloom_filter_size):
    bloom_filter = [0] * bloom_filter_size
    for keyword in keywords:
        keyword_hash = hash_obj.hashToZr(keyword)
        index = int(keyword_hash) % bloom_filter_size
        bloom_filter[index] = 1
    return bloom_filter

def build_index(master_key, public_key, sig_key, keywords, data_files):

    bloom_filters = []
    signatures = {}
    index = []

    for data_file, keyword_group in zip(data_files, keywords):
        symmetric_key = group.random(ZR)
        encrypted_file = symmetric_encrypt(data_file, symmetric_key)

        encrypted_key = abe.encrypt(public_key, symmetric_key, 'AND')

        bloom_filter = create_bloom_filter(keyword_group, 1000)
        bloom_filters.append(bloom_filter)

        for keyword in keyword_group:
            encrypted_keyword = abe.encrypt(public_key, hash_obj.hashToZr(keyword), 'AND')

            if isinstance(encrypted_keyword, dict) and 'ciphertext' in encrypted_keyword:
                encrypted_keyword = encrypted_keyword['ciphertext']  # Adjust based on actual output structure

            # Attempt to serialize after confirming type
            try:
                serialized_keyword = group.serialize(encrypted_keyword)
            except TypeError:
                raise TypeError("Failed to serialize encrypted_keyword. Ensure it is a valid group element.")

            # signature = sig.sign(sig_key['sk'], encrypted_keyword)
            signature = sig.sign(sig_key[1], encrypted_keyword)
            signatures[keyword] = (encrypted_keyword, signature)
            index.append((encrypted_keyword, encrypted_file, signature))

    # global_sig = sig.sign(sig_key['sk'], "".join(str(bloom_filters)))
    global_sig = sig.sign(sig_key[1], "".join(str(bloom_filters)))
    return index, bloom_filters, global_sig

def symmetric_encrypt(data, key):
    return data[::-1]  # Reverse data as a placeholder for actual encryption

def token_gen(master_key, public_key, user_attributes, keyword):
    user_key = abe.keygen(public_key, master_key, user_attributes)
    token = abe.decrypt(user_key, hash_obj.hashToZr(keyword))
    return token

def search_index(index, bloom_filters, global_sig, token, sig_key):
    for encrypted_keyword, encrypted_file, sig in index:
        if abe.decrypt(token, encrypted_keyword):
            # Verify the keyword's local signature
            # if sig.verify(sig_key['pk'], encrypted_keyword, sig):
            if sig.verify(sig_key[0], encrypted_keyword, sig):
                return encrypted_file, "Keyword Found and Verified"
            else:
                return None, "Verification Failed"
    for bloom_filter in bloom_filters:
        if bloom_filter_contains(bloom_filter, token):
            return None, "Keyword Not Found"
    return None, "Keyword Not Found"

def bloom_filter_contains(bloom_filter, token):
    token_index = int(token) % len(bloom_filter)
    return bloom_filter[token_index] == 1

def verify(public_key, sig_key, token, search_result, proof, bloom_filters):
    encrypted_file, verification_msg = search_result
    if verification_msg == "Keyword Found and Verified":
        # return sig.verify(sig_key['pk'], "".join(str(bloom_filters)), proof)
        return sig.verify(sig_key[0], "".join(str(bloom_filters)), proof)
    return False

def test_vabks():
    
    master_key, public_key, sig_key, bloom_filter_size = setup()
    
    data_files = ["Data file 1 contents", "Data file 2 contents"]
    keywords = [["keyword1", "keyword2"], ["keyword3", "keyword4"]]

    index, bloom_filters, global_sig = build_index(master_key, public_key, sig_key, keywords, data_files)

    token = token_gen(master_key, public_key, ['A', 'B'], "keyword1")

    search_result = search_index(index, bloom_filters, global_sig, token, sig_key)

    verification = verify(public_key, sig_key, token, search_result, global_sig, bloom_filters)
    
    print("Search Result:", search_result)
    print("Verification:", "Success" if verification else "Failed")

test_vabks()
