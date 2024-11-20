from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, GT, pair
from charm.toolbox.hash_module import Hash
from charm.schemes.abenc.abenc_bsw07 import CPabe_BSW07
from charm.toolbox.secretutil import SecretUtil
from charm.schemes.pksig.pksig_bls04 import BLS01
import random
import base64

group = PairingGroup('SS512')
abe = CPabe_BSW07(group)
sig = BLS01(group)
hash_obj = Hash(group)
util = SecretUtil(group, verbose=False)

def setup():
    (master_key, public_key) = abe.setup()
    sig_key = sig.keygen()
    bloom_filter_size = 1000  # Adjust as needed
    return master_key, public_key, sig_key, bloom_filter_size

def create_bloom_filter_optimized(keywords, bloom_filter_size, num_hashes):
    bloom_filter = [0] * bloom_filter_size
    for keyword in keywords:
        for i in range(num_hashes):
            index = int(hash_obj.hashToZr(str(keyword) + str(i))) % bloom_filter_size
            bloom_filter[index] = 1
    return bloom_filter

def create_masked_bloom_filter(keywords, bloom_filter_size, num_hashes, random_number):
    bloom_filter = create_bloom_filter_optimized(keywords, bloom_filter_size, num_hashes)
    masked_bloom_filter = [(bit ^ int(random_number)) for bit in bloom_filter]
    return masked_bloom_filter

def generate_local_signature(sig_key, keyword_ciphertexts):
    group_signature = sig.sign(sig_key, "".join(str(c) for c in keyword_ciphertexts))
    return group_signature

def generate_global_signature(sig_key, bloom_filters):
    combined_filter_str = "".join(str(filter) for filter in bloom_filters)
    global_signature = sig.sign(sig_key, combined_filter_str)
    return global_signature

def symmetric_encrypt(data, key):
    return data[::-1]  # Simple reverse as placeholder

def build_index(master_key, public_key, sig_key, keywords, data_files):
    bloom_filters = []
    masked_filters = []
    signatures = {}
    index = []
    random_number = group.random(ZR)  # Random for masking

    for data_file, keyword_group in zip(data_files, keywords):
        symmetric_key = group.random(ZR)
        encrypted_file = symmetric_encrypt(data_file, symmetric_key)

        encrypted_key = abe.encrypt(public_key, symmetric_key, 'AND')

        masked_bloom_filter = create_masked_bloom_filter(
            keyword_group, 1000, num_hashes=3, random_number=random_number
        )
        bloom_filters.append(masked_bloom_filter)

        for keyword in keyword_group:
            encrypted_keyword = abe.encrypt(public_key, hash_obj.hashToZr(str(keyword)), 'AND')
            signature = sig.sign(sig_key[1], encrypted_keyword)
            signatures[keyword] = (encrypted_keyword, signature)
            index.append((encrypted_keyword, encrypted_file, signature))

    local_sig = generate_local_signature(sig_key[1], [i[0] for i in index])
    global_sig = generate_global_signature(sig_key[1], bloom_filters)

    return index, bloom_filters, global_sig, masked_filters, local_sig

def token_gen(master_key, public_key, user_attributes, keyword):
    user_key = abe.keygen(public_key, master_key, user_attributes)
    token = abe.encrypt(public_key, hash_obj.hashToZr(str(keyword)), 'AND')
    return token

def search_index_with_null_validation(index, masked_filters, token, sig_key):
    for encrypted_keyword, encrypted_file, sig in index:
        if abe.decrypt(token, encrypted_keyword):
            if sig.verify(sig_key[0], encrypted_keyword, sig):
                return encrypted_file, "Keyword Found and Verified"
            else:
                return None, "Verification Failed"

    for masked_filter in masked_filters:
        if bloom_filter_contains_masked(masked_filter, token):
            return None, "Keyword Not Found"

    return None, "Keyword Not Found"

def bloom_filter_contains_masked(masked_bloom_filter, token):
    token_index = int(token) % len(masked_bloom_filter)
    return masked_bloom_filter[token_index] == 1

def verify_with_full_proof(public_key, sig_key, token, search_result, proof, masked_filters):
    encrypted_file, verification_msg = search_result

    if not sig.verify(sig_key[0], "".join(str(masked_filters)), proof['global_sig']):
        return False, "Global Signature Verification Failed"

    if verification_msg == "Keyword Found and Verified":
        local_sig = proof['local_sig']
        if not sig.verify(sig_key[0], "".join(proof['ciphertexts']), local_sig):
            return False, "Local Signature Verification Failed"
        return True, "Verification Successful"

    masked_bloom_filter = proof['masked_bloom_filter']
    if bloom_filter_contains_masked(masked_bloom_filter, token):
        return False, "Masked Bloom Filter Verification Failed"

    return True, "Verification Successful"

def test_vabks():
    master_key, public_key, sig_key, bloom_filter_size = setup()

    data_files = ["Data file 1 contents", "Data file 2 contents"]
    keywords = [["keyword1", "keyword2"], ["keyword3", "keyword4"]]

    index, bloom_filters, global_sig, masked_filters, local_sig = build_index(
        master_key, public_key, sig_key, keywords, data_files
    )

    token = token_gen(master_key, public_key, ['A', 'B'], "keyword1")
    search_result = search_index_with_null_validation(index, masked_filters, token, sig_key)

    proof = {
        'global_sig': global_sig,
        'local_sig': local_sig,
        'masked_bloom_filter': masked_filters[0],
        'ciphertexts': [i[0] for i in index]
    }

    verification = verify_with_full_proof(public_key, sig_key, token, search_result, proof, masked_filters)

    print("Search Result:", search_result)
    print("Verification:", "Success" if verification else "Failed")

# Run the test
test_vabks()
