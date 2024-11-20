# abe_setup.py
from charm.toolbox.pairinggroup import PairingGroup
from charm.schemes.abenc.abenc_waters09 import CPabe09

def abe_initialize():
    # Initialize pairing group for cryptographic operations
    group = PairingGroup('SS512')  # Use a secure pairing group
    abe = CPabe09(group)

    # Generate ABE master key and public key
    master_key, public_key = abe.setup()
    return abe, master_key, public_key
