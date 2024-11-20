from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT, pair
from charm.schemes.abenc.abenc_bsw07 import CPabe_BSW07  # Import CPabe_BSW07

group = PairingGroup('SS512')
cpabe = CPabe_BSW07(group)
msg = group.random(GT)
attributes = ['ONE', 'TWO', 'THREE']
access_policy = '((four or three) and (three or one))'
(master_public_key, master_key) = cpabe.setup()
secret_key = cpabe.keygen(master_public_key, master_key, attributes)
cipher_text = cpabe.encrypt(master_public_key, msg, access_policy)
decrypted_msg = cpabe.decrypt(master_public_key, secret_key, cipher_text)
print(msg == decrypted_msg)  # Should print True if encryption and decryption work correctly
