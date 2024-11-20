from charm.toolbox.pairinggroup import PairingGroup
from charm.toolbox.pairinggroup import PairingGroup
from charm.toolbox.pksig_bls04 import BLS01 

group = PairingGroup('MNT224')
messages = { 'a':"hello world!!!", 'b':"test message" }
ib = BLS01(group)
(public_key, secret_key) = ib.keygen()
signature = ib.sign(secret_key['x'], messages)
ib.verify(public_key, signature, messages)
