from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, pair

# Initialize a pairing group
group = PairingGroup('SS512')  # Select a group based on a security parameter

# Generate random elements in G1, G2, and ZR
a = group.random(ZR)
g1 = group.random(G1)
g2 = group.random(G2)

# Pairing operation example
pairing_result = pair(g1, g2) ** a

print("Random element in ZR (a):", a)
print("Random element in G1 (g1):", g1)
print("Random element in G2 (g2):", g2)
print("Pairing result:", pairing_result)
