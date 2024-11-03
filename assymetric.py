#!/usr/bin/env python3

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
import sys

# 1. Generate RSA Key Pair (Only once)
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
public_key = private_key.public_key()

# 2. Serialize (export) the keys if you need to store them
private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# 3. Get the message from command-line arguments and encrypt it
if len(sys.argv) < 2:
    print("Usage: ./assymmetric.py <message>")
    sys.exit(1)

# Join arguments into a single string and encode as bytes
message = " ".join(sys.argv[1:]).encode('utf-8')

# Encrypt the message
encrypted_message = public_key.encrypt(
    message,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

# Decrypt the message
decrypted_message = private_key.decrypt(
    encrypted_message,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

# Print results
print("Original message:", message.decode('utf-8'))
print("Encrypted message:", encrypted_message)
print("Decrypted message:", decrypted_message.decode('utf-8'))
