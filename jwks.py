from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import time

class JWKS:
    def __init__(self):
        self.keys = []

    def generate_rsa_key(self):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        public_key = private_key.public_key()
        kid = str(len(self.keys) + 1)
        expiry = int(time.time()) + 3600
        
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        self.keys.append({
            "kid": kid,
            "private_key": private_pem,
            "public_key": public_pem.decode('utf-8'),
            "expiry": expiry
        })
        
        return private_key  # Return the private key

    def get_public_keys(self):
        return [
            {
                "kid": key["kid"],
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "n": key["public_key"],
                "e": str(65537)  # Ensure the exponent is returned as a string
            }
            for key in self.keys if key["expiry"] > time.time()
        ]
