from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from base64 import urlsafe_b64encode

# Load your public key
with open('public.pem', 'rb') as f:
    public_key = serialization.load_pem_public_key(
        f.read(),
        backend=default_backend()
    )

# Ensure the loaded key is RSA (this example is specific to RSA keys)
if not isinstance(public_key, rsa.RSAPublicKey):
    raise ValueError("The public key is not an RSA key.")

# Extract the modulus and exponent
public_num = public_key.public_numbers()
n = urlsafe_b64encode(public_num.n.to_bytes((public_num.n.bit_length() + 7) // 8, byteorder='big')).decode('utf-8').rstrip("=")
e = urlsafe_b64encode(public_num.e.to_bytes((public_num.e.bit_length() + 7) // 8, byteorder='big')).decode('utf-8').rstrip("=")

# Construct the JWKS
jwks = {
    "keys": [
        {
            "kty": "RSA",
            "use": "sig",
            "kid": "jwt_challenge",  # You should assign a meaningful and unique ID here
            "alg": "RS256",
            "n": n,
            "e": e
        }
    ]
}

# Print or save the JWKS to a file
print(jwks)
