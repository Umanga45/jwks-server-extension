import jwt
import time

def issue_jwt(jwks, private_key=None, expired=False):
    if expired:
        # Use an expired key for the token (dummy implementation)
        # Implement your logic to get the expired key if needed
        pass

    # Default to the first key in the list
    key = jwks.keys[0]["private_key"] if private_key is None else private_key

    # Create a JWT token
    token = jwt.encode(
        {
            "sub": "fakeuser",  # Subject of the token
            "iat": time.time(),  # Issued at time
            "exp": time.time() + 3600  # Expiration time (1 hour)
        },
        key,
        algorithm="RS256"
    )
    return token
