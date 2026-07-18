import os
from fastapi import HTTPException, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import jwt, JWTError
import requests
from functools import lru_cache

# Read Cognito configuration from environment variables
COGNITO_REGION = os.getenv("COGNITO_REGION", "us-east-2")
COGNITO_USER_POOL_ID = os.getenv("COGNITO_USER_POOL_ID", "us-east-2_4qSZVI2WH")
COGNITO_APP_CLIENT_ID = os.getenv("COGNITO_APP_CLIENT_ID", "223nnbea9edf3tach13ilck1mq")

# Construct the JWKs URL
COGNITO_JWKS_URL = f"https://cognito-idp.{COGNITO_REGION}.amazonaws.com/{COGNITO_USER_POOL_ID}/.well-known/jwks.json"

security = HTTPBearer()

@lru_cache()
def get_jwks():
    """Fetch and cache the JSON Web Key Set from Cognito"""
    response = requests.get(COGNITO_JWKS_URL)
    return response.json()

def verify_token(credentials: HTTPAuthorizationCredentials = Security(security)):
    """
    Verify the JWT token from AWS Cognito
    """
    token = credentials.credentials
    
    try:
        # Get the JWT headers to find the key id (kid)
        headers = jwt.get_unverified_headers(token)
        kid = headers['kid']
        
        # Find the correct key from JWKS
        jwks = get_jwks()
        key = None
        for jwk_key in jwks['keys']:
            if jwk_key['kid'] == kid:
                key = jwk_key
                break
        
        if not key:
            raise HTTPException(status_code=401, detail="Invalid token: key not found")
        
        # Verify and decode the token (removed audience check for access tokens)
        payload = jwt.decode(
            token,
            key,
            algorithms=['RS256'],
            options={
                "verify_exp": True,
                "verify_aud": False  # Cognito access tokens don't have audience
            }
        )
        
        return payload
        
    except JWTError as e:
        raise HTTPException(status_code=401, detail=f"Invalid token: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"Token validation failed: {str(e)}")

def get_current_user(token_payload: dict = Security(verify_token)):
    """
    Extract user information from the validated token
    """
    # Handle both ID token and access token formats
    email = token_payload.get("email") or token_payload.get("username")
    return {
        "email": email,
        "sub": token_payload.get("sub"),
        "username": token_payload.get("cognito:username") or token_payload.get("username")
    }