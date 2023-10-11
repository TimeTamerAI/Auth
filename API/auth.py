import json
import traceback

import redis
from fastapi import Depends, FastAPI, HTTPException, Request
from firebase_admin import auth, credentials, initialize_app

from settings import (BASE_URL, REDIS_HOST, REDIS_PASSWORD, REDIS_PORT,
                      REDIS_TLS_CERT_PATH, SERVICE_ACCOUNT_KEY)
from Token.token import SessionTokenManager

app = FastAPI()

# Initialize Firebase Admin SDK
cred = credentials.Certificate(SERVICE_ACCOUNT_KEY)
initialize_app(cred)

redis_client = redis.StrictRedis(
    host=REDIS_HOST,
    port=REDIS_PORT,
    db=0,
    password=REDIS_PASSWORD,
    ssl=True,
    ssl_ca_certs=REDIS_TLS_CERT_PATH,
)

# Initialize SessionTokenManager with Redis client
token_manager = SessionTokenManager(redis_client)


def verify_session_token(request: Request) -> dict:
    """
    Verify the session token from the request headers.

    Args:
    - request (Request): The incoming request.

    Returns:
    - dict: Token data if valid.

    Raises:
    - HTTPException: If the session token is missing or invalid.
    """
    session_token = request.headers.get("Authorization")
    if not session_token:
        raise HTTPException(status_code=401, detail="No session token provided")

    token_data = redis_client.get(session_token)
    if not token_data:
        raise HTTPException(status_code=401, detail="Invalid session token")

    # Decode token data from bytes to a dictionary
    return json.loads(token_data)


@app.post("/signup")
async def signup(email: str) -> dict:
    """
    Generate a verification link for the user's email for sign-up.

    Args:
    - email (str): The user's email address.

    Returns:
    - dict: A message indicating the result of the operation.
    """
    try:
        user_record = auth.create_user(email=email)

        action_code_settings = auth.ActionCodeSettings(
            url=f"{BASE_URL}/login",
        )

        link = auth.generate_email_verification_link(email, action_code_settings)
        return {"link": link, "user_id": user_record.uid}

    except Exception as e:
        print(traceback.format_exc())  # Keep this for future debugging
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/start_session")
async def start_session(firebase_token: str) -> dict:
    """
    Start a server-side session after verifying the Firebase token.

    Args:
    - firebase_token (str): The token from Firebase.

    Returns:
    - dict: The session token.
    """
    try:
        # Verify the Firebase token
        decoded_token = auth.verify_id_token(firebase_token)
        uid = decoded_token["uid"]

        # Generate a session token for your server-side session handling
        session_token, token_data = token_manager.generate_session_token(
            uid, {"role": "user"}
        )
        redis_client.setex(
            session_token,
            SessionTokenManager.TOKEN_EXPIRATION_SECONDS,
            json.dumps(token_data),
        )

        return {"session_token": session_token}
    except Exception as e:
        raise HTTPException(status_code=401, detail=str(e))


@app.post("/revoke_session")
async def revoke_session(token_data: dict = Depends(verify_session_token)) -> dict:
    """
    Revoke a session token.

    Args:
    - token_data (dict): The token data, obtained from the request headers.

    Returns:
    - dict: A message indicating the result of the operation.
    """
    try:
        session_token = token_data.get("session_token")
        if redis_client.exists(session_token):
            redis_client.delete(session_token)
            return {"message": "Session token revoked successfully"}
        else:
            raise HTTPException(status_code=400, detail="Invalid session token")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    return token_data


@app.post("/logout")
async def logout(token_data: dict = Depends(verify_session_token)) -> dict:
    """
    Log the user out by deleting their session token.

    Args:
    - token_data (dict): The token data, obtained from the request headers.

    Returns:
    - dict: A message indicating the result of the operation.
    """
    try:
        session_token = token_data.get("session_token")
        if redis_client.exists(session_token):
            redis_client.delete(session_token)
            return {"message": "Logged out successfully"}
        else:
            raise HTTPException(status_code=400, detail="Invalid session token")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
