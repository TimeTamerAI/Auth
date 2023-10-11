import base64
import json
import logging
import traceback

import redis
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from firebase_admin import auth, credentials, initialize_app
from pydantic import BaseModel

from settings import (BASE_URL, REDIS_HOST, REDIS_PASSWORD, REDIS_PORT,
                      REDIS_TLS_CERT_PATH, SERVICE_ACCOUNT_KEY)
from Token.token import SessionTokenManager

logging.basicConfig(
    level=logging.INFO, format="[%(asctime)s] [%(levelname)s] - %(message)s"
)

origins = [
    BASE_URL,  # Frontend origin
    # Add any other origins if needed
]


app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize Firebase Admin SDK
cred = credentials.Certificate(SERVICE_ACCOUNT_KEY)
initialize_app(cred)

redis_client = redis.StrictRedis(
    host=REDIS_HOST,
    port=REDIS_PORT,
    db=0,
    # password=REDIS_PASSWORD,
    # ssl=True,
    # ssl_ca_certs=REDIS_TLS_CERT_PATH,
)

# Initialize SessionTokenManager with Redis client
token_manager = SessionTokenManager(redis_client)


class SignupRequest(BaseModel):
    email: str


def decode_jwt_payload(jwt_token):
    # Split the token into its parts: header, payload, signature
    header, payload, signature = jwt_token.split(".")

    # Decode the payload
    payload += "=" * ((4 - len(payload) % 4) % 4)  # Ensure padding exists
    decoded_payload = base64.urlsafe_b64decode(payload).decode("utf-8")

    return json.loads(decoded_payload)


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
async def signup(request_data: SignupRequest) -> dict:
    """
    Generate a verification link for the user's email for sign-up.

    Args:
    - email (str): The user's email address.

    Returns:
    - dict: A message indicating the result of the operation.
    """
    email = request_data.email
    logging.info(f"Signup endpoint called with email: {email}")
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
async def start_session(data: dict) -> dict:
    """
    Start a server-side session after verifying the Firebase token.

    Args:
    - data (dict): JSON data containing the "firebase_token".

    Returns:
    - dict: The session token.
    """
    logging.info(
        f"start_session endpoint called with token: {data.get('firebase_token')}"
    )
    try:
        firebase_token = data.get("firebase_token")
        if not firebase_token:
            raise HTTPException(status_code=400, detail="Missing firebase_token")

        decoded_payload = decode_jwt_payload(firebase_token)
        print("Issued At (iat):", decoded_payload.get("iat"))
        print("Not Before (nbf):", decoded_payload.get("nbf"))

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
        logging.exception("Error in start_session: %s", str(e))
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
    logging.info("Revoke session endpoint called.")
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
    logging.info("Logout endpoint called.")
    try:
        session_token = token_data.get("session_token")
        if redis_client.exists(session_token):
            redis_client.delete(session_token)
            return {"message": "Logged out successfully"}
        else:
            raise HTTPException(status_code=400, detail="Invalid session token")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
