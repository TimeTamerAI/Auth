import json
import logging
import traceback
import os

import firebase_admin.auth as firebase_auth
import redis
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from firebase_admin import credentials, initialize_app
from pydantic import BaseModel
from tortoise.exceptions import IntegrityError

from db_config import close_db, init_db
from Model.user import User, UserProfile
from settings import BASE_URL, REDIS_HOST, REDIS_PORT, SERVICE_ACCOUNT_KEY
from Token.token import SessionTokenManager

logging.basicConfig(
    level=logging.INFO, format="[%(asctime)s] [%(levelname)s] - %(message)s"
)

origins = [
    BASE_URL,  # Frontend origin
    # Add any other origins if needed
]


app = FastAPI()


@app.on_event("startup")
async def startup_event():
    if os.environ.get("ENV") != "TEST":
        await init_db()


@app.on_event("shutdown")
async def shutdown_event():
    if os.environ.get("ENV") != "TEST":
        await close_db()


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
    name: str
    email: str


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

    # Check if the token has the "Bearer " prefix and strip it
    if session_token and session_token.startswith("Bearer "):
        session_token = session_token[7:]

    logging.info(f"session token to be verified: {session_token}")

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
     - request_data (SignupRequest): Contains the user's name and email.

     Returns:
     - dict: A message indicating the result of the operation.
    """
    email = request_data.email
    name = request_data.name
    logging.info(f"Signup endpoint called with email: {email} and name: {name}")
    try:
        user_record = firebase_auth.create_user(email=email, display_name=name)

        # Create user in the local database
        try:
            await User.create(firebase_uid=user_record.uid, name=name, email=email)
        except IntegrityError:
            raise HTTPException(status_code=400, detail="User already exists")

        action_code_settings = firebase_auth.ActionCodeSettings(
            url=f"{BASE_URL}/login",
        )

        link = firebase_auth.generate_email_verification_link(
            email, action_code_settings
        )
        return {"link": link, "user_id": user_record.uid}

    except Exception as e:
        print(traceback.format_exc())  # Keep this for future debugging
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/start_session")
async def start_session(data: dict) -> dict:
    """
    Starts a session for the authenticated user.

    This function performs the following steps:
    1. Extracts the Firebase token from the provided data.
    2. Verifies the Firebase token.
    3. Fetches the user's details from the database using the UID from the decoded token.
    4. Generates a session token using the user's details.
    5. Stores the session token and its associated data in Redis.
    6. Returns the session token as a response.

    Args:
    - data (dict): A dictionary containing the Firebase token.

    Returns:
    - dict: A dictionary containing the session token for the authenticated user.

    Raises:
    - HTTPException: If the Firebase token is missing or if the user is not found in the database.
    - Any exceptions that might occur during token verification, session token generation, or Redis operations.
    """
    logging.info(
        f"start_session endpoint called with token: {data.get('firebase_token')}"
    )

    try:
        firebase_token = data.get("firebase_token")
        if not firebase_token:
            raise HTTPException(status_code=400, detail="Missing firebase_token")

        # Verify the Firebase token
        decoded_token = firebase_auth.verify_id_token(firebase_token)
        uid = decoded_token["uid"]

        # Fetch the user details from the database using the uid
        user = await User.get(firebase_uid=uid)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        user_info = {
            "id": user.id,
            "firebase_uid": user.firebase_uid,
            "name": user.name,
            "email": user.email,
        }

        # Generate a session token with the user details
        session_token, token_data = token_manager.generate_session_token(
            uid, user_info=user_info
        )

        # Store the session token and its data in Redis
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


@app.get("/me", response_model=UserProfile)
async def get_user_profile(
    token_data: dict = Depends(verify_session_token),
) -> UserProfile:
    """
    Retrieves the profile information of the authenticated user.

    This function performs the following steps:
    1. Extracts the `user_info` dictionary from the provided token data.
    2. Extracts the user's Firebase UID, name, and email from the `user_info`.
    3. Checks the completeness of the extracted details.
    4. Returns the user's profile information as a `UserProfile` model.

    Note: To ensure the user exists in the database, uncomment the relevant lines in the function.

    Args:
    - token_data (dict): A dictionary containing the decoded session token data.

    Returns:
    - UserProfile: A model containing the user's Firebase UID, name, and email.

    Raises:
    - HTTPException: If the user details in the token are incomplete or if there are any other exceptions during processing.
    """
    try:
        # Get the user_info dictionary from the token_data
        user_info = token_data.get("user_info", {})

        # Extract details from the user_info dictionary
        firebase_uid = user_info.get("firebase_uid")
        name = user_info.get("name")
        email = user_info.get("email")

        # Ensure all the necessary details are present
        if not firebase_uid or not name or not email:
            raise HTTPException(
                status_code=400, detail="Incomplete user details in token"
            )

        # If you want to ensure the user exists in the database, uncomment the next lines
        # user = await User.get(firebase_uid=firebase_uid)
        # if not user:
        #     raise HTTPException(status_code=404, detail="User not found")

        return UserProfile(firebase_uid=firebase_uid, name=name, email=email)

    except Exception as e:
        logging.error(traceback.format_exc())
        raise HTTPException(status_code=500, detail=str(e))
