import uuid
import hashlib
import time
import json
from typing import Dict, Tuple, Optional, Union


class SessionTokenManager:
    """Manages the creation, validation, and storage of session tokens."""

    TOKEN_EXPIRATION_SECONDS = 30 * 24 * 60 * 60  # 1 month in seconds

    def __init__(self, redis_client) -> None:
        """
        Initialize the SessionTokenManager with the given Redis client.

        Args:
        - redis_client: The Redis client used for token storage and retrieval.
        """
        self.redis = redis_client

    def generate_session_token(
        self, uid: str, claims: Optional[Dict[str, str]] = None
    ) -> Tuple[str, Dict[str, Union[str, int, Dict[str, str]]]]:
        """
        Generate a new session token for the given user ID and claims.

        Args:
        - uid (str): The unique identifier for the user.
        - claims (Optional[Dict[str, str]]): Additional claims to include in the token.

        Returns:
        - Tuple[str, Dict[str, Union[str, int, Dict[str, str]]]]: The generated session token and its data.
        """
        # Create a base token dictionary
        token_dict = {
            "user_id": uid,
            "token_id": str(uuid.uuid4()),
            "issued_at": int(time.time()),  # current timestamp
            "expiry": int(time.time()) + self.TOKEN_EXPIRATION_SECONDS,
            "claims": claims or {},  # default to empty dict if no claims provided
        }

        # Convert token dictionary to string and hash it to produce the session token
        token_str = json.dumps(token_dict, sort_keys=True)
        session_token = hashlib.sha256(token_str.encode()).hexdigest()

        return session_token, token_dict

    def validate_session_token(
        self, token: str
    ) -> Optional[Dict[str, Union[str, int, Dict[str, str]]]]:
        """
        Validate the given session token.

        Args:
        - token (str): The session token to validate.

        Returns:
        - Optional[Dict[str, Union[str, int, Dict[str, str]]]]: The token data if valid, None otherwise.
        """
        token_details = self.redis.get(token)
        if not token_details:
            return None

        token_dict = json.loads(token_details.decode("utf-8"))

        # Check if the token has expired
        if token_dict["expiry"] < time.time():
            return None

        return token_dict
