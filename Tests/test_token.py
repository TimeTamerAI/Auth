import json
from unittest.mock import Mock, patch

from Token.token import SessionTokenManager


def test_generate_session_token():
    """
    Test the generation of a session token with claims and user info.

    This test checks if the token and token data returned by
    `generate_session_token` method have expected structures.
    """
    mock_redis = Mock()
    manager = SessionTokenManager(mock_redis)

    uid = "test-uid"
    claims = {"role": "user"}
    user_info = {"name": "John", "email": "john@example.com"}

    token, token_data = manager.generate_session_token(uid, claims, user_info)

    # Basic assertions to ensure the token and token_data have expected structures
    assert token
    assert isinstance(token, str)
    assert token_data["user_id"] == uid
    assert token_data["claims"] == claims
    assert token_data["user_info"] == user_info
    assert "token_id" in token_data
    assert "issued_at" in token_data
    assert "expiry" in token_data


def test_validate_session_token_valid():
    """
    Test the validation of a valid session token.

    This test ensures that a previously generated token is
    considered valid by the `validate_session_token` method.
    """
    mock_redis = Mock()
    manager = SessionTokenManager(mock_redis)

    uid = "test-uid"
    token, token_data = manager.generate_session_token(uid)

    # Mock Redis get() method to return our token_data
    mock_redis.get.return_value = json.dumps(token_data).encode()

    validated_data = manager.validate_session_token(token)

    # Assertions to ensure validation returns expected data
    assert validated_data == token_data


@patch("time.time", return_value=1)  # Mocking time to always return 1 for this test
def test_validate_session_token_expired(mock_time):
    """
    Test the validation of an expired session token.

    This test ensures that an expired token is correctly
    identified as such by the `validate_session_token` method.
    """
    mock_redis = Mock()
    manager = SessionTokenManager(mock_redis)

    uid = "test-uid"
    token, token_data = manager.generate_session_token(uid)

    # Setting expiry to the past
    token_data["expiry"] = 0

    # Mock Redis get() method to return our token_data
    mock_redis.get.return_value = json.dumps(token_data).encode()

    validated_data = manager.validate_session_token(token)

    # Assertions to ensure validation returns None for expired tokens
    assert validated_data is None


def test_validate_session_token_invalid():
    """
    Test the validation of an invalid session token.

    This test ensures that an invalid token (one that isn't in
    the Redis store) is correctly identified as invalid by the
    `validate_session_token` method.
    """
    mock_redis = Mock()
    manager = SessionTokenManager(mock_redis)

    # Mock Redis get() method to return None (simulating an invalid token)
    mock_redis.get.return_value = None

    validated_data = manager.validate_session_token("invalid-token")

    # Assertions to ensure validation returns None for invalid tokens
    assert validated_data is None
