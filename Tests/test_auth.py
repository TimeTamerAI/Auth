import json
from unittest.mock import AsyncMock, Mock, patch

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

import API.auth as auth_module
from API.auth import app

# Sample test data
valid_token_data = {
    "session_token": "sample_session_token",
    "user_info": {
        "firebase_uid": "sample_uid",
        "name": "John Doe",
        "email": "john@example.com",
    },
}

incomplete_token_data = {
    "session_token": "sample_session_token",
    "user_info": {
        "firebase_uid": "sample_uid",
        "name": "John Doe"
        # Missing email
    },
}

sample_firebase_token = "sample_firebase_token"


client = TestClient(app)


def test_verify_session_token_valid():
    """
    Test the function `verify_session_token` when provided with a valid session token.

    This test mocks the Redis client to return predefined token data when queried with a
    specific token. It then verifies that the function correctly decodes and returns this token data.
    """
    with patch("API.auth.redis_client.get", return_value=json.dumps(valid_token_data)):
        from API.auth import verify_session_token

        # Mock the request object
        mock_request = Mock()
        mock_request.headers.get.return_value = "Bearer sample_session_token"

        result = verify_session_token(mock_request)
        assert result == valid_token_data


def test_verify_session_token_invalid():
    """
    Test the function `verify_session_token` when provided with an invalid session token.

    This test mocks the Redis client to return None (indicating the token is not present in Redis).
    It then verifies that the function raises an HTTPException with a 401 status code.
    """
    with patch("API.auth.redis_client.get", return_value=None):
        from API.auth import verify_session_token

        # Mock the request object
        mock_request = Mock()
        mock_request.headers.get.return_value = "Bearer invalid_token"

        with pytest.raises(HTTPException) as exc:
            verify_session_token(mock_request)
        assert exc.value.status_code == 401


def test_signup():
    """
    Test the `/signup` endpoint.

    This test mocks the interactions with Firebase to create a user and generate an email verification link.
    It also mocks the interaction with the local database to create a user. It then verifies that the endpoint
    correctly calls the mocked functions with the expected arguments and returns the expected response.
    """
    with patch("firebase_admin.auth.create_user") as mock_create_user, patch(
        "Model.user.User.create"
    ) as mock_db_create, patch(
        "firebase_admin.auth.generate_email_verification_link"
    ) as mock_gen_link:
        # Mock return values for the functions you're mocking
        mock_create_user.return_value = Mock(uid="sample_uid")
        mock_gen_link.return_value = "sample_link"

        # Create a TestClient instance using the app from auth module in API directory
        client = TestClient(auth_module.app)

        # Call the signup endpoint
        response = client.post(
            "/signup", json={"name": "Test User", "email": "test@example.com"}
        )

        # Check that the mocked functions were called correctly
        mock_create_user.assert_called_once_with(
            email="test@example.com", display_name="Test User"
        )
        mock_db_create.assert_called_once_with(
            firebase_uid="sample_uid", name="Test User", email="test@example.com"
        )
        mock_gen_link.assert_called_once()

        # Check the response
        assert response.status_code == 200
        assert response.json() == {"link": "sample_link", "user_id": "sample_uid"}


@pytest.mark.asyncio
async def test_start_session_valid():
    """
    Test the `/start_session` endpoint when provided with a valid Firebase token.

    This test mocks the interactions with Firebase to verify a provided token, the local database to fetch
    user details, and Redis to set the session token. It also mocks the session token generation.
    It then verifies that the endpoint correctly calls the mocked functions with the expected arguments
    and returns the expected response.
    """
    with patch("API.auth.redis_client.setex", AsyncMock(return_value=True)):
        with patch(
            "API.auth.firebase_auth.verify_id_token", return_value={"uid": "sample_uid"}
        ):
            with patch(
                "API.auth.User.get",
                new_callable=AsyncMock,
                return_value=Mock(
                    id=1,
                    firebase_uid="sample_uid",
                    name="John Doe",
                    email="john@example.com",
                ),
            ):
                with patch(
                    "API.auth.token_manager.generate_session_token",
                    return_value=("sample_session_token", valid_token_data),
                ):
                    response = client.post(
                        "/start_session", json={"firebase_token": sample_firebase_token}
                    )
                    assert response.status_code == 200
                    assert response.json() == {"session_token": "sample_session_token"}


def test_get_user_profile_valid():
    """
    Test the `/me` endpoint to retrieve the user profile of an authenticated user.

    This test mocks the verification of the session token and the Redis client to return predefined token data.
    It then verifies that the endpoint correctly decodes the session token and returns the user's profile data.
    """
    with patch("API.auth.verify_session_token", return_value=valid_token_data):
        # Mock Redis client
        with patch(
            "API.auth.redis_client.get", return_value=json.dumps(valid_token_data)
        ):
            headers = {"Authorization": "Bearer sample_session_token"}
            response = client.get("/me", headers=headers)
        assert response.status_code == 200
        assert response.json() == {
            "firebase_uid": "sample_uid",
            "name": "John Doe",
            "email": "john@example.com",
        }
