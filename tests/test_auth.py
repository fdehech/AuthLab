import pytest
from unittest.mock import patch, MagicMock

def test_register_user(client):
    response = client.post(
        "/register",
        json={"sub": "testuser", "password": "testpassword", "role": "user"}
    )
    assert response.status_code == 200
    assert response.json()["message"] == "User created successfully"

def test_register_duplicate_user(client):
    # First registration
    client.post(
        "/register",
        json={"sub": "testuser2", "password": "testpassword", "role": "user"}
    )
    # Duplicate registration
    response = client.post(
        "/register",
        json={"sub": "testuser2", "password": "testpassword", "role": "user"}
    )
    assert response.status_code == 400
    assert response.json()["detail"] == "User/Email already registered"

@patch("app.routes.auth.storage")
@patch("app.auth.storage")
def test_login_success(mock_auth_storage, mock_route_storage, client):
    # Setup: Register a user
    client.post(
        "/register",
        json={"sub": "loginuser", "password": "loginpassword", "role": "user"}
    )
    
    # Mock Redis for rate limiting and session storage
    mock_auth_storage.incr.return_value = 1
    
    response = client.post(
        "/login",
        json={"sub": "loginuser", "password": "loginpassword"}
    )
    
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["token_type"] == "bearer"
    
    # Verify Redis calls (in the route)
    mock_route_storage.set.assert_called()
    mock_route_storage.sadd.assert_called()

@patch("app.routes.auth.storage")
@patch("app.auth.storage")
def test_login_invalid_credentials(mock_auth_storage, mock_route_storage, client):
    mock_auth_storage.incr.return_value = 1
    
    response = client.post(
        "/login",
        json={"sub": "nonexistent", "password": "wrongpassword"}
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid email or password"

@patch("app.routes.auth.storage")
def test_refresh_token(mock_route_storage, client):
    # Setup: Register and login to get a refresh token
    client.post(
        "/register",
        json={"sub": "refreshuser", "password": "password", "role": "user"}
    )
    
    # Mock Redis behavior for refresh token
    mock_route_storage.get.return_value = "refreshuser"
    
    response = client.post(
        "/refresh",
        json={"refresh_token": "valid_refresh_token"}
    )
    
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert "refresh_token" in data
    
    # Verify rotation logic
    mock_route_storage.delete.assert_called_with("refresh:valid_refresh_token")
    mock_route_storage.srem.assert_called()

@patch("app.routes.auth.storage")
def test_logout(mock_route_storage, client):
    mock_route_storage.get.return_value = "testuser"
    
    response = client.post(
        "/logout",
        json={"refresh_token": "some_token"}
    )
    
    assert response.status_code == 200
    assert response.json()["message"] == "Logout successful"
    mock_route_storage.delete.assert_called_with("refresh:some_token")
    mock_route_storage.srem.assert_called()

@patch("app.routes.auth.storage")
@patch("app.auth.storage")
def test_change_password(mock_auth_storage, mock_route_storage, client):
    # Setup: Register
    client.post(
        "/register",
        json={"sub": "changeuser", "password": "oldpassword", "role": "user"}
    )
    
    # Login to get access token
    mock_auth_storage.incr.return_value = 1
    login_resp = client.post(
        "/login",
        json={"sub": "changeuser", "password": "oldpassword"}
    )
    token = login_resp.json()["access_token"]
    
    # Mock Redis for session revocation
    mock_auth_storage.smembers.return_value = {b"token1", b"token2"}
    
    # Change password
    response = client.post(
        "/change-password",
        json={"current_password": "oldpassword", "new_password": "newpassword"},
        headers={"Authorization": f"Bearer {token}"}
    )
    
    assert response.status_code == 200
    assert "Logged out from all sessions" in response.json()["message"]
    
    # Verify old password no longer works
    login_resp_old = client.post(
        "/login",
        json={"sub": "changeuser", "password": "oldpassword"}
    )
    assert login_resp_old.status_code == 401
    
    # Verify new password works
    login_resp_new = client.post(
        "/login",
        json={"sub": "changeuser", "password": "newpassword"}
    )
    assert login_resp_new.status_code == 200
