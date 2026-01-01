import pytest
from unittest.mock import patch

@patch("app.routes.auth.storage")
@patch("app.auth.storage")
def test_get_me(mock_auth_storage, mock_route_storage, client):
    # Setup: Register and login
    client.post(
        "/register",
        json={"sub": "meuser", "password": "password", "role": "user"}
    )
    mock_auth_storage.incr.return_value = 1
    login_resp = client.post(
        "/login",
        json={"sub": "meuser", "password": "password"}
    )
    token = login_resp.json()["access_token"]
    
    response = client.get(
        "/me",
        headers={"Authorization": f"Bearer {token}"}
    )
    
    assert response.status_code == 200
    assert response.json()["sub"] == "meuser"
    assert response.json()["role"] == "user"

@patch("app.routes.auth.storage")
@patch("app.auth.storage")
def test_admin_route_access_denied(mock_auth_storage, mock_route_storage, client):
    # Setup: Register as regular user
    client.post(
        "/register",
        json={"sub": "regularuser", "password": "password", "role": "user"}
    )
    mock_auth_storage.incr.return_value = 1
    login_resp = client.post(
        "/login",
        json={"sub": "regularuser", "password": "password"}
    )
    token = login_resp.json()["access_token"]
    
    response = client.get(
        "/admin",
        headers={"Authorization": f"Bearer {token}"}
    )
    
    assert response.status_code == 403
    assert response.json()["detail"] == "Forbidden"

@patch("app.routes.auth.storage")
@patch("app.auth.storage")
def test_admin_route_access_granted(mock_auth_storage, mock_route_storage, client):
    # Setup: Register as admin
    client.post(
        "/register",
        json={"sub": "adminuser", "password": "password", "role": "admin"}
    )
    mock_auth_storage.incr.return_value = 1
    login_resp = client.post(
        "/login",
        json={"sub": "adminuser", "password": "password"}
    )
    token = login_resp.json()["access_token"]
    
    response = client.get(
        "/admin",
        headers={"Authorization": f"Bearer {token}"}
    )
    
    assert response.status_code == 200
    assert response.json()["message"] == "Admin only"
    assert response.json()["user"]["role"] == "admin"
