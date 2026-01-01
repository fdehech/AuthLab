import pytest
from unittest.mock import patch
from fastapi import HTTPException
from app.auth import check_login_rate_limit

@patch("app.auth.storage")
def test_rate_limit_not_exceeded(mock_storage):
    mock_storage.incr.return_value = 1
    # Should not raise exception
    check_login_rate_limit("127.0.0.1")
    mock_storage.expire.assert_called()

@patch("app.auth.storage")
def test_rate_limit_exceeded(mock_storage):
    mock_storage.incr.return_value = 6 # LOGIN_LIMIT is 5
    mock_storage.ttl.return_value = 30
    
    with pytest.raises(HTTPException) as excinfo:
        check_login_rate_limit("127.0.0.1")
    
    assert excinfo.value.status_code == 429
    assert "Too many login attempts" in excinfo.value.detail
