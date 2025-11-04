"""Pytest configuration and fixtures for testing."""

import pytest
from unittest.mock import Mock, MagicMock
from defender_cloud_apps import DefenderCloudAppsClient


@pytest.fixture
def mock_response():
    """Create a mock HTTP response object."""
    response = Mock()
    response.status_code = 200
    response.json.return_value = {"data": []}
    response.headers = {}
    return response


@pytest.fixture
def mock_session(mock_response):
    """Create a mock requests session."""
    session = MagicMock()
    session.request.return_value = mock_response
    session.get.return_value = mock_response
    session.post.return_value = mock_response
    session.put.return_value = mock_response
    session.delete.return_value = mock_response
    return session


@pytest.fixture
def client_with_token():
    """Create a client instance with API token authentication."""
    client = DefenderCloudAppsClient(
        base_url="https://test.portal.cloudappsecurity.com/api",
        api_token="test_token_12345"
    )
    return client


@pytest.fixture
def client_with_oauth2():
    """Create a client instance with OAuth2 authentication."""
    client = DefenderCloudAppsClient(
        base_url="https://test.portal.cloudappsecurity.com/api",
        tenant_id="test-tenant-id",
        client_id="test-client-id",
        client_secret="test-client-secret"
    )
    return client


@pytest.fixture
def sample_activity():
    """Sample activity data for testing."""
    return {
        "_id": "activity123",
        "timestamp": 1609459200000,
        "user": {
            "username": "user@example.com",
            "id": "user123"
        },
        "service": "Microsoft 365",
        "eventType": "EVENT_TYPE_LOGIN",
        "description": "User logged in"
    }


@pytest.fixture
def sample_alert():
    """Sample alert data for testing."""
    return {
        "_id": "alert123",
        "title": "Suspicious activity detected",
        "severity": {"value": 2, "label": "High"},
        "timestamp": 1609459200000,
        "status": {"value": 0, "label": "Open"},
        "description": "Multiple failed login attempts"
    }


@pytest.fixture
def sample_file():
    """Sample file data for testing."""
    return {
        "_id": "file123",
        "name": "document.docx",
        "fileType": "Document",
        "ownerName": "owner@example.com",
        "sharing": {
            "sharingLevel": "Public"
        },
        "modifiedDate": 1609459200000
    }


@pytest.fixture
def sample_entity():
    """Sample entity data for testing."""
    return {
        "_id": "entity123",
        "username": "user@example.com",
        "type": "user",
        "isAdmin": True,
        "isExternal": False,
        "riskScore": 8
    }


@pytest.fixture
def sample_discovered_app():
    """Sample discovered app data for testing."""
    return {
        "_id": "app123",
        "name": "Dropbox",
        "overall_score": 7,
        "revised_score": {
            "security": 8,
            "compliance": 7,
            "legal": 6,
            "provider": 9
        },
        "usersCount": 150
    }


@pytest.fixture
def sample_subnet():
    """Sample subnet data for testing."""
    return {
        "_id": "subnet123",
        "name": "HQ Network",
        "original_range": "10.0.0.0/16",
        "organization": "Headquarters",
        "location": "New York",
        "category": "Corporate"
    }
