"""Tests for the DefenderCloudAppsClient class."""

import pytest
from unittest.mock import patch, Mock
from defender_cloud_apps import DefenderCloudAppsClient


class TestClientInitialization:
    """Test client initialization and authentication."""

    def test_init_with_api_token(self):
        """Test client initialization with API token."""
        client = DefenderCloudAppsClient(
            base_url="https://test.portal.cloudappsecurity.com/api",
            api_token="test_token"
        )
        assert client.base_url == "https://test.portal.cloudappsecurity.com/api"
        assert client.api_token == "test_token"
        assert client.tenant_id is None

    def test_init_with_oauth2(self):
        """Test client initialization with OAuth2 credentials."""
        client = DefenderCloudAppsClient(
            base_url="https://test.portal.cloudappsecurity.com/api",
            tenant_id="tenant-id",
            client_id="client-id",
            client_secret="client-secret"
        )
        assert client.base_url == "https://test.portal.cloudappsecurity.com/api"
        assert client.tenant_id == "tenant-id"
        assert client.client_id == "client-id"
        assert client.client_secret == "client-secret"

    def test_init_without_credentials(self):
        """Test client initialization fails without credentials."""
        with pytest.raises(ValueError, match="Must provide either"):
            DefenderCloudAppsClient(
                base_url="https://test.portal.cloudappsecurity.com/api"
            )

    def test_init_with_both_credentials(self):
        """Test client initialization fails with both auth methods."""
        with pytest.raises(ValueError, match="Cannot use both"):
            DefenderCloudAppsClient(
                base_url="https://test.portal.cloudappsecurity.com/api",
                api_token="token",
                tenant_id="tenant",
                client_id="client",
                client_secret="secret"
            )

    def test_context_manager(self, client_with_token):
        """Test client works as context manager."""
        with client_with_token as client:
            assert client is not None

    def test_base_url_normalization(self):
        """Test base URL is normalized correctly."""
        client = DefenderCloudAppsClient(
            base_url="https://test.portal.cloudappsecurity.com/api/",
            api_token="test_token"
        )
        # URL should have trailing slash removed
        assert not client.base_url.endswith("/")


class TestClientConfiguration:
    """Test client configuration options."""

    def test_rate_limit_delay(self):
        """Test custom rate limit delay."""
        client = DefenderCloudAppsClient(
            base_url="https://test.portal.cloudappsecurity.com/api",
            api_token="test_token",
            rate_limit_delay=3.0
        )
        assert client.rate_limit_delay == 3.0

    def test_timeout_configuration(self):
        """Test custom timeout."""
        client = DefenderCloudAppsClient(
            base_url="https://test.portal.cloudappsecurity.com/api",
            api_token="test_token",
            timeout=60
        )
        assert client.timeout == 60

    def test_default_rate_limit(self):
        """Test default rate limit delay."""
        client = DefenderCloudAppsClient(
            base_url="https://test.portal.cloudappsecurity.com/api",
            api_token="test_token"
        )
        # Default should be 2.0 seconds
        assert client.rate_limit_delay == 2.0


class TestClientAPIAccess:
    """Test client API endpoint access."""

    def test_activities_api_access(self, client_with_token):
        """Test access to activities API."""
        assert hasattr(client_with_token, 'activities')
        assert client_with_token.activities is not None

    def test_alerts_api_access(self, client_with_token):
        """Test access to alerts API."""
        assert hasattr(client_with_token, 'alerts')
        assert client_with_token.alerts is not None

    def test_files_api_access(self, client_with_token):
        """Test access to files API."""
        assert hasattr(client_with_token, 'files')
        assert client_with_token.files is not None

    def test_entities_api_access(self, client_with_token):
        """Test access to entities API."""
        assert hasattr(client_with_token, 'entities')
        assert client_with_token.entities is not None

    def test_discovery_api_access(self, client_with_token):
        """Test access to discovery API."""
        assert hasattr(client_with_token, 'discovery')
        assert client_with_token.discovery is not None

    def test_data_enrichment_api_access(self, client_with_token):
        """Test access to data enrichment API."""
        assert hasattr(client_with_token, 'data_enrichment')
        assert client_with_token.data_enrichment is not None
