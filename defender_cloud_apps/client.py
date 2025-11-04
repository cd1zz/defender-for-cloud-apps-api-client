"""
Microsoft Defender for Cloud Apps API Client

This module provides a Python client for interacting with the Microsoft Defender
for Cloud Apps REST API.
"""

import time
from typing import Any, Dict, List, Optional
from datetime import datetime, timedelta
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


class DefenderCloudAppsError(Exception):
    """Base exception for Defender for Cloud Apps API errors."""
    pass


class AuthenticationError(DefenderCloudAppsError):
    """Raised when authentication fails."""
    pass


class RateLimitError(DefenderCloudAppsError):
    """Raised when rate limit is exceeded."""
    pass


class APIError(DefenderCloudAppsError):
    """Raised when API returns an error response."""
    pass


class DefenderCloudAppsClient:
    """
    Client for Microsoft Defender for Cloud Apps API.

    This client handles authentication, rate limiting, and provides methods
    to interact with various API endpoints including Activities, Alerts, Files,
    Entities, and Data Enrichment.

    Supports two authentication methods:
    1. Personal API Token (legacy)
    2. OAuth2 Client Credentials (recommended for applications)

    Attributes:
        base_url: The base API URL for your tenant
        api_token: Your personal API token (optional, mutually exclusive with oauth2)
        tenant_id: Microsoft Entra tenant ID (for OAuth2)
        client_id: Application ID (for OAuth2)
        client_secret: Client secret (for OAuth2)
        timeout: Request timeout in seconds (default: 30)
        rate_limit_delay: Delay between requests to avoid rate limiting (default: 2)
    """

    # Defender for Cloud Apps resource ID for OAuth2
    RESOURCE_ID = "05a65629-4c1b-48c1-a78b-804c4abdd4af"
    AZURE_LOGIN_URL = "https://login.microsoftonline.com"

    def __init__(
        self,
        base_url: str,
        api_token: Optional[str] = None,
        tenant_id: Optional[str] = None,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        timeout: int = 30,
        rate_limit_delay: float = 2.0,
        max_retries: int = 3
    ):
        """
        Initialize the Defender for Cloud Apps API client.

        Args:
            base_url: The base API URL (e.g., 'https://tenant.region.portal.cloudappsecurity.com/api')
            api_token: Personal API token (legacy authentication)
            tenant_id: Microsoft Entra tenant ID (for OAuth2)
            client_id: Application ID (for OAuth2)
            client_secret: Client secret (for OAuth2)
            timeout: Request timeout in seconds
            rate_limit_delay: Minimum delay between requests in seconds
            max_retries: Maximum number of retry attempts for failed requests

        Raises:
            ValueError: If neither api_token nor OAuth2 credentials are provided
        """
        # Validate that at least one authentication method is provided
        has_token = api_token is not None
        has_oauth2 = all([tenant_id, client_id, client_secret])

        if not has_token and not has_oauth2:
            raise ValueError(
                "Must provide either 'api_token' (legacy) or "
                "'tenant_id', 'client_id', and 'client_secret' (OAuth2)"
            )

        if has_token and has_oauth2:
            raise ValueError(
                "Cannot use both api_token and OAuth2 credentials. "
                "Choose one authentication method."
            )

        self.base_url = base_url.rstrip('/')
        self.api_token = api_token
        self.timeout = timeout
        self.rate_limit_delay = rate_limit_delay
        self._last_request_time = 0

        # OAuth2 attributes
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        self._oauth_token = None
        self._oauth_token_expiry = None

        # Configure session with retry strategy
        self.session = requests.Session()
        retry_strategy = Retry(
            total=max_retries,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "PUT", "DELETE", "OPTIONS", "TRACE", "POST"],
            backoff_factor=1
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("https://", adapter)
        self.session.mount("http://", adapter)

    def _get_headers(self) -> Dict[str, str]:
        """Get request headers including authorization."""
        if self.api_token:
            # Legacy token-based authentication
            return {
                "Authorization": f"Token {self.api_token}",
                "Content-Type": "application/json"
            }
        else:
            # OAuth2 authentication
            token = self._get_oauth_token()
            return {
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json"
            }

    def _get_oauth_token(self) -> str:
        """
        Get a valid OAuth2 access token for the Defender for Cloud Apps API.

        Tokens are cached and automatically refreshed when expired.

        Returns:
            Access token string

        Raises:
            AuthenticationError: If token acquisition fails
        """
        # Check if we have a valid cached token
        if self._oauth_token and self._oauth_token_expiry:
            # Refresh if within 5 minutes of expiry
            if datetime.utcnow() < self._oauth_token_expiry - timedelta(minutes=5):
                return self._oauth_token

        # Acquire a new token
        token_url = f"{self.AZURE_LOGIN_URL}/{self.tenant_id}/oauth2/v2.0/token"

        payload = {
            "grant_type": "client_credentials",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "scope": f"{self.RESOURCE_ID}/.default"
        }

        try:
            response = requests.post(
                token_url,
                data=payload,
                timeout=self.timeout
            )

            if response.status_code != 200:
                raise AuthenticationError(
                    f"Failed to acquire OAuth2 token: {response.status_code} - {response.text}"
                )

            token_response = response.json()
            self._oauth_token = token_response["access_token"]

            # Calculate expiry time (expires_in is in seconds)
            expires_in = int(token_response.get("expires_in", 3600))
            self._oauth_token_expiry = datetime.utcnow() + timedelta(seconds=expires_in)

            return self._oauth_token

        except requests.exceptions.RequestException as e:
            raise AuthenticationError(f"Failed to acquire OAuth2 token: {str(e)}")

    def _handle_rate_limit(self):
        """Implement rate limiting to stay within API limits (30 requests/minute)."""
        current_time = time.time()
        time_since_last_request = current_time - self._last_request_time

        if time_since_last_request < self.rate_limit_delay:
            time.sleep(self.rate_limit_delay - time_since_last_request)

        self._last_request_time = time.time()

    def _make_request(
        self,
        method: str,
        endpoint: str,
        data: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Make an API request with error handling and rate limiting.

        Args:
            method: HTTP method (GET, POST, etc.)
            endpoint: API endpoint path
            data: Request body data (for POST requests)
            params: Query parameters

        Returns:
            Response data as dictionary

        Raises:
            AuthenticationError: If authentication fails
            RateLimitError: If rate limit is exceeded
            APIError: If API returns an error
        """
        self._handle_rate_limit()

        url = f"{self.base_url}/{endpoint.lstrip('/')}"

        try:
            response = self.session.request(
                method=method,
                url=url,
                headers=self._get_headers(),
                json=data,
                params=params,
                timeout=self.timeout
            )

            # Handle authentication errors
            if response.status_code == 401:
                raise AuthenticationError("Authentication failed. Check your API token.")

            # Handle rate limiting
            if response.status_code == 429:
                raise RateLimitError("Rate limit exceeded. Try again later.")

            # Handle other errors
            if not response.ok:
                raise APIError(
                    f"API request failed with status {response.status_code}: {response.text}"
                )

            # Return empty dict for successful requests with no content
            if response.status_code == 204 or not response.content:
                return {}

            return response.json()

        except requests.exceptions.Timeout:
            raise APIError(f"Request timed out after {self.timeout} seconds")
        except requests.exceptions.RequestException as e:
            raise APIError(f"Request failed: {str(e)}")

    def _paginate(
        self,
        endpoint: str,
        filters: Optional[Dict[str, Any]] = None,
        limit: int = 100,
        skip: int = 0
    ) -> List[Dict[str, Any]]:
        """
        Handle pagination for list endpoints.

        Args:
            endpoint: API endpoint path
            filters: Filter criteria
            limit: Number of items per page (max 100)
            skip: Number of items to skip

        Returns:
            List of items from all pages
        """
        all_items = []
        current_skip = skip

        while True:
            data = {
                "filters": filters or {},
                "limit": min(limit, 100),  # API max is 100
                "skip": current_skip
            }

            response = self._make_request("POST", endpoint, data=data)
            items = response.get("data", [])

            if not items:
                break

            all_items.extend(items)

            # Check if there are more items
            if len(items) < limit:
                break

            current_skip += len(items)

        return all_items

    @property
    def activities(self):
        """
        Get or initialize the Activities API.

        Returns:
            ActivitiesAPI instance for accessing activity endpoints
        """
        if not hasattr(self, "_activities_api") or self._activities_api is None:
            from .activities import ActivitiesAPI
            self._activities_api = ActivitiesAPI(self)
        return self._activities_api

    @property
    def alerts(self):
        """
        Get or initialize the Alerts API.

        Returns:
            AlertsAPI instance for accessing alert endpoints
        """
        if not hasattr(self, "_alerts_api") or self._alerts_api is None:
            from .alerts import AlertsAPI
            self._alerts_api = AlertsAPI(self)
        return self._alerts_api

    @property
    def files(self):
        """
        Get or initialize the Files API.

        Returns:
            FilesAPI instance for accessing file endpoints
        """
        if not hasattr(self, "_files_api") or self._files_api is None:
            from .files import FilesAPI
            self._files_api = FilesAPI(self)
        return self._files_api

    @property
    def entities(self):
        """
        Get or initialize the Entities API.

        Returns:
            EntitiesAPI instance for accessing entity endpoints
        """
        if not hasattr(self, "_entities_api") or self._entities_api is None:
            from .entities import EntitiesAPI
            self._entities_api = EntitiesAPI(self)
        return self._entities_api

    @property
    def discovery(self):
        """
        Get or initialize the Cloud Discovery API.

        Returns:
            DiscoveryAPI instance for accessing discovery endpoints
        """
        if not hasattr(self, "_discovery_api") or self._discovery_api is None:
            from .discovery import DiscoveryAPI
            self._discovery_api = DiscoveryAPI(self)
        return self._discovery_api

    @property
    def data_enrichment(self):
        """
        Get or initialize the Data Enrichment API.

        Returns:
            DataEnrichmentAPI instance for accessing data enrichment endpoints
        """
        if not hasattr(self, "_data_enrichment_api") or self._data_enrichment_api is None:
            from .data_enrichment import DataEnrichmentAPI
            self._data_enrichment_api = DataEnrichmentAPI(self)
        return self._data_enrichment_api

    def close(self):
        """Close the HTTP session."""
        self.session.close()

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()
