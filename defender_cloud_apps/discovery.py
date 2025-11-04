"""
Cloud Discovery API endpoints for Microsoft Defender for Cloud Apps.

The Cloud Discovery API provides access to discovered apps, continuous reports,
and enables automation of log uploads and blocking of unsanctioned apps.
"""

from typing import Any, Dict, List, Optional
from .endpoints import APIEndpoints


class DiscoveryAPI:
    """
    Interface for the Cloud Discovery API endpoints.

    The Cloud Discovery API allows you to:
    - List continuous reports (streams)
    - List discovered apps within continuous reports
    - Get details about specific discovered apps
    - List app categories
    - Generate block scripts for network appliances
    """

    def __init__(self, client):
        """
        Initialize Cloud Discovery API.

        Args:
            client: DefenderCloudAppsClient instance
        """
        self._client = client

    def list_streams(self) -> List[Dict[str, Any]]:
        """
        List all continuous reports (streams).

        Continuous reports represent automatic log uploads from data sources
        like Microsoft Defender for Endpoint devices.

        Returns:
            List of continuous report objects with properties:
            - displayName: Name of the continuous report
            - logType: Data source type ID
            - streamType: 1=INPUT, 3=VIEW, 5=PREVIEW
            - receiverType: syslog or ftp
            - created: Creation timestamp
            - lastModified: Most recent update timestamp
            - lastDataReceived: When data was last ingested
            - supportedTrafficTypes: List (1=TOTAL_BYTES, 2=DOWNLOADED, 3=UPLOADED)
            - globalAggregated: Whether data merges into global reports

        Example:
            >>> streams = client.discovery.list_streams()
            >>> for stream in streams:
            ...     print(f"{stream['displayName']} - Last data: {stream['lastDataReceived']}")
        """
        response = self._client._make_request(
            "GET",
            APIEndpoints.DISCOVERY_STREAMS
        )

        # The response might be a dict with data key or a list directly
        if isinstance(response, dict):
            return response.get("data", [])
        return response

    def list_discovered_apps(
        self,
        stream_id: Optional[str] = None,
        filters: Optional[Dict[str, Any]] = None,
        limit: int = 100,
        skip: int = 0,
        sort_field: Optional[str] = None,
        sort_direction: str = "desc",
        time_frame: Optional[int] = None
    ) -> List[Dict[str, Any]]:
        """
        List discovered apps within a continuous report.

        Available filters (based on UI capabilities):
        - appName: Filter by app name
        - appTag: sanctioned, unsanctioned, or custom tags
        - category: App category (social networks, cloud storage, etc.)
        - riskScore: Risk score filter (0-10)
        - complianceRiskFactor: HIPAA, ISO 27001, SOC 2, PCI-DSS
        - generalRiskFactor: Consumer popularity, data center location
        - securityRiskFactor: Encryption, MFA support
        - legalRiskFactor: Regulations and data protection
        - usage: Filter by upload/download volume, user counts

        Args:
            stream_id: Continuous report ID to query (if None, queries all streams)
            filters: Dictionary of filter criteria
            limit: Maximum number of results (max 100 per request)
            skip: Number of results to skip
            sort_field: Field to sort by
            sort_direction: Sort direction ('asc' or 'desc')
            time_frame: Filter by days since last use

        Returns:
            List of discovered app records with details like:
            - appId: Unique app identifier
            - appName: Application name
            - category: App category
            - riskScore: Risk assessment score
            - usage: Traffic and user statistics
            - compliance: Compliance factors

        Example:
            >>> # List all discovered apps
            >>> apps = client.discovery.list_discovered_apps()
            >>>
            >>> # List high-risk apps in a specific stream
            >>> filters = {"riskScore": {"gte": 7}}
            >>> high_risk_apps = client.discovery.list_discovered_apps(
            ...     stream_id="stream_123",
            ...     filters=filters
            ... )
        """
        data: Dict[str, Any] = {
            "filters": filters or {},
            "limit": min(limit, 100),
            "skip": skip
        }

        if stream_id:
            data["streamId"] = stream_id

        if time_frame:
            data["timeFrame"] = time_frame

        if sort_field:
            data["sortField"] = sort_field
            data["sortDirection"] = sort_direction

        response = self._client._make_request(
            "POST",
            APIEndpoints.DISCOVERY_APPS_LIST,
            data=data
        )

        return response.get("data", [])

    def list_discovered_apps_paginated(
        self,
        stream_id: Optional[str] = None,
        filters: Optional[Dict[str, Any]] = None,
        limit: int = 100,
        skip: int = 0
    ) -> List[Dict[str, Any]]:
        """
        List all discovered apps with automatic pagination.

        This method automatically handles pagination and returns all matching apps.

        Args:
            stream_id: Continuous report ID to query
            filters: Dictionary of filter criteria
            limit: Number of items per page (max 100)
            skip: Number of items to skip initially

        Returns:
            List of all matching discovered app records

        Example:
            >>> all_apps = client.discovery.list_discovered_apps_paginated(
            ...     stream_id="stream_123"
            ... )
        """
        all_apps = []
        current_skip = skip

        while True:
            apps = self.list_discovered_apps(
                stream_id=stream_id,
                filters=filters,
                limit=limit,
                skip=current_skip
            )

            if not apps:
                break

            all_apps.extend(apps)

            if len(apps) < limit:
                break

            current_skip += len(apps)

        return all_apps

    def get_discovered_app(
        self,
        app_id: str,
        stream_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Get details about a specific discovered app.

        This method retrieves detailed information about a discovered app,
        similar to what you see in the UI when clicking on an app.

        Args:
            app_id: The app ID to retrieve
            stream_id: Optional stream ID for scoped queries

        Returns:
            Detailed app information including:
            - appId: Unique identifier
            - appName: Application name
            - category: App category
            - riskScore: Risk assessment
            - complianceFactors: Compliance information
            - securityFactors: Security capabilities
            - usage: Detailed usage statistics
            - users: User count and details
            - transactions: Transaction count
            - traffic: Upload/download volumes

        Example:
            >>> app_details = client.discovery.get_discovered_app("11161")
            >>> print(f"App: {app_details['appName']}")
            >>> print(f"Risk Score: {app_details['riskScore']}")
        """
        # Try to get the specific app by filtering
        filters = {"appId": {"eq": app_id}}

        apps = self.list_discovered_apps(
            stream_id=stream_id,
            filters=filters,
            limit=1
        )

        if not apps:
            raise ValueError(f"App with ID '{app_id}' not found")

        return apps[0]

    def search_discovered_apps(
        self,
        search_text: str,
        stream_id: Optional[str] = None,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """
        Search for discovered apps by name or domain.

        Args:
            search_text: Search query (app name or domain)
            stream_id: Optional stream ID to scope the search
            limit: Maximum number of results

        Returns:
            List of matching discovered apps

        Example:
            >>> apps = client.discovery.search_discovered_apps("dropbox")
        """
        filters = {
            "appName": {"contains": search_text}
        }

        return self.list_discovered_apps(
            stream_id=stream_id,
            filters=filters,
            limit=limit
        )

    def list_categories(
        self,
        stream_id: str,
        filters: Optional[Dict[str, Any]] = None,
        limit: int = 100,
        skip: int = 0,
        sort_field: Optional[str] = None,
        sort_direction: str = "desc",
        time_frame: Optional[int] = None
    ) -> List[Dict[str, Any]]:
        """
        List app categories for a continuous report.

        Args:
            stream_id: Continuous report ID (required)
            filters: Dictionary of filter criteria
            limit: Maximum number of results (max 100 per request)
            skip: Number of results to skip
            sort_field: Field to sort by (e.g., 'score' for app count)
            sort_direction: Sort direction ('asc' or 'desc')
            time_frame: Filter by days since last use

        Returns:
            List of category objects with:
            - id: Category identifier (e.g., 'SAASDB_CATEGORY_CLOUD_STORAGE')
            - total: Number of services in the category

        Example:
            >>> categories = client.discovery.list_categories(stream_id="stream_123")
            >>> for cat in categories:
            ...     print(f"{cat['id']}: {cat['total']} apps")
        """
        data: Dict[str, Any] = {
            "filters": filters or {},
            "streamId": stream_id,
            "limit": min(limit, 100),
            "skip": skip
        }

        if time_frame:
            data["timeFrame"] = time_frame

        if sort_field:
            data["sortField"] = sort_field
            data["sortDirection"] = sort_direction

        response = self._client._make_request(
            "POST",
            APIEndpoints.DISCOVERY_CATEGORIES,
            data=data
        )

        return response.get("data", [])

    def generate_block_script(
        self,
        appliance_type: str,
        stream_id: Optional[str] = None
    ) -> str:
        """
        Generate a block script for unsanctioned apps.

        This generates a script that can be imported into your network appliance
        to block access to unsanctioned apps.

        Args:
            appliance_type: Type of network appliance (e.g., 'cisco', 'paloalto', 'fortinet')
            stream_id: Optional stream ID to scope the script

        Returns:
            Block script content as a string

        Example:
            >>> script = client.discovery.generate_block_script("paloalto")
            >>> with open("block_script.txt", "w") as f:
            ...     f.write(script)
        """
        params = {"format": appliance_type}

        if stream_id:
            params["streamId"] = stream_id

        response = self._client._make_request(
            "GET",
            APIEndpoints.DISCOVERY_BLOCK_SCRIPT,
            params=params
        )

        # The response might be the script directly or in a field
        if isinstance(response, str):
            return response
        return response.get("script", str(response))

    def get_high_risk_apps(
        self,
        stream_id: Optional[str] = None,
        risk_threshold: int = 7,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """
        Get all discovered apps and filter for high-risk ones in Python.

        Note: The API's available filter names for discovered apps may vary.
        This method retrieves apps and filters them client-side.

        Args:
            stream_id: Optional stream ID to scope the query
            risk_threshold: Minimum risk score (0-10, default 7)
            limit: Maximum number of results

        Returns:
            List of high-risk apps

        Example:
            >>> high_risk = client.discovery.get_high_risk_apps(risk_threshold=8)
        """
        # Get all apps without filter (filter may not exist on API)
        all_apps = self.list_discovered_apps(
            stream_id=stream_id,
            limit=limit
        )

        # Filter client-side for apps with riskScore
        high_risk = [
            app for app in all_apps 
            if app.get('riskScore', 0) >= risk_threshold
        ]
        return high_risk

    def get_unsanctioned_apps(
        self,
        stream_id: Optional[str] = None,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """
        Get all unsanctioned discovered apps (client-side filtering).

        Note: This method retrieves apps and filters them client-side
        since the appTag filter may not be available on the API.

        Args:
            stream_id: Optional stream ID to scope the query
            limit: Maximum number of results

        Returns:
            List of unsanctioned apps

        Example:
            >>> unsanctioned = client.discovery.get_unsanctioned_apps()
        """
        # Get all apps without filter
        all_apps = self.list_discovered_apps(
            stream_id=stream_id,
            limit=limit
        )

        # Filter client-side for unsanctioned apps
        unsanctioned = [
            app for app in all_apps 
            if app.get('appTag', '').lower() == 'unsanctioned' or 
               app.get('isSanctioned', True) is False
        ]
        return unsanctioned

    def get_apps_by_category(
        self,
        category: str,
        stream_id: Optional[str] = None,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """
        Get discovered apps by category.

        Args:
            category: Category identifier (e.g., 'SAASDB_CATEGORY_CLOUD_STORAGE')
            stream_id: Optional stream ID to scope the query
            limit: Maximum number of results

        Returns:
            List of apps in the specified category

        Example:
            >>> storage_apps = client.discovery.get_apps_by_category(
            ...     "SAASDB_CATEGORY_CLOUD_STORAGE"
            ... )
        """
        filters = {
            "category": {"eq": category}
        }

        return self.list_discovered_apps(
            stream_id=stream_id,
            filters=filters,
            limit=limit
        )

    def get_noncompliant_apps(
        self,
        compliance_standard: str,
        stream_id: Optional[str] = None,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """
        Get apps that don't meet a specific compliance standard.

        Args:
            compliance_standard: Standard name (e.g., 'HIPAA', 'ISO 27001', 'SOC 2', 'PCI-DSS')
            stream_id: Optional stream ID to scope the query
            limit: Maximum number of results

        Returns:
            List of non-compliant apps

        Example:
            >>> non_hipaa = client.discovery.get_noncompliant_apps("HIPAA")
        """
        filters = {
            "complianceRiskFactor": {"neq": compliance_standard}
        }

        return self.list_discovered_apps(
            stream_id=stream_id,
            filters=filters,
            limit=limit
        )
