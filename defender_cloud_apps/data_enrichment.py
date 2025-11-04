"""
Data Enrichment API endpoints for Microsoft Defender for Cloud Apps.

The Data Enrichment API provides IP subnet management for cloud discovery
enrichment, allowing you to map IP ranges to organizational units and locations.
"""

from typing import Any, Dict, List, Optional
from .endpoints import APIEndpoints


class DataEnrichmentAPI:
    """
    Interface for the Data Enrichment API endpoints.

    The Data Enrichment API allows you to:
    - Create IP subnet to organization/location mappings
    - Update existing subnet configurations
    - Delete subnet mappings
    - Query subnet enrichment data
    - Enrich cloud discovery logs with corporate network context
    """

    def __init__(self, client):
        """
        Initialize Data Enrichment API.

        Args:
            client: DefenderCloudAppsClient instance
        """
        self._client = client

    def list_subnets(
        self,
        filters: Optional[Dict[str, Any]] = None,
        limit: int = 100,
        skip: int = 0
    ) -> List[Dict[str, Any]]:
        """
        List all configured IP subnets.

        Subnets are used to enrich cloud discovery data by mapping IP addresses
        to organizational units and locations.

        Available filters:
        - name: Filter by subnet name
        - originalRange: Filter by IP range in CIDR notation
        - organization: Filter by organizational unit
        - location: Filter by location
        - category: Filter by category type

        Args:
            filters: Dictionary of filters to apply to the query
            limit: Maximum number of subnets to return per page (max 100)
            skip: Number of subnets to skip for pagination

        Returns:
            List of subnet objects with properties:
            - _id: Subnet identifier
            - name: Subnet display name
            - originalRange: CIDR notation of IP range (e.g., "192.168.1.0/24")
            - range: Start and end IP address
            - organization: Organizational unit assignment
            - location: Geographic location
            - category: Subnet category (e.g., "Corporate", "ISP")
            - tags: Associated tags

        Raises:
            APIError: If the API request fails
            RateLimitError: If rate limit is exceeded

        Example:
            >>> data_enrichment = client.data_enrichment
            >>> subnets = data_enrichment.list_subnets()
            >>> for subnet in subnets:
            ...     print(f"{subnet['name']}: {subnet['originalRange']}")
        """
        data = {
            "filters": filters or {},
            "limit": min(limit, 100),
            "skip": skip
        }

        response = self._client._make_request("POST", APIEndpoints.SUBNET_LIST, data=data)
        return response.get("data", [])

    def get_subnet(self, subnet_id: str) -> Dict[str, Any]:
        """
        Get details for a specific subnet by ID.

        Args:
            subnet_id: The unique identifier for the subnet

        Returns:
            Subnet object with full details including:
            - _id: Subnet identifier
            - name: Subnet display name
            - originalRange: IP range in CIDR notation
            - range: IP range details (start, end, count)
            - organization: Organizational unit
            - location: Geographic location
            - category: Subnet category
            - tags: Associated tags
            - createdAt: Creation timestamp
            - modifiedAt: Last modification timestamp
            - createdBy: User who created the subnet
            - modifiedBy: User who last modified it

        Raises:
            APIError: If the API request fails
            AuthenticationError: If authentication fails

        Example:
            >>> data_enrichment = client.data_enrichment
            >>> subnet = data_enrichment.get_subnet("5f1234567890abcdef123456")
            >>> print(f"Subnet: {subnet['name']}, Org: {subnet['organization']}")
        """
        response = self._client._make_request("GET", APIEndpoints.SUBNET_DETAIL.format(subnet_id=subnet_id))
        return response.get("data", response)

    def create_subnet(
        self,
        name: str,
        original_range: str,
        organization: Optional[str] = None,
        location: Optional[str] = None,
        category: Optional[str] = None,
        tags: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Create a new IP subnet mapping for cloud discovery enrichment.

        This allows you to map IP ranges to your organization structure
        for enriching cloud discovery logs.

        Args:
            name: Display name for the subnet
            original_range: IP range in CIDR notation (e.g., "192.168.1.0/24")
            organization: Organizational unit to assign to this subnet
            location: Geographic location or site name
            category: Subnet category (e.g., "Corporate", "ISP", "Remote Office")
            tags: Optional list of tags for categorization

        Returns:
            Created subnet object with:
            - _id: New subnet identifier
            - name: Subnet display name
            - originalRange: IP range in CIDR notation
            - organization: Organizational unit
            - location: Geographic location
            - category: Subnet category
            - tags: Applied tags
            - createdAt: Creation timestamp

        Raises:
            APIError: If the API request fails or validation fails
            AuthenticationError: If authentication fails

        Example:
            >>> data_enrichment = client.data_enrichment
            >>> subnet = data_enrichment.create_subnet(
            ...     name="HQ Network",
            ...     original_range="10.0.0.0/16",
            ...     organization="Headquarters",
            ...     location="New York",
            ...     category="Corporate",
            ...     tags=["main-office", "trusted"]
            ... )
            >>> print(f"Created subnet: {subnet['_id']}")
        """
        data = {
            "name": name,
            "originalRange": original_range
        }

        if organization:
            data["organization"] = organization
        if location:
            data["location"] = location
        if category:
            data["category"] = category
        if tags:
            data["tags"] = tags

        response = self._client._make_request("POST", APIEndpoints.SUBNET_LIST, data=data)
        return response.get("data", response)

    def update_subnet(
        self,
        subnet_id: str,
        name: Optional[str] = None,
        organization: Optional[str] = None,
        location: Optional[str] = None,
        category: Optional[str] = None,
        tags: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Update an existing subnet mapping.

        Args:
            subnet_id: The unique identifier for the subnet to update
            name: New display name (optional)
            organization: New organizational unit (optional)
            location: New geographic location (optional)
            category: New subnet category (optional)
            tags: New list of tags (optional)

        Returns:
            Updated subnet object with new values

        Raises:
            APIError: If the API request fails or subnet not found
            AuthenticationError: If authentication fails

        Example:
            >>> data_enrichment = client.data_enrichment
            >>> updated = data_enrichment.update_subnet(
            ...     "5f1234567890abcdef123456",
            ...     organization="Sales Division",
            ...     location="New York"
            ... )
            >>> print(f"Updated: {updated['organization']}")
        """
        data = {}

        if name is not None:
            data["name"] = name
        if organization is not None:
            data["organization"] = organization
        if location is not None:
            data["location"] = location
        if category is not None:
            data["category"] = category
        if tags is not None:
            data["tags"] = tags

        response = self._client._make_request("PATCH", APIEndpoints.SUBNET_UPDATE.format(subnet_id=subnet_id), data=data)
        return response.get("data", response)

    def delete_subnet(self, subnet_id: str) -> bool:
        """
        Delete a subnet mapping.

        This removes the IP range mapping from your enrichment data.

        Args:
            subnet_id: The unique identifier for the subnet to delete

        Returns:
            True if deletion was successful, False otherwise

        Raises:
            APIError: If the API request fails or subnet not found
            AuthenticationError: If authentication fails

        Example:
            >>> data_enrichment = client.data_enrichment
            >>> success = data_enrichment.delete_subnet("5f1234567890abcdef123456")
            >>> if success:
            ...     print("Subnet deleted successfully")
        """
        try:
            self._client._make_request("DELETE", APIEndpoints.SUBNET_DELETE.format(subnet_id=subnet_id))
            return True
        except Exception:
            return False

    def get_subnet_by_name(self, name: str) -> Optional[Dict[str, Any]]:
        """
        Get subnet details by display name.

        Args:
            name: The display name of the subnet to retrieve

        Returns:
            Subnet object if found, None otherwise

        Raises:
            APIError: If the API request fails

        Example:
            >>> data_enrichment = client.data_enrichment
            >>> subnet = data_enrichment.get_subnet_by_name("HQ Network")
            >>> if subnet:
            ...     print(f"Found: {subnet['originalRange']}")
        """
        filters = {"name": {"eq": name}}
        results = self.list_subnets(filters=filters, limit=1)
        return results[0] if results else None

    def get_subnets_by_organization(
        self,
        organization: str,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """
        Get all subnets assigned to a specific organizational unit.

        Args:
            organization: The organizational unit name to filter by
            limit: Maximum number of subnets to return

        Returns:
            List of subnet objects for the organization

        Raises:
            APIError: If the API request fails

        Example:
            >>> data_enrichment = client.data_enrichment
            >>> hq_subnets = data_enrichment.get_subnets_by_organization("Headquarters")
            >>> print(f"HQ has {len(hq_subnets)} configured subnets")
        """
        filters = {"organization": {"eq": organization}}
        return self.list_subnets(filters=filters, limit=limit)

    def get_subnets_by_location(
        self,
        location: str,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """
        Get all subnets for a specific geographic location.

        Args:
            location: The location name to filter by
            limit: Maximum number of subnets to return

        Returns:
            List of subnet objects for the location

        Raises:
            APIError: If the API request fails

        Example:
            >>> data_enrichment = client.data_enrichment
            >>> ny_subnets = data_enrichment.get_subnets_by_location("New York")
            >>> for subnet in ny_subnets:
            ...     print(f"{subnet['name']}: {subnet['originalRange']}")
        """
        filters = {"location": {"eq": location}}
        return self.list_subnets(filters=filters, limit=limit)

    def get_subnets_by_category(
        self,
        category: str,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """
        Get all subnets in a specific category.

        Common categories include: Corporate, ISP, Remote Office, VPN, Datacenter

        Args:
            category: The category name to filter by
            limit: Maximum number of subnets to return

        Returns:
            List of subnet objects in the category

        Raises:
            APIError: If the API request fails

        Example:
            >>> data_enrichment = client.data_enrichment
            >>> remote = data_enrichment.get_subnets_by_category("Remote Office")
            >>> print(f"Found {len(remote)} remote office subnets")
        """
        filters = {"category": {"eq": category}}
        return self.list_subnets(filters=filters, limit=limit)

    def bulk_create_subnets(
        self,
        subnets: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Create multiple subnets in a single operation.

        This is more efficient than creating subnets one at a time.

        Args:
            subnets: List of subnet configurations, each with:
                - name: Display name
                - originalRange: CIDR notation IP range
                - organization: (optional) Organizational unit
                - location: (optional) Geographic location
                - category: (optional) Subnet category
                - tags: (optional) List of tags

        Returns:
            List of created subnet objects with their IDs

        Raises:
            APIError: If the API request fails

        Example:
            >>> data_enrichment = client.data_enrichment
            >>> new_subnets = data_enrichment.bulk_create_subnets([
            ...     {
            ...         "name": "HQ Network",
            ...         "originalRange": "10.0.0.0/16",
            ...         "organization": "Headquarters",
            ...         "category": "Corporate"
            ...     },
            ...     {
            ...         "name": "Remote Office",
            ...         "originalRange": "10.1.0.0/24",
            ...         "organization": "Sales",
            ...         "category": "Remote Office"
            ...     }
            ... ])
            >>> print(f"Created {len(new_subnets)} subnets")
        """
        created = []
        for subnet_config in subnets:
            try:
                created_subnet = self.create_subnet(**subnet_config)
                created.append(created_subnet)
            except Exception as e:
                # Log error but continue processing other subnets
                print(f"Failed to create subnet {subnet_config.get('name')}: {str(e)}")

        return created

    def search_subnets(self, query: str, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Search for subnets by name or organization.

        Args:
            query: Search query string
            limit: Maximum number of results

        Returns:
            List of matching subnet objects

        Raises:
            APIError: If the API request fails

        Example:
            >>> data_enrichment = client.data_enrichment
            >>> results = data_enrichment.search_subnets("HQ")
            >>> for subnet in results:
            ...     print(f"{subnet['name']}: {subnet['organization']}")
        """
        filters = {
            "name": {"contains": query}
        }

        results = self.list_subnets(filters=filters, limit=limit)

        # Filter client-side for better matching
        return [
            s for s in results
            if (query.lower() in s.get("name", "").lower() or
                query.lower() in s.get("organization", "").lower() or
                query.lower() in s.get("location", "").lower())
        ]

    def export_subnets(self) -> str:
        """
        Export all configured subnets as a formatted text report.

        Returns:
            Formatted string with all subnet configurations

        Raises:
            APIError: If the API request fails

        Example:
            >>> data_enrichment = client.data_enrichment
            >>> report = data_enrichment.export_subnets()
            >>> print(report)
        """
        subnets = self.list_subnets(limit=1000)

        lines = [
            "IP Subnet Configuration Report",
            "=" * 80,
            "",
            f"Total Subnets: {len(subnets)}",
            ""
        ]

        # Group by organization
        by_org = {}
        for subnet in subnets:
            org = subnet.get("organization", "Unassigned")
            if org not in by_org:
                by_org[org] = []
            by_org[org].append(subnet)

        for org in sorted(by_org.keys()):
            lines.append(f"\n{org}")
            lines.append("-" * len(org))

            for subnet in by_org[org]:
                lines.append(
                    f"  {subnet.get('name', 'N/A')}: "
                    f"{subnet.get('originalRange', 'N/A')} "
                    f"({subnet.get('category', 'N/A')}) "
                    f"[{subnet.get('location', 'N/A')}]"
                )

        return "\n".join(lines)
