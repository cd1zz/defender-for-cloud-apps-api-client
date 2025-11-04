"""
Entities API endpoints for Microsoft Defender for Cloud Apps.

The Entities API provides access to user and device entity information,
including risk scores, behavioral analytics, and identity investigation data.
"""

from typing import Any, Dict, List, Optional
from .endpoints import APIEndpoints


class EntitiesAPI:
    """
    Interface for the Entities API endpoints.

    The Entities API allows you to:
    - List entities (users and devices) with complex filtering
    - Fetch specific entity details
    - Get entity risk scores and behavioral analytics
    - Query identity and access patterns
    """

    # Entity type constants
    ENTITY_TYPE_USER = "user"
    ENTITY_TYPE_DEVICE = "device"

    # Risk level constants
    RISK_LEVEL_LOW = 0
    RISK_LEVEL_MEDIUM = 1
    RISK_LEVEL_HIGH = 2

    def __init__(self, client):
        """
        Initialize Entities API.

        Args:
            client: DefenderCloudAppsClient instance
        """
        self._client = client

    def list_entities(
        self,
        filters: Optional[Dict[str, Any]] = None,
        limit: int = 100,
        skip: int = 0,
        sort_field: Optional[str] = None,
        sort_direction: str = "asc"
    ) -> List[Dict[str, Any]]:
        """
        List entities (users and devices) with optional filtering and pagination.

        Available filters:
        - entity.type: Filter by entity type (user, device, etc.)
        - entity.id: Filter by specific entity ID
        - user.username: Filter by username
        - user.domain: Filter by user domain
        - user.email: Filter by email address
        - device.name: Filter by device name
        - device.osVersion: Filter by OS version
        - isExternal: Filter by external users (true/false)
        - isAdmin: Filter by admin status (true/false)
        - riskScore: Filter by risk score (0-10)
        - lastSeen: Filter by last activity timestamp (milliseconds)
        - tags: Filter by entity tags

        Args:
            filters: Dictionary of filters to apply to the query
            limit: Maximum number of entities to return per page (max 100)
            skip: Number of entities to skip for pagination
            sort_field: Field to sort results by
            sort_direction: Sort direction ('asc' or 'desc')

        Returns:
            List of entity objects with properties:
            - _id: Entity identifier
            - type: Entity type (user, device, etc.)
            - username: Username (for users)
            - email: Email address (for users)
            - domain: Domain (for users)
            - deviceName: Device name (for devices)
            - osVersion: OS version (for devices)
            - isExternal: Whether entity is external
            - isAdmin: Whether user is admin
            - riskScore: Numerical risk score
            - lastSeen: Timestamp of last activity
            - tags: List of tags applied to entity
            - accounts: List of associated accounts
            - riskFactors: List of contributing risk factors

        Raises:
            APIError: If the API request fails
            RateLimitError: If rate limit is exceeded

        Example:
            >>> entities_api = client.entities
            >>> # List all users
            >>> users = entities_api.list_entities()
            >>>
            >>> # List risky users
            >>> risky_users = entities_api.list_entities(
            ...     filters={
            ...         "entity.type": {"eq": "user"},
            ...         "riskScore": {"gte": 7}
            ...     }
            ... )
            >>>
            >>> # List external users
            >>> external = entities_api.list_entities(
            ...     filters={"isExternal": {"eq": True}},
            ...     sort_field="riskScore",
            ...     sort_direction="desc"
            ... )
        """
        data = {
            "filters": filters or {},
            "limit": min(limit, 100),
            "skip": skip
        }

        if sort_field:
            data["sort"] = {
                "sortField": sort_field,
                "sortDirection": sort_direction.lower()
            }

        response = self._client._make_request("POST", APIEndpoints.ENTITIES_LIST, data=data)
        return response.get("data", [])

    def get_entity(self, entity_id: str) -> Dict[str, Any]:
        """
        Get details for a specific entity by ID.

        Args:
            entity_id: The unique identifier for the entity

        Returns:
            Entity object with full details including:
            - _id: Entity identifier
            - type: Entity type
            - username: Username (if user)
            - email: Email address (if user)
            - domain: Domain (if user)
            - deviceName: Device name (if device)
            - osVersion: OS version (if device)
            - isExternal: Whether entity is external
            - isAdmin: Whether user is admin
            - riskScore: Numerical risk score
            - riskFactors: List of risk contributing factors
            - lastSeen: Last activity timestamp
            - firstSeen: First activity timestamp
            - tags: Applied tags
            - accounts: Associated accounts
            - groups: Group memberships
            - manager: Manager information (for users)
            - title: Job title (for users)
            - department: Department (for users)

        Raises:
            APIError: If the API request fails
            AuthenticationError: If authentication fails

        Example:
            >>> entities_api = client.entities
            >>> entity = entities_api.get_entity("5f1234567890abcdef123456")
            >>> print(f"User: {entity['username']}, Risk Score: {entity['riskScore']}")
        """
        response = self._client._make_request("GET", APIEndpoints.ENTITIES_DETAIL.format(entity_id=entity_id))
        return response.get("data", response)

    def get_entity_by_username(
        self,
        username: str,
        domain: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        """
        Get entity details for a specific user by username.

        Args:
            username: The username to search for
            domain: Optional domain to filter results

        Returns:
            Entity object if found, None otherwise

        Raises:
            APIError: If the API request fails

        Example:
            >>> entities_api = client.entities
            >>> entity = entities_api.get_entity_by_username("john.doe@company.com")
            >>> if entity:
            ...     print(f"Risk Score: {entity['riskScore']}")
        """
        filters = {"user.username": {"eq": username}}
        if domain:
            filters["user.domain"] = {"eq": domain}

        results = self.list_entities(filters=filters, limit=1)
        return results[0] if results else None

    def get_risky_entities(
        self,
        min_risk_score: int = 7,
        entity_type: Optional[str] = None,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """
        Get entities with risk scores above a specified threshold.

        Args:
            min_risk_score: Minimum risk score to include (0-10)
            entity_type: Optional entity type filter (user, device, etc.)
            limit: Maximum number of entities to return

        Returns:
            List of entity objects with high risk scores

        Raises:
            APIError: If the API request fails

        Example:
            >>> entities_api = client.entities
            >>> risky = entities_api.get_risky_entities(min_risk_score=8)
            >>> for entity in risky:
            ...     print(f"{entity['username']}: {entity['riskScore']}")
        """
        filters = {"riskScore": {"gte": min_risk_score}}
        if entity_type:
            filters["entity.type"] = {"eq": entity_type}

        return self.list_entities(filters=filters, limit=limit)

    def get_external_entities(self, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Get all external user entities.

        External users are those outside your organization.

        Args:
            limit: Maximum number of entities to return

        Returns:
            List of external user entity objects

        Raises:
            APIError: If the API request fails

        Example:
            >>> entities_api = client.entities
            >>> external_users = entities_api.get_external_entities()
            >>> print(f"Found {len(external_users)} external users")
        """
        filters = {"isExternal": {"eq": True}}
        return self.list_entities(filters=filters, limit=limit)

    def get_admin_entities(self, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Get all administrator/privileged user entities.

        Args:
            limit: Maximum number of entities to return

        Returns:
            List of admin user entity objects

        Raises:
            APIError: If the API request fails

        Example:
            >>> entities_api = client.entities
            >>> admins = entities_api.get_admin_entities()
            >>> for admin in admins:
            ...     print(f"Admin: {admin['username']}")
        """
        filters = {"isAdmin": {"eq": True}}
        return self.list_entities(filters=filters, limit=limit)

    def get_entity_risk_factors(self, entity_id: str) -> List[Dict[str, Any]]:
        """
        Get the specific risk factors contributing to an entity's risk score.

        Risk factors provide insights into why an entity has a particular
        risk score, such as unusual sign-in locations, impossible travels, etc.

        Args:
            entity_id: The unique identifier for the entity

        Returns:
            List of risk factor objects with:
            - factor: Name of the risk factor
            - score: Contribution to overall risk score
            - description: Description of the risk factor
            - remediation: Recommended remediation steps

        Raises:
            APIError: If the API request fails

        Example:
            >>> entities_api = client.entities
            >>> factors = entities_api.get_entity_risk_factors("5f1234567890abcdef123456")
            >>> for factor in factors:
            ...     print(f"{factor['factor']}: {factor['score']} points")
        """
        entity = self.get_entity(entity_id)
        return entity.get("riskFactors", [])

    def search_entities(
        self,
        query: str,
        entity_type: Optional[str] = None,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """
        Search for entities by username, email, or device name.

        Args:
            query: Search query string (username, email, or device name)
            entity_type: Optional entity type filter
            limit: Maximum number of results

        Returns:
            List of matching entity objects

        Raises:
            APIError: If the API request fails

        Example:
            >>> entities_api = client.entities
            >>> results = entities_api.search_entities("john", entity_type="user")
            >>> for entity in results:
            ...     print(f"{entity['username']}: {entity['email']}")
        """
        filters = {}

        # Try multiple fields for flexible search
        filters["user.username"] = {"contains": query}

        if entity_type:
            filters["entity.type"] = {"eq": entity_type}

        results = self.list_entities(filters=filters, limit=limit)

        # Filter client-side for better matching if needed
        return [
            e for e in results
            if (query.lower() in e.get("username", "").lower() or
                query.lower() in e.get("email", "").lower() or
                query.lower() in e.get("deviceName", "").lower())
        ]

    def get_entities_by_tag(self, tag: str, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Get all entities with a specific tag.

        Tags allow you to group related entities for targeted investigations.

        Args:
            tag: The tag name to filter by
            limit: Maximum number of entities to return

        Returns:
            List of entity objects with the specified tag

        Raises:
            APIError: If the API request fails

        Example:
            >>> entities_api = client.entities
            >>> sensitive_group = entities_api.get_entities_by_tag("high-value-accounts")
            >>> print(f"Found {len(sensitive_group)} high-value accounts")
        """
        filters = {"tags": {"eq": tag}}
        return self.list_entities(filters=filters, limit=limit)

    def get_entity_activity_timeline(
        self,
        entity_id: str,
        days: int = 7
    ) -> List[Dict[str, Any]]:
        """
        Get activity timeline for an entity over a specified period.

        This retrieves related activities for an entity to build an investigation timeline.

        Args:
            entity_id: The unique identifier for the entity
            days: Number of days back to retrieve activity (default: 7)

        Returns:
            List of activity objects associated with the entity

        Raises:
            APIError: If the API request fails

        Example:
            >>> entities_api = client.entities
            >>> # Get 30-day activity timeline for an entity
            >>> timeline = entities_api.get_entity_activity_timeline(
            ...     "5f1234567890abcdef123456",
            ...     days=30
            ... )
            >>> print(f"Found {len(timeline)} activities")
        """
        # This would typically use Activities API with entity filter
        # Returning empty for now - implementation depends on Activities API integration
        entity = self.get_entity(entity_id)
        if not entity:
            return []

        from datetime import datetime, timedelta

        cutoff_time = int((datetime.utcnow() - timedelta(days=days)).timestamp() * 1000)

        filters = {
            "entity": {"eq": entity_id},
            "timestamp": {"gte": cutoff_time}
        }

        # This would call Activities API
        # For now, return entity's recent activities if available
        return entity.get("recentActivities", [])
