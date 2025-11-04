"""
Activities API endpoints for Microsoft Defender for Cloud Apps.

The Activities API provides visibility into cloud app actions, enabling tracking
of user logins, file downloads, and activity patterns.
"""

from typing import Any, Dict, List, Optional


class ActivitiesAPI:
    """
    Interface for the Activities API endpoints.

    The Activities API allows you to:
    - List activities with complex filtering
    - Fetch specific activity details
    - Provide feedback on activities
    """

    def __init__(self, client):
        """
        Initialize Activities API.

        Args:
            client: DefenderCloudAppsClient instance
        """
        self._client = client

    def list_activities(
        self,
        filters: Optional[Dict[str, Any]] = None,
        limit: int = 100,
        skip: int = 0,
        sort_field: Optional[str] = None,
        sort_direction: str = "asc"
    ) -> List[Dict[str, Any]]:
        """
        List activities with optional filtering and pagination.

        Available filters:
        - user.username: Filter by username
        - user.domain: Filter by user domain
        - user.orgUnit: Filter by organizational unit
        - entity: Filter by activity performer (entity ID)
        - user.tags: Filter by user group IDs
        - service: Filter by app ID
        - actionType: Filter by action classification
        - activity.eventActionType: Filter by event type
        - activity.id: Find activity by ID
        - activity.impersonated: Filter impersonated vs legitimate events
        - activity.takenAction: Filter by action taken (block, proxy, encrypt, etc.)
        - device.type: Filter by device type (desktop, mobile, tablet, other)
        - device.tags: Filter by device tag IDs
        - location.country: Filter by country
        - ip.address: Filter by IP address
        - ip.category: Filter by IP category
        - ip.tags: Filter by IP tags
        - userAgent.userAgent: Filter by user agent string
        - userAgent.tags: Filter by user agent tags
        - fileSelector: Filter by file/folder
        - fileId: Filter by file ID
        - policy: Filter by policy ID
        - date: Filter by date range

        Filter operators: eq, neq, contains, startswith, isset, isnotset, gte, lte, range

        Args:
            filters: Dictionary of filter criteria
            limit: Maximum number of results to return (max 100 per request)
            skip: Number of results to skip
            sort_field: Field to sort by
            sort_direction: Sort direction ('asc' or 'desc')

        Returns:
            List of activity records

        Example:
            >>> activities = client.activities.list_activities(
            ...     filters={
            ...         "user.username": {"eq": "admin@example.com"},
            ...         "date": {"gte": 1609459200000}
            ...     },
            ...     limit=50
            ... )
        """
        data: Dict[str, Any] = {
            "filters": filters or {},
            "limit": min(limit, 100),
            "skip": skip
        }

        if sort_field:
            data["sortField"] = sort_field
            data["sortDirection"] = sort_direction

        response = self._client._make_request(
            "POST",
            "/v1/activities/",
            data=data
        )

        return response.get("data", [])

    def list_activities_paginated(
        self,
        filters: Optional[Dict[str, Any]] = None,
        limit: int = 100,
        skip: int = 0
    ) -> List[Dict[str, Any]]:
        """
        List all activities with automatic pagination.

        This method automatically handles pagination and returns all matching activities.

        Args:
            filters: Dictionary of filter criteria
            limit: Number of items per page (max 100)
            skip: Number of items to skip initially

        Returns:
            List of all matching activity records

        Example:
            >>> all_activities = client.activities.list_activities_paginated(
            ...     filters={"service": {"eq": 11770}}
            ... )
        """
        return self._client._paginate(
            "/v1/activities/",
            filters=filters,
            limit=limit,
            skip=skip
        )

    def get_activity(self, activity_id: str) -> Dict[str, Any]:
        """
        Fetch a specific activity by ID.

        Args:
            activity_id: The activity ID

        Returns:
            Activity details

        Example:
            >>> activity = client.activities.get_activity("5f8a7b2c3d4e5f6g7h8i9j0k")
        """
        response = self._client._make_request(
            "GET",
            f"/v1/activities/{activity_id}/"
        )

        return response

    def provide_feedback(
        self,
        activity_id: str,
        feedback: str,
        feedback_text: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Provide feedback on an activity.

        Args:
            activity_id: The activity ID
            feedback: Feedback type (e.g., "benign", "malicious")
            feedback_text: Optional feedback text/comment

        Returns:
            Response data

        Example:
            >>> client.activities.provide_feedback(
            ...     activity_id="5f8a7b2c3d4e5f6g7h8i9j0k",
            ...     feedback="benign",
            ...     feedback_text="Verified legitimate activity"
            ... )
        """
        data = {
            "feedback": feedback
        }

        if feedback_text:
            data["feedbackText"] = feedback_text

        response = self._client._make_request(
            "POST",
            f"/v1/activities/{activity_id}/feedback/",
            data=data
        )

        return response

    def search_activities(
        self,
        search_text: str,
        filters: Optional[Dict[str, Any]] = None,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """
        Search activities using free-text search combined with filters.

        Args:
            search_text: Free-text search query
            filters: Additional filter criteria
            limit: Maximum number of results

        Returns:
            List of matching activities

        Example:
            >>> activities = client.activities.search_activities(
            ...     search_text="login",
            ...     filters={"location.country": {"eq": "US"}}
            ... )
        """
        all_filters = filters or {}
        all_filters["text"] = {"eq": search_text}

        return self.list_activities(filters=all_filters, limit=limit)
