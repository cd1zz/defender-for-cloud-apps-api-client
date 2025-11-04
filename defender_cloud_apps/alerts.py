"""
Alerts API endpoints for Microsoft Defender for Cloud Apps.

The Alerts API provides information about immediate risks identified by
Defender for Cloud Apps that require attention.
"""

from typing import Any, Dict, List, Optional
from .endpoints import APIEndpoints


class AlertsAPI:
    """
    Interface for the Alerts API endpoints.

    The Alerts API allows you to:
    - List alerts with filtering
    - Fetch specific alert details
    - Close alerts (benign, false positive, true positive)
    - Mark alerts as read/unread
    """

    # Alert status values
    STATUS_UNREAD = 0
    STATUS_READ = 1
    STATUS_ARCHIVED = 2

    # Severity values
    SEVERITY_LOW = 0
    SEVERITY_MEDIUM = 1
    SEVERITY_HIGH = 2
    SEVERITY_INFORMATIONAL = 3

    # Resolution status values
    RESOLUTION_OPEN = 0
    RESOLUTION_DISMISSED = 1
    RESOLUTION_BENIGN = 2
    RESOLUTION_TRUE_POSITIVE = 3
    RESOLUTION_FALSE_POSITIVE = 4
    RESOLUTION_RESOLVED = 5

    def __init__(self, client):
        """
        Initialize Alerts API.

        Args:
            client: DefenderCloudAppsClient instance
        """
        self._client = client

    def list_alerts(
        self,
        filters: Optional[Dict[str, Any]] = None,
        limit: int = 100,
        skip: int = 0,
        sort_field: Optional[str] = None,
        sort_direction: str = "desc"
    ) -> List[Dict[str, Any]]:
        """
        List alerts with optional filtering and pagination.

        Available filters:
        - entity.entity: Filter by specific entities
        - entity.ip: Filter by IP addresses
        - entity.service: Filter by service appId
        - alertOpen: Boolean filter for open/closed alerts
        - severity: Filter by severity level (0-3)
        - resolutionStatus: Filter by resolution status (0-5)
        - read: Boolean filter for read/unread alerts
        - date: Timestamp-based filtering (gte, lte, range)
        - alertType: Filter by alert type
        - source: Filter by origin (built-in or policy)

        Args:
            filters: Dictionary of filter criteria
            limit: Maximum number of results to return (max 100 per request)
            skip: Number of results to skip
            sort_field: Field to sort by
            sort_direction: Sort direction ('asc' or 'desc')

        Returns:
            List of alert records

        Example:
            >>> alerts = client.alerts.list_alerts(
            ...     filters={
            ...         "severity": {"eq": 2},  # High severity
            ...         "alertOpen": {"eq": True}
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
            APIEndpoints.ALERTS_LIST,
            data=data
        )

        return response.get("data", [])

    def list_alerts_paginated(
        self,
        filters: Optional[Dict[str, Any]] = None,
        limit: int = 100,
        skip: int = 0
    ) -> List[Dict[str, Any]]:
        """
        List all alerts with automatic pagination.

        This method automatically handles pagination and returns all matching alerts.

        Args:
            filters: Dictionary of filter criteria
            limit: Number of items per page (max 100)
            skip: Number of items to skip initially

        Returns:
            List of all matching alert records

        Example:
            >>> all_alerts = client.alerts.list_alerts_paginated(
            ...     filters={"severity": {"eq": 2}}
            ... )
        """
        return self._client._paginate(
            APIEndpoints.ALERTS_LIST,
            filters=filters,
            limit=limit,
            skip=skip
        )

    def get_alert(self, alert_id: str) -> Dict[str, Any]:
        """
        Fetch a specific alert by ID.

        Args:
            alert_id: The alert ID

        Returns:
            Alert details including properties like:
            - _id: Alert type identifier
            - timestamp: When alert was raised
            - title: Alert title
            - statusValue: State (0-2)
            - severityValue: Severity (0-3)
            - resolutionStatusValue: Resolution status (0-5)
            - stories: Risk categories
            - intent: Kill chain intent (MITRE ATT&CK)

        Example:
            >>> alert = client.alerts.get_alert("5f8a7b2c3d4e5f6g7h8i9j0k")
        """
        response = self._client._make_request(
            "GET",
            APIEndpoints.ALERTS_DETAIL.format(alert_id=alert_id)
        )

        return response

    def close_benign(
        self,
        alert_id: str,
        comment: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Close an alert as benign.

        Args:
            alert_id: The alert ID
            comment: Optional comment explaining the closure

        Returns:
            Response data

        Example:
            >>> client.alerts.close_benign(
            ...     alert_id="5f8a7b2c3d4e5f6g7h8i9j0k",
            ...     comment="Verified as legitimate business activity"
            ... )
        """
        data = {}
        if comment:
            data["comment"] = comment

        response = self._client._make_request(
            "POST",
            APIEndpoints.ALERTS_CLOSE_BENIGN.format(alert_id=alert_id),
            data=data
        )

        return response

    def close_false_positive(
        self,
        alert_id: str,
        comment: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Close an alert as a false positive.

        Args:
            alert_id: The alert ID
            comment: Optional comment explaining why it's a false positive

        Returns:
            Response data

        Example:
            >>> client.alerts.close_false_positive(
            ...     alert_id="5f8a7b2c3d4e5f6g7h8i9j0k",
            ...     comment="Alert triggered incorrectly"
            ... )
        """
        data = {}
        if comment:
            data["comment"] = comment

        response = self._client._make_request(
            "POST",
            APIEndpoints.ALERTS_CLOSE_FALSE_POSITIVE.format(alert_id=alert_id),
            data=data
        )

        return response

    def close_true_positive(
        self,
        alert_id: str,
        comment: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Close an alert as a true positive (confirmed threat).

        Args:
            alert_id: The alert ID
            comment: Optional comment about the threat and actions taken

        Returns:
            Response data

        Example:
            >>> client.alerts.close_true_positive(
            ...     alert_id="5f8a7b2c3d4e5f6g7h8i9j0k",
            ...     comment="Confirmed malicious activity, user account suspended"
            ... )
        """
        data = {}
        if comment:
            data["comment"] = comment

        response = self._client._make_request(
            "POST",
            APIEndpoints.ALERTS_CLOSE_TRUE_POSITIVE.format(alert_id=alert_id),
            data=data
        )

        return response

    def mark_as_read(self, alert_id: str) -> Dict[str, Any]:
        """
        Mark an alert as read.

        Args:
            alert_id: The alert ID

        Returns:
            Response data

        Example:
            >>> client.alerts.mark_as_read("5f8a7b2c3d4e5f6g7h8i9j0k")
        """
        response = self._client._make_request(
            "POST",
            APIEndpoints.ALERTS_MARK_READ.format(alert_id=alert_id)
        )

        return response

    def mark_as_unread(self, alert_id: str) -> Dict[str, Any]:
        """
        Mark an alert as unread.

        Args:
            alert_id: The alert ID

        Returns:
            Response data

        Example:
            >>> client.alerts.mark_as_unread("5f8a7b2c3d4e5f6g7h8i9j0k")
        """
        response = self._client._make_request(
            "POST",
            APIEndpoints.ALERTS_MARK_UNREAD.format(alert_id=alert_id)
        )

        return response

    def get_open_alerts(
        self,
        severity: Optional[int] = None,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """
        Get all open alerts, optionally filtered by severity.

        Args:
            severity: Optional severity filter (0: Low, 1: Medium, 2: High, 3: Informational)
            limit: Maximum number of results

        Returns:
            List of open alerts

        Example:
            >>> high_priority_alerts = client.alerts.get_open_alerts(severity=2)
        """
        filters: Dict[str, Any] = {
            "alertOpen": {"eq": True}
        }

        if severity is not None:
            filters["severity"] = {"eq": severity}

        return self.list_alerts(filters=filters, limit=limit)

    def get_unread_alerts(self, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Get all unread alerts.

        Args:
            limit: Maximum number of results

        Returns:
            List of unread alerts

        Example:
            >>> unread = client.alerts.get_unread_alerts()
        """
        filters = {
            "read": {"eq": False}
        }

        return self.list_alerts(filters=filters, limit=limit)
