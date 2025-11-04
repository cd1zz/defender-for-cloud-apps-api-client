"""
Centralized API endpoint constants for Microsoft Defender for Cloud Apps.

This module provides a single source of truth for all API endpoints used
throughout the client library. Centralizing endpoints improves maintainability,
prevents typos, and makes API version upgrades easier.
"""


class APIEndpoints:
    """
    Centralized storage for all Microsoft Defender for Cloud Apps API endpoints.

    ## What is the Microsoft Defender for Cloud Apps API?

    The Microsoft Defender for Cloud Apps API provides programmatic access to
    security monitoring and threat protection for cloud applications. It enables:

    - **Security Monitoring**: Track user activities, file access, and anomalous behavior
    - **Threat Detection**: Identify and investigate security alerts and incidents
    - **Risk Assessment**: Analyze user and entity risk scores with behavioral analytics
    - **Cloud Discovery**: Monitor shadow IT and unsanctioned cloud app usage
    - **Data Protection**: Control file sharing and detect sensitive data exposure
    - **Compliance**: Audit cloud app usage against corporate policies

    The API is organized into 6 main endpoint groups, each focusing on a specific
    aspect of cloud security and governance.
    """

    # ========================================================================
    # Activities API - User activity monitoring and investigation
    # ========================================================================
    ACTIVITIES_LIST = "/v1/activities/"
    ACTIVITIES_DETAIL = "/v1/activities/{activity_id}/"
    ACTIVITIES_FEEDBACK = "/v1/activities/{activity_id}/feedback/"

    # ========================================================================
    # Alerts API - Security alert management
    # ========================================================================
    ALERTS_LIST = "/v1/alerts/"
    ALERTS_DETAIL = "/v1/alerts/{alert_id}/"
    ALERTS_CLOSE_BENIGN = "/v1/alerts/{alert_id}/close_benign/"
    ALERTS_CLOSE_FALSE_POSITIVE = "/v1/alerts/{alert_id}/close_false_positive/"
    ALERTS_CLOSE_TRUE_POSITIVE = "/v1/alerts/{alert_id}/close_true_positive/"
    ALERTS_MARK_READ = "/v1/alerts/{alert_id}/read/"
    ALERTS_MARK_UNREAD = "/v1/alerts/{alert_id}/unread/"

    # ========================================================================
    # Files API - File metadata and sharing information
    # ========================================================================
    FILES_LIST = "/v1/files/"
    FILES_DETAIL = "/v1/files/{file_id}/"

    # ========================================================================
    # Entities API - User and device entity information
    # ========================================================================
    ENTITIES_LIST = "v1/entities"
    ENTITIES_DETAIL = "v1/entities/{entity_id}"

    # ========================================================================
    # Cloud Discovery API - Shadow IT and app discovery
    # ========================================================================
    DISCOVERY_STREAMS = "discovery/streams/"
    DISCOVERY_APPS_LIST = "v1/discovery/discovered_apps/"
    DISCOVERY_APP_DETAIL = "v1/discovery/discovered_apps/{app_id}/"
    DISCOVERY_CATEGORIES = "v1/discovery/discovered_apps/categories/"
    DISCOVERY_BLOCK_SCRIPT = "discovery/block_script/"

    # ========================================================================
    # Data Enrichment API - IP subnet management for cloud discovery
    # ========================================================================
    SUBNET_LIST = "v1/subnet"
    SUBNET_CREATE = "v1/subnet"
    SUBNET_DETAIL = "v1/subnet/{subnet_id}"
    SUBNET_UPDATE = "v1/subnet/{subnet_id}"
    SUBNET_DELETE = "v1/subnet/{subnet_id}"
