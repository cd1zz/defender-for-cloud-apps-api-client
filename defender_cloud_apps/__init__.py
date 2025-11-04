"""
Microsoft Defender for Cloud Apps API Client

A Python client library for interacting with the Microsoft Defender for Cloud Apps REST API.
"""

from defender_cloud_apps.client import (
    DefenderCloudAppsClient,
    DefenderCloudAppsError,
    AuthenticationError,
    RateLimitError,
    APIError
)
from defender_cloud_apps.activities import ActivitiesAPI
from defender_cloud_apps.alerts import AlertsAPI
from defender_cloud_apps.files import FilesAPI
from defender_cloud_apps.entities import EntitiesAPI
from defender_cloud_apps.discovery import DiscoveryAPI
from defender_cloud_apps.data_enrichment import DataEnrichmentAPI
from defender_cloud_apps.filters import FilterBuilder, TimeHelper

__version__ = "0.2.0"
__all__ = [
    "DefenderCloudAppsClient",
    "DefenderCloudAppsError",
    "AuthenticationError",
    "RateLimitError",
    "APIError",
    "ActivitiesAPI",
    "AlertsAPI",
    "FilesAPI",
    "EntitiesAPI",
    "DiscoveryAPI",
    "DataEnrichmentAPI",
    "FilterBuilder",
    "TimeHelper",
]
