"""Tests for the Activities API."""

import pytest
from unittest.mock import patch, Mock


class TestActivitiesAPI:
    """Test Activities API methods."""

    @patch('defender_cloud_apps.client.DefenderCloudAppsClient._make_request')
    def test_list_activities(self, mock_request, client_with_token, sample_activity):
        """Test listing activities."""
        mock_request.return_value = {"data": [sample_activity]}

        activities = client_with_token.activities.list_activities(limit=10)

        assert len(activities) == 1
        assert activities[0]["_id"] == "activity123"
        assert activities[0]["user"]["username"] == "user@example.com"

    @patch('defender_cloud_apps.client.DefenderCloudAppsClient._make_request')
    def test_list_activities_with_filters(self, mock_request, client_with_token, sample_activity):
        """Test listing activities with filters."""
        mock_request.return_value = {"data": [sample_activity]}

        filters = {"service": {"eq": "Microsoft 365"}}
        activities = client_with_token.activities.list_activities(filters=filters, limit=10)

        assert len(activities) == 1
        mock_request.assert_called_once()

    @patch('defender_cloud_apps.client.DefenderCloudAppsClient._make_request')
    def test_get_activity(self, mock_request, client_with_token, sample_activity):
        """Test getting a specific activity."""
        mock_request.return_value = sample_activity

        activity = client_with_token.activities.get_activity("activity123")

        assert activity["_id"] == "activity123"
        assert activity["user"]["username"] == "user@example.com"

    @patch('defender_cloud_apps.client.DefenderCloudAppsClient._make_request')
    def test_search_activities(self, mock_request, client_with_token, sample_activity):
        """Test searching activities."""
        mock_request.return_value = {"data": [sample_activity]}

        activities = client_with_token.activities.search_activities(search_text="login", limit=10)

        assert len(activities) == 1
        assert activities[0]["eventType"] == "EVENT_TYPE_LOGIN"

    @patch('defender_cloud_apps.client.DefenderCloudAppsClient._make_request')
    def test_list_activities_paginated(self, mock_request, client_with_token, sample_activity):
        """Test paginated activity listing."""
        # Create a second activity for pagination
        activity2 = sample_activity.copy()
        activity2["_id"] = "activity456"

        # Simulate two pages: first page full (1 item with limit=1), second page empty
        mock_request.side_effect = [
            {"data": [sample_activity]},  # First page with 1 item (limit=1 means continue)
            {"data": [activity2]},  # Second page with 1 item
            {"data": []}  # Third call returns empty (stops pagination)
        ]

        activities = client_with_token.activities.list_activities_paginated(limit=1)

        assert len(activities) == 2
        assert activities[0]["_id"] == "activity123"
        assert activities[1]["_id"] == "activity456"
