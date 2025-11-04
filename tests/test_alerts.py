"""Tests for the Alerts API."""

import pytest
from unittest.mock import patch, Mock


class TestAlertsAPI:
    """Test Alerts API methods."""

    @patch('defender_cloud_apps.client.DefenderCloudAppsClient._make_request')
    def test_list_alerts(self, mock_request, client_with_token, sample_alert):
        """Test listing alerts."""
        mock_request.return_value = {"data": [sample_alert]}

        alerts = client_with_token.alerts.list_alerts(limit=10)

        assert len(alerts) == 1
        assert alerts[0]["_id"] == "alert123"
        assert alerts[0]["title"] == "Suspicious activity detected"

    @patch('defender_cloud_apps.client.DefenderCloudAppsClient._make_request')
    def test_get_alert(self, mock_request, client_with_token, sample_alert):
        """Test getting a specific alert."""
        mock_request.return_value = sample_alert

        alert = client_with_token.alerts.get_alert("alert123")

        assert alert["_id"] == "alert123"
        assert alert["severity"]["label"] == "High"

    @patch('defender_cloud_apps.client.DefenderCloudAppsClient._make_request')
    def test_get_open_alerts(self, mock_request, client_with_token, sample_alert):
        """Test getting open alerts."""
        mock_request.return_value = {"data": [sample_alert]}

        alerts = client_with_token.alerts.get_open_alerts(limit=10)

        assert len(alerts) == 1
        assert alerts[0]["status"]["label"] == "Open"

    @patch('defender_cloud_apps.client.DefenderCloudAppsClient._make_request')
    def test_get_unread_alerts(self, mock_request, client_with_token, sample_alert):
        """Test getting unread alerts."""
        mock_request.return_value = {"data": [sample_alert]}

        alerts = client_with_token.alerts.get_unread_alerts(limit=10)

        assert len(alerts) == 1

    @patch('defender_cloud_apps.client.DefenderCloudAppsClient._make_request')
    def test_mark_as_read(self, mock_request, client_with_token):
        """Test marking alert as read."""
        mock_request.return_value = {"success": True}

        result = client_with_token.alerts.mark_as_read("alert123")

        assert result["success"] is True
        mock_request.assert_called_once()

    @patch('defender_cloud_apps.client.DefenderCloudAppsClient._make_request')
    def test_mark_as_unread(self, mock_request, client_with_token):
        """Test marking alert as unread."""
        mock_request.return_value = {"success": True}

        result = client_with_token.alerts.mark_as_unread("alert123")

        assert result["success"] is True

    @patch('defender_cloud_apps.client.DefenderCloudAppsClient._make_request')
    def test_close_benign(self, mock_request, client_with_token):
        """Test closing alert as benign."""
        mock_request.return_value = {"success": True}

        result = client_with_token.alerts.close_benign("alert123", comment="False positive")

        assert result["success"] is True

    @patch('defender_cloud_apps.client.DefenderCloudAppsClient._make_request')
    def test_close_false_positive(self, mock_request, client_with_token):
        """Test closing alert as false positive."""
        mock_request.return_value = {"success": True}

        result = client_with_token.alerts.close_false_positive("alert123", comment="Not a threat")

        assert result["success"] is True

    @patch('defender_cloud_apps.client.DefenderCloudAppsClient._make_request')
    def test_close_true_positive(self, mock_request, client_with_token):
        """Test closing alert as true positive."""
        mock_request.return_value = {"success": True}

        result = client_with_token.alerts.close_true_positive("alert123", comment="Confirmed")

        assert result["success"] is True

    @patch('defender_cloud_apps.client.DefenderCloudAppsClient._make_request')
    def test_list_alerts_paginated(self, mock_request, client_with_token, sample_alert):
        """Test paginated alert listing."""
        # Create a second alert for pagination
        alert2 = sample_alert.copy()
        alert2["_id"] = "alert456"

        # Simulate two pages: first page full (1 item with limit=1), second page empty
        mock_request.side_effect = [
            {"data": [sample_alert]},  # First page with 1 item (limit=1 means continue)
            {"data": [alert2]},  # Second page with 1 item
            {"data": []}  # Third call returns empty (stops pagination)
        ]

        alerts = client_with_token.alerts.list_alerts_paginated(limit=1)

        assert len(alerts) == 2
        assert alerts[0]["_id"] == "alert123"
        assert alerts[1]["_id"] == "alert456"


class TestAlertConstants:
    """Test alert-related constants."""

    def test_severity_constants(self, client_with_token):
        """Test severity constants are available."""
        assert hasattr(client_with_token.alerts, 'SEVERITY_LOW')
        assert hasattr(client_with_token.alerts, 'SEVERITY_MEDIUM')
        assert hasattr(client_with_token.alerts, 'SEVERITY_HIGH')

    def test_status_constants(self, client_with_token):
        """Test status constants are available."""
        assert hasattr(client_with_token.alerts, 'STATUS_UNREAD')
        assert hasattr(client_with_token.alerts, 'STATUS_READ')

    def test_resolution_constants(self, client_with_token):
        """Test resolution constants are available."""
        assert hasattr(client_with_token.alerts, 'RESOLUTION_OPEN')
        assert hasattr(client_with_token.alerts, 'RESOLUTION_BENIGN')
        assert hasattr(client_with_token.alerts, 'RESOLUTION_FALSE_POSITIVE')
        assert hasattr(client_with_token.alerts, 'RESOLUTION_TRUE_POSITIVE')
