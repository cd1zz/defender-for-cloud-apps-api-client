# Examples

This directory contains example scripts demonstrating how to use the Microsoft Defender for Cloud Apps API client.

## Setup

Before running the examples, you need to set up your environment:

1. Install the client library:
   ```bash
   pip install defender-cloud-apps-api-client
   ```

2. Configure your credentials using a `.env` file:
   ```bash
   # Copy the example file
   cp ../.env.example .env

   # Edit .env and add your credentials
   # DEFENDER_CLOUD_APPS_URL=https://your-tenant.region.portal.cloudappsecurity.com/api
   # DEFENDER_CLOUD_APPS_TOKEN=your-api-token-here
   ```

   The examples will automatically load credentials from the `.env` file using `python-dotenv`.

   **Alternative: Environment Variables (Optional)**

   You can also set environment variables directly if you prefer:

   Linux/macOS:
   ```bash
   export DEFENDER_CLOUD_APPS_URL="https://your-tenant.region.portal.cloudappsecurity.com/api"
   export DEFENDER_CLOUD_APPS_TOKEN="your-api-token-here"
   ```

   Windows (PowerShell):
   ```powershell
   $env:DEFENDER_CLOUD_APPS_URL="https://your-tenant.region.portal.cloudappsecurity.com/api"
   $env:DEFENDER_CLOUD_APPS_TOKEN="your-api-token-here"
   ```

## Available Examples

### [list_alerts.py](list_alerts.py)

Demonstrates how to list and filter alerts.

**Features:**
- List high-severity open alerts
- Get unread alerts
- Filter alerts by date range
- Display alert details

**Usage:**
```bash
python list_alerts.py
```

### [export_activities.py](export_activities.py)

Exports activity data to CSV format.

**Features:**
- Query activities with date filters
- Automatic pagination
- CSV export with formatted timestamps
- Extract user, device, and location data

**Usage:**
```bash
python export_activities.py
```

**Output:** Creates a CSV file named `activities_export_YYYYMMDD_HHMMSS.csv` in the current directory.

### [monitor_public_files.py](monitor_public_files.py)

Monitors and reports on publicly shared files.

**Features:**
- Find all publicly shared files
- Group files by type
- Identify externally shared files
- Check for policy violations

**Usage:**
```bash
python monitor_public_files.py
```

### [list_discovered_apps.py](list_discovered_apps.py)

Lists and analyzes discovered cloud apps from Cloud Discovery.

**Features:**
- List all continuous reports (streams)
- List all discovered apps
- Get detailed information about specific apps
- Find high-risk and unsanctioned apps
- Search for apps by name
- List app categories

**Usage:**
```bash
python list_discovered_apps.py
```

**Note:** This example requires that you have Cloud Discovery configured with:
- Microsoft Defender for Endpoint integration, OR
- Log collectors configured, OR
- Manually uploaded discovery logs

## Getting Your API Credentials

### API URL

1. Open the Microsoft Defender Portal
2. Navigate to **Settings** > **Cloud Apps** > **System** > **About**
3. Copy the API URL (should look like: `https://tenant.region.portal.cloudappsecurity.com`)
4. Add `/api` to the end if not already present

### API Token

1. Go to **Settings** > **Cloud Apps** > **System** > **API tokens**
2. Click **Generate new token**
3. Provide a name for the token
4. Copy the generated token immediately (you won't be able to see it again)

## Common Patterns

### Error Handling

```python
from defender_cloud_apps import (
    DefenderCloudAppsClient,
    AuthenticationError,
    RateLimitError,
    APIError
)

try:
    with DefenderCloudAppsClient(base_url=..., api_token=...) as client:
        alerts = client.alerts.list_alerts()
except AuthenticationError:
    print("Authentication failed. Check your API token.")
except RateLimitError:
    print("Rate limit exceeded. Wait before retrying.")
except APIError as e:
    print(f"API error: {e}")
```

### Using Filters

```python
from defender_cloud_apps import FilterBuilder, TimeHelper

# Build complex filters
filters = (FilterBuilder()
    .equals("severity", 2)
    .in_last_n_days("date", 7)
    .equals("alertOpen", True)
    .build())

alerts = client.alerts.list_alerts(filters=filters)
```

### Pagination

```python
# Get all results with automatic pagination
all_activities = client.activities.list_activities_paginated(
    filters={"service": {"eq": 11770}},
    limit=100
)
```

## Troubleshooting

### Authentication Errors

If you get authentication errors:
- Verify your API token is correct
- Check that the token hasn't expired
- Ensure the token has appropriate permissions

### Rate Limiting

The API has a limit of 30 requests per minute. If you hit rate limits:
- Increase the `rate_limit_delay` parameter when creating the client
- Reduce the frequency of your requests
- Use pagination efficiently to minimize requests

### No Data Returned

If queries return no data:
- Verify your filters are correct
- Check the date range (timestamps are in milliseconds)
- Ensure you have data in your Defender for Cloud Apps tenant
- Verify your API token has permission to access the data

## Contributing

Feel free to submit additional examples via pull requests!
