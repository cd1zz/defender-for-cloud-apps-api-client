# Microsoft Defender for Cloud Apps API Client

A comprehensive Python client library for interacting with the Microsoft Defender for Cloud Apps REST API with support for both personal API tokens and OAuth2 Client Credentials authentication.

## Features

- **Complete API Coverage**: All 6 API endpoints with 58 methods (Activities, Alerts, Files, Entities, Cloud Discovery, Data Enrichment)
- **Dual Authentication**: Personal API tokens (legacy) and OAuth2 Client Credentials (recommended)
- **Automatic Token Management**: OAuth2 tokens are automatically acquired, cached, and refreshed with 5-minute pre-expiry logic
- **Type Hints**: Full type annotations for better IDE support and autocomplete
- **Comprehensive Error Handling**: Custom exceptions for authentication, rate limiting, and API errors
- **Rate Limiting**: Built-in rate limiting to stay within API constraints (30 requests/minute)
- **Pagination**: Automatic pagination support for large result sets
- **Advanced Filtering**: 16+ filter operators (eq, neq, gt, gte, lt, lte, contains, startswith, endswith, etc.)
- **Filter Builder**: Fluent interface for building complex filter queries
- **Retry Logic**: Automatic retry with exponential backoff for transient failures

## Installation

```bash
pip install defender-cloud-apps-api-client
```

Or install from source:

```bash
git clone https://github.com/yourusername/defender-for-cloud-apps-api-client.git
cd defender-for-cloud-apps-api-client
pip install -e .
```

## Quick Start - OAuth2 (Recommended)

1. Create application in Azure Entra ID (see [Microsoft Docs](https://learn.microsoft.com/en-us/defender-cloud-apps/api-authentication-application))
2. Create `.env` file:

```bash
DEFENDER_CLOUD_APPS_URL=https://your-tenant.region.portal.cloudappsecurity.com/api
DEFENDER_CLOUD_APPS_TENANT_ID=your-tenant-id
DEFENDER_CLOUD_APPS_CLIENT_ID=your-app-id
DEFENDER_CLOUD_APPS_CLIENT_SECRET=your-secret
```

3. Use in code:

```python
from defender_cloud_apps import DefenderCloudAppsClient
import os
from dotenv import load_dotenv

load_dotenv()
client = DefenderCloudAppsClient(
    base_url=os.getenv("DEFENDER_CLOUD_APPS_URL"),
    tenant_id=os.getenv("DEFENDER_CLOUD_APPS_TENANT_ID"),
    client_id=os.getenv("DEFENDER_CLOUD_APPS_CLIENT_ID"),
    client_secret=os.getenv("DEFENDER_CLOUD_APPS_CLIENT_SECRET"),
)

with client:
    # Get high-risk users
    risky = client.entities.get_risky_entities(min_risk_score=7)
    for user in risky:
        print(f"{user['username']}: Risk {user['riskScore']}")
    
    # Get alerts
    alerts = client.alerts.list_alerts(limit=10)
    for alert in alerts:
        print(f"{alert['title']}")
```

## Supported Endpoints

### 1. Activities API (`/api/v1/activities/`)

Monitor and investigate user actions across cloud apps. **5 methods available.**

```python
# List activities with filtering
activities = client.activities.list_activities(
    filters={"service": {"eq": "salesforce"}},
    limit=100
)

# Automatic pagination for large result sets
all_activities = client.activities.list_activities_paginated(
    filters={"date": {"gte": timestamp}},
    limit=1000
)

# Get specific activity details
activity = client.activities.get_activity(activity_id)

# Search activities with free-text
results = client.activities.search_activities(
    query="login",
    filters={"user.username": {"contains": "admin"}}
)

# Provide feedback on an activity
client.activities.provide_feedback(
    activity_id=activity_id,
    feedback_type="benign",
    comment="Expected behavior"
)
```

### 2. Alerts API (`/api/v1/alerts/`)

Manage security alerts and incidents. **10 methods available.**

```python
# List all alerts
alerts = client.alerts.list_alerts(limit=10)

# Get open high-severity alerts
critical = client.alerts.get_open_alerts(severity=client.alerts.SEVERITY_HIGH)

# Get unread alerts
unread = client.alerts.get_unread_alerts(limit=50)

# Get specific alert details
alert = client.alerts.get_alert(alert_id)

# Close alerts with different dispositions
client.alerts.close_benign(alert_id, comment="False alarm")
client.alerts.close_false_positive(alert_id, comment="Not a threat")
client.alerts.close_true_positive(alert_id, comment="Confirmed attack")

# Mark alerts as read/unread
client.alerts.mark_as_read(alert_id)
client.alerts.mark_as_unread(alert_id)

# Automatic pagination for all alerts
all_alerts = client.alerts.list_alerts_paginated(
    filters={"severity": {"gte": 2}}
)
```

**Available Constants:**

- Status: `STATUS_UNREAD`, `STATUS_READ`, `STATUS_ARCHIVED`
- Severity: `SEVERITY_LOW`, `SEVERITY_MEDIUM`, `SEVERITY_HIGH`, `SEVERITY_INFORMATIONAL`
- Resolution: `RESOLUTION_OPEN`, `RESOLUTION_DISMISSED`, `RESOLUTION_BENIGN`, `RESOLUTION_TRUE_POSITIVE`, `RESOLUTION_FALSE_POSITIVE`

### 3. Files API (`/api/v1/files/`)

Monitor files, sharing permissions, and data exposure. **10 methods available.**

```python
# List files with filtering
files = client.files.list_files(
    filters={"sharing.sharingLevel": {"eq": "Public"}},
    limit=50
)

# Get publicly shared files
public_files = client.files.get_public_files(limit=100)

# Get externally shared files
external_files = client.files.get_external_files(limit=100)

# Get quarantined files
quarantined = client.files.get_quarantined_files()

# Get files by owner
user_files = client.files.get_files_by_owner(entity_id="user@example.com")

# Get files by type or extension
documents = client.files.get_files_by_type(
    file_type=client.files.FILE_TYPE_DOCUMENT
)
excel_files = client.files.get_files_by_extension(extension="xlsx")

# Get recently modified files
recent = client.files.get_recently_modified_files(days=7, limit=50)

# Get specific file details
file_info = client.files.get_file(file_id)

# Automatic pagination
all_files = client.files.list_files_paginated(
    filters={"owner": {"eq": "admin@contoso.com"}}
)
```

**Available Constants:**

- File Types: `FILE_TYPE_DOCUMENT`, `FILE_TYPE_SPREADSHEET`, `FILE_TYPE_PRESENTATION`, `FILE_TYPE_TEXT`, `FILE_TYPE_IMAGE`, `FILE_TYPE_FOLDER`, `FILE_TYPE_OTHER`
- Sharing Levels: `SHARING_PUBLIC_INTERNET`, `SHARING_PUBLIC`, `SHARING_EXTERNAL`, `SHARING_INTERNAL`, `SHARING_PRIVATE`

### 4. Entities API (`/api/v1/entities/`)

Investigate users and devices with risk scoring. **10 methods available.**

```python
# List all entities with filtering
entities = client.entities.list_entities(
    filters={"isAdmin": {"eq": True}},
    limit=100
)

# Get high-risk entities
risky = client.entities.get_risky_entities(
    min_risk_score=8,
    limit=50
)

# Get external users
external_users = client.entities.get_external_entities(limit=100)

# Get administrator accounts
admins = client.entities.get_admin_entities(limit=50)

# Get entity details
entity = client.entities.get_entity(entity_id)
user = client.entities.get_entity_by_username("user@example.com")

# Get risk factors for an entity
risk_factors = client.entities.get_entity_risk_factors(entity_id)

# Search for entities
results = client.entities.search_entities(
    query="john",
    limit=50
)

# Get entities by tag
tagged = client.entities.get_entities_by_tag(
    tag="VIP",
    limit=100
)

# Get activity timeline for an entity
timeline = client.entities.get_entity_activity_timeline(
    entity_id=entity_id,
    start_timestamp=start_time,
    end_timestamp=end_time
)
```

**Available Constants:**

- Entity Types: `ENTITY_TYPE_USER`, `ENTITY_TYPE_DEVICE`
- Risk Levels: `RISK_LEVEL_LOW`, `RISK_LEVEL_MEDIUM`, `RISK_LEVEL_HIGH`

### 5. Cloud Discovery API (`/api/v1/discovery/`)

Analyze and manage discovered cloud applications. **11 methods available.**

```python
# List all continuous reports (streams)
streams = client.discovery.list_streams()
stream_id = streams[0].get('_id') if streams else None

# List discovered apps
apps = client.discovery.list_discovered_apps(
    stream_id=stream_id,
    limit=100
)

# Get high-risk apps
high_risk = client.discovery.get_high_risk_apps(
    stream_id=stream_id,
    min_risk_score=8
)

# Get unsanctioned apps
unsanctioned = client.discovery.get_unsanctioned_apps(stream_id=stream_id)

# Get non-compliant apps
non_compliant = client.discovery.get_noncompliant_apps(
    stream_id=stream_id,
    compliance_standard="SOC2"
)

# Search for apps
search_results = client.discovery.search_discovered_apps(
    stream_id=stream_id,
    query="dropbox"
)

# Get apps by category
storage_apps = client.discovery.get_apps_by_category(
    stream_id=stream_id,
    category="Cloud Storage"
)

# Get specific app details
app = client.discovery.get_discovered_app(
    stream_id=stream_id,
    app_id=app_id
)

# List app categories
categories = client.discovery.list_categories(stream_id=stream_id)

# Generate block script for unsanctioned apps
script = client.discovery.generate_block_script(
    stream_id=stream_id,
    format="paloalto"  # or "checkpoint", "fortigate", etc.
)

# Automatic pagination
all_apps = client.discovery.list_discovered_apps_paginated(
    stream_id=stream_id
)
```

### 6. Data Enrichment API (`/api/subnet/`)

Manage IP subnet mappings for enhanced cloud discovery. **12 methods available.**

```python
# List all subnets
subnets = client.data_enrichment.list_subnets(limit=100)

# Create subnet mapping
subnet = client.data_enrichment.create_subnet(
    name="HQ Network",
    original_range="10.0.0.0/16",
    organization="Headquarters",
    location="New York",
    category="Corporate",
    tags=["main-office", "vpn"]
)

# Update subnet
client.data_enrichment.update_subnet(
    subnet_id=subnet_id,
    location="San Francisco"
)

# Delete subnet
client.data_enrichment.delete_subnet(subnet_id)

# Get specific subnet
subnet = client.data_enrichment.get_subnet(subnet_id)
subnet_by_name = client.data_enrichment.get_subnet_by_name("HQ Network")

# Filter subnets
hq_subnets = client.data_enrichment.get_subnets_by_organization("Headquarters")
sf_subnets = client.data_enrichment.get_subnets_by_location("San Francisco")
corp_subnets = client.data_enrichment.get_subnets_by_category("Corporate")

# Search subnets
results = client.data_enrichment.search_subnets(
    query="office",
    limit=50
)

# Bulk create subnets
subnets_to_create = [
    {
        "name": "Office 1",
        "original_range": "10.1.0.0/24",
        "organization": "Branch Offices"
    },
    {
        "name": "Office 2",
        "original_range": "10.2.0.0/24",
        "organization": "Branch Offices"
    }
]
results = client.data_enrichment.bulk_create_subnets(subnets_to_create)

# Export all subnets as formatted report
report = client.data_enrichment.export_subnets()
print(report)
```

## Advanced Filtering

All endpoints support advanced filtering with 16+ operators:

```python
# Filter activities
filters = {
    "timestamp": {"gte": week_ago},
    "user.username": {"contains": "admin"},
    "service": {"eq": "salesforce"}
}
activities = client.activities.list_activities(filters=filters)

# Filter alerts by severity
filters = {"severity": {"gte": 2}, "alertStatus": {"eq": 0}}
alerts = client.alerts.list_alerts(filters=filters)

# Filter entities
filters = {
    "isExternal": {"eq": True},
    "riskScore": {"gte": 7}
}
risky_external = client.entities.list_entities(filters=filters)
```

### Available Operators

- `eq`, `neq` - Equality operators
- `gt`, `gte`, `lt`, `lte` - Numeric comparisons
- `contains`, `ncontains` - Substring matching
- `startswith`, `endswith`, `doesnotstartwith` - String prefix/suffix
- `text` - Full text search
- `isset`, `isnotset` - Null checks
- `range` - Range matching
- `descendantof` - Organizational hierarchy

## Examples

See [examples/](examples/) directory for comprehensive scripts demonstrating all API endpoints.

All examples support **two output modes**:

1. **Curated Terminal View** (default) - Formatted, human-readable output highlighting key information
2. **Complete JSON File Output** (`--output-file`) - Full API response written to file for automation

### Available Examples

- `list_alerts.py` - List and filter security alerts
- `export_activities.py` - Export user activities with pagination
- `list_discovered_apps.py` - Discover and analyze cloud apps
- `monitor_public_files.py` - Monitor publicly shared files
- `entity_investigation.py` - Investigate users and devices with risk scoring
- `data_enrichment_management.py` - Manage IP subnet mappings
- `advanced_filtering.py` - Advanced filtering techniques across all endpoints

### Running Examples

```bash
# Show curated view in terminal (default)
python examples/list_alerts.py

# Save complete JSON output to file
python examples/list_alerts.py --output-file alerts.json

# Use command-line parameters
python examples/entity_investigation.py --min-risk-score 8 --limit-risky 20
python examples/export_activities.py --days 7 --limit 50 --output-file recent.json

# Get help for any example
python examples/list_discovered_apps.py --help
```

## Authentication Details

### OAuth2 Client Credentials

Tokens are automatically:

- Acquired on first use
- Cached in memory
- Refreshed 5 minutes before expiry
- Renewed on 401 responses

### Personal API Token

For backwards compatibility. Set either OAuth2 credentials OR API token, not both.

## Rate Limiting

API limit: **30 requests/minute**

Client handles this automatically:

- 2 second delay between requests (configurable)
- Exponential backoff retry
- `RateLimitError` if exceeded

Configure:

```python
client = DefenderCloudAppsClient(
    ...,
    rate_limit_delay=3.0,    # seconds
    max_retries=3
)
```

## Error Handling

```python
from defender_cloud_apps import (
    AuthenticationError,
    RateLimitError,
    APIError
)

try:
    results = client.alerts.list_alerts()
except AuthenticationError as e:
    print(f"Auth failed: {e}")
except RateLimitError as e:
    print(f"Rate limited: {e}")
except APIError as e:
    print(f"API error: {e}")
```

## Requirements

- Python 3.8+
- requests >= 2.31.0
- urllib3 >= 2.0.0
- python-dotenv >= 0.19.0

## References

- [API Introduction](https://learn.microsoft.com/en-us/defender-cloud-apps/api-introduction)
- [OAuth2 Setup](https://learn.microsoft.com/en-us/defender-cloud-apps/api-authentication-application)
- [Activities Filters](https://learn.microsoft.com/en-us/defender-cloud-apps/activity-filters)
- [Alert Management](https://learn.microsoft.com/en-us/defender-cloud-apps/alert-management-remediation)

## License

MIT License - see [LICENSE](LICENSE) file
