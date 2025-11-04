#!/usr/bin/env python3
"""
Advanced Filtering Examples

This script demonstrates advanced filtering techniques across all API endpoints
and outputs results as JSON.

Output modes:
- Default (curated): Shows key filtering examples in a readable format
- Full output: Writes complete JSON response to a file (use --output-file)
"""

import os
import sys
import json
import argparse
from datetime import datetime, timedelta
from dotenv import load_dotenv
from defender_cloud_apps import DefenderCloudAppsClient, FilterBuilder

# Load environment variables
load_dotenv()

# Get configuration from environment
BASE_URL = os.getenv("DEFENDER_CLOUD_APPS_URL")
TENANT_ID = os.getenv("DEFENDER_CLOUD_APPS_TENANT_ID")
CLIENT_ID = os.getenv("DEFENDER_CLOUD_APPS_CLIENT_ID")
CLIENT_SECRET = os.getenv("DEFENDER_CLOUD_APPS_CLIENT_SECRET")
API_TOKEN = os.getenv("DEFENDER_CLOUD_APPS_TOKEN")


def print_curated_view(result):
    """Print a curated view of filtering results to terminal."""
    print("\n" + "="*80)
    print("ADVANCED FILTERING EXAMPLES REPORT")
    print("="*80 + "\n")

    if 'error' in result:
        print(f"Error: {result['error']}")
        return

    # Summary counts
    print("FILTERING RESULTS SUMMARY")
    print("-" * 80)
    print(f"  - Activities by date: {len(result.get('activities_by_date', []))}")
    print(f"  - High severity alerts: {len(result.get('high_severity_alerts', []))}")
    print(f"  - Public files: {len(result.get('public_files', []))}")
    print(f"  - Risky external admins: {len(result.get('risky_external_admins', []))}")
    print(f"  - Medium risk users: {len(result.get('medium_risk_users', []))}")
    print(f"  - Login activities: {len(result.get('login_activities', []))}")
    print(f"  - Company documents: {len(result.get('company_documents', []))}")
    print(f"  - HQ corporate subnets: {len(result.get('hq_corporate_subnets', []))}\n")

    # Show available operators
    print("AVAILABLE FILTER OPERATORS")
    print("-" * 80)
    operators = result.get('available_operators', [])
    for op in operators:
        print(f"  {op.get('operator', 'N/A'):20s} - {op.get('description', 'No description')}")

    # Show some example high severity alerts
    alerts = result.get('high_severity_alerts', [])
    if alerts and "high_severity_alerts_error" not in result:
        print(f"\n\nHIGH SEVERITY ALERTS (showing up to 5)")
        print("-" * 80)
        for i, alert in enumerate(alerts[:5], 1):
            title = alert.get('title', 'Untitled')
            severity = alert.get('severity', {})
            print(f"{i}. {title}")
            print(f"   Severity: {severity}")

    # Show risky external admins
    risky = result.get('risky_external_admins', [])
    if risky and "risky_external_admins_error" not in result:
        print(f"\n\nRISKY EXTERNAL ADMINISTRATORS (showing up to 5)")
        print("-" * 80)
        for i, entity in enumerate(risky[:5], 1):
            username = entity.get('username', 'Unknown')
            risk = entity.get('riskScore', 'N/A')
            print(f"{i}. {username} (Risk: {risk})")

    # Show medium risk users
    medium = result.get('medium_risk_users', [])
    if medium and "medium_risk_users_error" not in result:
        print(f"\n\nMEDIUM RISK USERS (showing up to 5)")
        print("-" * 80)
        for i, entity in enumerate(medium[:5], 1):
            username = entity.get('username', 'Unknown')
            risk = entity.get('riskScore', 'N/A')
            print(f"{i}. {username} (Risk: {risk})")

    # Show login activities
    logins = result.get('login_activities', [])
    if logins and "login_activities_error" not in result:
        print(f"\n\nRECENT LOGIN ACTIVITIES (showing up to 5)")
        print("-" * 80)
        for i, activity in enumerate(logins[:5], 1):
            username = activity.get('user', {}).get('username', 'Unknown')
            timestamp = activity.get('timestamp', 'N/A')
            print(f"{i}. {username} at {timestamp}")

    print(f"\n\nThis demonstrates various filtering capabilities across different endpoints.")
    print(f"Use --output-file to save complete filtered data.\n")


def main():
    """Run advanced filtering examples."""

    # Parse command-line arguments
    parser = argparse.ArgumentParser(
        description="Demonstrate advanced filtering in Microsoft Defender for Cloud Apps",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Show curated view in terminal
  python advanced_filtering.py

  # Save full JSON output to file
  python advanced_filtering.py --output-file filtered_results.json

  # Adjust date range and severity filters
  python advanced_filtering.py --days 14 --min-severity 1

  # Adjust limits for different query types
  python advanced_filtering.py --limit-activities 50 --limit-alerts 20
        """
    )
    parser.add_argument(
        '--output-file', '-o',
        type=str,
        help='Write complete JSON output to specified file'
    )
    parser.add_argument(
        '--days',
        type=int,
        default=7,
        help='Number of days to look back for activities (default: 7)'
    )
    parser.add_argument(
        '--days-files',
        type=int,
        default=30,
        help='Number of days to look back for files (default: 30)'
    )
    parser.add_argument(
        '--min-severity',
        type=int,
        default=2,
        help='Minimum alert severity (default: 2)'
    )
    parser.add_argument(
        '--min-risk-score',
        type=int,
        default=5,
        help='Minimum risk score for entities (default: 5)'
    )
    parser.add_argument(
        '--max-risk-score',
        type=int,
        default=8,
        help='Maximum risk score for medium risk users (default: 8)'
    )
    parser.add_argument(
        '--limit-activities',
        type=int,
        default=5,
        help='Maximum number of activities to retrieve (default: 5)'
    )
    parser.add_argument(
        '--limit-alerts',
        type=int,
        default=5,
        help='Maximum number of alerts to retrieve (default: 5)'
    )
    parser.add_argument(
        '--limit-files',
        type=int,
        default=5,
        help='Maximum number of files to retrieve (default: 5)'
    )
    parser.add_argument(
        '--limit-entities',
        type=int,
        default=5,
        help='Maximum number of entities to retrieve (default: 5)'
    )
    parser.add_argument(
        '--limit-subnets',
        type=int,
        default=5,
        help='Maximum number of subnets to retrieve (default: 5)'
    )

    args = parser.parse_args()

    result = {
        'activities_by_date': [],
        'high_severity_alerts': [],
        'public_files': [],
        'risky_external_admins': [],
        'medium_risk_users': [],
        'login_activities': [],
        'company_documents': [],
        'hq_corporate_subnets': [],
        'available_operators': [
            {"operator": "eq", "description": "Equals - exact match"},
            {"operator": "neq", "description": "Not equals - excludes matches"},
            {"operator": "gt", "description": "Greater than - numeric comparison"},
            {"operator": "gte", "description": "Greater than or equal"},
            {"operator": "lt", "description": "Less than - numeric comparison"},
            {"operator": "lte", "description": "Less than or equal"},
            {"operator": "contains", "description": "Contains substring"},
            {"operator": "startswith", "description": "Starts with string prefix"},
            {"operator": "endswith", "description": "Ends with string suffix"},
            {"operator": "doesnotstartwith", "description": "Does not start with"},
            {"operator": "ncontains", "description": "Does not contain substring"},
            {"operator": "text", "description": "Full text search"},
            {"operator": "isset", "description": "Field exists and is not empty"},
            {"operator": "isnotset", "description": "Field does not exist or is empty"},
            {"operator": "range", "description": "Within numeric range"},
            {"operator": "descendantof", "description": "Organizational hierarchy match"},
        ]
    }

    # Determine authentication method
    if not BASE_URL:
        result['error'] = "DEFENDER_CLOUD_APPS_URL environment variable is required"
        print(json.dumps(result, indent=2))
        return

    has_oauth2 = all([TENANT_ID, CLIENT_ID, CLIENT_SECRET])
    has_token = API_TOKEN is not None

    if not has_oauth2 and not has_token:
        result['error'] = "Must provide either OAuth2 credentials or API_TOKEN"
        print(json.dumps(result, indent=2))
        return

    # Initialize client
    try:
        if has_oauth2:
            client = DefenderCloudAppsClient(
                base_url=BASE_URL,
                tenant_id=TENANT_ID,
                client_id=CLIENT_ID,
                client_secret=CLIENT_SECRET
            )
        else:
            client = DefenderCloudAppsClient(
                base_url=BASE_URL,
                api_token=API_TOKEN
            )

        with client:
            # Filter activities by date range
            try:
                now = int(datetime.utcnow().timestamp() * 1000)
                days_ago = int((datetime.utcnow() - timedelta(days=args.days)).timestamp() * 1000)

                filters = {
                    "timestamp": {"gte": days_ago, "lte": now}
                }

                activities = client.activities.list_activities(filters=filters, limit=args.limit_activities)
                result['activities_by_date'] = activities
            except Exception as e:
                result['activities_by_date_error'] = str(e)

            # Filter alerts by severity and status
            try:
                filters = {
                    "severity": {"gte": args.min_severity},
                    "alertStatus": {"eq": 0}
                }

                alerts = client.alerts.list_alerts(filters=filters, limit=args.limit_alerts)
                result['high_severity_alerts'] = alerts
            except Exception as e:
                result['high_severity_alerts_error'] = str(e)

            # Filter files by sharing level and modification date
            try:
                now = int(datetime.utcnow().timestamp() * 1000)
                days_ago_files = int((datetime.utcnow() - timedelta(days=args.days_files)).timestamp() * 1000)

                filters = {
                    "sharing.sharingLevel": {"eq": "Public"},
                    "file.modifiedDate": {"gte": days_ago_files, "lte": now}
                }

                files = client.files.list_files(filters=filters, limit=args.limit_files)
                result['public_files'] = files
            except Exception as e:
                result['public_files_error'] = str(e)

            # Filter entities by multiple criteria
            try:
                filters = {
                    "entity.type": {"eq": "user"},
                    "isExternal": {"eq": True},
                    "isAdmin": {"eq": True},
                    "riskScore": {"gte": args.min_risk_score}
                }

                entities = client.entities.list_entities(filters=filters, limit=args.limit_entities)
                result['risky_external_admins'] = entities
            except Exception as e:
                result['risky_external_admins_error'] = str(e)

            # Filter with range operators
            try:
                filters = {
                    "entity.type": {"eq": "user"},
                    "riskScore": {"gte": args.min_risk_score, "lte": args.max_risk_score}
                }

                medium_risk = client.entities.list_entities(filters=filters, limit=args.limit_entities)
                result['medium_risk_users'] = medium_risk
            except Exception as e:
                result['medium_risk_users_error'] = str(e)

            # Filter activities by action type
            try:
                filters = {
                    "activity.eventActionType": {"contains": "login"}
                }

                login_activities = client.activities.list_activities(filters=filters, limit=args.limit_activities)
                result['login_activities'] = login_activities
            except Exception as e:
                result['login_activities_error'] = str(e)

            # Filter files by type and owner
            try:
                filters = {
                    "file.fileType": {"eq": "Document"},
                    "file.ownerDomain": {"contains": "company.com"}
                }

                docs = client.files.list_files(filters=filters, limit=args.limit_files)
                result['company_documents'] = docs
            except Exception as e:
                result['company_documents_error'] = str(e)

            # Filter subnets by multiple attributes
            try:
                filters = {
                    "organization": {"eq": "Headquarters"},
                    "category": {"eq": "Corporate"}
                }

                hq_corporate = client.data_enrichment.list_subnets(filters=filters, limit=args.limit_subnets)
                result['hq_corporate_subnets'] = hq_corporate
            except Exception as e:
                result['hq_corporate_subnets_error'] = str(e)

    except Exception as e:
        result['error'] = str(e)

    # Output based on mode
    if args.output_file:
        # Mode 1: Write complete output to file
        try:
            with open(args.output_file, 'w', encoding='utf-8') as f:
                json.dump(result, f, indent=2, ensure_ascii=False)
            print(f"\nComplete output written to: {args.output_file}")
            print(f"Filtering results summary:")
            print(f"  - Activities by date: {len(result.get('activities_by_date', []))}")
            print(f"  - High severity alerts: {len(result.get('high_severity_alerts', []))}")
            print(f"  - Public files: {len(result.get('public_files', []))}")
            print(f"  - Risky external admins: {len(result.get('risky_external_admins', []))}")
            print(f"  - Medium risk users: {len(result.get('medium_risk_users', []))}")
        except Exception as e:
            print(f"Error writing to file: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        # Mode 2: Show curated view in terminal
        print_curated_view(result)


if __name__ == "__main__":
    main()
