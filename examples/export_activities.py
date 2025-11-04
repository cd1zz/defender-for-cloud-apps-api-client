"""
Example: Export activities from Microsoft Defender for Cloud Apps as JSON.

This script demonstrates how to:
- Query activities with filters
- Use pagination to get all results
- Output data as formatted JSON

Output modes:
- Default (curated): Shows key activity information in a readable format
- Full output: Writes complete JSON response to a file (use --output-file)
"""

import os
import sys
import json
import argparse
from datetime import datetime
from dotenv import load_dotenv
from defender_cloud_apps import DefenderCloudAppsClient, FilterBuilder, TimeHelper

# Load environment variables from .env file
load_dotenv()


def print_curated_view(result):
    """Print a curated view of activities to terminal."""
    print("\n" + "="*80)
    print("ACTIVITIES EXPORT")
    print("="*80 + "\n")

    if 'error' in result:
        print(f"Error: {result['error']}")
        return

    activities = result.get('activities', [])
    total = result.get('total_count', 0)

    print(f"Export timestamp: {result.get('export_timestamp', 'N/A')}")
    print(f"Total activities: {total}\n")

    if not activities:
        print("No activities found.")
        return

    # Group by service
    by_service = {}
    for activity in activities:
        service = activity.get('service', 'Unknown')
        if service not in by_service:
            by_service[service] = []
        by_service[service].append(activity)

    print("ACTIVITIES BY SERVICE")
    print("-" * 80)
    for service, acts in sorted(by_service.items(), key=lambda x: len(x[1]), reverse=True):
        print(f"\n{service}: {len(acts)} activities")

        # Show top 5 for this service
        for activity in acts[:5]:
            timestamp = activity.get('timestamp', 'N/A')
            username = activity.get('username', 'Unknown')
            event_type = activity.get('event_type', 'N/A')
            description = activity.get('description', '')

            print(f"  - [{timestamp}] {username}: {event_type}")
            if description:
                desc_short = description[:80] + '...' if len(description) > 80 else description
                print(f"    {desc_short}")

        if len(acts) > 5:
            print(f"  ... and {len(acts) - 5} more activities")

    # Show most active users
    print("\n\nMOST ACTIVE USERS")
    print("-" * 80)
    user_counts = {}
    for activity in activities:
        username = activity.get('username', 'Unknown')
        user_counts[username] = user_counts.get(username, 0) + 1

    for username, count in sorted(user_counts.items(), key=lambda x: x[1], reverse=True)[:10]:
        print(f"  {username}: {count} activities")

    print(f"\n\nUse --output-file to save all {total} activities to a file.\n")


def main():
    # Parse command-line arguments
    parser = argparse.ArgumentParser(
        description="Export activities from Microsoft Defender for Cloud Apps",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Show curated view in terminal
  python export_activities.py

  # Save full JSON output to file
  python export_activities.py --output-file activities.json

  # Export activities from last 7 days only
  python export_activities.py --days 7 --output-file recent_activities.json

  # Limit number of activities
  python export_activities.py --limit 50
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
        default=30,
        help='Number of days to look back (default: 30)'
    )
    parser.add_argument(
        '--limit',
        type=int,
        default=100,
        help='Maximum number of activities to retrieve (default: 100)'
    )

    args = parser.parse_args()

    # Get credentials from environment variables
    base_url = os.getenv("DEFENDER_CLOUD_APPS_URL")

    # Try OAuth2 authentication first
    tenant_id = os.getenv("DEFENDER_CLOUD_APPS_TENANT_ID")
    client_id = os.getenv("DEFENDER_CLOUD_APPS_CLIENT_ID")
    client_secret = os.getenv("DEFENDER_CLOUD_APPS_CLIENT_SECRET")

    # Fall back to token-based authentication
    api_token = os.getenv("DEFENDER_CLOUD_APPS_TOKEN")

    result = {
        'export_timestamp': datetime.now().isoformat(),
        'activities': [],
        'total_count': 0
    }

    if not base_url:
        result['error'] = "Please set DEFENDER_CLOUD_APPS_URL in your .env file"
        print(json.dumps(result, indent=2))
        return

    # Determine which authentication method to use
    if tenant_id and client_id and client_secret:
        client_kwargs = {
            "base_url": base_url,
            "tenant_id": tenant_id,
            "client_id": client_id,
            "client_secret": client_secret,
        }
    elif api_token:
        client_kwargs = {
            "base_url": base_url,
            "api_token": api_token,
        }
    else:
        result['error'] = "Please configure either OAuth2 credentials or API Token in .env file"
        print(json.dumps(result, indent=2))
        return

    try:
        # Initialize the client
        with DefenderCloudAppsClient(**client_kwargs) as client:
            # Build filters for activities from specified days
            filters = (
                FilterBuilder()
                .in_last_n_days("date", args.days)
                .build()
            )

            # Get all activities with pagination
            activities = client.activities.list_activities_paginated(
                filters=filters,
                limit=args.limit
            )

            result['total_count'] = len(activities)

            # Process activity data
            for activity in activities:
                timestamp = activity.get('timestamp')
                timestamp_str = TimeHelper.to_datetime(timestamp).isoformat() if timestamp else ''

                user = activity.get('user', {})
                device = activity.get('device', {})
                location = activity.get('location', {})

                activity_data = {
                    'activity_id': activity.get('_id', ''),
                    'timestamp': timestamp_str,
                    'username': user.get('username', ''),
                    'user_domain': user.get('domain', ''),
                    'description': activity.get('description', ''),
                    'event_type': activity.get('eventTypeName', ''),
                    'service': activity.get('service', ''),
                    'ip_address': activity.get('ipAddress', ''),
                    'location_country': location.get('country', ''),
                    'device_type': device.get('type', '')
                }

                result['activities'].append(activity_data)

    except Exception as e:
        result['error'] = str(e)

    # Output based on mode
    if args.output_file:
        # Mode 1: Write complete output to file
        try:
            # For full output, include raw activity data
            full_result = {
                'export_timestamp': result['export_timestamp'],
                'total_count': result['total_count'],
                'activities': activities if 'activities' in locals() else result['activities'],
                'filter_days': args.days
            }
            if 'error' in result:
                full_result['error'] = result['error']

            with open(args.output_file, 'w', encoding='utf-8') as f:
                json.dump(full_result, f, indent=2, ensure_ascii=False)
            print(f"\nComplete output written to: {args.output_file}")
            print(f"Total activities exported: {full_result['total_count']}")
        except Exception as e:
            print(f"Error writing to file: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        # Mode 2: Show curated view in terminal
        print_curated_view(result)


if __name__ == "__main__":
    main()
