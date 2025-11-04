"""
Example: List and filter alerts from Microsoft Defender for Cloud Apps.

This script demonstrates how to:
- List all alerts
- Get open alerts by severity
- Get unread alerts
- Filter alerts by date range

Output modes:
- Default (curated): Shows key alert information in a readable format
- Full output: Writes complete JSON response to a file (use --output-file)
"""

import os
import sys
import json
import argparse
from dotenv import load_dotenv
from defender_cloud_apps import DefenderCloudAppsClient, FilterBuilder

# Load environment variables from .env file
load_dotenv()


def print_curated_view(result):
    """Print a curated view of alerts to terminal."""
    print("\n" + "="*80)
    print("ALERTS REPORT")
    print("="*80 + "\n")

    # Open alerts summary
    open_alerts = result.get("open_alerts", [])
    unread_alerts = result.get("unread_alerts", [])
    recent_alerts = result.get("recent_alerts", [])

    print(f"Summary:")
    print(f"  - Open alerts: {len(open_alerts)}")
    print(f"  - Unread alerts: {len(unread_alerts)}")
    print(f"  - Recent alerts (7 days): {len(recent_alerts)}\n")

    if "open_alerts_error" in result:
        print(f"Error fetching open alerts: {result['open_alerts_error']}\n")

    # Show high priority open alerts
    if open_alerts:
        print("HIGH PRIORITY OPEN ALERTS")
        print("-" * 80)
        # Sort by severity (assuming higher number = more severe)
        sorted_alerts = sorted(open_alerts, key=lambda x: x.get('severity', {}).get('value', 0), reverse=True)

        for i, alert in enumerate(sorted_alerts[:10], 1):
            title = alert.get('title', 'Untitled Alert')
            severity = alert.get('severity', {}).get('label', 'Unknown')
            timestamp = alert.get('timestamp', 'N/A')
            description = alert.get('description', '')

            print(f"\n{i}. [{severity}] {title}")
            print(f"   Time: {timestamp}")
            if description:
                desc_short = description[:150] + '...' if len(description) > 150 else description
                print(f"   Description: {desc_short}")

        if len(sorted_alerts) > 10:
            print(f"\n... and {len(sorted_alerts) - 10} more open alerts\n")
    else:
        print("No open alerts found.\n")

    # Show unread alerts
    if unread_alerts and "unread_alerts_error" not in result:
        print("\nUNREAD ALERTS")
        print("-" * 80)
        for i, alert in enumerate(unread_alerts[:5], 1):
            title = alert.get('title', 'Untitled Alert')
            severity = alert.get('severity', {}).get('label', 'Unknown')
            print(f"{i}. [{severity}] {title}")

        if len(unread_alerts) > 5:
            print(f"... and {len(unread_alerts) - 5} more unread alerts\n")

    print(f"\nUse --output-file to save complete alert data to a file.\n")


def main():
    # Parse command-line arguments
    parser = argparse.ArgumentParser(
        description="List and filter alerts from Microsoft Defender for Cloud Apps",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Show curated view in terminal
  python list_alerts.py

  # Save full JSON output to file
  python list_alerts.py --output-file alerts.json

  # Adjust limits for different alert types
  python list_alerts.py --limit-open 200 --limit-unread 100
        """
    )
    parser.add_argument(
        '--output-file', '-o',
        type=str,
        help='Write complete JSON output to specified file'
    )
    parser.add_argument(
        '--limit-open',
        type=int,
        default=100,
        help='Maximum number of open alerts to retrieve (default: 100)'
    )
    parser.add_argument(
        '--limit-unread',
        type=int,
        default=50,
        help='Maximum number of unread alerts to retrieve (default: 50)'
    )
    parser.add_argument(
        '--limit-recent',
        type=int,
        default=100,
        help='Maximum number of recent alerts to retrieve (default: 100)'
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

    if not base_url:
        print(json.dumps({
            "error": "DEFENDER_CLOUD_APPS_URL not configured",
            "message": "Copy .env.example to .env and fill in your credentials"
        }, indent=2))
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
        print(json.dumps({
            "error": "No authentication configured",
            "message": "Configure either OAuth2 or API Token in .env"
        }, indent=2))
        return

    # Initialize the client
    with DefenderCloudAppsClient(**client_kwargs) as client:
        result = {
            "open_alerts": [],
            "unread_alerts": [],
            "recent_alerts": []
        }

        # Get all open alerts
        try:
            open_alerts = client.alerts.list_alerts(limit=args.limit_open)
            result["open_alerts"] = open_alerts
        except Exception as e:
            result["open_alerts_error"] = str(e)

        # Get unread alerts
        try:
            unread_alerts = client.alerts.get_unread_alerts(limit=args.limit_unread)
            result["unread_alerts"] = unread_alerts
        except Exception as e:
            result["unread_alerts_error"] = str(e)

        # Get alerts from last 7 days
        try:
            filters = (
                FilterBuilder()
                .in_last_n_days("date", 7)
                .build()
            )
            recent_alerts = client.alerts.list_alerts(filters=filters, limit=args.limit_recent)
            result["recent_alerts"] = recent_alerts
        except Exception as e:
            result["recent_alerts_error"] = str(e)

        # Output based on mode
        if args.output_file:
            # Mode 1: Write complete output to file
            try:
                with open(args.output_file, 'w', encoding='utf-8') as f:
                    json.dump(result, f, indent=2, ensure_ascii=False)
                print(f"\nComplete output written to: {args.output_file}")
                print(f"  - Open alerts: {len(result.get('open_alerts', []))}")
                print(f"  - Unread alerts: {len(result.get('unread_alerts', []))}")
                print(f"  - Recent alerts: {len(result.get('recent_alerts', []))}")
            except Exception as e:
                print(f"Error writing to file: {e}", file=sys.stderr)
                sys.exit(1)
        else:
            # Mode 2: Show curated view in terminal
            print_curated_view(result)


if __name__ == "__main__":
    main()
