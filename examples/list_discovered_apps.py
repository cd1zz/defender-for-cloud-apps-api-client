"""
Example: List discovered apps from Microsoft Defender for Cloud Apps.

This script demonstrates how to:
- List all continuous reports (streams)
- List all discovered apps
- Get details about a specific app
- Find high-risk and unsanctioned apps
- List app categories

Output modes:
- Default (curated): Shows key app information in a readable format
- Full output: Writes complete JSON response to a file (use --output-file)
"""

import os
import sys
import json
import argparse
from dotenv import load_dotenv
from defender_cloud_apps import DefenderCloudAppsClient

# Load environment variables from .env file
load_dotenv()


def print_curated_view(result):
    """Print a curated view of discovered apps to terminal."""
    print("\n" + "="*80)
    print("DISCOVERED APPS REPORT")
    print("="*80 + "\n")

    if "streams_error" in result:
        print(f"Warning: Could not fetch streams - {result['streams_error']}\n")

    if "apps_error" in result:
        print(f"Error fetching apps: {result['apps_error']}")
        return

    apps = result.get("apps", [])
    if not apps:
        print("No discovered apps found.")
        return

    print(f"Total apps discovered: {len(apps)}\n")

    # Sort by overall score (highest risk first)
    sorted_apps = sorted(apps, key=lambda x: x.get("overall_score", 0), reverse=True)

    # Show top 20 apps
    for i, app in enumerate(sorted_apps[:20], 1):
        print(f"{i}. {app['name']}")
        print(f"   Overall Risk Score: {app['overall_score']}/10")

        scores = app['risk_scores']
        print(f"   Risk Breakdown: Security={scores['security']}, Compliance={scores['compliance']}, "
              f"Legal={scores['legal']}, Provider={scores['provider']}")

        usage = app['usage']
        print(f"   Usage: {usage['users']} users, {usage['events_30d']} events (30d)")
        print(f"   First/Last Seen: {usage['first_seen']} / {usage['last_seen']}")

        if app.get('urls'):
            print(f"   URLs: {', '.join(app['urls'][:3])}")

        print()

    if len(sorted_apps) > 20:
        print(f"... and {len(sorted_apps) - 20} more apps")
        print(f"\nUse --output-file to save all {len(sorted_apps)} apps to a file.\n")


def main():
    # Parse command-line arguments
    parser = argparse.ArgumentParser(
        description="List discovered apps from Microsoft Defender for Cloud Apps",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Show curated view in terminal
  python list_discovered_apps.py

  # Save full JSON output to file
  python list_discovered_apps.py --output-file discovered_apps.json

  # Limit number of apps retrieved
  python list_discovered_apps.py --limit 50 --output-file apps.json
        """
    )
    parser.add_argument(
        '--output-file', '-o',
        type=str,
        help='Write complete JSON output to specified file'
    )
    parser.add_argument(
        '--limit',
        type=int,
        default=100,
        help='Maximum number of apps to retrieve (default: 100)'
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
            "apps": []
        }

        # Step 1: List continuous reports
        stream_id = None
        try:
            streams = client.discovery.list_streams()
            stream_id = streams[0].get('_id') or streams[0].get('id') if streams else None
        except Exception as e:
            result["streams_error"] = str(e)

        # Step 2: List discovered apps with key details
        try:
            all_apps = client.discovery.list_discovered_apps(
                stream_id=stream_id,
                limit=args.limit
            )
            
            # Extract key information: name, detailed risk scores, and URLs
            for app in all_apps:
                revised_score = app.get("revised_score", {})
                usage_7d = app.get("timeFrames", {}).get("7", {})
                usage_30d = app.get("timeFrames", {}).get("30", {})
                usage_90d = app.get("timeFrames", {}).get("90", {})
                
                app_info = {
                    "name": app.get("name", "Unknown"),
                    "urls": app.get("domainList", []),
                    "overall_score": round(app.get("revised_score_total", 0), 2),
                    "risk_scores": {
                        "security": round(revised_score.get("security", 0), 2),
                        "compliance": round(revised_score.get("compliance", 0), 2),
                        "legal": round(revised_score.get("legal", 0), 2),
                        "provider": round(revised_score.get("provider", 0), 2)
                    },
                    "usage": {
                        "first_seen": app.get("firstUsed", "").split("T")[0],
                        "last_seen": app.get("lastUsed", "").split("T")[0],
                        "events_7d": usage_7d.get("totalEvents", 0),
                        "events_30d": usage_30d.get("totalEvents", 0),
                        "events_90d": usage_90d.get("totalEvents", 0),
                        "users": app.get("usersCount", 0)
                    }
                }
                result["apps"].append(app_info)
        except Exception as e:
            result["apps_error"] = str(e)

        # Output based on mode
        if args.output_file:
            # Mode 1: Write complete output to file
            try:
                # Store complete API response with all fields
                full_result = {
                    "apps": all_apps if 'all_apps' in locals() else [],
                    "streams": streams if 'streams' in locals() else []
                }
                if "streams_error" in result:
                    full_result["streams_error"] = result["streams_error"]
                if "apps_error" in result:
                    full_result["apps_error"] = result["apps_error"]

                with open(args.output_file, 'w', encoding='utf-8') as f:
                    json.dump(full_result, f, indent=2, ensure_ascii=False)
                print(f"\nComplete output written to: {args.output_file}")
                print(f"Total apps: {len(full_result['apps'])}")
            except Exception as e:
                print(f"Error writing to file: {e}", file=sys.stderr)
                sys.exit(1)
        else:
            # Mode 2: Show curated view in terminal
            print_curated_view(result)


if __name__ == "__main__":
    main()
