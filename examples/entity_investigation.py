#!/usr/bin/env python3
"""
Entity Investigation Example

This script demonstrates how to use the Entities API to investigate users and devices,
and outputs results as JSON for easy integration with other tools.

Output modes:
- Default (curated): Shows key entity information in a readable format
- Full output: Writes complete JSON response to a file (use --output-file)
"""

import os
import sys
import json
import argparse
from dotenv import load_dotenv
from defender_cloud_apps import DefenderCloudAppsClient

# Load environment variables
load_dotenv()

# Get configuration from environment
BASE_URL = os.getenv("DEFENDER_CLOUD_APPS_URL")
TENANT_ID = os.getenv("DEFENDER_CLOUD_APPS_TENANT_ID")
CLIENT_ID = os.getenv("DEFENDER_CLOUD_APPS_CLIENT_ID")
CLIENT_SECRET = os.getenv("DEFENDER_CLOUD_APPS_CLIENT_SECRET")
API_TOKEN = os.getenv("DEFENDER_CLOUD_APPS_TOKEN")


def print_curated_view(result):
    """Print a curated view of entity investigation results to terminal."""
    print("\n" + "="*80)
    print("ENTITY INVESTIGATION REPORT")
    print("="*80 + "\n")

    if 'error' in result:
        print(f"Error: {result['error']}")
        return

    entities = result.get('entities', [])
    risky_entities = result.get('risky_entities', [])
    external_users = result.get('external_users', [])
    admins = result.get('admins', [])

    print(f"Summary:")
    print(f"  - Total entities: {len(entities)}")
    print(f"  - Risky entities: {len(risky_entities)}")
    print(f"  - External users: {len(external_users)}")
    print(f"  - Administrators: {len(admins)}\n")

    # Show risky entities
    if risky_entities and "risky_entities_error" not in result:
        print("HIGH RISK ENTITIES")
        print("-" * 80)
        for i, entity in enumerate(risky_entities[:10], 1):
            username = entity.get('username', 'Unknown')
            risk_score = entity.get('riskScore', 0)
            entity_type = entity.get('type', 'Unknown')
            is_admin = entity.get('isAdmin', False)
            admin_flag = " [ADMIN]" if is_admin else ""

            print(f"{i}. {username}{admin_flag}")
            print(f"   Type: {entity_type}, Risk Score: {risk_score}/10")

        if len(risky_entities) > 10:
            print(f"\n... and {len(risky_entities) - 10} more risky entities")
        print()

    # Show external users
    if external_users and "external_users_error" not in result:
        print("EXTERNAL USERS")
        print("-" * 80)
        for i, user in enumerate(external_users[:10], 1):
            username = user.get('username', 'Unknown')
            domain = user.get('domain', 'Unknown')
            print(f"{i}. {username} (Domain: {domain})")

        if len(external_users) > 10:
            print(f"... and {len(external_users) - 10} more external users")
        print()

    # Show admins
    if admins and "admins_error" not in result:
        print("ADMINISTRATORS")
        print("-" * 80)
        for i, admin in enumerate(admins[:15], 1):
            username = admin.get('username', 'Unknown')
            risk_score = admin.get('riskScore', 0)
            print(f"{i}. {username} (Risk Score: {risk_score})")

        if len(admins) > 15:
            print(f"... and {len(admins) - 15} more administrators")
        print()

    # Show search results
    search_results = result.get('search_results', {})
    if search_results and search_results.get('results'):
        query = search_results.get('query', 'N/A')
        results_list = search_results.get('results', [])
        print(f"SEARCH RESULTS FOR: '{query}'")
        print("-" * 80)
        for i, entity in enumerate(results_list[:10], 1):
            username = entity.get('username', 'Unknown')
            entity_type = entity.get('type', 'Unknown')
            print(f"{i}. {username} (Type: {entity_type})")

        if len(results_list) > 10:
            print(f"... and {len(results_list) - 10} more results")
        print()

    print(f"\nUse --output-file to save complete entity data.\n")


def main():
    """Run entity investigation examples."""

    # Parse command-line arguments
    parser = argparse.ArgumentParser(
        description="Investigate entities in Microsoft Defender for Cloud Apps",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Show curated view in terminal
  python entity_investigation.py

  # Save full JSON output to file
  python entity_investigation.py --output-file entities.json

  # Search for specific entities
  python entity_investigation.py --search "admin" --output-file admin_search.json

  # Adjust minimum risk score and limits
  python entity_investigation.py --min-risk-score 8 --limit-entities 20
        """
    )
    parser.add_argument(
        '--output-file', '-o',
        type=str,
        help='Write complete JSON output to specified file'
    )
    parser.add_argument(
        '--search',
        type=str,
        default='admin',
        help='Search query for entities (default: "admin")'
    )
    parser.add_argument(
        '--min-risk-score',
        type=int,
        default=7,
        help='Minimum risk score for risky entities (default: 7)'
    )
    parser.add_argument(
        '--limit-entities',
        type=int,
        default=5,
        help='Maximum number of general entities to retrieve (default: 5)'
    )
    parser.add_argument(
        '--limit-risky',
        type=int,
        default=10,
        help='Maximum number of risky entities to retrieve (default: 10)'
    )
    parser.add_argument(
        '--limit-external',
        type=int,
        default=10,
        help='Maximum number of external entities to retrieve (default: 10)'
    )
    parser.add_argument(
        '--limit-admins',
        type=int,
        default=10,
        help='Maximum number of admin entities to retrieve (default: 10)'
    )
    parser.add_argument(
        '--limit-search',
        type=int,
        default=10,
        help='Maximum number of search results to retrieve (default: 10)'
    )

    args = parser.parse_args()

    result = {
        'entities': [],
        'risky_entities': [],
        'external_users': [],
        'admins': [],
        'search_results': {},
        'entity_details': {}
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
            # Get all entities
            try:
                entities = client.entities.list_entities(limit=args.limit_entities)
                result['entities'] = entities
            except Exception as e:
                result['entities_error'] = str(e)

            # Get high-risk entities
            try:
                risky_entities = client.entities.get_risky_entities(
                    min_risk_score=args.min_risk_score,
                    limit=args.limit_risky
                )
                result['risky_entities'] = risky_entities
            except Exception as e:
                result['risky_entities_error'] = str(e)

            # Get external users
            try:
                external_users = client.entities.get_external_entities(limit=args.limit_external)
                result['external_users'] = external_users
            except Exception as e:
                result['external_users_error'] = str(e)

            # Get administrators
            try:
                admins = client.entities.get_admin_entities(limit=args.limit_admins)
                result['admins'] = admins
            except Exception as e:
                result['admins_error'] = str(e)

            # Search for entities
            try:
                search_results = client.entities.search_entities(args.search, limit=args.limit_search)
                result['search_results'] = {
                    'query': args.search,
                    'results': search_results
                }
            except Exception as e:
                result['search_error'] = str(e)

            # Get entity by specific username
            try:
                entities = client.entities.list_entities(limit=1)
                if entities:
                    username = entities[0].get("username")
                    if username:
                        entity = client.entities.get_entity_by_username(username)
                        if entity:
                            result['entity_details'] = {
                                'username': username,
                                'details': entity
                            }
            except Exception as e:
                result['entity_details_error'] = str(e)

    except Exception as e:
        result['error'] = str(e)

    # Output based on mode
    if args.output_file:
        # Mode 1: Write complete output to file
        try:
            with open(args.output_file, 'w', encoding='utf-8') as f:
                json.dump(result, f, indent=2, ensure_ascii=False)
            print(f"\nComplete output written to: {args.output_file}")
            print(f"  - Total entities: {len(result.get('entities', []))}")
            print(f"  - Risky entities: {len(result.get('risky_entities', []))}")
            print(f"  - External users: {len(result.get('external_users', []))}")
            print(f"  - Administrators: {len(result.get('admins', []))}")
        except Exception as e:
            print(f"Error writing to file: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        # Mode 2: Show curated view in terminal
        print_curated_view(result)


if __name__ == "__main__":
    main()
