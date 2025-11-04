#!/usr/bin/env python3
"""
Data Enrichment Management Example

This script demonstrates how to use the Data Enrichment API to manage IP subnet
mappings and outputs results as JSON.

Output modes:
- Default (curated): Shows key subnet information in a readable format
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
    """Print a curated view of data enrichment results to terminal."""
    print("\n" + "="*80)
    print("DATA ENRICHMENT MANAGEMENT REPORT")
    print("="*80 + "\n")

    if 'error' in result:
        print(f"Error: {result['error']}")
        return

    subnets = result.get('subnets', [])
    print(f"Total subnets configured: {len(subnets)}\n")

    if subnets and "subnets_error" not in result:
        print("CONFIGURED SUBNETS")
        print("-" * 80)

        # Group by organization
        by_org = {}
        for subnet in subnets:
            org = subnet.get('organization', 'Unknown')
            if org not in by_org:
                by_org[org] = []
            by_org[org].append(subnet)

        for org, org_subnets in sorted(by_org.items()):
            print(f"\n{org}: {len(org_subnets)} subnets")
            for subnet in org_subnets[:5]:
                name = subnet.get('name', 'Unnamed')
                category = subnet.get('category', 'N/A')
                location = subnet.get('location', 'N/A')
                print(f"  - {name}")
                print(f"    Category: {category}, Location: {location}")

            if len(org_subnets) > 5:
                print(f"  ... and {len(org_subnets) - 5} more subnets")

    # Show organization-specific subnets
    org_subnets = result.get('organization_subnets', {})
    if org_subnets and org_subnets.get('subnets'):
        org_name = org_subnets.get('organization', 'N/A')
        subnets_list = org_subnets.get('subnets', [])
        print(f"\n\nSUBNETS FOR ORGANIZATION: '{org_name}'")
        print("-" * 80)
        print(f"Found {len(subnets_list)} subnets")

    # Show category-specific subnets
    cat_subnets = result.get('category_subnets', {})
    if cat_subnets and cat_subnets.get('subnets'):
        category = cat_subnets.get('category', 'N/A')
        subnets_list = cat_subnets.get('subnets', [])
        print(f"\n\nSUBNETS FOR CATEGORY: '{category}'")
        print("-" * 80)
        print(f"Found {len(subnets_list)} subnets")

    # Show location-specific subnets
    loc_subnets = result.get('location_subnets', {})
    if loc_subnets and loc_subnets.get('subnets'):
        location = loc_subnets.get('location', 'N/A')
        subnets_list = loc_subnets.get('subnets', [])
        print(f"\n\nSUBNETS FOR LOCATION: '{location}'")
        print("-" * 80)
        print(f"Found {len(subnets_list)} subnets")

    # Show search results
    search_results = result.get('search_results', {})
    if search_results and search_results.get('results'):
        query = search_results.get('query', 'N/A')
        results_list = search_results.get('results', [])
        print(f"\n\nSEARCH RESULTS FOR: '{query}'")
        print("-" * 80)
        print(f"Found {len(results_list)} subnets")
        for subnet in results_list[:5]:
            name = subnet.get('name', 'Unnamed')
            org = subnet.get('organization', 'Unknown')
            print(f"  - {name} (Org: {org})")

    print(f"\n\nUse --output-file to save complete subnet data.\n")


def main():
    """Run data enrichment management examples."""

    # Parse command-line arguments
    parser = argparse.ArgumentParser(
        description="Manage data enrichment in Microsoft Defender for Cloud Apps",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Show curated view in terminal
  python data_enrichment_management.py

  # Save full JSON output to file
  python data_enrichment_management.py --output-file subnets.json

  # Filter by organization, category, or location
  python data_enrichment_management.py --organization "Headquarters"
  python data_enrichment_management.py --category "Corporate" --location "New York"

  # Search for subnets
  python data_enrichment_management.py --search "office" --output-file office_subnets.json
        """
    )
    parser.add_argument(
        '--output-file', '-o',
        type=str,
        help='Write complete JSON output to specified file'
    )
    parser.add_argument(
        '--organization',
        type=str,
        default='Headquarters',
        help='Filter by organization (default: "Headquarters")'
    )
    parser.add_argument(
        '--category',
        type=str,
        default='Corporate',
        help='Filter by category (default: "Corporate")'
    )
    parser.add_argument(
        '--location',
        type=str,
        default='New York',
        help='Filter by location (default: "New York")'
    )
    parser.add_argument(
        '--search',
        type=str,
        default='office',
        help='Search query for subnets (default: "office")'
    )
    parser.add_argument(
        '--limit',
        type=int,
        default=10,
        help='Maximum number of subnets to retrieve (default: 10)'
    )
    parser.add_argument(
        '--limit-search',
        type=int,
        default=10,
        help='Maximum number of search results to retrieve (default: 10)'
    )

    args = parser.parse_args()

    result = {
        'subnets': [],
        'organization_subnets': {},
        'category_subnets': {},
        'location_subnets': {},
        'search_results': {}
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
            # List all configured subnets
            try:
                subnets = client.data_enrichment.list_subnets(limit=args.limit)
                result['subnets'] = subnets
            except Exception as e:
                result['subnets_error'] = str(e)

            # Get subnets by organization
            try:
                org_subnets = client.data_enrichment.get_subnets_by_organization(args.organization)
                result['organization_subnets'] = {
                    'organization': args.organization,
                    'subnets': org_subnets if org_subnets else []
                }
            except Exception as e:
                result['organization_subnets_error'] = str(e)

            # Get subnets by category
            try:
                category_subnets = client.data_enrichment.get_subnets_by_category(args.category)
                result['category_subnets'] = {
                    'category': args.category,
                    'subnets': category_subnets if category_subnets else []
                }
            except Exception as e:
                result['category_subnets_error'] = str(e)

            # Get subnets by location
            try:
                location_subnets = client.data_enrichment.get_subnets_by_location(args.location)
                result['location_subnets'] = {
                    'location': args.location,
                    'subnets': location_subnets if location_subnets else []
                }
            except Exception as e:
                result['location_subnets_error'] = str(e)

            # Search subnets
            try:
                search_results = client.data_enrichment.search_subnets(args.search, limit=args.limit_search)
                result['search_results'] = {
                    'query': args.search,
                    'results': search_results if search_results else []
                }
            except Exception as e:
                result['search_error'] = str(e)

            # Export subnets report
            try:
                report = client.data_enrichment.export_subnets()
                result['export_report'] = report
            except Exception as e:
                result['export_error'] = str(e)

    except Exception as e:
        result['error'] = str(e)

    # Output based on mode
    if args.output_file:
        # Mode 1: Write complete output to file
        try:
            with open(args.output_file, 'w', encoding='utf-8') as f:
                json.dump(result, f, indent=2, ensure_ascii=False)
            print(f"\nComplete output written to: {args.output_file}")
            print(f"  - Total subnets: {len(result.get('subnets', []))}")
            print(f"  - Organization '{args.organization}': {len(result.get('organization_subnets', {}).get('subnets', []))}")
            print(f"  - Category '{args.category}': {len(result.get('category_subnets', {}).get('subnets', []))}")
            print(f"  - Location '{args.location}': {len(result.get('location_subnets', {}).get('subnets', []))}")
        except Exception as e:
            print(f"Error writing to file: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        # Mode 2: Show curated view in terminal
        print_curated_view(result)


if __name__ == "__main__":
    main()
