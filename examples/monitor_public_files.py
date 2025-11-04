"""
Example: Monitor publicly shared files in Microsoft Defender for Cloud Apps.

This script demonstrates how to find publicly shared files and outputs results as JSON.

Output modes:
- Default (curated): Shows key file information in a readable format
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
    """Print a curated view of public files to terminal."""
    print("\n" + "="*80)
    print("PUBLIC FILES MONITORING REPORT")
    print("="*80 + "\n")

    if 'error' in result:
        print(f"Error: {result['error']}")
        return

    public_files = result.get('public_files', [])
    external_files = result.get('external_files', [])
    summary = result.get('summary', {})

    print(f"Summary:")
    print(f"  - Public files: {summary.get('total_public_files', 0)}")
    print(f"  - External files: {summary.get('total_external_files', 0)}\n")

    if "public_files_error" in result:
        print(f"Error fetching public files: {result['public_files_error']}\n")

    # Show files by type
    files_by_type = result.get('files_by_type', {})
    if files_by_type:
        print("FILES BY TYPE")
        print("-" * 80)
        for file_type, files in sorted(files_by_type.items(), key=lambda x: len(x[1]), reverse=True):
            print(f"\n{file_type}: {len(files)} files")

            # Show first 3 files of this type
            for i, file in enumerate(files[:3], 1):
                file_name = file.get('name', 'Unknown')
                owner = file.get('ownerName', 'Unknown')
                modified = file.get('modifiedDate', 'N/A')
                print(f"  {i}. {file_name}")
                print(f"     Owner: {owner}, Modified: {modified}")

            if len(files) > 3:
                print(f"  ... and {len(files) - 3} more files")

    # Show external files
    if external_files and "external_files_error" not in result:
        print("\n\nEXTERNAL FILES (Shared outside organization)")
        print("-" * 80)
        for i, file in enumerate(external_files[:10], 1):
            file_name = file.get('name', 'Unknown')
            owner = file.get('ownerName', 'Unknown')
            file_type = file.get('fileType', 'Unknown')
            print(f"{i}. [{file_type}] {file_name}")
            print(f"   Owner: {owner}")

        if len(external_files) > 10:
            print(f"\n... and {len(external_files) - 10} more external files")

    print(f"\n\nUse --output-file to save complete file data.\n")


def main():
    # Parse command-line arguments
    parser = argparse.ArgumentParser(
        description="Monitor publicly shared files in Microsoft Defender for Cloud Apps",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Show curated view in terminal
  python monitor_public_files.py

  # Save full JSON output to file
  python monitor_public_files.py --output-file public_files.json

  # Adjust limits
  python monitor_public_files.py --limit-public 200 --limit-external 100
        """
    )
    parser.add_argument(
        '--output-file', '-o',
        type=str,
        help='Write complete JSON output to specified file'
    )
    parser.add_argument(
        '--limit-public',
        type=int,
        default=100,
        help='Maximum number of public files to retrieve (default: 100)'
    )
    parser.add_argument(
        '--limit-external',
        type=int,
        default=50,
        help='Maximum number of external files to retrieve (default: 50)'
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
        'public_files': [],
        'files_by_type': {},
        'external_files': [],
        'summary': {}
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
            # Get all publicly shared files
            try:
                public_files = client.files.get_public_files(limit=args.limit_public)
                result['public_files'] = public_files if public_files else []

                # Group by file type
                if public_files:
                    files_by_type = {}
                    for file in public_files:
                        file_type = file.get('fileType', 'Unknown')
                        if file_type not in files_by_type:
                            files_by_type[file_type] = []
                        files_by_type[file_type].append(file)

                    result['files_by_type'] = files_by_type
                    result['summary']['total_public_files'] = len(public_files)
                    result['summary']['file_types'] = {ft: len(files) for ft, files in files_by_type.items()}

            except Exception as e:
                result['public_files_error'] = str(e)

            # Check for externally shared files
            try:
                external_files = client.files.get_external_files(limit=args.limit_external)
                result['external_files'] = external_files if external_files else []
                result['summary']['total_external_files'] = len(external_files) if external_files else 0
            except Exception as e:
                result['external_files_error'] = str(e)

    except Exception as e:
        result['error'] = str(e)

    # Output based on mode
    if args.output_file:
        # Mode 1: Write complete output to file
        try:
            with open(args.output_file, 'w', encoding='utf-8') as f:
                json.dump(result, f, indent=2, ensure_ascii=False)
            print(f"\nComplete output written to: {args.output_file}")
            print(f"  - Public files: {result.get('summary', {}).get('total_public_files', 0)}")
            print(f"  - External files: {result.get('summary', {}).get('total_external_files', 0)}")
        except Exception as e:
            print(f"Error writing to file: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        # Mode 2: Show curated view in terminal
        print_curated_view(result)


if __name__ == "__main__":
    main()
