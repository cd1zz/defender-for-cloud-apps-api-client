"""
Files API endpoints for Microsoft Defender for Cloud Apps.

The Files API provides metadata about files and folders in cloud apps,
including last modification date, ownership, and related attributes.

Note: This API is unavailable for Microsoft 365 Cloud App Security.
"""

from typing import Any, Dict, List, Optional


class FilesAPI:
    """
    Interface for the Files API endpoints.

    The Files API allows you to:
    - List files with complex filtering
    - Fetch specific file details
    """

    # File type constants
    FILE_TYPE_DOCUMENT = "Document"
    FILE_TYPE_SPREADSHEET = "Spreadsheet"
    FILE_TYPE_PRESENTATION = "Presentation"
    FILE_TYPE_TEXT = "Text"
    FILE_TYPE_IMAGE = "Image"
    FILE_TYPE_FOLDER = "Folder"
    FILE_TYPE_OTHER = "Other"

    # Sharing level constants
    SHARING_PUBLIC_INTERNET = "Public (Internet)"
    SHARING_PUBLIC = "Public"
    SHARING_EXTERNAL = "External"
    SHARING_INTERNAL = "Internal"
    SHARING_PRIVATE = "Private"

    def __init__(self, client):
        """
        Initialize Files API.

        Args:
            client: DefenderCloudAppsClient instance
        """
        self._client = client

    def list_files(
        self,
        filters: Optional[Dict[str, Any]] = None,
        limit: int = 100,
        skip: int = 0,
        sort_field: Optional[str] = None,
        sort_direction: str = "desc"
    ) -> List[Dict[str, Any]]:
        """
        List files with optional filtering and pagination.

        Available filters:

        File Characteristics:
        - fileType: Document, Spreadsheet, Presentation, Text, Image, Folder, or Other
        - extension: Filter by file extension
        - mimeType: Filter by MIME type
        - filename: Exact filename matching

        Ownership & Sharing:
        - owner.entity: Filter by file owner
        - owner.orgUnit: Filter by organizational unit
        - sharing: Public (Internet), Public, External, Internal, or Private levels
        - collaborators.entity: Filter by shared entities
        - collaborators.domains: Filter by domain sharing
        - collaborators.groups: Filter by group sharing

        Temporal Filters:
        - modifiedDate: Last modification timestamp (range, before, after)
        - createdDate: Creation timestamp
        - snapshotLastModifiedDate: Snapshot modification date

        File State:
        - trashed: Include/exclude trashed files
        - quarantined: Filter quarantined status
        - allowDeleted: Include deleted files
        - folder: Distinguish folders from files

        Organization:
        - service: Filter by app ID
        - instance: Filter by specified instances
        - parentFolder: Filter by containing folder
        - policy: Filter by matched policies
        - fileLabels: Filter by tags/labels
        - fileScanLabels: Filter by content inspection warnings

        Args:
            filters: Dictionary of filter criteria
            limit: Maximum number of results to return (max 100 per request)
            skip: Number of results to skip
            sort_field: Field to sort by
            sort_direction: Sort direction ('asc' or 'desc')

        Returns:
            List of file records

        Example:
            >>> files = client.files.list_files(
            ...     filters={
            ...         "fileType": {"eq": "Document"},
            ...         "sharing": {"eq": "Public"},
            ...         "modifiedDate": {"gte": 1609459200000}
            ...     },
            ...     limit=50
            ... )
        """
        data: Dict[str, Any] = {
            "filters": filters or {},
            "limit": min(limit, 100),
            "skip": skip
        }

        if sort_field:
            data["sortField"] = sort_field
            data["sortDirection"] = sort_direction

        response = self._client._make_request(
            "POST",
            "/v1/files/",
            data=data
        )

        return response.get("data", [])

    def list_files_paginated(
        self,
        filters: Optional[Dict[str, Any]] = None,
        limit: int = 100,
        skip: int = 0
    ) -> List[Dict[str, Any]]:
        """
        List all files with automatic pagination.

        This method automatically handles pagination and returns all matching files.

        Args:
            filters: Dictionary of filter criteria
            limit: Number of items per page (max 100)
            skip: Number of items to skip initially

        Returns:
            List of all matching file records

        Example:
            >>> all_public_files = client.files.list_files_paginated(
            ...     filters={"sharing": {"eq": "Public"}}
            ... )
        """
        return self._client._paginate(
            "/v1/files/",
            filters=filters,
            limit=limit,
            skip=skip
        )

    def get_file(self, file_id: str) -> Dict[str, Any]:
        """
        Fetch a specific file by ID.

        Args:
            file_id: The file ID

        Returns:
            File metadata and details

        Example:
            >>> file_info = client.files.get_file("5f8a7b2c3d4e5f6g7h8i9j0k")
        """
        response = self._client._make_request(
            "GET",
            f"/v1/files/{file_id}/"
        )

        return response

    def get_public_files(
        self,
        service: Optional[int] = None,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """
        Get all publicly shared files.

        Args:
            service: Optional service/app ID filter
            limit: Maximum number of results

        Returns:
            List of publicly shared files

        Example:
            >>> public_files = client.files.get_public_files()
        """
        filters: Dict[str, Any] = {
            "sharing": {"eq": self.SHARING_PUBLIC}
        }

        if service:
            filters["service"] = {"eq": service}

        return self.list_files(filters=filters, limit=limit)

    def get_external_files(
        self,
        service: Optional[int] = None,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """
        Get all externally shared files.

        Args:
            service: Optional service/app ID filter
            limit: Maximum number of results

        Returns:
            List of externally shared files

        Example:
            >>> external_files = client.files.get_external_files()
        """
        filters: Dict[str, Any] = {
            "sharing": {"eq": self.SHARING_EXTERNAL}
        }

        if service:
            filters["service"] = {"eq": service}

        return self.list_files(filters=filters, limit=limit)

    def get_quarantined_files(
        self,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """
        Get all quarantined files.

        Args:
            limit: Maximum number of results

        Returns:
            List of quarantined files

        Example:
            >>> quarantined = client.files.get_quarantined_files()
        """
        filters = {
            "quarantined": {"eq": True}
        }

        return self.list_files(filters=filters, limit=limit)

    def get_files_by_owner(
        self,
        owner_entity_id: str,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """
        Get files owned by a specific entity.

        Args:
            owner_entity_id: The owner's entity ID
            limit: Maximum number of results

        Returns:
            List of files owned by the entity

        Example:
            >>> user_files = client.files.get_files_by_owner("entity_id_123")
        """
        filters = {
            "owner.entity": {"eq": owner_entity_id}
        }

        return self.list_files(filters=filters, limit=limit)

    def get_files_by_type(
        self,
        file_type: str,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """
        Get files by type.

        Args:
            file_type: File type (Document, Spreadsheet, Presentation, Text, Image, Folder, Other)
            limit: Maximum number of results

        Returns:
            List of files of the specified type

        Example:
            >>> documents = client.files.get_files_by_type("Document")
        """
        filters = {
            "fileType": {"eq": file_type}
        }

        return self.list_files(filters=filters, limit=limit)

    def get_files_by_extension(
        self,
        extension: str,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """
        Get files by extension.

        Args:
            extension: File extension (e.g., "pdf", "docx")
            limit: Maximum number of results

        Returns:
            List of files with the specified extension

        Example:
            >>> pdf_files = client.files.get_files_by_extension("pdf")
        """
        filters = {
            "extension": {"eq": extension}
        }

        return self.list_files(filters=filters, limit=limit)

    def get_recently_modified_files(
        self,
        days: int = 7,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """
        Get files modified within the last N days.

        Args:
            days: Number of days to look back
            limit: Maximum number of results

        Returns:
            List of recently modified files

        Example:
            >>> recent_files = client.files.get_recently_modified_files(days=7)
        """
        import time
        current_time = int(time.time() * 1000)  # milliseconds
        days_in_ms = days * 24 * 60 * 60 * 1000

        filters = {
            "modifiedDate": {"gte": current_time - days_in_ms}
        }

        return self.list_files(filters=filters, limit=limit)
