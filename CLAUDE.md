# Technical Reference

## User Preferences
- Keep project directory clean - only maintain CLAUDE.md and README.md for documentation
- Do NOT create temporary progress files, implementation notes, or scattered .md files
- No erroneous markdown files cluttering the repository

## Complete API Implementation

### Modules

**API Endpoints (9 total)**
- `activities.py` - Activity monitoring and filtering
- `alerts.py` - Security alerts and investigations
- `files.py` - File metadata and sharing
- `entities.py` - User and device investigation (NEW)
- `discovery.py` - Cloud app discovery
- `data_enrichment.py` - IP subnet management (NEW)
- `client.py` - Core client with OAuth2 and token auth
- `filters.py` - Advanced filter builder
- `__init__.py` - Package exports

### API Methods Summary

**EntitiesAPI** (10 methods)
- `list_entities()` - List with filtering
- `get_entity()` - Get by ID
- `get_entity_by_username()` - Find user
- `get_risky_entities()` - Risk analysis
- `get_external_entities()` - External users
- `get_admin_entities()` - Administrators
- `get_entity_risk_factors()` - Risk breakdown
- `search_entities()` - Search
- `get_entities_by_tag()` - Tagged entities
- `get_entity_activity_timeline()` - Activity history

**DataEnrichmentAPI** (12 methods)
- `list_subnets()` - List all
- `get_subnet()` - Get by ID
- `create_subnet()` - Create
- `update_subnet()` - Update
- `delete_subnet()` - Delete
- `get_subnet_by_name()` - Find by name
- `get_subnets_by_organization()` - Filter by org
- `get_subnets_by_location()` - Filter by location
- `get_subnets_by_category()` - Filter by category
- `bulk_create_subnets()` - Batch create
- `search_subnets()` - Search
- `export_subnets()` - Generate report

### Authentication

**OAuth2 Client Credentials (Recommended)**
- Resource ID: `05a65629-4c1b-48c1-a78b-804c4abdd4af`
- Token endpoint: `https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token`
- Scope: `{resource_id}/.default`
- Automatic token refresh 5 minutes before expiry
- In-memory caching

**Personal API Token (Legacy)**
- Environment variable: `DEFENDER_CLOUD_APPS_TOKEN`
- Format: `Token {token}`
- Mutual exclusivity validation with OAuth2
- Single token per client instance
- Automatic acquisition on first request

### 2. Configuration (`.env.example`)

Updated to document all authentication options:

```bash
# Option 1: Personal API Token (Legacy)
DEFENDER_CLOUD_APPS_TOKEN=your-api-token-here

# Option 2: OAuth2 Client Credentials (Recommended)
DEFENDER_CLOUD_APPS_TENANT_ID=your-tenant-id-here
DEFENDER_CLOUD_APPS_CLIENT_ID=your-client-id-here
DEFENDER_CLOUD_APPS_CLIENT_SECRET=your-client-secret-here
```

### 3. Example Scripts

All four example scripts updated with dual authentication support:

**Files Updated:**
- `examples/list_alerts.py`
- `examples/export_activities.py`
- `examples/list_discovered_apps.py`
- `examples/monitor_public_files.py`

**Implementation Pattern:**
```python
# Try OAuth2 first
tenant_id = os.getenv("DEFENDER_CLOUD_APPS_TENANT_ID")
client_id = os.getenv("DEFENDER_CLOUD_APPS_CLIENT_ID")
client_secret = os.getenv("DEFENDER_CLOUD_APPS_CLIENT_SECRET")

# Fall back to token
api_token = os.getenv("DEFENDER_CLOUD_APPS_TOKEN")

# Determine which to use
if tenant_id and client_id and client_secret:
    client = DefenderCloudAppsClient(
        base_url=base_url,
        tenant_id=tenant_id,
        client_id=client_id,
        client_secret=client_secret,
    )
elif api_token:
    client = DefenderCloudAppsClient(
        base_url=base_url,
        api_token=api_token,
    )
```

## OAuth2 Authentication Flow

### Token Acquisition

1. Client initialized with OAuth2 credentials
2. First API call triggers `_get_headers()`
3. `_get_headers()` calls `_get_oauth_token()`
4. `_get_oauth_token()` constructs OAuth2 request:
   ```
   POST https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token
   
   Parameters:
   - grant_type: client_credentials
   - client_id: {application_id}
   - client_secret: {client_secret}
   - scope: 05a65629-4c1b-48c1-a78b-804c4abdd4af/.default
   ```
5. Azure AD responds with access token and expiry
6. Token cached with expiry timestamp
7. Token included in subsequent API requests via Bearer header

### Token Refresh

1. Before each API request, `_get_headers()` calls `_get_oauth_token()`
2. Method checks if cached token exists and is still valid
3. If token expires within 5 minutes, refresh by acquiring new token
4. Otherwise, return cached token
5. Subsequent requests reuse cached token until expiry window

## Backward Compatibility

- Existing code using `api_token` parameter continues to work unchanged
- Legacy authentication has priority in examples (checks OAuth2 first)
- `.env` files with only `DEFENDER_CLOUD_APPS_TOKEN` work without modification
- Personal API tokens remain fully functional
- No breaking changes to public API

## Security Considerations

### Best Practices Implemented
- Tokens acquired dynamically, not stored at initialization
- Token cache is in-memory only (no disk storage)
- Automatic refresh prevents token expiry during long operations
- Each client instance has independent token management
- Bearer token format follows OAuth2 standards

### User Responsibilities
- Keep client secrets confidential
- Never commit `.env` files to version control
- Use environment variables or secure vaults for secrets
- Rotate client secrets regularly
- Use appropriate API permission scopes in Azure Entra ID

## Testing & Validation

All example scripts tested with OAuth2 credentials:
- ✅ `list_alerts.py` - Successfully acquires and uses OAuth2 token
- ✅ `export_activities.py` - Successfully exports 1518 activities with OAuth2
- ✅ `list_discovered_apps.py` - Successfully authenticates with OAuth2
- ✅ `monitor_public_files.py` - Successfully authenticates with OAuth2

All Python files verified for syntax errors.

## Migration Guide

### From Personal Token to OAuth2

1. **Create Azure Entra ID Application:**
   - Go to Azure Portal > Entra ID > App registrations
   - Create new registration
   - Copy Application (client) ID and Directory (tenant) ID
   - Create client secret under Certificates & secrets

2. **Configure API Permissions:**
   - Add "Microsoft Cloud App Security" API
   - Grant "Investigation.Read" or appropriate scope
   - Grant admin consent

3. **Update `.env` File:**
   ```bash
   # Before
   DEFENDER_CLOUD_APPS_URL=https://...
   DEFENDER_CLOUD_APPS_TOKEN=your-token

   # After
   DEFENDER_CLOUD_APPS_URL=https://...
   DEFENDER_CLOUD_APPS_TENANT_ID=your-tenant-id
   DEFENDER_CLOUD_APPS_CLIENT_ID=your-client-id
   DEFENDER_CLOUD_APPS_CLIENT_SECRET=your-client-secret
   ```

4. **No Code Changes Needed:**
   - Examples automatically detect OAuth2 credentials
   - Existing code continues to work if you keep `DEFENDER_CLOUD_APPS_TOKEN`

## Error Handling

### OAuth2 Specific Errors

**`AuthenticationError` - Token Acquisition Failed**
- Cause: Invalid credentials, permissions, or network issue
- HTTP Status Codes:
  - 400: Invalid request (typo in credentials)
  - 401: Invalid credentials (wrong secret)
  - 403: Insufficient permissions (app lacks API access)
  - 5xx: Azure AD service error
- Solution: Check credentials, verify API permissions, check network

### Validation Errors

**`ValueError` - Authentication Configuration Invalid**
- Missing both `api_token` and OAuth2 credentials
- Solution: Configure exactly one authentication method

**`ValueError` - Mixed Authentication Methods**
- Both `api_token` and OAuth2 credentials provided
- Solution: Choose one authentication method

## Technical References

- [Microsoft Entra OAuth2 Client Credentials Flow](https://learn.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-client-creds-grant-flow)
- [Defender for Cloud Apps API Authentication](https://learn.microsoft.com/en-us/defender-cloud-apps/api-authentication-application)
- [Azure REST API Authentication](https://learn.microsoft.com/en-us/azure/active-directory/develop/active-directory-v2-protocols)

## Future Enhancements

Potential improvements for future versions:
- Token persistence (optional secure storage between runs)
- Refresh token support (if API supports)
- Multi-tenant support for ISV scenarios
- Additional authentication methods (certificate-based)
- Async/await support for concurrent operations
