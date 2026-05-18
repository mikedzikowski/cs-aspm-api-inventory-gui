# ASPM ServiceNow Integration Investigation

## Overview

This investigation explores ServiceNow integration capabilities in the CrowdStrike ASPM (Application Security Posture Management) API. Based on user confirmation that "SERVICENOW ENDPOINT FOR ASPM SHOULD WORK", this analysis provides tools and guidance to discover and test these integration endpoints.

## Investigation Tools Created

### 1. ServiceNow Endpoint Tester (`test_servicenow_endpoints.py`)

**Purpose**: Systematically tests various ServiceNow integration endpoints to identify what's available and functional.

**Usage**:
```bash
# Interactive mode
python3 test_servicenow_endpoints.py

# Command line mode
python3 test_servicenow_endpoints.py <client_id> <client_secret> [base_url]

# Example
python3 test_servicenow_endpoints.py "abc123..." "xyz789..." "https://api.crowdstrike.com"
```

**What it tests**:
- `/aspm-api-gateway/api/v1/integrations/servicenow` - Main ServiceNow integration endpoint
- `/aspm-api-gateway/api/v1/integrations/servicenow/config` - Configuration
- `/aspm-api-gateway/api/v1/integrations/servicenow/status` - Integration status
- `/aspm-api-gateway/api/v1/integrations/servicenow/sync` - Sync status
- `/aspm-api-gateway/api/v1/integrations/servicenow/cmdb` - CMDB data
- `/aspm-api-gateway/api/v1/integrations/servicenow/incidents` - Incidents
- `/aspm-api-gateway/api/v1/integrations/servicenow/assets` - Asset sync
- Alternative API versions (v2) and paths
- Query-based ServiceNow data discovery

**Output**:
- Console report with test results
- JSON file with detailed endpoint responses
- Identifies working vs. failed endpoints
- Shows data structures returned by successful endpoints

### 2. ASPM Data Type Explorer (`explore_aspm_data_types.py`)

**Purpose**: Discovers all available data types in the ASPM API and searches for ServiceNow-related data.

**Usage**:
```bash
# Interactive mode
python3 explore_aspm_data_types.py

# Command line mode
python3 explore_aspm_data_types.py <client_id> <client_secret> [base_url]
```

**What it explores**:
- 50+ potential ASPM data types including:
  - Core: services, interfaces, hosts, assets, applications
  - Network: networkConnections, serviceDependencies
  - Integrations: integrations, externalIntegrations
  - CMDB: cmdb, cmdbItems, inventory
  - Security: vulnerabilities, findings, risks
  - Incidents: incidents, alerts, events
  - Cloud: cloudResources, containers, clusters

**ServiceNow searches**:
- Direct keyword searches: "servicenow", "snow"
- Integration queries: "type:integration servicenow"
- CMDB queries: "cmdb", "external_integration"

**Output**:
- Comprehensive report of available data types
- ServiceNow-specific findings
- Sample data structures for each type
- JSON file with all results
- Text report with recommendations

## Authentication Pattern

Both tools use the standard CrowdStrike OAuth2 authentication flow:

```python
# Authentication endpoint
POST https://api.crowdstrike.com/oauth2/token

# Headers
Content-Type: application/x-www-form-urlencoded

# Body
client_id=<your_client_id>
client_secret=<your_client_secret>
grant_type=client_credentials

# Response
{
  "access_token": "...",
  "token_type": "bearer",
  "expires_in": 1800
}
```

## ASPM API Query Pattern

The ASPM API uses a consistent query pattern based on the `/aspm-api-gateway/api/v1/query` endpoint:

```python
POST /aspm-api-gateway/api/v1/query

# Headers
Authorization: Bearer <access_token>
Content-Type: application/json

# Body
{
  "query": "in:<data_type> [search_terms]",
  "params": {
    "selectFields": {
      "fields": ["*"],
      "withoutServices": false
    },
    "paginate": {
      "limit": 100,
      "offset": 0
    }
  }
}
```

### Known Working Data Types

Based on the existing application (`live_data_server_with_auth.py`), these data types are confirmed to work:

1. **interfaces** - Service interfaces and endpoints
2. **networkConnections** - Network connections between services
3. **serviceDependencies** - Service-to-service dependencies
4. **services** - Application services (implied by interface data)

## Expected ServiceNow Integration Capabilities

Based on typical ASPM ServiceNow integrations, the following capabilities should be available:

### 1. CMDB Synchronization
- Sync discovered assets to ServiceNow CMDB
- Update configuration items (CIs)
- Maintain asset inventory
- Track asset relationships

**Expected endpoints**:
- GET `/aspm-api-gateway/api/v1/integrations/servicenow/cmdb`
- POST `/aspm-api-gateway/api/v1/integrations/servicenow/cmdb/sync`

### 2. Incident Creation
- Automatically create incidents for security findings
- Update incident status based on remediation
- Link incidents to affected assets

**Expected endpoints**:
- GET `/aspm-api-gateway/api/v1/integrations/servicenow/incidents`
- POST `/aspm-api-gateway/api/v1/integrations/servicenow/incidents`

### 3. Asset Discovery Sync
- Push discovered services and hosts to ServiceNow
- Update asset metadata
- Sync deployment information

**Expected endpoints**:
- GET `/aspm-api-gateway/api/v1/integrations/servicenow/assets`
- POST `/aspm-api-gateway/api/v1/integrations/servicenow/assets/sync`

### 4. Configuration Management
- Configure ServiceNow connection details
- Set sync schedules
- Define field mappings

**Expected endpoints**:
- GET `/aspm-api-gateway/api/v1/integrations/servicenow/config`
- PUT `/aspm-api-gateway/api/v1/integrations/servicenow/config`

### 5. Status and Monitoring
- Check integration health
- View sync status
- Monitor error logs

**Expected endpoints**:
- GET `/aspm-api-gateway/api/v1/integrations/servicenow/status`
- GET `/aspm-api-gateway/api/v1/integrations/servicenow/sync`

## How to Run the Investigation

### Step 1: Gather Credentials

You need CrowdStrike API credentials with ASPM permissions:
- Client ID
- Client Secret
- Base URL (usually `https://api.crowdstrike.com`)

### Step 2: Test Direct Endpoints

```bash
# Test ServiceNow-specific endpoints
python3 test_servicenow_endpoints.py

# Follow prompts to enter credentials
# Review output for successful endpoints
```

### Step 3: Explore Data Types

```bash
# Discover available ASPM data types
python3 explore_aspm_data_types.py

# Follow prompts to enter credentials
# Review which data types contain integration information
```

### Step 4: Analyze Results

Review the generated files:
- `servicenow_test_results_<timestamp>.json` - Endpoint test results
- `aspm_data_types_<timestamp>.json` - Data type exploration results
- `aspm_servicenow_report_<timestamp>.txt` - Comprehensive analysis report

## Integration with Existing Application

The existing application (`live_data_server_with_auth.py`) provides:

**Current capabilities**:
- OAuth2 authentication with token caching
- Service discovery via interface queries
- Host-to-service mapping
- Network connection tracking
- Service dependency analysis

**Potential ServiceNow integration points**:

1. **Export service inventory to ServiceNow CMDB**:
   ```python
   # After querying interfaces, push to ServiceNow
   services = query_interfaces_for_service(token, service_name)
   sync_to_servicenow_cmdb(services)
   ```

2. **Create incidents for exposed services**:
   ```python
   # For publicly exposed services, create ServiceNow incidents
   if interface.get('exposed') or interface.get('external'):
       create_servicenow_incident(interface)
   ```

3. **Sync host inventory**:
   ```python
   # Push discovered hosts to ServiceNow
   hosts = query_host_details(token, hostname)
   sync_hosts_to_servicenow(hosts)
   ```

## Expected Data Structures

### ServiceNow Integration Object
```json
{
  "id": "integration-123",
  "type": "servicenow",
  "status": "active",
  "config": {
    "instance_url": "https://company.service-now.com",
    "username": "integration_user",
    "sync_enabled": true,
    "sync_schedule": "0 */6 * * *",
    "cmdb_table": "cmdb_ci",
    "incident_table": "incident"
  },
  "last_sync": "2026-05-17T12:00:00Z",
  "sync_stats": {
    "assets_synced": 1234,
    "incidents_created": 56,
    "errors": 0
  }
}
```

### CMDB Sync Data
```json
{
  "ci_type": "application_service",
  "name": "api.example.com",
  "status": "operational",
  "environment": "production",
  "discovered_by": "crowdstrike_aspm",
  "attributes": {
    "ip_address": "10.0.1.100",
    "port": 443,
    "protocol": "https",
    "owner": "platform-team",
    "criticality": "high"
  },
  "relationships": [
    {
      "type": "depends_on",
      "target": "database-postgres-01"
    }
  ]
}
```

### Incident Creation
```json
{
  "short_description": "Public exposure detected: api.example.com",
  "description": "ASPM discovered publicly exposed service without proper security controls",
  "priority": "2 - High",
  "category": "Security",
  "assignment_group": "Security Operations",
  "cmdb_ci": "api.example.com",
  "source": "crowdstrike_aspm",
  "correlation_id": "aspm-finding-789"
}
```

## API Permissions Required

For ServiceNow integration, your CrowdStrike API credentials likely need:

- **ASPM Read** - Query services, hosts, and interfaces
- **ASPM Write** (optional) - Update integration configurations
- **Integration Read** - View integration status
- **Integration Write** - Configure ServiceNow connection

## Troubleshooting

### Issue: Authentication Fails
```
Error: 401 Unauthorized
```

**Solution**:
- Verify client ID and secret are correct
- Ensure credentials have ASPM API scope
- Check if base URL is correct for your region

### Issue: No ServiceNow Endpoints Found
```
Error: 404 Not Found on all ServiceNow endpoints
```

**Possible causes**:
1. ServiceNow integration not enabled in your ASPM instance
2. Integration requires separate configuration/activation
3. Endpoints use different path structure
4. Feature requires higher tier license

**Actions**:
1. Run data type explorer to find integration data
2. Check ASPM UI for ServiceNow configuration
3. Contact CrowdStrike support for endpoint documentation
4. Review ASPM license/features

### Issue: Empty Results
```
Success: 200 OK, but no data returned
```

**Possible causes**:
1. ServiceNow integration not yet configured
2. No data synced yet
3. Insufficient permissions

**Actions**:
1. Configure ServiceNow integration in ASPM UI
2. Trigger initial sync
3. Verify API permissions

## Next Steps

After running the investigation tools:

1. **Review Results**:
   - Identify working endpoints
   - Analyze data structures returned
   - Note any error patterns

2. **Configure Integration** (if needed):
   - Access ASPM web interface
   - Navigate to Integrations > ServiceNow
   - Enter ServiceNow instance details
   - Configure sync settings

3. **Test Integration**:
   - Trigger manual sync
   - Verify data appears in ServiceNow
   - Test incident creation
   - Validate CMDB updates

4. **Implement in Application**:
   - Add ServiceNow sync functions to `live_data_server_with_auth.py`
   - Create UI for ServiceNow export
   - Add incident creation workflow
   - Implement scheduled syncs

5. **Monitor and Maintain**:
   - Track sync success rates
   - Monitor API rate limits
   - Handle sync errors gracefully
   - Update field mappings as needed

## Reference Documentation

**CrowdStrike API Documentation**:
- Main API: https://falcon.crowdstrike.com/documentation/page/a2a7fc0e/crowdstrike-oauth2-based-apis
- ASPM: Check CrowdStrike portal for ASPM-specific docs

**ServiceNow Integration**:
- ServiceNow REST API: https://docs.servicenow.com/bundle/tokyo-application-development/page/integrate/inbound-rest/concept/c_RESTAPI.html
- CMDB API: https://docs.servicenow.com/bundle/tokyo-servicenow-platform/page/product/configuration-management/reference/cmdb-table-property-descriptions.html

## Support

For additional assistance:
- **CrowdStrike Support**: Access through your CrowdStrike portal
- **API Issues**: Check CrowdStrike API support forums
- **Integration Questions**: Consult CrowdStrike ASPM documentation

## File Inventory

Investigation outputs:
```
/home/miked/aspm-api-query/
├── test_servicenow_endpoints.py          # ServiceNow endpoint tester
├── explore_aspm_data_types.py            # Data type explorer
├── servicenow_test_results_*.json        # Endpoint test results
├── aspm_data_types_*.json                # Data type exploration results
├── aspm_servicenow_report_*.txt          # Analysis report
└── SERVICENOW_INTEGRATION_INVESTIGATION.md  # This document
```

## Conclusion

This investigation provides comprehensive tools to:
1. Test ServiceNow integration endpoints
2. Discover available ASPM data types
3. Identify ServiceNow-related data
4. Document integration capabilities
5. Guide implementation

Run the provided scripts with your CrowdStrike credentials to discover the exact ServiceNow integration capabilities available in your ASPM instance.
