# ServiceNow Integration Investigation - Quick Start

## What This Is

Investigation tools to discover and test CrowdStrike ASPM ServiceNow integration endpoints and capabilities.

## Quick Start

### Option 1: Run Complete Investigation (Recommended)
```bash
./investigate_servicenow.sh
```
Follow the prompts to enter your CrowdStrike API credentials.

### Option 2: Run Individual Tests

**Test ServiceNow Endpoints**:
```bash
python3 test_servicenow_endpoints.py
```

**Explore Data Types**:
```bash
python3 explore_aspm_data_types.py
```

## What Gets Tested

### ServiceNow Endpoints
- `/aspm-api-gateway/api/v1/integrations/servicenow` - Main integration
- `/aspm-api-gateway/api/v1/integrations/servicenow/config` - Configuration
- `/aspm-api-gateway/api/v1/integrations/servicenow/cmdb` - CMDB sync
- `/aspm-api-gateway/api/v1/integrations/servicenow/incidents` - Incidents
- Plus 10+ more variations and paths

### Data Types
- 50+ ASPM data types including:
  - integrations, services, hosts, assets
  - cmdb, incidents, vulnerabilities
  - networkConnections, serviceDependencies
  - And many more...

## Expected Capabilities

If ServiceNow integration is configured, you should find:

✅ **CMDB Synchronization** - Sync discovered assets to ServiceNow CMDB
✅ **Incident Creation** - Automatically create incidents for findings
✅ **Asset Discovery** - Push services and hosts to ServiceNow
✅ **Configuration Management** - Configure connection and sync settings
✅ **Status Monitoring** - Check integration health and sync status

## Output Files

After running the investigation, you'll get:

```
servicenow_test_results_<timestamp>.json  # Detailed endpoint test results
aspm_data_types_<timestamp>.json          # All available data types
aspm_servicenow_report_<timestamp>.txt    # Human-readable report
```

## Understanding Results

### ✅ Success - Endpoint Returns 200 OK
The endpoint exists and is returning data. Review the response structure to understand what's available.

### ❌ Failed - 404 Not Found
The endpoint doesn't exist at that path. This is normal for exploratory testing.

### ❌ Failed - 401/403
Authentication issue or insufficient permissions.

### ✅ Data Type Found with Count > 0
This data type exists and contains data you can query.

## Common Scenarios

### Scenario 1: ServiceNow Integration is Configured
**Expected**:
- `/integrations/servicenow` endpoints return 200
- Configuration details are available
- Sync status shows recent activity
- CMDB/incident endpoints are functional

**Action**: Review endpoint responses and implement integration

### Scenario 2: ServiceNow Integration Not Configured
**Expected**:
- Most ServiceNow endpoints return 404
- `integrations` data type exists but contains no ServiceNow entries
- No ServiceNow-specific data found

**Action**: Configure ServiceNow integration in ASPM UI first

### Scenario 3: Integration Data in Query Results
**Expected**:
- Direct endpoints return 404
- But `in:integrations` query shows ServiceNow data
- Configuration stored in ASPM data structure

**Action**: Use query interface to access integration data

## Next Steps After Investigation

1. **Review Generated Reports**
   - Check which endpoints work
   - Examine data structures
   - Identify available capabilities

2. **Configure Integration** (if needed)
   - Access ASPM web console
   - Navigate to Integrations → ServiceNow
   - Enter ServiceNow instance details
   - Configure sync settings

3. **Implement in Your Application**
   - Use working endpoints in your code
   - Add ServiceNow export functionality
   - Implement incident creation
   - Set up scheduled syncs

4. **Test Integration**
   - Verify data syncs to ServiceNow
   - Test incident creation
   - Validate CMDB updates
   - Monitor for errors

## Troubleshooting

**Issue**: Authentication fails
```
Solution: Verify credentials have ASPM API scope
```

**Issue**: All endpoints return 404
```
Possible causes:
- ServiceNow integration not enabled
- Integration requires configuration
- Feature not available in your license

Action: Check ASPM UI for integration settings
```

**Issue**: Endpoints work but return empty data
```
Possible causes:
- Integration configured but not synced yet
- No ServiceNow connection established

Action: Configure ServiceNow connection in ASPM UI
```

## Authentication

Tools use standard CrowdStrike OAuth2:
```
POST https://api.crowdstrike.com/oauth2/token
Body: client_id, client_secret, grant_type=client_credentials
Response: access_token (valid for 30 minutes)
```

## Required Credentials

You need:
- **CrowdStrike Client ID** - From Falcon console → Support → API Clients
- **CrowdStrike Client Secret** - Generated when creating API client
- **ASPM API Scope** - Ensure API client has ASPM permissions

## Documentation

For comprehensive details, see:
- `SERVICENOW_INTEGRATION_INVESTIGATION.md` - Full investigation guide
- `README.md` - Main application documentation

## Support

**CrowdStrike API Issues**: Access support through your Falcon console
**Integration Questions**: Consult ASPM documentation in Falcon console
**Tool Issues**: Review error messages and check credentials

## Files in This Investigation

```
investigate_servicenow.sh                 # Quick start script
test_servicenow_endpoints.py              # Endpoint tester
explore_aspm_data_types.py                # Data type explorer
SERVICENOW_INTEGRATION_INVESTIGATION.md   # Full documentation
SERVICENOW_README.md                      # This quick start guide
```

## One-Liner

```bash
./investigate_servicenow.sh
```

That's it! The script will walk you through everything.

---

**Questions?** Review the full investigation documentation in `SERVICENOW_INTEGRATION_INVESTIGATION.md`
