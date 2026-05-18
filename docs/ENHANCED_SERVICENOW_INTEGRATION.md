# Enhanced ServiceNow Integration Guide

## Overview

This enhanced version of the ASPM Service Inventory application provides comprehensive ServiceNow integration capabilities with JSON export functionality for both services and hosts, including complete ASPM-discovered application data.

## 🚀 Enhanced Features

### 1. **Comprehensive Host Data Integration**
- **Falcon Host Details**: Complete host information including IP addresses, OS, platform, agent versions
- **ASPM-discovered Applications**: All applications and services deployed on each host
- **Rich Application Context**: Service technologies, endpoints, interface details, risk scores

### 2. **ServiceNow JSON Export Formats**

#### **For Services (3 formats):**
1. **📋 CMDB CI** - ServiceNow Configuration Item format
2. **🚨 Incident** - ServiceNow Incident ticket format
3. **🔗 Integration** - Complete integration payload format

#### **For Hosts (3 formats):**
1. **📋 Host CMDB CI** - Host Configuration Item with ASPM applications
2. **🚨 Host Incident** - Host security incident format
3. **🔗 Host Integration** - Complete host integration payload

### 3. **Real-time Data Sources**
- **Live ASPM Data**: Real endpoints and applications discovered by CrowdStrike ASPM
- **Live Falcon Data**: Real host information from CrowdStrike Falcon Host Management
- **No Mock Data**: All data comes directly from authenticated API calls

## 📋 Sample Data Structure

### Host with ASPM Applications
```json
{
  "host": {
    "hostname": "frontend-vm",
    "ip_address": "10.0.1.4",
    "external_ip": "20.124.26.186",
    "mac_address": "7c-1e-52-46-bc-bf",
    "os_type": "Ubuntu 22.04",
    "platform": "Linux",
    "agent_version": "7.35.18803.0",
    "bios_version": "Hyper-V UEFI Release v4.1",
    "system_manufacturer": "Microsoft Corporation"
  },
  "deployed_services": [
    {
      "name": "app",
      "service_id": 17179879308,
      "technology": "Gunicorn",
      "service_type": "Application",
      "endpoints_count": 8,
      "sample_endpoints": [
        {
          "path": "/submit-user-data",
          "method": "POST",
          "type": "HTTP",
          "technology": "REST",
          "interface_id": 184683605564
        },
        {
          "path": "/api/metals",
          "method": "GET",
          "type": "HTTP",
          "technology": "REST"
        }
      ]
    }
  ]
}
```

### ServiceNow Host CMDB Export
```json
{
  "name": "frontend-vm",
  "ci_class": "cmdb_ci_computer",
  "operational_status": "1",
  "ip_address": "10.0.1.4",
  "host_name": "frontend-vm",
  "os": "Ubuntu 22.04",
  "manufacturer": "Microsoft Corporation",
  "mac_address": "7c-1e-52-46-bc-bf",
  "u_external_ip": "20.124.26.186",
  "u_agent_version": "7.35.18803.0",
  "u_deployed_applications": [
    {
      "name": "app",
      "service_id": 17179879308,
      "technology": "Gunicorn",
      "service_type": "Application",
      "endpoints_count": 8,
      "sample_endpoints": [...]
    }
  ],
  "u_deployed_applications_count": 2,
  "u_deployed_applications_names": "app, asmp-dotnet-app"
}
```

## 🔧 Technical Implementation

### Enhanced Server Features
- **File**: `live_data_server_enhanced_with_servicenow.py` (172KB)
- **UI Integration**: Complete frontend with export buttons and modal dialogs
- **Backend APIs**: 6 ServiceNow export endpoints
- **Data Integration**: Combines Falcon host data with ASPM application data

### Key API Endpoints
```
POST /api/servicenow/export-service           # Service CMDB CI
POST /api/servicenow/export-incident          # Service Incident
POST /api/servicenow/export-integration       # Service Integration
POST /api/servicenow/export-host-cmdb         # Host CMDB CI
POST /api/servicenow/export-host-incident     # Host Incident
POST /api/servicenow/export-host-integration  # Host Integration
```

## 🚀 Deployment

### Local Deployment
```bash
PORT=5555 CROWDSTRIKE_CLIENT_ID="your-id" CROWDSTRIKE_CLIENT_SECRET="your-secret" \
python3 live_data_server_enhanced_with_servicenow.py
```

### Kubernetes Deployment
```bash
kubectl apply -f k8s/deployment.yaml
```
- **Image**: `ghcr.io/mikedzikowski/aspm-api-inventory:v1.1.0-servicenow`
- **Version**: `v1.1.0-servicenow`

## 🔍 Data Quality

### Real Endpoints Discovered
- `/submit-user-data` - User data submission endpoints
- `/api/metals`, `/api/stocks/<symbol>` - Financial API endpoints
- `/health` - Health check endpoints
- `/api/external-pii-stats` - PII statistics endpoints
- `/api/user/:id` - User management endpoints

### Host Information Available
- **Network**: IP addresses (internal/external), MAC addresses
- **System**: OS versions, BIOS details, manufacturer information
- **Agent**: CrowdStrike agent versions and status
- **Applications**: Complete inventory of deployed services with endpoints

## 📊 ServiceNow Integration Benefits

1. **Complete Asset Inventory**: Hosts with all deployed applications
2. **Security Context**: Risk scores and security findings integration
3. **Change Management**: Track application deployments and changes
4. **Incident Response**: Automatic ticket creation with full context
5. **Compliance**: Complete application and endpoint visibility

## 🔧 Configuration

### Environment Variables
```bash
CROWDSTRIKE_CLIENT_ID="your-falcon-client-id"
CROWDSTRIKE_CLIENT_SECRET="your-falcon-client-secret"
PORT=5555  # Default application port
```

### Authentication
- **Method**: CrowdStrike Falcon OAuth2
- **Scopes**: ASPM API access + Falcon Host Management
- **Session**: Persistent web authentication

## 📈 Usage Analytics

### Performance Metrics
- **Host Search**: ~2-5 seconds with full application data
- **Export Generation**: <1 second for all formats
- **Data Freshness**: Real-time API calls (no caching for data accuracy)
- **Session Management**: Persistent authentication with token caching

### Typical Data Volumes
- **Services per Host**: 1-5 applications typical
- **Endpoints per Service**: 5-20 interfaces typical
- **Export Size**: 2-10KB per host (with applications)

This enhanced integration provides the foundation for complete ServiceNow CMDB population with real-time CrowdStrike security and application posture data.