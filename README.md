# 🔍 ASPM Service Inventory

A web application for discovering and managing services using the CrowdStrike ASPM API.

## ✨ Features

- **Service Discovery**: Search services by hostname and platform
- **Host-to-Service Mapping**: Find which services are deployed on hosts
- **Real-time Data**: Live integration with CrowdStrike ASPM API
- **Secure Authentication**: OAuth2-based CrowdStrike authentication
- **Web Interface**: Modern, responsive interface for service exploration

## 🚀 Deployment Options

### Option 1: GitHub Container Registry (Recommended)

```bash
# Pull and run from GitHub Container Registry
docker run -d \
  --name aspm-service-inventory \
  -p 8080:8080 \
  -e CROWDSTRIKE_CLIENT_ID="your_client_id" \
  -e CROWDSTRIKE_CLIENT_SECRET="your_client_secret" \
  ghcr.io/mikedzikowski/aspm-api-inventory:v1.0.0
```

**Access**: http://localhost:8080

### Option 2: Local Docker Build

```bash
# Clone repository
git clone https://github.com/mikedzikowski/cs-aspm-api-inventory-gui.git
cd cs-asmp-api-inventory-gui

# Build and run
docker build -f Dockerfile.secure -t aspm-inventory .
docker run -d \
  --name aspm-service-inventory \
  -p 8080:8080 \
  -e CROWDSTRIKE_CLIENT_ID="your_client_id" \
  -e CROWDSTRIKE_CLIENT_SECRET="your_client_secret" \
  aspm-inventory
```

**Access**: http://localhost:8080

### Option 3: Direct Python Execution

```bash
# Clone repository
git clone https://github.com/mikedzikowski/cs-aspm-api-inventory-gui.git
cd cs-aspm-api-inventory-gui

# Install dependencies
pip install -r requirements.txt

# Run application
PORT=8080 \
CROWDSTRIKE_CLIENT_ID="your_client_id" \
CROWDSTRIKE_CLIENT_SECRET="your_client_secret" \
python3 live_data_server_with_auth.py
```

**Access**: http://localhost:8080

### Option 4: Environment File Configuration

```bash
# Clone repository
git clone https://github.com/mikedzikowski/cs-aspm-api-inventory-gui.git
cd cs-aspm-api-inventory-gui

# Create environment file
cp .env.example .env

# Edit .env with your credentials
nano .env
```

**.env file:**
```env
CROWDSTRIKE_CLIENT_ID=your_client_id_here
CROWDSTRIKE_CLIENT_SECRET=your_client_secret_here
PORT=8080
FLASK_ENV=production
```

```bash
# Run with environment file
python3 live_data_server_with_auth.py
```

## 🔧 Configuration

### Required Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `CROWDSTRIKE_CLIENT_ID` | Your CrowdStrike API Client ID | Yes |
| `CROWDSTRIKE_CLIENT_SECRET` | Your CrowdStrike API Client Secret | Yes |
| `PORT` | Application port (default: 8080) | No |
| `FLASK_ENV` | Flask environment (production/development) | No |

### Custom Port Configuration

```bash
# Run on different port
PORT=9000 CROWDSTRIKE_CLIENT_ID="..." python3 live_data_server_with_auth.py

# Docker with custom port
docker run -d -p 9000:9000 -e PORT=9000 -e CROWDSTRIKE_CLIENT_ID="..." aspm-inventory
```

## 🌐 Usage

1. **Access Application**: Open http://localhost:8080 (or your custom port)
2. **Service Search**:
   - Use the "Search Services" tab
   - Enter service name for discovery
   - View deployment details and metadata
3. **Host Details**:
   - Use the "Host Details" tab
   - Enter hostname to find deployed services
   - View service-to-host mappings

## 🔐 Security Features

- ✅ No hardcoded credentials (environment variable based)
- ✅ OAuth2 authentication with CrowdStrike
- ✅ Non-root container execution
- ✅ Health check monitoring
- ✅ Certificate-free Docker builds

## 🐛 Troubleshooting

### Authentication Issues
```bash
# Verify credentials are set
echo $CROWDSTRIKE_CLIENT_ID

# Test application health
curl http://localhost:8080/
```

### Port Already in Use
```bash
# Use different port
PORT=8181 python3 live_data_server_with_auth.py
```

### Docker Issues
```bash
# Clean Docker environment
docker system prune -f
docker build --no-cache -f Dockerfile.secure -t aspm-inventory .
```

## 📋 API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Web interface |
| `/login` | POST | Authentication |
| `/api/aspm/query` | POST | Service search |
| `/api/aspm/host-details` | POST | Host-to-service mapping |

## 📄 Version Information

- **Version**: 1.0.0
- **Release Date**: 2026-05-16
- **Compatibility**: CrowdStrike ASPM API
- **Container Registry**: ghcr.io/mikedzikowski/aspm-api-inventory

## 🤝 Support

- **Repository**: https://github.com/mikedzikowski/cs-aspm-api-inventory-gui
- **Issues**: Report via GitHub Issues
- **Container Registry**: GitHub Container Registry (GHCR)

## 🎯 Quick Reference

**One-liner deployment:**
```bash
docker run -d --name aspm-inventory -p 8080:8080 -e CROWDSTRIKE_CLIENT_ID="xxx" -e CROWDSTRIKE_CLIENT_SECRET="yyy" ghcr.io/mikedzikowski/aspm-api-inventory:v1.0.0
```

**Local development:**
```bash
git clone https://github.com/mikedzikowski/cs-aspm-api-inventory-gui.git && cd cs-aspm-api-inventory-gui && pip install -r requirements.txt
```

**Health check:**
```bash
curl http://localhost:8080/
```