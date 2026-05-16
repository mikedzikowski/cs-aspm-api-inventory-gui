# ASPM Service Inventory - V1.0.0 Customer Release

## Overview

The ASPM Service Inventory is a secure web application that integrates with CrowdStrike ASPM API to provide:

- **Service Discovery**: Search for services and view their deployment details
- **Host-to-Service Mapping**: Find which services are deployed on specific hosts
- **Real-time Integration**: Live data from CrowdStrike ASPM API
- **Secure Authentication**: OAuth2-based authentication with CrowdStrike

## Prerequisites

- Python 3.11 or later
- Docker (optional, for containerized deployment)
- CrowdStrike ASPM API credentials (Client ID and Secret)

## Quick Start with Docker (Recommended)

### Option A: Use Pre-built Image from GitHub Container Registry

```bash
# Pull and run the latest release directly from GitHub
docker run -d \
  --name aspm-service-inventory \
  -p 8080:8080 \
  -e CROWDSTRIKE_CLIENT_ID="your_client_id_here" \
  -e CROWDSTRIKE_CLIENT_SECRET="your_client_secret_here" \
  ghcr.io/[YOUR-GITHUB-USERNAME]/aspm-api-query:v1.0.0
```

> **Note**: Replace `[YOUR-GITHUB-USERNAME]` with the actual GitHub username/organization. Images are automatically built and published to GitHub Container Registry on each release.

### Option B: Build Locally

#### 1. Build the Docker Image

```bash
docker build -f Dockerfile.secure -t aspm-service-inventory:v1.0.0 .
```

#### 2. Run the Container

```bash
docker run -d \
  --name aspm-service-inventory \
  -p 8080:8080 \
  -e CROWDSTRIKE_CLIENT_ID="your_client_id_here" \
  -e CROWDSTRIKE_CLIENT_SECRET="your_client_secret_here" \
  aspm-service-inventory:v1.0.0
```

### 3. Access the Application

Open your browser and navigate to: `http://localhost:8080`

## Manual Installation

### 1. Clone/Extract the Application

```bash
# Extract the application files to your desired directory
cd /path/to/aspm-service-inventory
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. Configure Environment Variables

Copy the example environment file:

```bash
cp .env.example .env
```

Edit the `.env` file with your CrowdStrike credentials:

```env
CROWDSTRIKE_CLIENT_ID=your_client_id_here
CROWDSTRIKE_CLIENT_SECRET=your_client_secret_here
FLASK_ENV=production
PORT=8080
```

### 4. Run the Application

```bash
python live_data_server_with_auth.py
```

The application will start on `http://localhost:8080`

## Configuration Options

### Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `CROWDSTRIKE_CLIENT_ID` | Yes | - | Your CrowdStrike API Client ID |
| `CROWDSTRIKE_CLIENT_SECRET` | Yes | - | Your CrowdStrike API Client Secret |
| `PORT` | No | 8080 | Port for the web server |
| `FLASK_ENV` | No | production | Flask environment mode |

### Custom Port

To run on a different port:

```bash
# Using environment variable
export PORT=9000
python live_data_server_with_auth.py

# Or using Docker
docker run -d -p 9000:9000 -e PORT=9000 -e CROWDSTRIKE_CLIENT_ID="..." aspm-service-inventory:v1.0.0
```

## Security Features

✅ **No Hardcoded Secrets**: All credentials are provided via environment variables
✅ **Non-Root Container**: Docker image runs as non-privileged user
✅ **Health Checks**: Built-in container health monitoring
✅ **Secure Authentication**: OAuth2 token-based API authentication

## Usage Guide

### Service Search

1. Navigate to the web interface at `http://localhost:8080`
2. Use the "Search Services" tab
3. Enter a service name (supports partial matching)
4. View deployment details, hosts, and service metadata

### Host-to-Service Mapping

1. Use the "Host Details" tab
2. Enter a hostname to find deployed services
3. View which services are running on that host
4. Access deployment-specific information

### API Endpoints

The application also provides REST API endpoints:

- **POST** `/api/aspm/query` - Service search
- **POST** `/api/aspm/host-details` - Host-to-service mapping

## Troubleshooting

### Authentication Issues

```
Error: Failed to authenticate with CrowdStrike API
```

**Solution**: Verify your Client ID and Secret are correct and have ASPM API permissions.

### Connection Issues

```
Error: Cannot connect to CrowdStrike API
```

**Solution**: Check your network connectivity and firewall settings for HTTPS outbound traffic.

### Port Already in Use

```
Error: Address already in use
```

**Solution**: Use a different port with the `PORT` environment variable.

## Production Deployment

### Security Recommendations

1. **Use HTTPS**: Deploy behind a reverse proxy (nginx, Apache) with SSL/TLS
2. **Network Security**: Restrict network access to authorized users only
3. **Environment Variables**: Use secure secret management for credentials
4. **Monitoring**: Set up logging and monitoring for the application

### Example with nginx

```nginx
server {
    listen 443 ssl;
    server_name your-domain.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    location / {
        proxy_pass http://localhost:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

## Support

For technical support or questions about this application, please contact your system administrator or refer to the CrowdStrike ASMP API documentation.

## Version Information

- **Version**: 1.0.0
- **Release Date**: 2026-05-16
- **Compatibility**: CrowdStrike ASPM API
- **License**: Proprietary