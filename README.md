# 🔍 ASPM Service Inventory Web Application

A comprehensive web application for discovering and analyzing services across your infrastructure using the CrowdStrike ASPM (Application Security Posture Management) API.

## ✨ Features

- **🚀 Real-time Service Discovery**: Query CrowdStrike ASPM API by hostname and platform
- **🎯 Dynamic Filtering**: Filter results by API architecture type (REST, SOAP, gRPC, GraphQL, MQ variants) and schema (HTTP/HTTPS)
- **📊 Visual Analytics**: Interactive charts showing architecture breakdown and schema distribution
- **📋 Detailed Results**: Comprehensive service/interface information with expandable details
- **📥 Export Functionality**: Download filtered results as JSON with full metadata
- **🔐 Secure Authentication**: OAuth2 client credentials flow with automatic token refresh
- **📱 Responsive Design**: Works seamlessly on desktop, tablet, and mobile devices
- **🐳 Single Container**: Easy deployment with Docker

## 🏗️ Architecture

**Single Container Design**: Flask backend serving both API endpoints and React frontend static files.

```
📦 Docker Container (Port 5000)
├── 🐍 Flask Backend
│   ├── /api/aspm/query     → CrowdStrike API proxy with pagination
│   ├── /api/aspm/export    → Export functionality
│   ├── /api/health         → Health check endpoint
│   └── OAuth2 authentication & token management
└── ⚛️ React Frontend
    ├── Query panel with hostname/platform selection
    ├── Dynamic filtering by architecture & schema
    ├── Interactive results table with sorting
    ├── Summary dashboard with charts
    └── Export functionality
```

## 🚀 Quick Start (v1.0.0)

### Prerequisites
- Docker and docker-compose
- CrowdStrike ASPM API credentials

### Deploy in 30 seconds
```bash
# 1. Set your credentials
export CROWDSTRIKE_CLIENT_ID="your_client_id"
export CROWDSTRIKE_CLIENT_SECRET="your_client_secret"

# 2. Deploy the application
./deploy-v1.sh

# 3. Test the deployment
./test-production.sh

# 4. Open http://localhost:5000
```

### Manual Setup
```bash
# Alternative: Manual Docker setup
cp .env.example .env
# Edit .env with your credentials

docker-compose up --build
```

## ✨ Features (Production Ready)

- **🔍 Live Service Discovery**: Query services by hostname and platform (Linux, Windows, Azure)
- **📡 Real-time ASPM Data**: Direct integration with CrowdStrike ASPM API - **no local storage**
- **🎯 Smart Schema Detection**: Automatic HTTP/HTTPS detection using ASPM port and certificate data
- **🔧 API Architecture Detection**: Identifies REST, SOAP, gRPC, and other API types
- **📊 Interactive Dashboard**: Modern React interface with sorting, filtering, and visualization
- **📤 Export Capabilities**: Export filtered results with metadata for compliance and audits
- **🐳 Production Deployment**: Containerized with health checks and proper security

# Edit .env with your CrowdStrike credentials
nano .env
```

### 2. Configure Environment Variables

Edit `.env` file:

```bash
CROWDSTRIKE_CLIENT_ID=your_client_id_here
CROWDSTRIKE_CLIENT_SECRET=your_client_secret_here
FLASK_ENV=production
```

### 3. Build and Run

```bash
# Build and start the application
docker-compose up --build

# Or run in detached mode
docker-compose up -d --build
```

### 4. Access Application

Open your browser to: **http://localhost:5000**

## 📖 Usage Guide

### 1. Query Services
- Enter a server hostname (e.g., `webserver01`)
- Select platform: Linux, Windows, or Azure Cloud
- Click "Query Services"

### 2. Filter Results
- Use dynamic filters on the left panel
- Filter by API architecture (REST, SOAP, gRPC, GraphQL, MQ variants)
- Filter by schema (HTTPS, HTTP, Unknown)
- Multiple selections supported
- Active filters displayed as removable tags

### 3. Analyze Results
- **Summary Panel**: Visual breakdown with charts
- **Results Table**: Sortable columns, expandable details
- **Service Details**: Click ▼ to expand detailed information

### 4. Export Data
- **Export Panel**: Download filtered results as JSON
- Includes metadata (query params, filters, timestamp)
- Filename: `aspm_export_{hostname}_{date}.json`

## 🔧 Development

### Local Development Setup

```bash
# Backend development
cd backend
pip install -r requirements.txt
python app.py

# Frontend development (separate terminal)
cd frontend
npm install
npm start
```

**Development URLs:**
- Frontend: http://localhost:3000 (hot reload)
- Backend: http://localhost:5000 (API endpoints)

### Project Structure

```
aspm-api-query/
├── backend/
│   ├── app.py                    # Main Flask application
│   ├── requirements.txt          # Python dependencies
│   ├── services/
│   │   ├── aspm_client.py       # CrowdStrike API client
│   │   └── data_transformer.py  # Data processing logic
│   └── utils/
│       ├── schema_detector.py   # HTTP/HTTPS detection
│       └── architecture_detector.py # API architecture detection
├── frontend/
│   ├── package.json             # React dependencies
│   ├── public/
│   │   └── index.html          # HTML template
│   └── src/
│       ├── App.js              # Main React component
│       ├── hooks/              # Custom React hooks
│       ├── components/         # React UI components
│       └── styles/             # CSS stylesheets
├── Dockerfile                   # Single container build
├── docker-compose.yml          # Development/deployment config
└── .env.example                # Environment template
```

## 📊 API Architecture Detection

The application automatically detects API architecture types using the following logic:

| Architecture | Detection Criteria |
|-------------|-------------------|
| **REST** | Technology contains `rest`/`http`/`api`, or HTTP method + path present |
| **SOAP** | Technology contains `soap`, path contains `wsdl`, or port type contains `soap` |
| **gRPC/RPC** | Technology contains `grpc`, port type contains `grpc`, or port is `50051` |
| **GraphQL** | Technology contains `graphql`, or path contains `/graphql` |
| **MQ (Kafka)** | Technology contains `kafka` |
| **MQ (RabbitMQ)** | Technology contains `rabbitmq` |
| **MQ (Pub/Sub)** | Technology contains `pubsub` |
| **MQ** | Technology contains `mq`/`amqp`/`jms` or interface type contains `queue`/`topic` |
| **Unknown** | Fallback when no patterns match |

## 🔐 Schema Detection

HTTP vs HTTPS detection follows this priority order:

1. **Port Type Analysis**: Check if `port_type` contains `https`/`ssl`/`tls` → **HTTPS**
2. **HTTP Port Type**: Check if `port_type` contains `http` (without `https`) → **HTTP**
3. **Port & Certificate**: Port `443`/`8443` or SSL certificate present → **HTTPS**
4. **HTTP Ports**: Port `80`/`8080` → **HTTP**
5. **Fallback**: → **Unknown**

## 🌐 Deployment Options

### Docker Container Registry

```bash
# Build and tag image
docker build -t aspm-inventory:latest .

# Push to registry
docker tag aspm-inventory:latest your-registry/aspm-inventory:latest
docker push your-registry/aspm-inventory:latest
```

### Cloud Deployment

#### Google Cloud Run
```bash
gcloud run deploy aspm-inventory \
  --image gcr.io/project-id/aspm-inventory:latest \
  --port 5000 \
  --set-env-vars CROWDSTRIKE_CLIENT_ID=xxx,CROWDSTRIKE_CLIENT_SECRET=yyy
```

#### AWS ECS/Fargate
```bash
# Use the provided Dockerfile with ECS task definition
# Set environment variables in ECS task configuration
```

#### Kubernetes
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: aspm-inventory
spec:
  replicas: 1
  selector:
    matchLabels:
      app: aspm-inventory
  template:
    spec:
      containers:
      - name: aspm-inventory
        image: aspm-inventory:latest
        ports:
        - containerPort: 5000
        env:
        - name: CROWDSTRIKE_CLIENT_ID
          valueFrom:
            secretKeyRef:
              name: crowdstrike-creds
              key: client-id
```

## 🔍 API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/health` | GET | Health check and authentication status |
| `/api/aspm/query` | POST | Query ASPM services by hostname/platform |
| `/api/aspm/export` | POST | Export service records with metadata |
| `/` | GET | Serve React frontend application |

### Example API Request

```bash
curl -X POST http://localhost:5000/api/aspm/query \
  -H "Content-Type: application/json" \
  -d '{
    "hostname": "webserver01",
    "platform": "Linux"
  }'
```

## 🐛 Troubleshooting

### Common Issues

**Authentication Errors:**
```bash
# Check credentials
curl http://localhost:5000/api/health

# Verify environment variables
docker-compose exec aspm-app env | grep CROWDSTRIKE
```

**Container Build Issues:**
```bash
# Clean build
docker-compose down
docker system prune -f
docker-compose up --build --no-cache
```

**Frontend Not Loading:**
- Check that React build completed successfully
- Verify Flask is serving static files from `/frontend/build`
- Check browser developer console for errors

**API Rate Limiting:**
- The application implements automatic retry with exponential backoff
- Monitor logs for rate limit messages
- CrowdStrike API has standard rate limits for enterprise customers

### Logs and Debugging

```bash
# View application logs
docker-compose logs -f aspm-app

# Debug mode (development)
FLASK_ENV=development docker-compose up

# Check health endpoint
curl http://localhost:5000/api/health
```

## 📝 Data Model

### Service Record Structure

Each service interface record contains:

```json
{
  "composite_key": "hostname::service_name",
  "service_name": "user-service",
  "hostname": "webserver01",
  "ip_address": "10.0.1.5",
  "path_uri": "/api/users",
  "schema": "HTTPS",
  "api_architecture": "REST",
  "api_method": "GET",
  "port": 443,
  "service_type": "API",
  "technology_type": "REST",
  "region": "us-east-1",
  "cloud_provider": "AWS",
  "risk_score": 25,
  "ssl_certificate_issuer": "Let's Encrypt",
  "dependencies": [...],
  "violations": [...]
}
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature-name`
3. Make changes and test locally
4. Commit changes: `git commit -m "Description"`
5. Push to branch: `git push origin feature-name`
6. Create a Pull Request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🆘 Support

- **Issues**: Report bugs and feature requests via GitHub Issues
- **Documentation**: Additional documentation in the `docs/` folder
- **API Reference**: See `swagger.json` for complete ASPM API specification

## 🎯 Roadmap

- [ ] Real-time progress indicators during API pagination
- [ ] Advanced filtering (by risk score, cloud provider, etc.)
- [ ] Bulk export functionality (CSV, Excel)
- [ ] Scheduled queries and alerting
- [ ] Multi-tenant support
- [ ] API authentication improvements (SSO integration)