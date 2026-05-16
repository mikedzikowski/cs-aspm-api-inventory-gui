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

**Access**: <http://localhost:8080>

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

**Access**: <http://localhost:8080>

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

**Access**: <http://localhost:8080>

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

### Option 5: Kubernetes Deployment

#### Quick Deploy with kubectl

```bash
# Create secret for CrowdStrike credentials
kubectl create secret generic crowdstrike-credentials \
  --from-literal=client-id="your_client_id" \
  --from-literal=client-secret="your_client_secret"

# Apply deployment manifests
kubectl apply -f k8s/
```

#### Manual Kubernetes Manifests

**Create namespace (optional):**
```yaml
# k8s/namespace.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: aspm-inventory
```

**Secret for credentials:**
```yaml
# k8s/secret.yaml
apiVersion: v1
kind: Secret
metadata:
  name: crowdstrike-credentials
  namespace: aspm-inventory
type: Opaque
stringData:
  client-id: "your_client_id_here"
  client-secret: "your_client_secret_here"
```

**Deployment:**
```yaml
# k8s/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: aspm-service-inventory
  namespace: aspm-inventory
spec:
  replicas: 2
  selector:
    matchLabels:
      app: aspm-service-inventory
  template:
    metadata:
      labels:
        app: aspm-service-inventory
    spec:
      containers:
      - name: aspm-inventory
        image: ghcr.io/mikedzikowski/aspm-api-inventory:v1.0.0
        ports:
        - containerPort: 8080
        env:
        - name: CROWDSTRIKE_CLIENT_ID
          valueFrom:
            secretKeyRef:
              name: crowdstrike-credentials
              key: client-id
        - name: CROWDSTRIKE_CLIENT_SECRET
          valueFrom:
            secretKeyRef:
              name: crowdstrike-credentials
              key: client-secret
        - name: PORT
          value: "8080"
        livenessProbe:
          httpGet:
            path: /
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 30
        readinessProbe:
          httpGet:
            path: /
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 5
        resources:
          requests:
            memory: "128Mi"
            cpu: "100m"
          limits:
            memory: "512Mi"
            cpu: "500m"
```

**Service:**
```yaml
# k8s/service.yaml
apiVersion: v1
kind: Service
metadata:
  name: aspm-service-inventory
  namespace: aspm-inventory
spec:
  selector:
    app: aspm-service-inventory
  ports:
  - protocol: TCP
    port: 80
    targetPort: 8080
  type: ClusterIP
```

**Ingress (optional):**
```yaml
# k8s/ingress.yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: aspm-service-inventory
  namespace: aspm-inventory
  annotations:
    nginx.ingress.kubernetes.io/rewrite-target: /
spec:
  rules:
  - host: aspm-inventory.yourdomain.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: aspm-service-inventory
            port:
              number: 80
```

#### Helm Chart Deployment

**Create Helm chart:**
```bash
# Create custom values file
cat > values.yaml << EOF
image:
  repository: ghcr.io/mikedzikowski/aspm-api-inventory
  tag: v1.0.0

crowdstrike:
  clientId: "your_client_id"
  clientSecret: "your_client_secret"

ingress:
  enabled: true
  host: aspm-inventory.yourdomain.com

resources:
  requests:
    memory: 128Mi
    cpu: 100m
  limits:
    memory: 512Mi
    cpu: 500m
EOF

# Install with Helm
helm install aspm-inventory ./helm/aspm-inventory -f values.yaml
```

#### OpenShift Deployment

```bash
# Create new project
oc new-project aspm-inventory

# Create secret
oc create secret generic crowdstrike-credentials \
  --from-literal=client-id="your_client_id" \
  --from-literal=client-secret="your_client_secret"

# Deploy application
oc new-app ghcr.io/mikedzikowski/aspm-api-inventory:v1.0.0 \
  --name=aspm-service-inventory

# Set environment variables from secret
oc set env deployment/aspm-service-inventory \
  --from=secret/crowdstrike-credentials

# Expose service
oc expose svc/aspm-service-inventory
```

**Access**: `kubectl port-forward svc/aspm-service-inventory 8080:80` then http://localhost:8080

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