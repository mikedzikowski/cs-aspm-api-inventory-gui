# Kubernetes Deployment Files

This directory contains Kubernetes deployment manifests for the ASPM Service Inventory application.

## Quick Start

```bash
# Create the namespace and secret
kubectl apply -f k8s/namespace.yaml
kubectl apply -f k8s/secret.yaml

# Update the secret with your actual CrowdStrike credentials
kubectl patch secret crowdstrike-credentials -n aspm-inventory \
  --patch='{"stringData":{"client-id":"your_actual_client_id","client-secret":"your_actual_client_secret"}}'

# Deploy the application
kubectl apply -f k8s/
```

## Files Overview

- **namespace.yaml** - Creates the `aspm-inventory` namespace
- **secret.yaml** - CrowdStrike API credentials (update with actual values)
- **deployment.yaml** - Main application deployment with security best practices
- **service.yaml** - ClusterIP service for internal communication
- **ingress.yaml** - Optional ingress for external access (requires NGINX ingress controller)

## Security Features

- Non-root container execution
- Security contexts with dropped capabilities
- Resource limits and requests
- Health checks (startup, liveness, readiness)
- Secure secret management

## Access the Application

```bash
# Port forwarding (for testing)
kubectl port-forward -n aspm-inventory svc/aspm-service-inventory 8080:80

# Access at http://localhost:8080
```

For production use, configure the ingress.yaml file with your domain and deploy it.