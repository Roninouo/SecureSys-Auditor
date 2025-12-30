# SecureSys Auditor Kubernetes Manifests

This directory contains Kubernetes manifests for deploying SecureSys Auditor in production.

## Directory Structure

```
k8s/
├── base/                    # Base configurations
│   ├── namespace.yaml       # Namespace definition
│   ├── configmap.yaml       # Application configuration
│   ├── secrets.yaml         # Secrets template (use sealed-secrets in prod)
│   └── service-account.yaml # Service account with RBAC
├── backend/                 # Backend API deployment
│   ├── deployment.yaml      # Django API deployment
│   ├── service.yaml         # ClusterIP service
│   ├── hpa.yaml             # Horizontal Pod Autoscaler
│   └── pdb.yaml             # Pod Disruption Budget
├── worker/                  # Celery worker deployment
│   ├── deployment.yaml      # Worker pods
│   ├── hpa.yaml             # Worker autoscaling
│   └── pdb.yaml             # Worker PDB
├── frontend/                # Frontend deployment
│   ├── deployment.yaml      # Nginx serving React
│   ├── service.yaml         # Frontend service
│   └── hpa.yaml             # Frontend autoscaling
├── ingress/                 # Ingress configuration
│   ├── ingress.yaml         # NGINX Ingress
│   └── certificate.yaml     # cert-manager Certificate
├── monitoring/              # Monitoring stack
│   ├── service-monitor.yaml # Prometheus ServiceMonitor
│   └── pod-monitor.yaml     # Pod monitoring
└── kustomization.yaml       # Kustomize overlay
```

## Prerequisites

- Kubernetes cluster 1.25+
- kubectl configured
- cert-manager (for TLS certificates)
- NGINX Ingress Controller
- Prometheus Operator (optional, for monitoring)
- Sealed Secrets or external secrets operator

## Quick Start

### 1. Create namespace and base resources

```bash
kubectl apply -k k8s/
```

### 2. Configure secrets

Before deploying, create the required secrets.

If you use ExternalSecrets, configure [k8s/base/external-secret.yaml](k8s/base/external-secret.yaml).

If you don't have ExternalSecrets/SealedSecrets available, use the local template:

- [k8s/base/secrets.local.yaml.template](k8s/base/secrets.local.yaml.template)

Example (manual creation):

```bash
kubectl create secret generic securesys-secrets \
  --from-literal=DJANGO_SECRET_KEY=<generated> \
  --from-literal=DB_USER=securesys_user \
  --from-literal=DB_PASSWORD=<db-password> \
  --from-literal=WEBHOOK_SECRET=<generated> \
  -n securesys
```

Windows helper script:

```powershell
./scripts/k8s-bootstrap.ps1
```

### 3. Deploy application

```bash
kubectl apply -f k8s/backend/
kubectl apply -f k8s/worker/
kubectl apply -f k8s/frontend/
kubectl apply -f k8s/ingress/
```

### 4. Verify deployment

```bash
kubectl get pods -n securesys
kubectl get hpa -n securesys
kubectl get ingress -n securesys
```

## Resource Recommendations

### Production Sizing (per component)

| Component | Replicas | CPU Request | CPU Limit | Memory Request | Memory Limit |
|-----------|----------|-------------|-----------|----------------|--------------|
| Backend   | 3-10     | 500m        | 2000m     | 512Mi          | 2Gi          |
| Worker    | 2-20     | 250m        | 1000m     | 256Mi          | 1Gi          |
| Frontend  | 2-5      | 100m        | 500m      | 128Mi          | 256Mi        |

### HPA Configuration

- **Backend**: Scale on CPU (70%) and memory (80%), 3-10 replicas
- **Worker**: Scale on CPU (60%) and queue depth (custom metric), 2-20 replicas
- **Frontend**: Scale on CPU (70%), 2-5 replicas

## Monitoring

Deploy ServiceMonitor for Prometheus:

```bash
kubectl apply -f k8s/monitoring/
```

## Troubleshooting

### Check pod status

```bash
kubectl describe pod -l app=securesys-backend -n securesys
kubectl logs -l app=securesys-backend -n securesys --tail=100
```

### Check HPA status

```bash
kubectl describe hpa securesys-backend -n securesys
```

### Check ingress

```bash
kubectl describe ingress securesys -n securesys
```
