Param(
  [Parameter(Mandatory=$false)][string]$Namespace = "securesys",
  [Parameter(Mandatory=$false)][string]$KustomizePath = "k8s/",
  [Parameter(Mandatory=$false)][string]$SecretsTemplate = "k8s/base/secrets.local.yaml.template"
)

$ErrorActionPreference = "Stop"

function Require-Command($name) {
  if (-not (Get-Command $name -ErrorAction SilentlyContinue)) {
    throw "Required command not found in PATH: $name"
  }
}

Require-Command "kubectl"

Write-Host "Applying kustomize resources from $KustomizePath ..."
& kubectl apply -k $KustomizePath

Write-Host "Checking for securesys-secrets in namespace $Namespace ..."
$secret = & kubectl get secret securesys-secrets -n $Namespace -o name 2>$null

if (-not $secret) {
  Write-Host "securesys-secrets not found." -ForegroundColor Yellow
  Write-Host "Template: $SecretsTemplate" -ForegroundColor Yellow
  Write-Host "Create it (example):" -ForegroundColor Yellow
  Write-Host "  kubectl apply -f $SecretsTemplate" -ForegroundColor Yellow
  Write-Host "Then edit the Secret values (or use ExternalSecrets)." -ForegroundColor Yellow
}

Write-Host "Waiting for backend rollout..."
& kubectl rollout status deployment/securesys-backend -n $Namespace

Write-Host "Waiting for worker rollout..."
& kubectl rollout status deployment/securesys-worker -n $Namespace

Write-Host "Waiting for frontend rollout..."
& kubectl rollout status deployment/securesys-frontend -n $Namespace

Write-Host "Done."