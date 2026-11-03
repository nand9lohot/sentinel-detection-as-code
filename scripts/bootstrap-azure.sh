#!/usr/bin/env bash
# Creates two Entra app registrations that GitHub Actions can use through OIDC, with no secrets:
#   sdac-reader:   Microsoft Sentinel Reader, for plan and drift checks
#   sdac-deployer: Microsoft Sentinel Contributor, for deployments
# Both roles are scoped to the one workspace. Requires az login with rights to create app
# registrations and role assignments.
set -euo pipefail

usage() {
  echo "Usage: $0 <subscription-id> <resource-group> <workspace-name> <github-owner/repo>" >&2
  exit 1
}
[ "$#" -eq 4 ] || usage

SUBSCRIPTION_ID="$1"
RESOURCE_GROUP="$2"
WORKSPACE="$3"
REPO="$4"
case "$REPO" in
  */*) ;;
  *) usage ;;
esac

SCOPE="/subscriptions/$SUBSCRIPTION_ID/resourceGroups/$RESOURCE_GROUP/providers/Microsoft.OperationalInsights/workspaces/$WORKSPACE"

az account set --subscription "$SUBSCRIPTION_ID"
az resource show --ids "$SCOPE" --query id -o none
TENANT_ID="$(az account show --query tenantId -o tsv)"

# Creates the identity if needed. Prints only the client ID on stdout.
create_identity() {
  local name="$1" role="$2" environment="$3" client_id object_id
  client_id="$(az ad app list --display-name "$name" --query '[0].appId' -o tsv)"
  if [ -z "$client_id" ]; then
    client_id="$(az ad app create --display-name "$name" --query appId -o tsv)"
  fi
  object_id="$(az ad sp list --filter "appId eq '$client_id'" --query '[0].id' -o tsv)"
  if [ -z "$object_id" ]; then
    object_id="$(az ad sp create --id "$client_id" --query id -o tsv)"
  fi

  local subject="repo:$REPO:environment:$environment"
  local existing
  existing="$(az ad app federated-credential list --id "$client_id" --query "[?subject=='$subject'] | length(@)" -o tsv)"
  if [ "$existing" = "0" ]; then
    az ad app federated-credential create --id "$client_id" --parameters "{
      \"name\": \"github-$environment\",
      \"issuer\": \"https://token.actions.githubusercontent.com\",
      \"subject\": \"$subject\",
      \"audiences\": [\"api://AzureADTokenExchange\"]
    }" -o none
  fi

  # Retries because a new service principal can take a moment to replicate.
  local attempt
  for attempt in 1 2 3 4 5 6; do
    if az role assignment create --assignee-object-id "$object_id" --assignee-principal-type ServicePrincipal \
      --role "$role" --scope "$SCOPE" -o none 2>/dev/null; then
      break
    fi
    if [ "$attempt" = "6" ]; then
      echo "Could not assign '$role' to $name." >&2
      exit 1
    fi
    sleep 10
  done
  echo "$client_id"
}

READER_ID="$(create_identity sdac-reader "Microsoft Sentinel Reader" sentinel-read)"
DEPLOYER_ID="$(create_identity sdac-deployer "Microsoft Sentinel Contributor" sentinel-production)"

cat <<NEXT

Azure is ready. To configure GitHub, run:

gh variable set AZURE_TENANT_ID --repo $REPO --body $TENANT_ID
gh variable set AZURE_SUBSCRIPTION_ID --repo $REPO --body $SUBSCRIPTION_ID
gh variable set SENTINEL_RESOURCE_GROUP --repo $REPO --body $RESOURCE_GROUP
gh variable set SENTINEL_WORKSPACE --repo $REPO --body $WORKSPACE
gh api --method PUT repos/$REPO/environments/sentinel-read --silent
gh api --method PUT repos/$REPO/environments/sentinel-production --silent
gh variable set AZURE_CLIENT_ID --repo $REPO --env sentinel-read --body $READER_ID
gh variable set AZURE_CLIENT_ID --repo $REPO --env sentinel-production --body $DEPLOYER_ID

These values are identifiers, not secrets.
NEXT
