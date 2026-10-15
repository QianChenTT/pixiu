#!/bin/bash
# Prints a saved plan's summary for a CI run page: Terraform's own count line, then each
# resource that would change and how. Addresses and actions only, never values: the plan holds
# the node's user data and resource IDs.
# Usage, from infra/pixiu/platform: bash plan-summary.sh <saved plan> <title>
set -euo pipefail

plan_json=$(terraform show -json "$1")

# Counted the way terraform plan counts: a replace is one to add and one to destroy, and reading
# a data source isn't counted
counts=$(jq -r '[.resource_changes[] | select(.mode == "managed") | .change.actions] as $a
  | "Plan: \([$a[] | select(any(.[]; . == "create"))] | length) to add, "
  + "\([$a[] | select(any(.[]; . == "update"))] | length) to change, "
  + "\([$a[] | select(any(.[]; . == "delete"))] | length) to destroy."' <<< "$plan_json")

rows=$(jq -r '.resource_changes[]
  | select(.mode == "managed" and .change.actions != ["no-op"])
  | "| `\(.address)` | \(.change.actions | join(" then ")) |"' <<< "$plan_json")

echo "### $2"
echo
echo "**$counts**"
if [ -n "$rows" ]; then
  echo
  echo "| Resource | Action |"
  echo "|---|---|"
  echo "$rows"
fi
