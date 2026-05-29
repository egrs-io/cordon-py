#!/usr/bin/env bash
#
# Create a fresh disposable GitHub repo for a live demo run.
#
# Usage:
#   export CORDON_DEMO_GITHUB_TOKEN=ghp_...
#   ./examples/demo/setup_repo.sh
#
# On success: prints the new repo's full_name (owner/name) on stdout.
# Anything else (curl progress, errors) goes to stderr.
#
# The new repo is created under the *authenticated user* and is public by
# default (you can pass --private as an arg to make it private). It is
# named egress-demo-<unix-epoch> so the cleanup script can find and
# delete it later.
set -euo pipefail

if [[ -z "${CORDON_DEMO_GITHUB_TOKEN:-}" ]]; then
  echo "error: CORDON_DEMO_GITHUB_TOKEN is not set" >&2
  echo "  export CORDON_DEMO_GITHUB_TOKEN=ghp_..." >&2
  exit 2
fi

private="false"
if [[ "${1:-}" == "--private" ]]; then
  private="true"
fi

name="egress-demo-$(date +%s)"

# Capture both body and HTTP status. Status goes on the last line, body
# above. Using -sS so curl stays quiet on success but still surfaces errors.
response=$(curl -sS -w "\n%{http_code}" \
  -X POST https://api.github.com/user/repos \
  -H "Accept: application/vnd.github+json" \
  -H "Authorization: Bearer ${CORDON_DEMO_GITHUB_TOKEN}" \
  -H "X-GitHub-Api-Version: 2022-11-28" \
  -d "{\"name\":\"${name}\",\"private\":${private},\"auto_init\":true,\"description\":\"disposable repo for an cordon-sdk demo run -- safe to delete\"}")

http_code=$(echo "$response" | tail -n1)
body=$(echo "$response" | sed '$d')

if [[ "$http_code" != "201" ]]; then
  echo "error: GitHub API returned HTTP $http_code" >&2
  echo "$body" >&2
  exit 1
fi

# Extract full_name from the JSON without depending on jq.
full_name=$(echo "$body" | python3 -c 'import json,sys; print(json.load(sys.stdin)["full_name"])')
echo "$full_name"
