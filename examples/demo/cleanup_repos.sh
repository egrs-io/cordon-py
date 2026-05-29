#!/usr/bin/env bash
#
# Delete every `egress-demo-*` repo owned by the authenticated user that
# is older than $MIN_AGE_HOURS (default: 1 hour). Repos that don't match
# the prefix are NEVER touched -- the script lists, filters by name and
# age, then deletes only the matches.
#
# Usage:
#   export EGRESS_DEMO_GITHUB_TOKEN=ghp_...
#   ./examples/demo/cleanup_repos.sh                # delete matches
#   ./examples/demo/cleanup_repos.sh --dry-run      # show what would be deleted
#
# Override the age threshold:
#   MIN_AGE_HOURS=0 ./examples/demo/cleanup_repos.sh    # nuke all matches
set -euo pipefail

if [[ -z "${EGRESS_DEMO_GITHUB_TOKEN:-}" ]]; then
  echo "error: EGRESS_DEMO_GITHUB_TOKEN is not set" >&2
  exit 2
fi

dry_run=false
if [[ "${1:-}" == "--dry-run" ]]; then
  dry_run=true
fi

min_age_hours="${MIN_AGE_HOURS:-1}"

# Paginate /user/repos and collect full_name + created_at for matching repos.
# We rely on python3 only for JSON parsing -- no jq dependency.
candidates=$(python3 - "$min_age_hours" <<'PY'
import json, os, sys, urllib.request, urllib.error, datetime as dt

token = os.environ["EGRESS_DEMO_GITHUB_TOKEN"]
min_age_hours = float(sys.argv[1])
cutoff = dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=min_age_hours)

page = 1
matches = []
while True:
    req = urllib.request.Request(
        f"https://api.github.com/user/repos?per_page=100&page={page}&affiliation=owner",
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    try:
        with urllib.request.urlopen(req) as r:
            repos = json.load(r)
    except urllib.error.HTTPError as e:
        sys.stderr.write(f"error: GitHub API returned HTTP {e.code}\n{e.read().decode()}\n")
        sys.exit(1)
    if not repos:
        break
    for r in repos:
        name = r.get("name", "")
        if not name.startswith("egress-demo-"):
            continue
        created = dt.datetime.fromisoformat(r["created_at"].replace("Z", "+00:00"))
        if created > cutoff:
            continue
        matches.append(r["full_name"])
    if len(repos) < 100:
        break
    page += 1

for m in matches:
    print(m)
PY
)

if [[ -z "$candidates" ]]; then
  echo "no egress-demo-* repos older than ${min_age_hours}h to delete"
  exit 0
fi

count=0
while IFS= read -r full_name; do
  [[ -z "$full_name" ]] && continue
  if $dry_run; then
    echo "DRY-RUN  would delete: $full_name"
  else
    http_code=$(curl -sS -o /dev/null -w "%{http_code}" \
      -X DELETE "https://api.github.com/repos/${full_name}" \
      -H "Accept: application/vnd.github+json" \
      -H "Authorization: Bearer ${EGRESS_DEMO_GITHUB_TOKEN}" \
      -H "X-GitHub-Api-Version: 2022-11-28")
    if [[ "$http_code" == "204" ]]; then
      echo "deleted: $full_name"
    else
      echo "FAILED ($http_code): $full_name" >&2
    fi
  fi
  count=$((count + 1))
done <<< "$candidates"

if $dry_run; then
  echo "dry-run: $count repos matched"
else
  echo "deleted $count repos"
fi
