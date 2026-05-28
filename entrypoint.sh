#!/bin/bash
set -e

echo "Starting Sentinel DevSecOps Action..."

export ANTHROPIC_API_KEY="${INPUT_ANTHROPIC_API_KEY}"
export GITHUB_TOKEN="${INPUT_GITHUB_TOKEN}"
export SENTINEL_ALLOWED_REPO_ROOTS="${GITHUB_WORKSPACE}"

# The GitHub Workspace is mounted by the runner. 
# We run the CLI script with the workspace as the target.
python3 /app/sentinel_cli.py \
    --repo-path "${GITHUB_WORKSPACE}" \
    --auto-pr "${INPUT_AUTO_PR}" \
    --severity "${INPUT_SEVERITY_THRESHOLD}"
