#!/usr/bin/env bash
# Runs a Cedar CLI command in the container, on the repository files.
# Example: tools/cedar-cli/run.sh format --check --policies tests/policies/documents-api/documents.cedar
set -euo pipefail
cd "$(dirname "$0")/../.."

docker run --rm -v "$PWD:/work" -w /work cedar-cli:4.10.0 "$@"
